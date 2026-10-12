package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/clientaddr"
)

// viaTrustedProxy reports whether a request came through a reverse proxy
// listed in server.trusted_proxies that says the browser used HTTPS.
// X-Forwarded-Proto from anyone else is ignored, since any client can
// send it.
func (s *Server) viaTrustedProxy(r *http.Request) bool {
	proto, _, _ := strings.Cut(r.Header.Get("X-Forwarded-Proto"), ",")
	if !strings.EqualFold(strings.TrimSpace(proto), "https") {
		return false
	}
	from := clientaddr.Parse(r.RemoteAddr)
	return from.IsValid() && s.Config.Server.TrustsProxy(from)
}

// overHTTPS reports whether the browser reached Signalith over HTTPS:
// directly, or through a trusted proxy.
func (s *Server) overHTTPS(r *http.Request) bool {
	return r.TLS != nil || s.viaTrustedProxy(r)
}

type plaintextKey struct{}

// plaintextIngest reports whether an ingest request came over plain HTTP
// to the HTTPS port (see PlainHandler).
func plaintextIngest(r *http.Request) bool {
	v, _ := r.Context().Value(plaintextKey{}).(bool)
	return v
}

// PlainHandler answers plain HTTP on the port that serves HTTPS, so
// http:// addresses keep working without ever handling a password or
// session in clear text. secure is the handler from Handler.
//
//   - Browsers asking for a page are sent to the same address over HTTPS.
//   - Sign-in, and any request carrying a password (HTTP Basic) or a
//     session for the API, is refused with a message to use https://.
//   - Agents may still send events when server.tls.plaintext_ingest is
//     allow; each one is noted so the Health page can name it. Otherwise
//     they are told to get a new config from the Add data page.
//   - A trusted reverse proxy that says the browser used HTTPS is served
//     as usual.
func (s *Server) PlainHandler(secure http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.viaTrustedProxy(r) {
			secure.ServeHTTP(w, r)
			return
		}
		target := s.httpsURL(r)
		route := r.Method + " " + r.URL.Path
		if route == "POST /api/ingest" {
			if s.Config.Server.PlaintextIngest() {
				secure.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), plaintextKey{}, true)))
				return
			}
			plainRefusal(w, r, http.StatusUpgradeRequired, "This server only accepts events over HTTPS. Get a new configuration for this agent "+
				"from the Add data page (it sends to "+s.httpsBase(r)+"), or, until every agent has one, set server.tls.plaintext_ingest: allow.")
			return
		}
		_, _, basic := r.BasicAuth()
		_, err1 := r.Cookie(sessionCookie)
		_, err2 := r.Cookie(secureSessionCookie)
		hasSession := err1 == nil || err2 == nil
		switch {
		case basic || route == "POST /api/login":
			plainRefusal(w, r, http.StatusForbidden, "Signalith only accepts passwords over HTTPS, so this was refused. Use "+target+" instead.")
		case hasSession && strings.HasPrefix(r.URL.Path, "/api/"):
			plainRefusal(w, r, http.StatusForbidden, "Signalith only accepts sessions over HTTPS, so this was refused. Use "+target+" instead.")
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			if hasSession {
				// A session cookie from when this server spoke plain HTTP:
				// it is no use now, so the browser forgets it.
				http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			}
			http.Redirect(w, r, target, http.StatusPermanentRedirect)
		default:
			plainRefusal(w, r, http.StatusForbidden, "Signalith only answers this over HTTPS. Use "+target+" instead.")
		}
	})
}

// plainRefusal answers a plain-HTTP request that must use HTTPS, as JSON
// for the API and as text otherwise.
func plainRefusal(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeError(w, status, errors.New(msg))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(msg + "\n"))
}

// httpsBase is https:// and the host and port the client asked for, the
// same port serving HTTPS; or public_url's when the Host header is not a
// usable host and port.
func (s *Server) httpsBase(r *http.Request) string {
	if host := r.Host; validHostHeader(host) {
		return "https://" + host
	}
	if u, err := url.Parse(s.Config.Server.PublicURL); err == nil && u.Host != "" {
		return "https://" + u.Host
	}
	return "https://localhost"
}

// httpsURL is the address of the request over HTTPS.
func (s *Server) httpsURL(r *http.Request) string {
	return s.httpsBase(r) + r.URL.RequestURI()
}

// validHostHeader accepts host or host:port made of the characters host
// names and IP addresses use, so a redirect cannot be bent elsewhere.
func validHostHeader(h string) bool {
	if h == "" || len(h) > 300 {
		return false
	}
	for _, c := range h {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune(".-_:[]", c)) {
			return false
		}
	}
	host := h
	if strings.Count(h, ":") > 1 && !strings.HasPrefix(h, "[") {
		return false // an IPv6 address needs brackets
	}
	if strings.HasPrefix(h, "[") || strings.Count(h, ":") == 1 {
		hh, port, err := net.SplitHostPort(h)
		if err != nil || port == "" {
			return false
		}
		host = hh
	}
	return host != ""
}
