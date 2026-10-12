package api

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
)

// sessionCookie holds the sign-in session token for the web UI.
const sessionCookie = "signalith_session"

type userKey struct{}

// routeLogin adds the routes that work without signing in: the sign-in
// page, its static assets, and sign-in and sign-out.
func (s *Server) routeLogin(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	if s.UI != nil {
		mux.HandleFunc("GET /login", s.handleLoginPage)
		// Stylesheets, fonts, the logo and the sign-in script are public so
		// the sign-in page can use them.
		mux.Handle("GET /assets/", http.FileServerFS(s.UI))
		mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/assets/favicon.svg", http.StatusMovedPermanently)
		})
	}
}

func (s *Server) sessions() *auth.Sessions {
	s.authOnce.Do(func() {
		if s.Sessions == nil {
			s.Sessions = auth.NewSessions(s.Config.SessionIdle())
		}
		if s.Limiter == nil {
			s.Limiter = auth.NewLimiter()
		}
	})
	return s.Sessions
}

func (s *Server) limiter() *auth.Limiter {
	s.sessions()
	return s.Limiter
}

// requireAdmin admits requests with a valid sign-in session or HTTP Basic
// credentials. Signed-out browsers are sent to the sign-in page; API
// clients get 401.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok, err := s.authenticate(r)
		if err != nil {
			writeError(w, http.StatusTooManyRequests, err)
			return
		}
		if !ok {
			s.unauthorized(w, r)
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, user)))
	})
}

// authenticate checks the session cookie, then Basic credentials.
// Successful Basic credentials are cached by hash so bcrypt runs once per
// password; failures count toward the sign-in limit.
func (s *Server) authenticate(r *http.Request) (string, bool, error) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if ss, ok := s.sessions().Lookup(c.Value); ok {
			return ss.User, true, nil
		}
	}
	user, pass, ok := r.BasicAuth()
	if !ok {
		return "", false, nil
	}
	key := sha256.Sum256([]byte(user + "\x00" + pass + "\x00" + s.Config.Auth.AdminPasswordHash))
	if _, hit := s.authCache.Load(key); hit {
		return user, true, nil
	}
	client := clientIP(r)
	if allowed, wait := s.limiter().Allow(client); !allowed {
		return "", false, lockedOut(wait)
	}
	if !s.Config.CheckPassword(user, pass) {
		s.limiter().Fail(client)
		return "", false, nil
	}
	s.limiter().Succeed(client)
	s.authCache.Store(key, struct{}{})
	return user, true, nil
}

func lockedOut(wait time.Duration) error {
	return fmt.Errorf("too many failed sign-ins from this address; try again in %d minutes", int(math.Ceil(wait.Minutes())))
}

func (s *Server) unauthorized(w http.ResponseWriter, r *http.Request) {
	browser := r.Header.Get("Sec-Fetch-Mode") != ""
	if !strings.HasPrefix(r.URL.Path, "/api/") && (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		(r.Header.Get("Sec-Fetch-Mode") == "navigate" || strings.Contains(r.Header.Get("Accept"), "text/html")) {
		next := r.URL.RequestURI()
		target := "/login"
		if next != "/" {
			target += "?next=" + url.QueryEscape(next)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}
	if !browser {
		// Only non-browser clients get the Basic challenge; in a browser it
		// would pop up the native password dialog instead of the sign-in page.
		w.Header().Set("WWW-Authenticate", `Basic realm="Signalith", charset="UTF-8"`)
	}
	writeError(w, http.StatusUnauthorized, errors.New("sign in required"))
}

// sameOrigin rejects state-changing requests a browser sent from another
// site. Requests without browser headers (API clients) pass.
func sameOrigin(r *http.Request) bool {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return true
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin" || site == "none"
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		u, err := url.Parse(origin)
		return err == nil && strings.EqualFold(u.Host, r.Host)
	}
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) secureCookie(r *http.Request) bool {
	return r.TLS != nil || strings.HasPrefix(s.Config.Server.PublicURL, "https://") ||
		strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Remember bool   `json:"remember"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	client := clientIP(r)
	lim := s.limiter()
	if allowed, wait := lim.Allow(client); !allowed {
		w.Header().Set("Retry-After", fmt.Sprint(int(math.Ceil(wait.Seconds()))))
		writeError(w, http.StatusTooManyRequests, lockedOut(wait))
		return
	}
	user := strings.TrimSpace(req.Username)
	if !s.Config.CheckPassword(user, req.Password) {
		locked := lim.Fail(client)
		s.Log.Warn("sign-in failed", "user", user, "client", client, "locked_out", locked)
		writeError(w, http.StatusUnauthorized, errors.New("wrong username or password"))
		return
	}
	lim.Succeed(client)
	token := s.sessions().Create(user, req.Remember)
	c := &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)}
	if req.Remember {
		c.MaxAge = int(s.sessions().MaxAge.Seconds())
	}
	http.SetCookie(w, c)
	s.Log.Info("signed in", "user", user, "client", client)
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, errors.New("cross-site request refused"))
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions().Delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Secure: s.secureCookie(r)})
	writeJSON(w, http.StatusOK, map[string]any{})
}

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if _, ok := s.sessions().Lookup(c.Value); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	page, err := fs.ReadFile(s.UI, "login.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

// userOf returns the signed-in user.
func userOf(r *http.Request) string {
	if u, ok := r.Context().Value(userKey{}).(string); ok && u != "" {
		return u
	}
	if u, _, ok := r.BasicAuth(); ok {
		return u
	}
	return "unknown"
}

// authMethod reports how the request signed in, so the UI knows whether
// signing out means anything.
func authMethod(r *http.Request) string {
	if _, err := r.Cookie(sessionCookie); err == nil {
		if _, _, basic := r.BasicAuth(); !basic {
			return "session"
		}
	}
	return "basic"
}
