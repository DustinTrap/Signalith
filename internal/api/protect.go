package api

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// contentSecurityPolicy lets pages load only Signalith's own scripts,
// styles, fonts and images, never be framed, and never submit forms or
// change their base URL to another site.
const contentSecurityPolicy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets the browser protections on every response,
// including the sign-in page and errors.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		if r.TLS != nil || strings.HasPrefix(s.Config.Server.PublicURL, "https://") {
			// Browsers then use only HTTPS for this site for a year. They
			// ignore the header over plain HTTP or with a certificate
			// they had to be told to accept.
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			// API replies carry events, cases and the ingest token; keep
			// them out of the browser's disk cache.
			h.Set("Cache-Control", "no-store")
			if r.URL.Path == "/api/logout" && r.Method == http.MethodPost {
				// Signing out also empties the browser's cache of this
				// site. Stored preferences such as the theme stay.
				h.Set("Clear-Site-Data", `"cache"`)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// revalidate makes browsers check with the server before reusing a cached
// copy of a signed-in file, so after signing out the app sends them to the
// sign-in page instead of showing a stale copy. Pages themselves are not
// stored at all, so Back after signing out cannot bring one up.
func revalidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "/" || strings.HasSuffix(p, ".html") {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		next.ServeHTTP(w, r)
	})
}

// Request body deadlines. The http.Server has no ReadTimeout because, once
// it passes, net/http also cancels the request's context, which would stop
// long searches; instead each request body gets its own deadline here.
var (
	// bodyTimeout is how long a client has to send a request body: ample
	// for any JSON request, and short enough that a client trickling a
	// body (to the sign-in form, say) cannot hold a connection for long.
	bodyTimeout = time.Minute
	// uploadTimeout is how long a signed-in upload (asset lists,
	// indicators) may take to arrive over a slow link. Agent batches have
	// their own, shorter, deadline (ingestReadTimeout in server.go)
	// because each holds one of the pipeline's slots while it arrives.
	uploadTimeout = 10 * time.Minute
)

// limitBodies gives each request body bodyTimeout to arrive.
func limitBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			rc := http.NewResponseController(w)
			if rc.SetReadDeadline(time.Now().Add(bodyTimeout)) == nil {
				r.Body = &deadlineBody{ReadCloser: r.Body, rc: rc}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// allowSlowUpload gives the request body uploadTimeout to arrive. Call it
// only once the client has proved who it is.
func allowSlowUpload(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(uploadTimeout))
}

// deadlineBody lifts the read deadline once the whole body has arrived.
// After the body, net/http keeps reading the connection in the background
// to notice a client that goes away, and a deadline passing there would
// cancel a long-running request.
type deadlineBody struct {
	io.ReadCloser
	rc   *http.ResponseController
	done bool
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF && !b.done {
		b.done = true
		_ = b.rc.SetReadDeadline(time.Time{})
	}
	return n, err
}
