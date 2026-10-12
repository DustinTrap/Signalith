package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/httpserver"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// The server restarts itself when the Settings page asks: it builds every
// component again from the saved settings inside the same process, so a
// restart works the same under Docker, systemd, a Windows service or a
// terminal, with nothing outside to restart it. Sign-in sessions, the
// failed sign-in limits and the user store carry over, so admins stay
// signed in.
//
// A restart first checks that the new settings cannot lock anyone out:
// the new web address can be listened on, and OpenSearch answers with the
// new connection settings. If not, nothing changes and the page says why.
// Then the old components stop and new ones start; if they cannot, the
// previous settings are started again.

// Timings of a restart; tests shorten them.
var (
	// restartDelay lets the answer to "restart" reach the browser first.
	restartDelay = 200 * time.Millisecond
	// drainWait is how long a restart waits for requests in progress.
	drainWait = 5 * time.Second
	// oldAddressGrace is how long the old web address keeps answering
	// after a move, so the page there can learn where to go.
	oldAddressGrace = 30 * time.Second
	// pauseLimit is how long a request waits for a restart to finish
	// before it is answered 503.
	pauseLimit = 30 * time.Second
)

// runner runs the server and restarts it in-process.
type runner struct {
	path    string
	log     *slog.Logger
	started time.Time

	// These carry over a restart.
	sessions *auth.Sessions
	limiter  *auth.Limiter
	people   *users.Store

	front *front
	// cert is the web server's certificate, loaded again on each restart.
	cert atomic.Pointer[tls.Certificate]

	requests chan restartRequest
	mu       sync.Mutex
	busy     bool
	last     *api.RestartResult

	// Owned by run.
	cur     *instance
	web     *webServer
	retired sync.WaitGroup // old web servers still answering for a while

	// failStart, for tests, makes starting with a config fail.
	failStart func(*config.Config) error
}

type restartRequest struct{ by, client string }

func newRunner(path string, log *slog.Logger) *runner {
	return &runner{
		path: path, log: log, started: time.Now(),
		sessions: auth.NewSessions(12 * time.Hour), limiter: auth.NewLimiter(),
		front: &front{}, requests: make(chan restartRequest, 1),
	}
}

// Restart implements api.Restarter.
func (r *runner) Restart(by, client string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy {
		return api.ErrRestarting
	}
	r.busy = true
	go func() {
		time.Sleep(restartDelay)
		r.requests <- restartRequest{by: by, client: client}
	}()
	return nil
}

// RestartStatus implements api.Restarter.
func (r *runner) RestartStatus() api.RestartStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return api.RestartStatus{InProgress: r.busy, Last: r.last}
}

// run serves until ctx ends, restarting when asked.
func (r *runner) run(ctx context.Context, c *config.Config) error {
	in, ln, err := r.open(ctx, c)
	if err != nil && len(c.PageKeys()) > 0 {
		// Settings saved on the Settings page must not keep Signalith from
		// starting, which would also lock everyone out of the page that
		// can fix them: start with signalith.yaml alone, and say why there.
		r.log.Error("Signalith could not start with the settings saved on the Settings page; starting with signalith.yaml alone",
			"err", err, "settings", strings.Join(c.PageKeys(), ","), "file", c.SettingsFile())
		base, berr := config.LoadWithoutPage(r.path, fmt.Sprintf("Signalith could not start with them (%v)", err))
		if berr != nil {
			return err
		}
		c = base
		in, ln, err = r.open(ctx, c)
	}
	if err != nil {
		return err
	}
	r.cur = in
	r.front.resume(in.handler)
	r.web = r.serveWeb(c, ln)
	r.log.Info("signalith listening", "addr", ln.Addr().String(), "ui", c.Server.PublicURL, "version", version)
	for {
		select {
		case err := <-r.web.errc:
			r.cur.stop()
			r.retired.Wait()
			return err
		case req := <-r.requests:
			if err := r.restart(ctx, req); err != nil {
				r.log.Error("Signalith stopped: it could not start with the new settings or the previous ones", "err", err)
				r.shutdown()
				return err
			}
		case <-ctx.Done():
			r.log.Info("shutting down")
			return r.shutdown()
		}
	}
}

// open loads the web server's certificate, listens on the web address
// and starts the components.
func (r *runner) open(ctx context.Context, c *config.Config) (*instance, net.Listener, error) {
	cert, err := loadCert(c)
	if err != nil {
		return nil, nil, err
	}
	ln, err := httpserver.Listen(c.Server.Listen, webLimits(c), r.log)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot listen on %s: %w", c.Server.Listen, opError(err))
	}
	in, err := r.start(ctx, c)
	if err != nil {
		ln.Close()
		return nil, nil, err
	}
	r.cert.Store(cert)
	return in, ln, nil
}

// shutdown stops the web server and the components.
func (r *runner) shutdown() error {
	var err error
	if r.web != nil {
		err = r.web.close(10 * time.Second)
	}
	if r.cur != nil {
		r.cur.stop()
	}
	r.retired.Wait()
	return err
}

// finish records how a restart went.
func (r *runner) finish(res *api.RestartResult) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last, r.busy = res, false
}

// restart applies the saved settings. Problems found before the switch
// keep everything as it was; a failure after it goes back to the previous
// settings. It returns an error only when neither can run.
func (r *runner) restart(ctx context.Context, req restartRequest) error {
	start := time.Now()
	res := &api.RestartResult{At: start.UTC(), By: req.by, Keys: []string{}}
	paused := false
	defer func() {
		res.TookMS = time.Since(start).Milliseconds()
		if res.OK {
			r.log.Info("restarted with the saved settings", "audit", true, "by", req.by, "client", req.client, "settings", strings.Join(res.Keys, ","), "took_ms", res.TookMS)
		} else {
			r.log.Error("restart failed", "audit", true, "by", req.by, "client", req.client, "settings", strings.Join(res.Keys, ","), "rolled_back", res.RolledBack, "reason", res.Error)
		}
		// The result is in place before the requests held back go through,
		// so the page sees it at once.
		r.finish(res)
		if paused {
			r.front.resume(r.cur.handler)
		}
	}()
	old := r.cur
	// The settings in use, including those applied at once from the
	// Settings page since the last start.
	prev := old.srv.Running()
	next, err := config.Load(r.path)
	if err != nil {
		res.Error = fmt.Sprintf("The saved settings could not be loaded (%v). Signalith kept running with the previous settings.", err)
		return nil
	}
	if p := next.SettingsProblem(); p != "" {
		res.Error = "The settings saved on the Settings page cannot be used, so Signalith kept running with the previous settings. " + p
		return nil
	}
	res.Keys = changedSettings(prev, next)
	r.log.Info("restarting to apply the saved settings", "by", req.by, "settings", strings.Join(res.Keys, ","))
	plan, err := r.check(ctx, prev, next)
	if err != nil {
		res.Error = err.Error()
		return nil
	}

	// Switch: hold new requests back, stop the old components, start new ones.
	r.front.pause(drainWait)
	paused = true
	old.stop()
	in, err := r.start(ctx, next)
	if err == nil && plan.moveWeb && plan.ln == nil {
		// The new address takes the old one's port: free it, then listen.
		r.web.close(5 * time.Second)
		plan.ln, err = httpserver.Listen(next.Server.Listen, webLimits(next), r.log)
		if err != nil {
			in.stop()
			err = fmt.Errorf("cannot listen on %s: %w", next.Server.Listen, err)
			back, lerr := httpserver.Listen(prev.Server.Listen, webLimits(prev), r.log)
			if lerr != nil {
				return fmt.Errorf("%v, and the previous address %s cannot be listened on again: %w", err, prev.Server.Listen, lerr)
			}
			r.web = r.serveWeb(prev, back)
		}
	}
	if err != nil {
		res.RolledBack = true
		res.Error = fmt.Sprintf("Signalith could not start with the saved settings (%v), so it went back to the previous settings.", err)
		if plan.ln != nil {
			plan.ln.Close()
		}
		back, err2 := r.start(ctx, prev)
		if err2 != nil {
			return fmt.Errorf("with the saved settings: %v; with the previous ones: %w", err, err2)
		}
		r.cur = back
		return nil
	}
	if plan.cert != nil {
		r.cert.Store(plan.cert)
	}
	if plan.moveWeb {
		prev := r.web
		r.web = r.serveWeb(next, plan.ln)
		r.log.Info("signalith listening", "addr", plan.ln.Addr().String(), "ui", next.Server.PublicURL, "version", version)
		if prev.open() {
			// The page at the old address asks how the restart went
			// before it moves; then the old address closes.
			r.retired.Go(func() {
				select {
				case <-time.After(oldAddressGrace):
				case <-ctx.Done():
				}
				prev.close(10 * time.Second)
			})
		}
	}
	r.cur = in
	res.OK = true
	return nil
}

// plan is what the checks before a restart prepared.
type plan struct {
	// moveWeb is true when the web listener changes. ln is the new one,
	// already listening, or nil when it takes the old one's port and must
	// wait for it to close.
	moveWeb bool
	ln      net.Listener
	cert    *tls.Certificate
}

// check makes sure the new settings cannot lock anyone out before
// anything stops: the web page and syslog can listen on their new
// addresses, the certificate loads, and OpenSearch answers with the new
// connection settings.
func (r *runner) check(ctx context.Context, old, next *config.Config) (*plan, error) {
	const kept = "Signalith kept running with the previous settings."
	p := &plan{}
	cert, err := loadCert(next)
	if err != nil {
		return nil, fmt.Errorf("%v. %s", sentenceOf(err), kept)
	}
	p.cert = cert
	if webMoves(old, next) {
		p.moveWeb = true
		ln, err := httpserver.Listen(next.Server.Listen, webLimits(next), r.log)
		switch {
		case err == nil:
			p.ln = ln
		case samePort(old.Server.Listen, next.Server.Listen):
			// Listening on it waits for the old listener to close.
		default:
			return nil, fmt.Errorf("Signalith cannot listen on %s (%v). %s Choose another address or port.", next.Server.Listen, opError(err), kept)
		}
	}
	fail := func(err error) (*plan, error) {
		if p.ln != nil {
			p.ln.Close()
		}
		return nil, err
	}
	if openSearchMoves(old, next) {
		rep := store.Check(ctx, store.Config{URL: next.OpenSearch.URL, Username: next.OpenSearch.Username,
			Password: next.OpenSearch.Password, TLSSkipVerify: next.OpenSearch.TLSSkipVerify})
		if !rep.OK {
			return fail(fmt.Errorf("OpenSearch did not answer with the new settings: %s %s", rep.Message, kept))
		}
	}
	// New syslog addresses must be free; one that takes a port Signalith
	// uses now is freed by the switch.
	inUse := []string{old.Syslog.UDP, old.Syslog.TCP, old.Syslog.TLS, old.Server.Listen}
	for _, l := range []struct{ setting, network, addr string }{
		{"syslog.udp", "udp", next.Syslog.UDP}, {"syslog.tcp", "tcp", next.Syslog.TCP}, {"syslog.tls", "tcp", next.Syslog.TLS},
	} {
		if l.addr == "" || slices.ContainsFunc(inUse, func(a string) bool { return samePort(a, l.addr) }) {
			continue
		}
		if err := tryListen(l.network, l.addr); err != nil {
			return fail(fmt.Errorf("Signalith cannot receive syslog on %s/%s (%v). %s Choose another address or port for %s.", l.addr, l.network, opError(err), kept, l.setting))
		}
	}
	return p, nil
}

// tryListen checks that an address can be listened on.
func tryListen(network, addr string) error {
	if network == "udp" {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	return ln.Close()
}

// opError is the reason in a listen error, without the address again.
func opError(err error) error {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err
	}
	return err
}

func sentenceOf(err error) string {
	s := err.Error()
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// loadCert loads the web server's certificate, or returns nil without TLS.
func loadCert(c *config.Config) (*tls.Certificate, error) {
	if c.Server.TLSCert == "" || c.Server.TLSKey == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.Server.TLSCert, c.Server.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("the certificate in server.tls_cert and server.tls_key cannot be used: %w", err)
	}
	return &cert, nil
}

// webMoves reports whether the web listener changes: another address, or
// HTTPS turned on or off.
func webMoves(old, next *config.Config) bool {
	tlsOn := func(c *config.Config) bool { return c.Server.TLSCert != "" && c.Server.TLSKey != "" }
	return old.Server.Listen != next.Server.Listen || tlsOn(old) != tlsOn(next) ||
		old.Server.MaxConnections != next.Server.MaxConnections || !slices.Equal(old.Server.SharedAddresses, next.Server.SharedAddresses)
}

// webLimits are the connection limits of the web listener.
func webLimits(c *config.Config) httpserver.Limits {
	return httpserver.Limits{Max: c.Server.MaxConnections, Shared: c.Server.SharedList()}
}

// openSearchMoves reports whether the OpenSearch connection changes.
func openSearchMoves(old, next *config.Config) bool {
	a, b := old.OpenSearch, next.OpenSearch
	return a.URL != b.URL || a.Username != b.Username || a.Password != b.Password || a.TLSSkipVerify != b.TLSSkipVerify
}

// samePort reports whether two listen addresses use the same port.
func samePort(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	_, pa, err1 := net.SplitHostPort(a)
	_, pb, err2 := net.SplitHostPort(b)
	return err1 == nil && err2 == nil && pa == pb && pa != "0"
}

// changedSettings lists the page's settings that differ between two
// configs, for the log and the restart result.
func changedSettings(a, b *config.Config) []string {
	out := []string{}
	for _, s := range config.Registry {
		if !config.SameValue(a, b, s.Key) {
			out = append(out, s.Key)
		}
	}
	return out
}

// webServer is one web listener.
type webServer struct {
	hs     *http.Server
	errc   chan error
	closed atomic.Bool
}

// serveWeb serves the front handler on ln, with HTTPS when c has a
// certificate.
func (r *runner) serveWeb(c *config.Config, ln net.Listener) *webServer {
	w := &webServer{hs: httpserver.New(r.front, webLimits(c), r.log), errc: make(chan error, 1)}
	useTLS := c.Server.TLSCert != "" && c.Server.TLSKey != ""
	if useTLS {
		// The certificate is read again on each restart.
		w.hs.TLSConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return r.cert.Load(), nil
		}
	}
	go func() {
		var err error
		if useTLS {
			err = w.hs.ServeTLS(ln, "", "")
		} else {
			err = w.hs.Serve(ln)
		}
		if w.closed.Load() && errors.Is(err, http.ErrServerClosed) {
			return
		}
		w.errc <- err
	}()
	return w
}

func (w *webServer) open() bool { return !w.closed.Load() }

// close stops the listener and waits up to wait for requests in progress.
func (w *webServer) close(wait time.Duration) error {
	if w.closed.Swap(true) {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return w.hs.Shutdown(ctx)
}

// front is the handler every web listener serves. It passes requests to
// the current components and holds new ones back while a restart swaps
// them.
type front struct {
	mu       sync.Mutex
	h        http.Handler
	paused   chan struct{} // closed when a pause ends; nil when not paused
	inflight int
	idle     chan struct{} // closed when the last request in progress ends
}

func (f *front) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := f.enter(r)
	if h == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "5")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Signalith is restarting. Try again in a few seconds.","code":"restarting"}` + "\n"))
		return
	}
	defer f.leave()
	h.ServeHTTP(w, r)
}

// enter waits while a restart swaps the components, and returns the
// handler to use, or nil when the wait was too long.
func (f *front) enter(r *http.Request) http.Handler {
	timeout := time.NewTimer(pauseLimit)
	defer timeout.Stop()
	for {
		f.mu.Lock()
		if f.paused == nil && f.h != nil {
			f.inflight++
			h := f.h
			f.mu.Unlock()
			return h
		}
		wait := f.paused
		f.mu.Unlock()
		if wait == nil {
			return nil
		}
		select {
		case <-wait:
		case <-r.Context().Done():
			return nil
		case <-timeout.C:
			return nil
		}
	}
}

func (f *front) leave() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inflight--
	if f.inflight == 0 && f.idle != nil {
		close(f.idle)
		f.idle = nil
	}
}

// pause holds new requests back and waits up to wait for those in
// progress to finish.
func (f *front) pause(wait time.Duration) {
	f.mu.Lock()
	if f.paused == nil {
		f.paused = make(chan struct{})
	}
	if f.inflight == 0 {
		f.mu.Unlock()
		return
	}
	if f.idle == nil {
		f.idle = make(chan struct{})
	}
	idle := f.idle
	f.mu.Unlock()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-idle:
	case <-t.C:
	}
}

// resume serves requests with h, letting those held back through.
func (f *front) resume(h http.Handler) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.h = h
	if f.paused != nil {
		close(f.paused)
		f.paused = nil
	}
}
