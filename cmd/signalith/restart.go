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
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
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
// A restart first checks that the new settings can work: the files and
// folders the components read, the new web and syslog addresses, the
// certificate, and OpenSearch with the new connection settings. If not,
// nothing changes, and the changes to blame are set aside in the
// settings file so the next start does not use them either. Then the old
// components stop and new ones start; if they cannot, the previous
// settings are started again, and if even those cannot, the web page
// stays up to say so while Signalith keeps trying.
//
// A restart that moves the web page (another address, or HTTPS turned on
// or off) waits for an admin to reach it at the new address. When nobody
// does within api.MoveWait, Signalith goes back to the old one; for a
// move to another port, the old address keeps answering until then.

// Timings of a restart; tests shorten them.
var (
	// restartDelay lets the answer to "restart" reach the browser first.
	restartDelay = 200 * time.Millisecond
	// drainWait is how long a restart waits for requests in progress.
	drainWait = 5 * time.Second
	// oldAddressGrace is how long the old web address keeps answering
	// after a move is confirmed, so the page there can learn where to go.
	oldAddressGrace = 30 * time.Second
	// pauseLimit is how long a request waits for a restart to finish
	// before it is answered 503.
	pauseLimit = 30 * time.Second
	// moveWait is how long a move of the web page waits for someone to
	// reach the new address.
	moveWait = api.MoveWait
	// downRetry is how often Signalith tries to start again when neither
	// the new settings nor the previous ones could.
	downRetry = 30 * time.Second
	// bootCheckTimeout bounds the OpenSearch check at startup.
	bootCheckTimeout = store.CheckTimeout
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

	requests  chan restartRequest
	confirmed chan *move
	mu        sync.Mutex
	busy      bool
	last      *api.RestartResult
	awaiting  *move

	// Owned by run.
	cur     *instance // nil while nothing could start
	good    *config.Config
	web     *webServer
	retired []*webServer // old web servers still answering for a while

	// failStart, for tests, makes starting with a config fail.
	failStart func(*config.Config) error
}

type restartRequest struct {
	by, client string
	// localOnly is true when the admin agreed that the web page answers
	// on the server itself only: a move is then not undone.
	localOnly bool
}

// move is a restart that moved the web page, waiting for someone to reach
// it at the new address.
type move struct {
	api.AwaitingMove
	// web is the new web server, where the confirmation must come in, and
	// old the previous one, kept answering until then (nil when the new
	// one took its port).
	web, old *webServer
	// prev are the settings to go back to, and refuse the changes made on
	// the Settings page that are set aside when it does.
	prev   *config.Config
	refuse []string
	timer  *time.Timer
}

func newRunner(path string, log *slog.Logger) *runner {
	return &runner{
		path: path, log: log, started: time.Now(),
		sessions: auth.NewSessions(12 * time.Hour), limiter: auth.NewLimiter(),
		front: &front{}, requests: make(chan restartRequest, 1), confirmed: make(chan *move, 1),
	}
}

// Restart implements api.Restarter.
func (r *runner) Restart(by, client string, localOnly bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy {
		return api.ErrRestarting
	}
	if r.awaiting != nil {
		return api.ErrAwaitingMove
	}
	r.busy = true
	go func() {
		time.Sleep(restartDelay)
		r.requests <- restartRequest{by: by, client: client, localOnly: localOnly}
	}()
	return nil
}

// RestartStatus implements api.Restarter.
func (r *runner) RestartStatus() api.RestartStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := api.RestartStatus{InProgress: r.busy, Last: r.last}
	if m := r.awaiting; m != nil {
		a := m.AwaitingMove
		st.Awaiting = &a
	}
	return st
}

// webKey is the context key of the web server a request came in at.
type webKey struct{}

// Confirm implements api.Restarter: a request that came in at the web
// server a move waits on confirms it.
func (r *runner) Confirm(req *http.Request) bool {
	w, _ := req.Context().Value(webKey{}).(*webServer)
	r.mu.Lock()
	defer r.mu.Unlock()
	m := r.awaiting
	if m == nil || w == nil || w != m.web {
		return false
	}
	r.awaiting = nil
	if r.last != nil {
		last := *r.last
		last.Confirmed = true
		r.last = &last
	}
	select {
	case r.confirmed <- m:
	default:
	}
	return true
}

// run serves until ctx ends, restarting when asked.
func (r *runner) run(ctx context.Context, c *config.Config) error {
	c = r.checkPageOpenSearch(ctx, c)
	in, ln, err := r.open(ctx, c)
	if err != nil && len(c.PageKeys()) > 0 {
		// Settings saved on the Settings page must not keep Signalith from
		// starting, which would also lock everyone out of the page that
		// can fix them: start with signalith.yaml alone, and say why there.
		// They are to blame only when that starts.
		keys := blame(err, c)
		base, berr := config.LoadWithoutPage(r.path, fmt.Sprintf("Signalith could not start with them (%v)", err), keys)
		if berr == nil {
			var bin *instance
			var bln net.Listener
			bin, bln, berr = r.open(ctx, base)
			if berr == nil {
				r.log.Error("Signalith could not start with the settings saved on the Settings page; started with signalith.yaml alone",
					"err", err, "settings", strings.Join(keys, ","), "file", c.SettingsFile())
				c, in, ln, err = base, bin, bln, nil
			}
		}
		if berr != nil {
			r.log.Error("Signalith cannot start with signalith.yaml alone either, so the Settings page is not to blame", "err", berr)
		}
	}
	if err != nil {
		return err
	}
	r.cur, r.good = in, c
	r.front.resume(in.handler)
	r.web = r.serveWeb(c, ln, r.cert.Load())
	r.log.Info("signalith listening", "addr", ln.Addr().String(), "ui", c.Server.PublicURL, "version", version)
	var retry <-chan time.Time
	for {
		var moveTimeout <-chan time.Time
		r.mu.Lock()
		if r.awaiting != nil {
			moveTimeout = r.awaiting.timer.C
		}
		r.mu.Unlock()
		select {
		case err := <-r.web.errc:
			r.shutdown()
			return err
		case req := <-r.requests:
			r.restart(ctx, req)
		case m := <-r.confirmed:
			m.timer.Stop()
			r.log.Info("new web address confirmed: someone reached it", "audit", true, "addr", m.To)
			if m.old != nil {
				r.retire(m.old, oldAddressGrace)
			}
		case <-moveTimeout:
			r.mu.Lock()
			m := r.awaiting
			if m != nil {
				r.awaiting, r.busy = nil, true
			}
			r.mu.Unlock()
			if m != nil {
				r.revert(ctx, m)
			}
		case <-retry:
		case <-ctx.Done():
			r.log.Info("shutting down")
			return r.shutdown()
		}
		retry = nil
		if r.cur == nil {
			if !r.recover(ctx) {
				retry = time.After(downRetry)
			}
		}
	}
}

// open loads the web server's certificate, listens on the web address
// and starts the components.
func (r *runner) open(ctx context.Context, c *config.Config) (*instance, net.Listener, error) {
	cert, err := loadCert(c)
	if err != nil {
		return nil, nil, keyed(err, "server.tls_cert", "server.tls_key")
	}
	ln, err := httpserver.Listen(c.Server.Listen, webLimits(c), r.log)
	if err != nil {
		return nil, nil, keyed(fmt.Errorf("cannot listen on %s: %w", c.Server.Listen, opError(err)), "server.listen")
	}
	in, err := r.start(ctx, c)
	if err != nil {
		ln.Close()
		return nil, nil, err
	}
	r.cert.Store(cert)
	return in, ln, nil
}

// keyedError is an error about some settings.
type keyedError struct {
	err  error
	keys []string
}

func (e *keyedError) Error() string { return e.err.Error() }
func (e *keyedError) Unwrap() error { return e.err }

func keyed(err error, keys ...string) error { return &keyedError{err: err, keys: keys} }

// blame returns the settings changed on the Settings page that err is
// about, or every one that a restart applies when that is not known.
func blame(err error, c *config.Config) []string {
	var ke *keyedError
	var keys []string
	if errors.As(err, &ke) {
		for _, k := range ke.keys {
			if c.Source(k).Kind == config.FromPage {
				keys = append(keys, k)
			}
		}
		if keys != nil {
			return keys
		}
	}
	base := c.Base()
	for _, k := range c.PageKeys() {
		if !config.SameValue(base, c, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// openSearchKeys are the settings of the OpenSearch connection.
var openSearchKeys = []string{"opensearch.url", "opensearch.username", "opensearch.password", "opensearch.ca_file",
	"opensearch.cert_file", "opensearch.key_file", "opensearch.proxy", "opensearch.allow_insecure_http", "opensearch.tls_skip_verify"}

// checkPageOpenSearch checks, at startup, an OpenSearch connection set on
// the Settings page that no restart has checked: one saved with no
// restart since. When OpenSearch answers with signalith.yaml's settings
// but not with the page's, those are set aside, and Signalith starts with
// signalith.yaml's. When neither answers, OpenSearch is just not up yet.
func (r *runner) checkPageOpenSearch(ctx context.Context, c *config.Config) *config.Config {
	var keys []string
	unchecked := false
	for _, k := range openSearchKeys {
		if c.Source(k).Kind == config.FromPage {
			keys = append(keys, k)
			unchecked = unchecked || !c.PageChecked(k)
		}
	}
	base := c.Base()
	if !unchecked || base.OpenSearchConnection() == c.OpenSearchConnection() {
		return c
	}
	check := func(c *config.Config) store.Report {
		cfg := c.OpenSearchConnection()
		cfg.Timeout = bootCheckTimeout
		return store.Check(ctx, cfg)
	}
	rep := check(c)
	if rep.OK {
		if err := config.MarkChecked(c.SettingsFile(), keys); err != nil {
			r.log.Warn("could not note in the settings file that its OpenSearch settings work", "err", err)
		}
		return c
	}
	if !check(base).OK {
		return c
	}
	reason := "When Signalith started, OpenSearch did not answer with these settings but did with those in signalith.yaml: " + rep.Message
	r.setAside(c.SettingsFile(), keys, reason)
	next, err := config.LoadSetAside(r.path, keys, reason)
	if err != nil {
		return c
	}
	r.log.Error("OpenSearch did not answer with the settings saved on the Settings page, but did with those in signalith.yaml; using those",
		"settings", strings.Join(keys, ","), "problem", rep.Message)
	return next
}

// shutdown stops the web servers and the components. A move of the web
// page that nobody confirmed is set aside, so the next start uses the
// address that is known to work.
func (r *runner) shutdown() error {
	r.mu.Lock()
	m := r.awaiting
	r.awaiting = nil
	r.mu.Unlock()
	if m != nil {
		r.setAside(m.prev.SettingsFile(), m.refuse, "Signalith stopped before anyone opened it at "+m.To+", so it was not used")
	}
	var err error
	if r.web != nil {
		err = r.web.close(10 * time.Second)
	}
	var wg sync.WaitGroup
	for _, w := range r.retired {
		w.keep()
		wg.Go(func() { w.close(10 * time.Second) })
	}
	if r.cur != nil {
		r.cur.stop()
	}
	wg.Wait()
	return err
}

// finish records how a restart went.
func (r *runner) finish(res *api.RestartResult, m *move) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.last, r.busy = res, false
	if m != nil {
		r.awaiting = m
	}
}

// restart applies the saved settings. Problems found before the switch
// keep everything as it was; a failure after it goes back to the previous
// settings.
func (r *runner) restart(ctx context.Context, req restartRequest) {
	start := time.Now()
	res := &api.RestartResult{At: start.UTC(), By: req.by, Keys: []string{}}
	var awaiting *move
	defer func() { r.done(res, req, start, awaiting) }()
	if r.cur == nil {
		res.Error = "Signalith is not running its parts, so it cannot restart. It tries to start again every 30 seconds."
		return
	}
	// The settings in use, including those applied at once from the
	// Settings page since the last start.
	prev := r.cur.srv.Running()
	next, err := config.Load(r.path)
	if err != nil {
		res.Error = fmt.Sprintf("The saved settings could not be loaded (%v). Signalith kept running with the previous settings.", err)
		return
	}
	if p := next.SettingsProblem(); p != "" {
		res.Error = "The settings saved on the Settings page cannot be used, so Signalith kept running with the previous settings. " + p
		return
	}
	r.log.Info("restarting to apply the saved settings", "by", req.by, "settings", strings.Join(changedSettings(prev, next), ","))
	confirm := moved(prev, next) && !req.localOnly
	if !r.switchTo(ctx, prev, next, res, confirm) || !res.OK {
		return
	}
	if err := config.MarkChecked(next.SettingsFile(), next.PageKeys()); err != nil {
		r.log.Warn("could not note in the settings file that its settings work", "err", err)
	}
	if confirm {
		awaiting = r.awaitMove(prev, next)
	}
}

// done logs and records how a restart went, and lets the requests held
// back through.
func (r *runner) done(res *api.RestartResult, req restartRequest, start time.Time, m *move) {
	res.TookMS = time.Since(start).Milliseconds()
	switch {
	case res.OK && res.Reverted:
		r.log.Warn("went back to the previous web address", "audit", true, "by", req.by, "settings", strings.Join(res.Keys, ","), "reason", res.Error)
	case res.OK:
		r.log.Info("restarted with the saved settings", "audit", true, "by", req.by, "client", req.client, "settings", strings.Join(res.Keys, ","), "took_ms", res.TookMS)
	default:
		r.log.Error("restart failed", "audit", true, "by", req.by, "client", req.client, "settings", strings.Join(res.Keys, ","),
			"rolled_back", res.RolledBack, "set_aside", strings.Join(res.Refused, ","), "reason", res.Error)
	}
	// The result is in place before the requests held back go through,
	// so the page sees it at once.
	r.finish(res, m)
	if r.cur != nil {
		r.front.resume(r.cur.handler)
	}
}

// moved reports whether the web page answers somewhere else with next:
// another address, or HTTPS turned on or off.
func moved(prev, next *config.Config) bool {
	return prev.Server.Listen != next.Server.Listen || httpsOn(prev) != httpsOn(next)
}

func httpsOn(c *config.Config) bool { return c.Server.TLSCert != "" && c.Server.TLSKey != "" }

// webAddress names where a web server answers, for people.
func webAddress(c *config.Config) string {
	if httpsOn(c) {
		return "https://" + c.Server.Listen
	}
	return "http://" + c.Server.Listen
}

// awaitMove starts waiting for someone to reach the web page at the
// address it moved to.
func (r *runner) awaitMove(prev, next *config.Config) *move {
	m := &move{web: r.web, prev: prev, timer: time.NewTimer(moveWait)}
	m.From, m.To, m.Until = webAddress(prev), webAddress(next), time.Now().Add(moveWait).UTC()
	m.Keys = []string{}
	for _, k := range []string{"server.listen", "server.tls_cert", "server.tls_key"} {
		if !config.SameValue(prev, next, k) {
			m.Keys = append(m.Keys, k)
			if next.Source(k).Kind == config.FromPage {
				m.refuse = append(m.refuse, k)
			}
		}
	}
	for _, w := range r.retired {
		if w.cfg == nil || w.timer != nil || !w.open() {
			continue
		}
		if w.cfg.Server.Listen == prev.Server.Listen {
			m.old = w
		}
	}
	return m
}

// revert goes back to the previous web address after nobody reached the
// new one in time, and sets the changes that moved it aside.
func (r *runner) revert(ctx context.Context, m *move) {
	start := time.Now()
	res := &api.RestartResult{At: start.UTC(), By: "Signalith", Keys: []string{}, Reverted: true}
	req := restartRequest{by: "Signalith"}
	defer func() { r.done(res, req, start, nil) }()
	if r.cur == nil {
		return
	}
	reason := fmt.Sprintf("Nobody opened Signalith at %s within %d minutes, so it went back to %s", m.To, int(moveWait.Minutes()), m.From)
	if moveWait < time.Minute {
		reason = fmt.Sprintf("Nobody opened Signalith at %s in time, so it went back to %s", m.To, m.From)
	}
	cur := r.cur.srv.Running()
	res.Refused = r.setAside(cur.SettingsFile(), m.refuse, reason)
	next, err := config.LoadSetAside(r.path, m.refuse, reason)
	if err != nil || next.SettingsProblem() != "" || moved(m.prev, next) {
		// The move came from signalith.yaml, or the settings cannot be
		// read now: go back to the settings in use before it.
		next = m.prev
	}
	if m.old != nil {
		// It still answers at the old address: nothing to wait for.
		m.old.keep()
	}
	if r.switchTo(ctx, cur, next, res, false) {
		res.ProblemKeys = m.Keys
		if res.OK {
			res.Error = reason + "."
		}
	}
}

// setAside sets the changes made on the Settings page to keys aside in
// its file, for reason, and returns those it did. Keys not changed there
// are left alone.
func (r *runner) setAside(file string, keys []string, reason string) []string {
	if len(keys) == 0 {
		return nil
	}
	marked, err := config.MarkRefused(file, keys, reason)
	if err != nil {
		r.log.Error("could not set changes from the Settings page aside in its file; the next start may use them again",
			"settings", strings.Join(keys, ","), "file", file, "err", err)
		return nil
	}
	return marked
}

// switchTo checks next and switches to it from prev, filling in res. It
// reports false when the checks refused next, so nothing changed. confirm
// is true when a move of the web page waits to be confirmed: the old web
// server then keeps answering until it is.
func (r *runner) switchTo(ctx context.Context, prev, next *config.Config, res *api.RestartResult, confirm bool) bool {
	res.Keys = changedSettings(prev, next)
	plan, err := r.check(ctx, prev, next)
	if err != nil {
		res.Error = err.Error()
		var ke *keyedError
		if errors.As(err, &ke) {
			res.ProblemKeys = ke.keys
			// Not used at the next start either, until tried again. The
			// reason is the cause alone: the setting is not in use.
			res.Refused = r.setAside(next.SettingsFile(), ke.keys, strings.TrimSuffix(res.Error, keptRunning))
		}
		return false
	}

	// Switch: hold new requests back, stop the old components, start new ones.
	old := r.cur
	r.front.pause(drainWait)
	old.stop()
	in, err := r.start(ctx, next)
	if err == nil && plan.moveWeb && plan.ln == nil && plan.reuse == nil {
		// The new address takes the old one's port: free it, then listen.
		r.web.close(5 * time.Second)
		plan.ln, err = httpserver.Listen(next.Server.Listen, webLimits(next), r.log)
		if err != nil {
			in.stop()
			err = keyed(fmt.Errorf("cannot listen on %s: %w", next.Server.Listen, opError(err)), "server.listen")
			if back, lerr := httpserver.Listen(prev.Server.Listen, webLimits(prev), r.log); lerr == nil {
				r.web = r.serveWeb(prev, back, r.cert.Load())
			} else {
				r.log.Error("the previous web address cannot be listened on again", "addr", prev.Server.Listen, "err", lerr)
			}
		}
	}
	if err != nil {
		res.RolledBack = true
		res.Error = fmt.Sprintf("Signalith could not start with the saved settings (%v), so it went back to the previous settings.", err)
		if plan.ln != nil {
			plan.ln.Close()
		}
		if plan.reuse != nil {
			r.retire(plan.reuse, 0)
		}
		res.ProblemKeys = blame(err, next)
		res.Refused = r.setAside(next.SettingsFile(), res.ProblemKeys, fmt.Sprintf("Signalith could not start with it (%v).", err))
		back, err2 := r.start(ctx, prev)
		if err2 != nil {
			res.Error = fmt.Sprintf("Signalith could not start with the saved settings (%v) or the previous ones (%v). It tries again every 30 seconds.", err, err2)
			r.log.Error("Signalith could not start with the new settings or the previous ones; it tries again every 30 seconds", "new", err, "previous", err2)
			r.cur = nil
			r.front.resume(downHandler)
			return true
		}
		r.cur = back
		return true
	}
	// The certificate is read again on each restart.
	r.cert.Store(plan.cert)
	if plan.moveWeb {
		prevWeb := r.web
		if plan.reuse != nil {
			r.web = plan.reuse
			r.web.cert.Store(plan.cert)
			r.retired = slices.DeleteFunc(r.retired, func(w *webServer) bool { return w == plan.reuse })
		} else {
			r.web = r.serveWeb(next, plan.ln, plan.cert)
		}
		r.log.Info("signalith listening", "addr", next.Server.Listen, "ui", next.Server.PublicURL, "version", version)
		if prevWeb.open() {
			// The page at the old address asks how the restart went before
			// it moves. A move then waits to be confirmed; otherwise the
			// old address closes after a while.
			if confirm {
				r.retire(prevWeb, -1)
			} else {
				r.retire(prevWeb, oldAddressGrace)
			}
		}
	} else {
		r.web.cert.Store(plan.cert)
	}
	r.cur, r.good = in, next
	res.OK = true
	return true
}

// recover tries to start again after neither the new settings nor the
// previous ones could: with the saved settings, then the last ones that
// ran. It reports whether one did.
func (r *runner) recover(ctx context.Context) bool {
	try := func(c *config.Config) bool {
		if r.web == nil || !r.web.open() {
			cert, err := loadCert(c)
			if err != nil {
				return false
			}
			ln, err := httpserver.Listen(c.Server.Listen, webLimits(c), r.log)
			if err != nil {
				return false
			}
			r.cert.Store(cert)
			r.web = r.serveWeb(c, ln, cert)
		}
		in, err := r.start(ctx, c)
		if err != nil {
			r.log.Error("Signalith still cannot start; it tries again in 30 seconds", "err", err)
			return false
		}
		r.cur, r.good = in, c
		r.front.resume(in.handler)
		r.log.Info("Signalith started again", "audit", true)
		r.finish(&api.RestartResult{At: time.Now().UTC(), By: "Signalith", OK: true, Keys: []string{}}, nil)
		return true
	}
	// The saved settings, unless they move the web page: that is checked
	// by a restart.
	if c, err := config.Load(r.path); err == nil && c.SettingsProblem() == "" && (r.web == nil || !moved(r.web.cfg, c)) {
		if try(c) {
			return true
		}
	}
	return r.good != nil && try(r.good)
}

// plan is what the checks before a restart prepared.
type plan struct {
	// moveWeb is true when the web listener changes. ln is the new one,
	// already listening, or reuse an old web server that answers there
	// already; both are nil when the new address takes the old one's port
	// and must wait for it to close.
	moveWeb bool
	ln      net.Listener
	reuse   *webServer
	cert    *tls.Certificate
}

// keptRunning ends the words of a check that failed.
const keptRunning = " Signalith kept running with the previous settings."

// refuse words a check that failed: Signalith kept running with the
// previous settings.
func refuse(format string, args ...any) error {
	return fmt.Errorf(format+keptRunning, args...)
}

// check makes sure the new settings can work before anything stops: no
// data retention job would be cut short, the folders and files the
// components read open, the certificate loads, OpenSearch answers with the
// new connection settings, and the web page and syslog can listen on
// their new addresses.
func (r *runner) check(ctx context.Context, old, next *config.Config) (*plan, error) {
	if ret := r.cur.retention; ret != nil {
		if job := ret.Job(); job != "" {
			what := map[string]string{"run": "deleting or archiving old days", "restore": "restoring archived days"}[job]
			return nil, refuse("Data retention is %s right now, which a restart would cut short. Restart again when it has finished; the Data retention page shows how it is going.", what)
		}
	}
	if err := checkFiles(r.people, next); err != nil {
		return nil, refuse("%s. Fix it on the server, then restart again.", sentenceOf(err))
	}
	p := &plan{}
	cert, err := loadCert(next)
	if err != nil {
		return nil, keyed(refuse("%s.", sentenceOf(err)), "server.tls_cert", "server.tls_key")
	}
	p.cert = cert
	if openSearchMoves(old, next) {
		var keys []string
		for _, k := range openSearchKeys {
			if !config.SameValue(old, next, k) {
				keys = append(keys, k)
			}
		}
		if rep := store.Check(ctx, next.OpenSearchConnection()); !rep.OK {
			return nil, keyed(refuse("OpenSearch did not answer with the new settings: %s", rep.Message), keys...)
		}
	}
	if webChanges(old, next) {
		p.moveWeb = true
		if w := r.retiredAt(next); w != nil {
			p.reuse = w
		} else {
			// An old web server still answering after an earlier move gives
			// its address up.
			r.closeRetired(next.Server.Listen)
			ln, err := httpserver.Listen(next.Server.Listen, webLimits(next), r.log)
			switch {
			case err == nil:
				p.ln = ln
			case addrInUse(err) && overlaps(old.Server.Listen, next.Server.Listen):
				// The web server in use holds it: listening waits for it to
				// close.
			default:
				return nil, keyed(refuse("Signalith cannot listen on %s (%v). Choose another address or port.", next.Server.Listen, opError(err)), "server.listen")
			}
		}
	}
	fail := func(err error) (*plan, error) {
		if p.ln != nil {
			p.ln.Close()
		}
		return nil, err
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
			return fail(keyed(refuse("Signalith cannot receive syslog on %s/%s (%v). Choose another address or port.", l.addr, l.network, opError(err)), l.setting))
		}
	}
	return p, nil
}

// checkFiles opens what the components read from files and folders, as
// starting with c does, so that one that cannot be read stops the restart
// before anything stops.
func checkFiles(people *users.Store, c *config.Config) error {
	if _, _, err := detect.NewLibrary(c.DetectionsDir()); err != nil {
		return err
	}
	if _, err := dashboards.NewStore(c.DashboardsDir()); err != nil {
		return fmt.Errorf("dashboards.dir: %w", err)
	}
	if people == nil || people.Path() != c.UsersFile() {
		if _, err := users.Open(c.UsersFile()); err != nil {
			return err
		}
	}
	fromFile, err := c.LDAP()
	if err != nil {
		return err
	}
	if _, err := users.OpenDirectory(c.DirectoryFile(), fromFile); err != nil {
		return err
	}
	return nil
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
	s := strings.TrimSuffix(err.Error(), ".")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// loadCert loads the web server's certificate, or returns nil without TLS.
func loadCert(c *config.Config) (*tls.Certificate, error) {
	if !httpsOn(c) {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.Server.TLSCert, c.Server.TLSKey)
	if err != nil {
		return nil, fmt.Errorf("the certificate in server.tls_cert and server.tls_key cannot be used: %w", err)
	}
	return &cert, nil
}

// webChanges reports whether the web listener changes: another address,
// HTTPS turned on or off, or other connection limits.
func webChanges(old, next *config.Config) bool {
	return moved(old, next) || old.Server.MaxConnections != next.Server.MaxConnections ||
		!slices.Equal(old.Server.SharedAddresses, next.Server.SharedAddresses)
}

// webLimits are the connection limits of the web listener.
func webLimits(c *config.Config) httpserver.Limits {
	return httpserver.Limits{Max: c.Server.MaxConnections, Shared: c.Server.SharedList()}
}

// openSearchMoves reports whether the OpenSearch connection changes.
func openSearchMoves(old, next *config.Config) bool {
	return old.OpenSearchConnection() != next.OpenSearchConnection() ||
		old.OpenSearch.AllowInsecureHTTP != next.OpenSearch.AllowInsecureHTTP
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

// overlaps reports whether a listener on a holds the port b asks for: the
// same port, on the same address or on every address.
func overlaps(a, b string) bool {
	if !samePort(a, b) {
		return false
	}
	ha, _, _ := net.SplitHostPort(a)
	hb, _, _ := net.SplitHostPort(b)
	any := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	loop := func(h string) bool {
		ip := net.ParseIP(h)
		return strings.EqualFold(h, "localhost") || (ip != nil && ip.IsLoopback())
	}
	return any(ha) || any(hb) || strings.EqualFold(ha, hb) || (loop(ha) && loop(hb))
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
	cfg    *config.Config
	errc   chan error
	closed atomic.Bool
	// cert is its certificate, with HTTPS.
	cert atomic.Pointer[tls.Certificate]
	// timer closes a retired web server; nil while it is kept.
	timer *time.Timer
}

// serveWeb serves the front handler on ln, with HTTPS when c has a
// certificate. Requests carry the web server they came in at, so a move
// can tell when someone reached the new one.
func (r *runner) serveWeb(c *config.Config, ln net.Listener, cert *tls.Certificate) *webServer {
	w := &webServer{hs: httpserver.New(r.front, webLimits(c), r.log), cfg: c, errc: make(chan error, 1)}
	w.cert.Store(cert)
	w.hs.ConnContext = func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, webKey{}, w)
	}
	useTLS := httpsOn(c)
	if useTLS {
		// The certificate is read again on each restart.
		w.hs.TLSConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return w.cert.Load(), nil
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

// keep stops a retired web server's timer, so it is not closed.
func (w *webServer) keep() bool {
	if w.timer == nil {
		return true
	}
	if !w.timer.Stop() {
		return false
	}
	w.timer = nil
	return true
}

// retire keeps an old web server answering for a while, then closes it:
// after the time given, at once for 0, or not until told for -1.
func (r *runner) retire(w *webServer, after time.Duration) {
	if !slices.Contains(r.retired, w) {
		r.retired = append(r.retired, w)
	}
	if w.timer != nil && !w.keep() {
		return
	}
	switch {
	case after < 0:
		return
	case after == 0:
		w.close(10 * time.Second)
		r.retired = slices.DeleteFunc(r.retired, func(o *webServer) bool { return o == w })
		return
	}
	w.timer = time.AfterFunc(after, func() { w.close(10 * time.Second) })
}

// retiredAt returns a retired web server that answers as next asks, to
// serve again instead of listening anew.
func (r *runner) retiredAt(next *config.Config) *webServer {
	for _, w := range r.retired {
		c := w.cfg
		if c == nil || !w.open() || c.Server.Listen != next.Server.Listen || httpsOn(c) != httpsOn(next) ||
			c.Server.MaxConnections != next.Server.MaxConnections || !slices.Equal(c.Server.SharedAddresses, next.Server.SharedAddresses) {
			continue
		}
		if w.keep() {
			return w
		}
	}
	return nil
}

// closeRetired closes the retired web servers that hold addr's port.
func (r *runner) closeRetired(addr string) {
	for _, w := range slices.Clone(r.retired) {
		if w.cfg != nil && overlaps(w.cfg.Server.Listen, addr) && w.keep() {
			r.retire(w, 0)
		}
	}
	r.retired = slices.DeleteFunc(r.retired, func(w *webServer) bool { return !w.open() })
}

// downHandler answers while Signalith cannot run its parts: neither the
// new settings nor the previous ones started. It says no more than that;
// the log on the server says why.
var downHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Retry-After", "30")
	w.Header().Set("Cache-Control", "no-store")
	const msg = "Signalith could not start and tries again every 30 seconds. Its log on the server says why."
	if strings.HasPrefix(r.URL.Path, "/api/") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"` + msg + `","code":"down"}` + "\n"))
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(msg + "\n"))
})

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
