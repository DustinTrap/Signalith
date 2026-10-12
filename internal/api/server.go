// Package api serves the REST API and the embedded web UI.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/clientaddr"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/syslog"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// Backend is what the API needs from OpenSearch beyond searching.
type Backend interface {
	Health(ctx context.Context) (string, error)
	Mapping(ctx context.Context, pattern string) (map[string]string, error)
}

// Server wires the API together.
type Server struct {
	Config   *config.Config
	Engine   *search.Engine
	Pipeline *ingest.Pipeline
	Backend  Backend
	// Detections, Scheduler and Findings enable detections and the
	// findings queue; when nil those endpoints return 503.
	Detections *detect.Library
	Scheduler  *detect.Scheduler
	Findings   findings.Store
	// Assets holds the asset and identity lists; nil disables them.
	Assets *assets.Store
	// Intel holds threat intel indicators and Feeds downloads them; nil
	// Intel disables the threat intel endpoints.
	Intel *intel.Store
	Feeds *intel.Feeds
	// Dashboards holds custom dashboards; nil disables them (the built-in
	// posture dashboard still works).
	Dashboards *dashboards.Store
	// Cases holds investigations; nil disables them.
	Cases cases.Store
	// Retention enforces data retention policies; nil disables the Data
	// retention page.
	Retention *retention.Manager
	// Assistant is an optional AI model for plain-English questions.
	Assistant *assistant.Client
	UI        fs.FS // web UI files; nil disables the UI
	Log       *slog.Logger
	Version   string

	// Syslog is the syslog receiver, for its stats; nil when it is off.
	Syslog *syslog.Receiver
	// TLS is the HTTPS certificate, for the CA agents and browsers trust;
	// nil when Signalith does not serve HTTPS itself.
	TLS *tlsauto.Manager
	// Runtime overrides what api/health says about the system the server
	// runs on; nil looks it up.
	Runtime *Runtime

	// Sessions and Limiter back the sign-in page; nil uses defaults.
	Sessions *auth.Sessions
	Limiter  *auth.Limiter
	// Users holds local users and directory users seen at sign-in, and
	// Directory the LDAP or Active Directory sign-in settings. nil keeps
	// them in memory only.
	Users     *users.Store
	Directory *users.Directory

	// DirectoryRecheck is how often signed-in directory users are looked
	// up again; 0 means every 5 minutes.
	DirectoryRecheck time.Duration

	authOnce     sync.Once
	creds        credCache  // recently checked Basic credentials
	routes       []route    // every API route and its role, from Handler
	caseMu       sync.Mutex // serializes case changes
	checksMu     sync.Mutex
	dirChecks    map[string]dirCheck // when each directory user was last checked
	dirSlotsOnce sync.Once
	dirSlots     chan struct{}  // limits directory connections at once
	background   sync.WaitGroup // directory checks still running
}

// Handler returns the HTTP handler. Every API route is registered with
// the least role that may use it (see router); the role table is in
// docs/users.md.
func (s *Server) Handler() http.Handler {
	s.sessions()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", s.handleIngest)

	api := &router{s: s, mux: http.NewServeMux()}
	api.viewer("GET /api/health", s.handleHealth)
	// Searching and the query tools only read events.
	api.viewer("POST /api/search", s.handleSearch)
	api.viewer("POST /api/explain", s.handleExplain)
	api.viewer("POST /api/build", s.handleBuild)
	api.viewer("POST /api/parse", s.handleParse)
	api.viewer("GET /api/datamodels", s.handleDatamodels)
	api.viewer("GET /api/fields", s.handleFields)
	api.viewer("GET /api/fields/values", s.handleFieldValues)
	api.viewer("GET /api/language", s.handleLanguage)
	// Agent configs carry the ingest token.
	api.admin("GET /api/agents/config", s.handleAgentConfig)
	s.routeDetections(api)
	s.routeRisk(api)
	s.routeAsk(api)
	s.routeIntel(api)
	s.routeDashboards(api)
	s.routeCases(api)
	s.routeUsers(api)
	s.routeRetention(api)
	if s.UI != nil {
		api.add(route{Pattern: "GET /", Role: users.Viewer}, revalidate(http.FileServerFS(s.UI)))
	}
	s.routes = api.routes
	s.routeLogin(mux)
	mux.Handle("/", s.requireUser(api.mux))
	return limitBodies(s.securityHeaders(s.guardAPI(mux)))
}

// guardAPI makes sure no /api/ route escapes sign-in: a route registered
// straight on the outer mux, rather than with a role on the router, is
// admin-only unless it is one of publicRoutes.
func (s *Server) guardAPI(mux *http.ServeMux) http.Handler {
	guarded := s.requireUser(s.allow(route{Pattern: "(outer mux)", Role: users.Admin, Unclassified: true}, mux))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if _, pattern := mux.Handler(r); pattern != "" && pattern != "/" && !slices.Contains(publicRoutes, pattern) {
				guarded.ServeHTTP(w, r)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	body := map[string]any{"error": err.Error()}
	var qe *query.Error
	if errors.As(err, &qe) {
		body["error"] = qe.Msg
		body["pos"] = qe.Pos
	}
	writeJSON(w, status, body)
}

// writeSearchError answers a failed search: 400 for a query that cannot
// run as written, 503 (retry shortly) when too many searches are running,
// and 502 when OpenSearch failed.
func writeSearchError(w http.ResponseWriter, err error) {
	var qe *search.QueryError
	switch {
	case errors.As(err, &qe):
		writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, search.ErrBusy):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, err)
	default:
		writeError(w, http.StatusBadGateway, err)
	}
}

func readJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		return errors.New("request body must be JSON: " + err.Error())
	}
	return nil
}

func decodeJSON(b []byte, v any) error {
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("request body must be JSON: " + err.Error())
	}
	return nil
}

// ---- ingest ----

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	if !s.validToken(r) {
		writeError(w, http.StatusUnauthorized, errors.New("missing or invalid ingest token"))
		return
	}
	if plaintextIngest(r) {
		s.Pipeline.NotePlaintext(clientaddr.Parse(r.RemoteAddr))
	}
	// The whole batch is read before a pipeline slot is taken, so a
	// sender that sends slowly holds only its connection and the bytes it
	// has sent, never a slot other agents are waiting for.
	body, release, err := s.readBatch(w, r)
	if err != nil {
		s.batchReadFailed(w, r, err)
		return
	}
	defer release()
	slot, err := s.Pipeline.Admit(r.Context(), ingestQueueWait)
	if err != nil {
		// 503 makes Fluent Bit retry later instead of dropping data.
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	defer slot()
	tag := r.Header.Get("X-Signalith-Tag")
	if tag == "" {
		tag = r.URL.Query().Get("tag")
	}
	res, err := s.Pipeline.IngestBody(r.Context(), tag, body)
	if err != nil {
		var bad *ingest.BodyError
		if errors.As(err, &bad) {
			writeError(w, bad.Status, bad)
			return
		}
		s.Log.Error("ingest failed", "err", err, "bytes", len(body))
		// 503 makes Fluent Bit retry later instead of dropping data. The
		// details, such as where OpenSearch is, stay in the server log.
		writeError(w, http.StatusServiceUnavailable, errors.New("events could not be stored right now; try again later"))
		return
	}
	if len(res.Errors) > 0 {
		s.Log.Warn("some events were rejected", "rejected", res.Rejected, "first", res.Errors[0].Reason)
	}
	writeJSON(w, http.StatusOK, res)
}

// Agent batches. The sender has proved who it is, so its batch may arrive
// more slowly than other request bodies, over a slow link: it has
// ingestReadTimeout, and while it keeps arriving (ingestProgressBytes at
// least every ingestProgressWindow) up to ingestMaxReadTime in all. A
// sender that stalls part way is cut off at the deadline. ingestQueueWait
// is how long a batch that has arrived waits for a free pipeline slot
// before the sender is told to retry. They are variables so tests can
// shorten them.
var (
	ingestReadTimeout    = 2 * time.Minute
	ingestMaxReadTime    = 10 * time.Minute
	ingestProgressWindow = 30 * time.Second
	ingestProgressBytes  = int64(16 << 10)
	ingestQueueWait      = 15 * time.Second
)

// ingestReplyTimeout is how long, once a batch has arrived, Signalith has
// to write it and reply: the server's usual write time, counted from then
// rather than from the request headers.
const ingestReplyTimeout = 10 * time.Minute

// readBatch reads an agent's request body within the ingest deadlines
// and the ingest memory budget (see ingest.Pipeline.ReadBody). Call release
// once the batch has been written.
func (s *Server) readBatch(w http.ResponseWriter, r *http.Request) (body []byte, release func(), err error) {
	rc := http.NewResponseController(w)
	in := &batchBody{ReadCloser: r.Body, rc: rc, start: time.Now()}
	in.deadline = in.start.Add(ingestReadTimeout)
	_ = rc.SetReadDeadline(in.deadline)
	sender := netip.Addr{}
	if from := clientaddr.Parse(r.RemoteAddr); !clientaddr.Shared(from, s.Config.Server.SharedList()) {
		sender = clientaddr.Key(from)
	}
	body, release, err = s.Pipeline.ReadBody(http.MaxBytesReader(w, in, ingest.MaxBodyBytes), sender, r.ContentLength)
	if err != nil {
		return nil, nil, &batchError{err: err, received: in.n, took: time.Since(in.start)}
	}
	_ = rc.SetWriteDeadline(time.Now().Add(ingestReplyTimeout))
	return body, release, nil
}

// batchError is why an agent's batch could not be read, with how much of
// it had arrived.
type batchError struct {
	err      error
	received int64
	took     time.Duration
}

func (e *batchError) Error() string { return e.err.Error() }
func (e *batchError) Unwrap() error { return e.err }

// batchReadFailed answers a batch that could not be read: 413 when it is
// too large, 408 when it did not arrive in time, and 503 (retry shortly)
// when too many batches are arriving at once.
func (s *Server) batchReadFailed(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	var bad *ingest.BodyError
	var be *batchError
	errors.As(err, &be)
	switch {
	case errors.As(err, &tooBig):
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Errorf("the request body is larger than %d MB; send smaller batches", ingest.MaxBodyBytes>>20))
	case errors.As(err, &bad):
		writeError(w, bad.Status, bad)
	case errors.Is(err, ingest.ErrBusy), errors.Is(err, ingest.ErrSenderBusy):
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusServiceUnavailable, errors.Unwrap(err))
	case errors.Is(err, os.ErrDeadlineExceeded) && be != nil:
		took := be.took.Round(time.Second)
		s.warnSlowBatch("an agent batch took too long to arrive and was refused; the agent will send it again (logged at most once a minute)",
			"client", r.RemoteAddr, "received_bytes", be.received, "took", took.String())
		writeError(w, http.StatusRequestTimeout, fmt.Errorf("the batch took too long to arrive (%d KB in %s). A batch must arrive within %s, "+
			"or within %s while at least %d KB arrives every %s. Send smaller batches (for example a lower Flush in Fluent Bit's [SERVICE] section) or check the network",
			be.received>>10, took, ingestReadTimeout, ingestMaxReadTime, ingestProgressBytes>>10, ingestProgressWindow))
	default:
		writeError(w, http.StatusBadRequest, fmt.Errorf("the request body could not be read: %w", errors.Unwrap(err)))
	}
}

var lastSlowBatchWarning atomic.Int64

// warnSlowBatch logs at most once a minute.
func (s *Server) warnSlowBatch(msg string, args ...any) {
	now := time.Now().UnixNano()
	prev := lastSlowBatchWarning.Load()
	if s.Log == nil || (prev != 0 && now-prev < int64(time.Minute)) || !lastSlowBatchWarning.CompareAndSwap(prev, now) {
		return
	}
	s.Log.Warn(msg, args...)
}

// batchBody gives an agent's batch more time while it keeps arriving:
// each ingestProgressBytes received moves the read deadline to at least
// ingestProgressWindow from then, but never past ingestMaxReadTime after
// the batch began.
type batchBody struct {
	io.ReadCloser
	rc              *http.ResponseController
	start, deadline time.Time
	n, sinceMove    int64
}

func (b *batchBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	b.sinceMove += int64(n)
	// Not once the body has ended: the deadline is lifted then (see
	// deadlineBody), and one set again would cancel the request when it
	// passed.
	if err == nil && b.sinceMove >= ingestProgressBytes {
		b.sinceMove = 0
		next := time.Now().Add(ingestProgressWindow)
		if last := b.start.Add(ingestMaxReadTime); next.After(last) {
			next = last
		}
		if next.After(b.deadline) {
			b.deadline = next
			_ = b.rc.SetReadDeadline(next)
		}
	}
	return n, err
}

func (s *Server) validToken(r *http.Request) bool {
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tok == "" {
		return false
	}
	for _, t := range s.Config.Ingest.Tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
			return true
		}
	}
	return false
}

// ---- search ----

type searchRequest struct {
	Query    string `json:"query"`
	Earliest string `json:"earliest,omitempty"` // time picker; overridden by earliest= in the query
	Latest   string `json:"latest,omitempty"`
}

func (s *Server) parseRequest(w http.ResponseWriter, r *http.Request) (*query.Query, bool) {
	var req searchRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	if strings.TrimSpace(req.Query) == "" {
		req.Query = "*"
	}
	q, err := query.Parse(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return nil, false
	}
	if q.Earliest == "" {
		q.Earliest = req.Earliest
	}
	if q.Latest == "" {
		q.Latest = req.Latest
	}
	return q, true
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseRequest(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) handleExplain(w http.ResponseWriter, r *http.Request) {
	q, ok := s.parseRequest(w, r)
	if !ok {
		return
	}
	plan, err := s.Engine.Compile(q)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"canonical": q.String(),
		"steps":     Explain(q),
		"index":     plan.Index,
		"body":      plan.Body,
	})
}

func (s *Server) handleBuild(w http.ResponseWriter, r *http.Request) {
	var spec query.Spec
	if err := readJSON(r, &spec); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"query": query.Build(spec).String()})
}

func (s *Server) handleParse(w http.ResponseWriter, r *http.Request) {
	var req searchRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	q, err := query.Parse(req.Query)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	spec, ok := query.FromQuery(q)
	writeJSON(w, http.StatusOK, map[string]any{"spec": spec, "builder_ok": ok, "canonical": q.String()})
}

// ---- fields ----

func (s *Server) handleDatamodels(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, datamodel.Models)
}

type fieldInfo struct {
	datamodel.Field
	Indexed bool `json:"indexed"` // seen in stored data
}

func (s *Server) handleFields(w http.ResponseWriter, r *http.Request) {
	dm := r.URL.Query().Get("datamodel")
	pattern, err := s.Engine.IndexPattern(&query.Query{Datamodel: dm})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	out := map[string]*fieldInfo{}
	var order []string
	for _, f := range datamodel.FieldsFor(dm) {
		out[f.Name] = &fieldInfo{Field: f}
		order = append(order, f.Name)
	}
	if s.Backend != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if mapping, err := s.Backend.Mapping(ctx, pattern); err == nil {
			var extra []string
			for name, typ := range mapping {
				switch name {
				case "@timestamp":
					name = "_time"
				case "message":
					name = "_raw"
				}
				if fi, ok := out[name]; ok {
					fi.Indexed = true
					continue
				}
				t := "string"
				switch typ {
				case "long", "integer", "short", "byte", "double", "float", "half_float", "scaled_float":
					t = "number"
				case "date":
					t = "time"
				case "text":
					t = "text"
				}
				out[name] = &fieldInfo{Field: datamodel.Field{Name: name, Type: t, Description: "Discovered in your data"}, Indexed: true}
				extra = append(extra, name)
			}
			sort.Strings(extra)
			order = append(order, extra...)
		}
	}
	list := make([]*fieldInfo, 0, len(order))
	for _, n := range order {
		list = append(list, out[n])
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) handleFieldValues(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	field := v.Get("field")
	if field == "" || strings.ContainsAny(field, " |\"()") {
		writeError(w, http.StatusBadRequest, errors.New("field is required"))
		return
	}
	q := &query.Query{
		Datamodel: v.Get("datamodel"),
		Earliest:  v.Get("earliest"),
		Commands:  []query.Command{&query.Top{Limit: 10, Fields: []string{field}}},
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		writeSearchError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res.Rows)
}

func (s *Server) handleLanguage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"commands":  query.Commands,
		"functions": query.AggFuncs,
		"operators": []string{"=", "!=", "<", "<=", ">", ">=", "IN", "AND", "OR", "NOT"},
	})
}

// ---- agents and health ----

// handleAgentConfig writes a Fluent Bit config. server=<url> replaces
// server.public_url as the address agents send to, for when the configured
// one (often localhost) is not reachable from the hosts being set up.
// When Signalith serves HTTPS, agents send over https and check the
// server with its CA, and the certificate is made to cover the address.
func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	server := s.Config.Server.PublicURL
	fieldError := func(err error) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "server"})
	}
	if o := v.Get("server"); o != "" {
		u, err := agents.ParseServerURL(o)
		if err != nil {
			fieldError(err)
			return
		}
		if u.Scheme == "http" && s.Config.Server.HTTPS() {
			fieldError(fmt.Errorf("this server only accepts agents over HTTPS; use https://%s", u.Host))
			return
		}
		server = o
	}
	u, err := agents.ParseServerURL(server)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("server.public_url: %w", err))
		return
	}
	// With HTTPS off, a certificate kept for syslog over TLS is not the
	// one agents meet (a proxy in front has its own).
	certs := s.TLS
	if !s.Config.Server.HTTPS() {
		certs = nil
	}
	if u.Scheme == "https" && certs != nil {
		if err := certs.EnsureName(u.Hostname()); err != nil {
			fieldError(err)
			return
		}
	}
	token := ""
	if len(s.Config.Ingest.Tokens) > 0 {
		token = s.Config.Ingest.Tokens[0]
	}
	opts := agents.Options{
		OS:          v.Get("os"),
		ServerURL:   server,
		Token:       token,
		LinuxSource: v.Get("source"),
		Sysmon:      v.Get("sysmon") == "true",
	}
	if certs != nil {
		opts.CA = string(certs.CAPEM())
		opts.CAUnknown = opts.CA == "" && !certs.PublicCA()
	}
	a, err := agents.Generate(opts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if a.CA != "" {
		a.CAFingerprint = certs.Fingerprint()
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out := map[string]any{"version": s.Version, "ingest": s.Pipeline.Stats(), "syslog": s.Syslog.Stats()}
	status, err := s.Backend.Health(ctx)
	if err != nil {
		status = "unreachable"
	}
	// Everyone signed in sees whether things work. Where they run (file
	// paths, addresses, the OpenSearch URL and its errors) and the setup
	// advice is for admins, who are the ones able to change it.
	if p := principalOf(r); p == nil || !p.Role.AtLeast(users.Admin) {
		out["opensearch"] = map[string]any{"status": status}
		writeJSON(w, http.StatusOK, out)
		return
	}
	out["config_file"] = s.Config.Path()
	// For the steps that turn syslog on: edit the section or add one.
	out["config_has_syslog"] = s.Config.HasSection("syslog")
	out["runtime"] = s.runtimeInfo()
	out["tls"] = s.tlsInfo()
	osURL := redact.URL(s.Config.OpenSearch.URL)
	if err != nil {
		out["opensearch"] = map[string]any{"status": status, "error": err.Error(), "url": osURL}
	} else {
		out["opensearch"] = map[string]any{"status": status, "url": osURL}
	}
	warnings := s.Config.Warnings()
	if len(s.Config.Ingest.Tokens) == 0 {
		warnings = append(warnings, "No ingest tokens are configured, so agents cannot send data. Add one under ingest.tokens.")
	}
	if senders := s.Pipeline.PlaintextSenders(time.Now().Add(-plaintextWindow)); len(senders) > 0 {
		out["plaintext_senders"] = senders
		warnings = append(warnings, plaintextWarning(senders))
	}
	if len(warnings) > 0 {
		out["warnings"] = warnings
	}
	writeJSON(w, http.StatusOK, out)
}

// tlsInfo says how Signalith serves HTTPS, the names its certificate
// covers and, when it has one to give out, the fingerprint of the CA
// certificate agents and syslog devices check it with (GET
// /api/tls/ca.pem). own_ca says the CA is Signalith's own, which issues
// certificates for this server only.
func (s *Server) tlsInfo() map[string]any {
	t := map[string]any{"mode": s.Config.Server.TLSMode()}
	if s.TLS != nil {
		t["names"] = s.TLS.Names()
	}
	if s.TLS.CAPEM() != nil {
		t["ca_sha256"] = s.TLS.Fingerprint()
		t["own_ca"] = s.TLS.LocalCA()
	}
	return t
}

// plaintextWindow is how far back the Health page looks for agents
// sending over plain HTTP: long enough to see agents that send rarely.
const plaintextWindow = 24 * time.Hour

// plaintextWarning names the agents still sending over plain HTTP and
// says how to move them to HTTPS.
func plaintextWarning(senders []ingest.PlaintextSender) string {
	var names []string
	for i, x := range senders {
		if i == 5 {
			names = append(names, fmt.Sprintf("%d more", len(senders)-5))
			break
		}
		names = append(names, x.Address)
	}
	list := names[0]
	if len(names) > 1 {
		list = strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
	}
	if len(senders) == 1 {
		return "An agent still sends events over plain HTTP, which anyone on the network can read: " + list + ". " +
			"On the Add data page, get a new configuration for it, which uses HTTPS, and put it on that agent. " +
			"Then set server.tls.plaintext_ingest: deny in signalith.yaml."
	}
	return fmt.Sprintf("%d agents still send events over plain HTTP, which anyone on the network can read: %s. "+
		"On the Add data page, get a new configuration, which uses HTTPS, and put it on each of them. "+
		"Once all are updated, set server.tls.plaintext_ingest: deny in signalith.yaml.", len(senders), list)
}
