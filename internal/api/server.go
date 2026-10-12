// Package api serves the REST API and the embedded web UI.
package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
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
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/syslog"
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
	// Assistant is an optional AI model for plain-English questions.
	Assistant *assistant.Client
	UI        fs.FS // web UI files; nil disables the UI
	Log       *slog.Logger
	Version   string

	// Syslog is the syslog receiver, for its stats; nil when it is off.
	Syslog *syslog.Receiver
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

	// Restarter restarts the server with the settings saved on the
	// Settings page; nil means the page cannot restart it. Started is when
	// the process started, for the page's uptime.
	Restarter Restarter
	Started   time.Time

	authOnce     sync.Once
	creds        credCache  // recently checked Basic credentials
	routes       []route    // every API route and its role, from Handler
	caseMu       sync.Mutex // serializes case changes
	checksMu     sync.Mutex
	dirChecks    map[string]dirCheck // when each directory user was last checked
	dirSlotsOnce sync.Once
	dirSlots     chan struct{}  // limits directory connections at once
	background   sync.WaitGroup // directory checks still running
	settingsMu   sync.Mutex     // serializes saves on the Settings page
	// live holds Config with the settings saved on the Settings page that
	// apply at once, and liveAI the assistant they give.
	live   atomic.Pointer[config.Config]
	liveAI atomic.Pointer[liveModel]
}

// liveModel is the assistant after a change on the Settings page; nil
// when it was turned off.
type liveModel struct{ c *assistant.Client }

// conf returns the configuration in use: Config, with the settings saved
// on the Settings page that apply at once.
func (s *Server) conf() *config.Config {
	if c := s.live.Load(); c != nil {
		return c
	}
	return s.Config
}

// Running returns the configuration in use: the one the server started
// with, plus the settings applied at once from the Settings page since.
func (s *Server) Running() *config.Config { return s.conf() }

// model returns the AI assistant in use, or nil when it is off.
func (s *Server) model() *assistant.Client {
	if m := s.liveAI.Load(); m != nil {
		return m.c
	}
	return s.Assistant
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
	s.routeSettings(api)
	if s.UI != nil {
		api.add(route{Pattern: "GET /", Role: users.Viewer}, revalidate(http.FileServerFS(s.UI)))
	}
	s.routes = api.routes
	s.routeLogin(mux)
	mux.Handle("/", s.requireUser(api.mux))
	return securityHeaders(s.guardAPI(mux))
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

// revalidate makes browsers check with the server before reusing a cached
// copy of a signed-in page, so after signing out the app sends them to the
// sign-in page instead of showing a stale copy.
func revalidate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:")
		next.ServeHTTP(w, r)
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
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	records, err := decodeRecords(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	tag := r.Header.Get("X-Signalith-Tag")
	if tag == "" {
		tag = r.URL.Query().Get("tag")
	}
	res, err := s.Pipeline.Ingest(r.Context(), tag, records)
	if err != nil {
		s.Log.Error("ingest failed", "err", err, "records", len(records))
		// 503 makes Fluent Bit retry later instead of dropping data.
		writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	if len(res.Errors) > 0 {
		s.Log.Warn("some events were rejected", "rejected", len(res.Errors), "first", res.Errors[0].Reason)
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) validToken(r *http.Request) bool {
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if tok == "" {
		return false
	}
	for _, t := range s.conf().Ingest.Tokens {
		if subtle.ConstantTimeCompare([]byte(t), []byte(tok)) == 1 {
			return true
		}
	}
	return false
}

// decodeRecords accepts a JSON array, a single object, or NDJSON.
func decodeRecords(body []byte) ([]map[string]any, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, nil
	}
	dec := func(b []byte, v any) error {
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		return d.Decode(v)
	}
	switch body[0] {
	case '[':
		var arr []map[string]any
		if err := dec(body, &arr); err != nil {
			return nil, errors.New("invalid JSON array: " + err.Error())
		}
		return arr, nil
	case '{':
		var out []map[string]any
		sc := bufio.NewScanner(bytes.NewReader(body))
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := dec(line, &m); err != nil {
				// Maybe one pretty-printed object.
				var single map[string]any
				if err2 := dec(body, &single); err2 == nil {
					return []map[string]any{single}, nil
				}
				return nil, errors.New("invalid JSON lines: " + err.Error())
			}
			out = append(out, m)
		}
		return out, sc.Err()
	}
	return nil, errors.New("body must be a JSON array or JSON lines")
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
		writeError(w, http.StatusBadGateway, err)
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
	out := map[string]*fieldInfo{}
	var order []string
	for _, f := range datamodel.FieldsFor(dm) {
		out[f.Name] = &fieldInfo{Field: f}
		order = append(order, f.Name)
	}
	if s.Backend != nil {
		pattern := s.Engine.IndexPattern(&query.Query{Datamodel: dm})
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
		writeError(w, http.StatusBadGateway, err)
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
func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	server := s.conf().Server.PublicURL
	if o := v.Get("server"); o != "" {
		if _, err := agents.ParseServerURL(o); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error(), "field": "server"})
			return
		}
		server = o
	}
	token := ""
	if len(s.conf().Ingest.Tokens) > 0 {
		token = s.conf().Ingest.Tokens[0]
	}
	a, err := agents.Generate(agents.Options{
		OS:          v.Get("os"),
		ServerURL:   server,
		Token:       token,
		LinuxSource: v.Get("source"),
		Sysmon:      v.Get("sysmon") == "true",
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	out := map[string]any{"version": s.Version, "ingest": s.Pipeline.Stats(), "syslog": s.Syslog.Stats(), "config_file": s.conf().Path(),
		// For the steps that turn syslog on: edit the section or add one.
		"config_has_syslog": s.conf().HasSection("syslog"), "runtime": s.runtimeInfo()}
	if status, err := s.Backend.Health(ctx); err != nil {
		out["opensearch"] = map[string]any{"status": "unreachable", "error": err.Error(), "url": s.conf().OpenSearch.URL}
	} else {
		out["opensearch"] = map[string]any{"status": status, "url": s.conf().OpenSearch.URL}
	}
	if len(s.conf().Ingest.Tokens) == 0 {
		out["warnings"] = []string{"No ingest tokens are configured, so agents cannot send data. Add one under ingest.tokens."}
	}
	writeJSON(w, http.StatusOK, out)
}
