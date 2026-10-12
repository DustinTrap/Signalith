// Package api serves the REST API and the embedded web UI.
package api

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
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
	// Assistant is an optional AI model for plain-English questions.
	Assistant *assistant.Client
	UI        fs.FS // web UI files; nil disables the UI
	Log       *slog.Logger
	Version   string

	authCache sync.Map // sha256(user:pass) -> struct{}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/ingest", s.handleIngest)

	api := http.NewServeMux()
	api.HandleFunc("GET /api/health", s.handleHealth)
	api.HandleFunc("POST /api/search", s.handleSearch)
	api.HandleFunc("POST /api/explain", s.handleExplain)
	api.HandleFunc("POST /api/build", s.handleBuild)
	api.HandleFunc("POST /api/parse", s.handleParse)
	api.HandleFunc("GET /api/datamodels", s.handleDatamodels)
	api.HandleFunc("GET /api/fields", s.handleFields)
	api.HandleFunc("GET /api/fields/values", s.handleFieldValues)
	api.HandleFunc("GET /api/agents/config", s.handleAgentConfig)
	api.HandleFunc("GET /api/language", s.handleLanguage)
	s.routeDetections(api)
	s.routeRisk(api)
	s.routeAsk(api)
	if s.UI != nil {
		api.Handle("GET /", http.FileServerFS(s.UI))
	}
	mux.Handle("/", s.requireAdmin(api))
	return securityHeaders(mux)
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

// requireAdmin enforces HTTP Basic auth for the UI and API. Successful
// credentials are cached by hash so bcrypt runs once per password.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if ok {
			key := sha256.Sum256([]byte(user + "\x00" + pass + "\x00" + s.Config.Auth.AdminPasswordHash))
			if _, hit := s.authCache.Load(key); hit {
				next.ServeHTTP(w, r)
				return
			}
			if s.Config.CheckPassword(user, pass) {
				s.authCache.Store(key, struct{}{})
				next.ServeHTTP(w, r)
				return
			}
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Signalith", charset="UTF-8"`)
		writeError(w, http.StatusUnauthorized, errors.New("sign in required"))
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
	for _, t := range s.Config.Ingest.Tokens {
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

func (s *Server) handleAgentConfig(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query()
	token := ""
	if len(s.Config.Ingest.Tokens) > 0 {
		token = s.Config.Ingest.Tokens[0]
	}
	a, err := agents.Generate(agents.Options{
		OS:          v.Get("os"),
		ServerURL:   s.Config.Server.PublicURL,
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
	out := map[string]any{"version": s.Version, "ingest": s.Pipeline.Stats(), "config_file": s.Config.Path()}
	if status, err := s.Backend.Health(ctx); err != nil {
		out["opensearch"] = map[string]any{"status": "unreachable", "error": err.Error(), "url": s.Config.OpenSearch.URL}
	} else {
		out["opensearch"] = map[string]any{"status": status, "url": s.Config.OpenSearch.URL}
	}
	if len(s.Config.Ingest.Tokens) == 0 {
		out["warnings"] = []string{"No ingest tokens are configured, so agents cannot send data. Add one under ingest.tokens."}
	}
	writeJSON(w, http.StatusOK, out)
}
