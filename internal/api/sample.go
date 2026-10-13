package api

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// routeSample adds the one-click sample-data endpoints. Loading and removing
// sample data writes and deletes documents for everyone, so every route is
// for admins only.
func (s *Server) routeSample(api *router) {
	api.admin("GET /api/sample", s.handleSampleStatus)
	api.admin("POST /api/sample/load", s.handleSampleLoad)
	api.admin("POST /api/sample/remove", s.handleSampleRemove)
}

var errSampleOff = errors.New("sample data is not available on this server")

// sampleJob tracks the sample-data load or remove this server started. Its
// own mutex guards the fields; the long-running work runs in a goroutine so
// the request returns at once. The loader's lock file keeps one job at a
// time across processes (the CLI, or this server after a restart in place).
type sampleJob struct {
	mu      sync.Mutex
	running bool
	op      string // "load" or "remove"
	prog    sample.Progress
	err     error
}

func (j *sampleJob) snapshot() (running bool, op string, prog sample.Progress, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.running, j.op, j.prog, j.err
}

// start begins a background job, refusing when one is already running. The
// work gets a detached context so it finishes even after the request returns,
// and a progress callback that records the latest step for the status reply.
func (j *sampleJob) start(op string, work func(ctx context.Context, prog sample.ProgressFn) error) bool {
	j.mu.Lock()
	if j.running {
		j.mu.Unlock()
		return false
	}
	j.running = true
	j.op = op
	j.prog = sample.Progress{Op: op}
	j.err = nil
	j.mu.Unlock()

	go func() {
		err := work(context.Background(), func(p sample.Progress) {
			j.mu.Lock()
			j.prog = p
			j.mu.Unlock()
		})
		j.mu.Lock()
		j.running = false
		j.err = err
		j.mu.Unlock()
	}()
	return true
}

// sampleStatus is the GET /api/sample reply: whether the feature is
// available, whether a set is loaded (or a load stopped part way), what a
// running job is doing, and the stories and counts so the card can show
// what to try.
type sampleStatus struct {
	Available bool `json:"available"`
	Loaded    bool `json:"loaded"`
	// Partial says a load stopped part way: what it wrote should be removed.
	Partial bool   `json:"partial,omitempty"`
	Running bool   `json:"running"`
	Op      string `json:"op,omitempty"`
	Phase   string `json:"phase,omitempty"`
	Percent int    `json:"percent,omitempty"`
	// Error says in plain English what went wrong with the last job this
	// server ran and what to do; ErrorDetail is the technical text.
	Error       string            `json:"error,omitempty"`
	ErrorDetail string            `json:"error_detail,omitempty"`
	State       *sample.State     `json:"state,omitempty"`
	Sizes       []sample.Size     `json:"sizes,omitempty"`
	CannotFire  map[string]string `json:"cannot_fire,omitempty"`
	// NoData says no events at all arrived in the last 7 days, so the
	// pages can point a new admin at the sample data.
	NoData bool `json:"no_data,omitempty"`
}

func (s *Server) handleSampleStatus(w http.ResponseWriter, r *http.Request) {
	if s.Sample == nil {
		writeJSON(w, http.StatusOK, sampleStatus{Available: false})
		return
	}
	st, err := s.Sample.Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	running, op, prog, jobErr := s.sampleJob.snapshot()
	resp := sampleStatus{
		Available:  true,
		Loaded:     st != nil && !st.Partial,
		Partial:    st != nil && st.Partial,
		Running:    running,
		Op:         op,
		Phase:      prog.Phase,
		Percent:    prog.Percent,
		State:      st,
		Sizes:      sample.Sizes,
		CannotFire: s.Sample.CannotFire(),
	}
	// A job in another process (the command line, or this server before a
	// restart in place) reports through the loader's lock.
	if !running {
		if a := s.Sample.Activity(); a != nil {
			resp.Running, resp.Op, resp.Phase, resp.Percent = true, a.Op, a.Phase, a.Percent
		}
	}
	if resp.Running {
		// While a load runs, its state is partial by design.
		resp.Partial = false
	} else if jobErr != nil {
		resp.Error, resp.ErrorDetail = sampleErrorText(op, jobErr, resp.Partial)
	}
	if st == nil && !resp.Running {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		resp.NoData = s.Sample.EventsSince(ctx, 7*24*time.Hour) == 0
		cancel()
	}
	writeJSON(w, http.StatusOK, resp)
}

// sampleErrorText puts a failed job's error in plain English with what to
// do next, and keeps the technical text for a Details disclosure.
func sampleErrorText(op string, err error, partial bool) (string, string) {
	what := "load the sample data"
	if op == "remove" {
		what = "remove the sample data"
	}
	next := " Try again."
	if partial {
		next = " Remove what was loaded, then load it again."
	}
	var ue *url.Error
	var se *store.Error
	var msg string
	switch {
	case errors.Is(err, sample.ErrBusy):
		return "Another sample-data load or removal is running. Wait for it to finish.", ""
	case errors.Is(err, sample.ErrAlreadyLoaded):
		return "Sample data is already loaded. Remove it before loading again.", ""
	case errors.Is(err, sample.ErrPartial):
		return "The last load did not finish. Remove what it loaded, then load again.", ""
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		msg = "Signalith stopped before it could " + what + "."
	case errors.As(err, &ue):
		msg = "Signalith lost its connection to OpenSearch and could not " + what + ". Check the Health page."
	case errors.As(err, &se) && (se.Status == http.StatusTooManyRequests || se.Status >= 500):
		msg = "OpenSearch was too busy to " + what + ". Check the Health page."
	case errors.As(err, &se) && se.Status == http.StatusForbidden && strings.Contains(se.Body, "cluster_block_exception"):
		msg = "OpenSearch is refusing changes (it may be low on disk space), so Signalith could not " + what + ". Check the Health page."
	case errors.Is(err, sample.ErrNothingWritten):
		msg = "OpenSearch did not accept any of the sample events, so nothing was loaded. Check the Health page."
	default:
		msg = "Something went wrong and Signalith could not " + what + "."
	}
	return msg + next, err.Error()
}

type sampleLoadRequest struct {
	Size sample.Size `json:"size"`
}

func (s *Server) handleSampleLoad(w http.ResponseWriter, r *http.Request) {
	if s.Sample == nil {
		writeError(w, http.StatusServiceUnavailable, errSampleOff)
		return
	}
	var req sampleLoadRequest
	if err := readStrict(r, &req); err != nil {
		// An empty body is fine; default the size.
		req = sampleLoadRequest{}
	}
	if req.Size == "" {
		req.Size = sample.SizeStandard
	}
	if !req.Size.Valid() {
		writeError(w, http.StatusBadRequest, errors.New("size must be \"standard\" or \"small\""))
		return
	}
	if !s.sampleFree(w, true) {
		return
	}
	loader := s.Sample
	size := req.Size
	user := userOf(r)
	started := s.sampleJob.start("load", func(ctx context.Context, prog sample.ProgressFn) error {
		_, err := loader.Load(ctx, size, prog)
		if err != nil {
			s.Log.Warn("sample data load failed", "audit", true, "by", user, "size", size, "err", err)
		}
		return err
	})
	if !started {
		sampleBusy(w)
		return
	}
	s.audit(r, "sample data load started", "size", size)
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "op": "load", "size": size})
}

func (s *Server) handleSampleRemove(w http.ResponseWriter, r *http.Request) {
	if s.Sample == nil {
		writeError(w, http.StatusServiceUnavailable, errSampleOff)
		return
	}
	if !s.sampleFree(w, false) {
		return
	}
	loader := s.Sample
	user := userOf(r)
	started := s.sampleJob.start("remove", func(ctx context.Context, prog sample.ProgressFn) error {
		_, err := loader.Remove(ctx, prog)
		if err != nil {
			s.Log.Warn("sample data remove failed", "audit", true, "by", user, "err", err)
		}
		return err
	})
	if !started {
		sampleBusy(w)
		return
	}
	s.audit(r, "sample data remove started")
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "op": "remove"})
}

// sampleFree answers 409 and reports false when a job runs anywhere, or
// when the state does not allow the step: a load needs nothing loaded, a
// removal needs something loaded (complete or partial).
func (s *Server) sampleFree(w http.ResponseWriter, load bool) bool {
	if running, _, _, _ := s.sampleJob.snapshot(); running || s.Sample.Activity() != nil {
		sampleBusy(w)
		return false
	}
	st, err := s.Sample.Status()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return false
	}
	switch {
	case load && st != nil && st.Partial:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "The last load did not finish. Remove what it loaded first.", "code": "partial"})
		return false
	case load && st != nil:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "Sample data is already loaded. Remove it first.", "code": "already_loaded"})
		return false
	case !load && st == nil:
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "There is no sample data to remove.", "code": "not_loaded"})
		return false
	}
	return true
}

func sampleBusy(w http.ResponseWriter) {
	writeJSON(w, http.StatusConflict, map[string]any{
		"error": "A sample-data load or removal is already running. Wait for it to finish.", "code": "busy"})
}
