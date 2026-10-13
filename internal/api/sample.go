package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sample"
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

// sampleJob tracks the single sample-data load or remove that may run at a
// time. Its own mutex guards the fields; the long-running work runs in a
// goroutine so the request returns at once.
type sampleJob struct {
	mu       sync.Mutex
	running  bool
	op       string // "load" or "remove"
	prog     sample.Progress
	started  time.Time
	finished time.Time
	err      string
}

func (j *sampleJob) snapshot() (running bool, op string, prog sample.Progress, errStr string, finished time.Time) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.running, j.op, j.prog, j.err, j.finished
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
	j.err = ""
	j.started = time.Now()
	j.finished = time.Time{}
	j.mu.Unlock()

	go func() {
		err := work(context.Background(), func(p sample.Progress) {
			j.mu.Lock()
			j.prog = p
			j.mu.Unlock()
		})
		j.mu.Lock()
		j.running = false
		j.finished = time.Now()
		if err != nil {
			j.err = err.Error()
		}
		j.mu.Unlock()
	}()
	return true
}

// sampleStatus is the GET /api/sample reply: whether the feature is
// available, whether a set is loaded, what a running job is doing, and the
// stories and counts so the card can show what to try.
type sampleStatus struct {
	Available  bool              `json:"available"`
	Loaded     bool              `json:"loaded"`
	Running    bool              `json:"running"`
	Op         string            `json:"op,omitempty"`
	Phase      string            `json:"phase,omitempty"`
	Done       int               `json:"done,omitempty"`
	Total      int               `json:"total,omitempty"`
	Error      string            `json:"error,omitempty"`
	State      *sample.State     `json:"state,omitempty"`
	Sizes      []sample.Size     `json:"sizes,omitempty"`
	CannotFire map[string]string `json:"cannot_fire,omitempty"`
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
	running, op, prog, errStr, _ := s.sampleJob.snapshot()
	resp := sampleStatus{
		Available:  true,
		Loaded:     st != nil,
		Running:    running,
		Op:         op,
		Phase:      prog.Phase,
		Done:       prog.Done,
		Total:      prog.Total,
		Error:      errStr,
		State:      st,
		Sizes:      sample.Sizes,
		CannotFire: s.Sample.CannotFire(),
	}
	writeJSON(w, http.StatusOK, resp)
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
	if s.Sample.Loaded() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "Sample data is already loaded. Remove it first.", "code": "already_loaded"})
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
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "A sample-data job is already running. Wait for it to finish.", "code": "busy"})
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
	if !s.Sample.Loaded() {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "There is no sample data to remove.", "code": "not_loaded"})
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
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "A sample-data job is already running. Wait for it to finish.", "code": "busy"})
		return
	}
	s.audit(r, "sample data remove started")
	writeJSON(w, http.StatusAccepted, map[string]any{"started": true, "op": "remove"})
}
