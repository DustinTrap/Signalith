package detect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// slowRunner answers at once, except for queries mentioning "slow", which
// run until their context ends. It records how many runs of each query
// overlap.
type slowRunner struct {
	mu      sync.Mutex
	running map[string]int
	overlap bool
	done    map[string]time.Time
}

func (r *slowRunner) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	key := q.String()
	if strings.Contains(key, "slow") {
		key = "slow"
	}
	r.mu.Lock()
	if r.running == nil {
		r.running, r.done = map[string]int{}, map[string]time.Time{}
	}
	r.running[key]++
	if r.running[key] > 1 {
		r.overlap = true
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running[key]--
		r.done[key] = time.Now()
		r.mu.Unlock()
	}()
	if key == "slow" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &search.Result{Kind: "table"}, nil
}

func libraryWithSlowRule(t *testing.T) *Library {
	t.Helper()
	lib, problems, err := NewLibrary(t.TempDir())
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	if err := lib.Put(&Detection{ID: "aaa-slow", Title: "Slow", Query: "user=slow", Enabled: true, Schedule: "5m", Lookback: "1h"}); err != nil {
		t.Fatal(err)
	}
	return lib
}

// TestSlowDetectionTimesOut reproduces dos-5: detections ran one at a
// time, each for up to five minutes, so one slow query (or several) held
// up every other detection. Now a run stops at its timeout and says so,
// and the other detections run on the other workers meanwhile.
func TestSlowDetectionTimesOut(t *testing.T) {
	lib := libraryWithSlowRule(t)
	run := &slowRunner{}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Workers: 2, Timeout: 300 * time.Millisecond}
	start := time.Now()
	s.RunDue(context.Background())
	took := time.Since(start)

	st := s.Status()
	slow := st["aaa-slow"]
	if !slow.TimedOut || !strings.Contains(slow.LastError, "timed out after 300ms") || slow.Running {
		t.Errorf("slow detection state %+v", slow)
	}
	ran := 0
	for _, d := range lib.List() {
		if !d.Enabled || d.ID == "aaa-slow" {
			continue
		}
		ran++
		if got, ok := st[d.ID]; !ok || got.LastRun.IsZero() || got.LastError != "" || got.TimedOut {
			t.Errorf("%s: %+v", d.ID, got)
		}
	}
	if ran == 0 {
		t.Fatal("no other detections enabled")
	}
	// The others finished while the slow one was still running.
	slowDone := run.done["slow"]
	for key, at := range run.done {
		if key != "slow" && !at.Before(slowDone) {
			t.Errorf("%s finished after the slow detection", key)
		}
	}
	if took > 5*time.Second {
		t.Errorf("RunDue took %v", took)
	}

	// A later run that finishes clears the timeout.
	s.Timeout = 0
	run2 := &fakeRunner{}
	s.Engine = run2
	d, _ := lib.Get("aaa-slow")
	if _, err := s.Run(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if st := s.Status()["aaa-slow"]; st.TimedOut || st.LastError != "" {
		t.Errorf("after a good run: %+v", st)
	}

	// A run stopped by its caller (the server shutting down, a closed
	// request) is not a timeout.
	s.Engine = run
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	_, err := s.Run(ctx, d)
	if !errors.Is(err, context.Canceled) || s.Status()["aaa-slow"].TimedOut {
		t.Errorf("cancelled run: %v, %+v", err, s.Status()["aaa-slow"])
	}
}

func TestRunTimeout(t *testing.T) {
	s := &Scheduler{}
	for sched, want := range map[string]time.Duration{
		"1m": time.Minute, "2m": 2 * time.Minute, "5m": 5 * time.Minute, "1h": MaxRunTimeout, "bogus": MaxRunTimeout,
	} {
		if got := s.RunTimeout(&Detection{Schedule: sched}); got != want {
			t.Errorf("schedule %s: %v, want %v", sched, got, want)
		}
	}
	s.Timeout = 10 * time.Second
	if got := s.RunTimeout(&Detection{Schedule: "1h"}); got != 10*time.Second {
		t.Errorf("explicit timeout: %v", got)
	}
}

// TestStartDoesNotOverlapRuns: with workers busy, a detection that is
// still waiting or running is not started again on the next tick.
func TestStartDoesNotOverlapRuns(t *testing.T) {
	lib := libraryWithSlowRule(t)
	run := &slowRunner{}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Workers: 1, Timeout: 100 * time.Millisecond, Tick: 5 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	s.Start(ctx)
	run.mu.Lock()
	defer run.mu.Unlock()
	if run.overlap {
		t.Error("a detection ran twice at once")
	}
	for key, n := range run.running {
		if n != 0 {
			t.Errorf("%s still running after Start returned", key)
		}
	}
}

// searcher answers every search with no hits, and blocks the ones whose
// request mentions "analyst" until release is closed.
type searcher struct{ started, release chan struct{} }

func (s searcher) Search(ctx context.Context, _ string, body map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	if strings.Contains(string(b), "analyst") {
		s.started <- struct{}{}
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return map[string]any{"hits": map[string]any{"total": map[string]any{"value": 0}, "hits": []any{}}}, nil
}

// TestDetectionsDoNotWaitForAnalysts: the search engine caps searches at
// once, but the scheduler's runs (already bounded by Workers) do not
// queue behind analysts' searches.
func TestDetectionsDoNotWaitForAnalysts(t *testing.T) {
	st := searcher{started: make(chan struct{}, 1), release: make(chan struct{})}
	eng := &search.Engine{Store: st, Opt: search.Options{MaxSearches: 1, QueueWait: 50 * time.Millisecond}}
	go eng.Run(context.Background(), "user=analyst")
	<-st.started
	if _, err := eng.Run(context.Background(), "user=other"); !errors.Is(err, search.ErrBusy) {
		t.Fatalf("second analyst search: %v, want ErrBusy", err)
	}

	lib, _, _ := NewLibrary("")
	s := &Scheduler{Library: lib, Engine: eng, Findings: findings.NewMemory()}
	s.RunDue(context.Background())
	ok := 0
	for id, rs := range s.Status() {
		switch {
		case strings.Contains(rs.LastError, "busy"):
			t.Errorf("%s: %s", id, rs.LastError)
		case rs.LastError == "" && !rs.LastRun.IsZero():
			ok++
		}
	}
	if ok == 0 {
		t.Error("no detection ran")
	}
	close(st.release)
}
