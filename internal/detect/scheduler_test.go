package detect

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
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
	if !slow.TimedOut || slow.Timeouts != 1 || !strings.Contains(slow.LastError, "timed out after 300ms") || slow.Running {
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
	if !errors.Is(err, context.Canceled) || s.Status()["aaa-slow"].TimedOut || s.Status()["aaa-slow"].Timeouts != 1 {
		t.Errorf("cancelled run: %v, %+v", err, s.Status()["aaa-slow"])
	}
}

// fakeClock is a clock tests move by hand; the scheduler's workers read
// it at once.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// clockRunner answers at once, but queries mentioning "slow" move the
// clock on by four and a half minutes, as a slow search would take. It
// records the windows the queries mentioning "fast" searched.
type clockRunner struct {
	clock   *fakeClock
	mu      sync.Mutex
	windows [][2]time.Time
}

func (r *clockRunner) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	key := q.String()
	switch {
	case strings.Contains(key, "slow"):
		r.clock.Add(4*time.Minute + 30*time.Second)
	case strings.Contains(key, "fast"):
		from, err1 := time.Parse(time.RFC3339, q.Earliest)
		to, err2 := time.Parse(time.RFC3339, q.Latest)
		if err1 != nil || err2 != nil {
			return nil, errors.Join(err1, err2)
		}
		r.mu.Lock()
		r.windows = append(r.windows, [2]time.Time{from, to})
		r.mu.Unlock()
	}
	return &search.Result{Kind: "table"}, nil
}

// TestStarvedDetectionLeavesNoGaps reproduces dos-5's remainder: with
// slow detections holding the only worker, a detection due every minute
// that looks back one minute ran every nine minutes or so and searched
// only the last minute each time, so most events were never searched, and
// nothing said so. Now each run searches on from where the last one
// stopped, and the lateness shows in its run state.
func TestStarvedDetectionLeavesNoGaps(t *testing.T) {
	lib := libraryWithSlowRule(t)
	for _, d := range []*Detection{
		{ID: "aaa-slow2", Title: "Slow 2", Query: "user=slow2", Enabled: true, Schedule: "5m", Lookback: "1h"},
		{ID: "zzz-fast", Title: "Fast", Query: "user=fast", Enabled: true, Schedule: "1m", Lookback: "1m"},
	} {
		if err := lib.Put(d); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	clock := &fakeClock{t: start}
	run := &clockRunner{clock: clock}
	s := &Scheduler{Library: lib, Engine: run, Findings: findings.NewMemory(), Workers: 1, Now: clock.Now, Log: slog.New(slog.DiscardHandler)}
	end := start.Add(time.Hour)
	behind := false
	for clock.Now().Before(end) {
		s.RunDue(context.Background())
		fast, _ := lib.Get("zzz-fast")
		behind = behind || Behind(fast, s.Status()["zzz-fast"], clock.Now())
		clock.Add(15 * time.Second) // the scheduler's tick
	}

	w := run.windows
	if len(w) < 2 || len(w) > 20 {
		t.Fatalf("the fast detection ran %d times; the test means it to be starved", len(w))
	}
	if want := start.Add(-time.Minute); !w[0][0].Equal(want) {
		t.Errorf("first window starts %v, want its lookback, %v", w[0][0], want)
	}
	for i := 1; i < len(w); i++ {
		if w[i][0].After(w[i-1][1]) {
			t.Errorf("events between %v and %v were never searched", w[i-1][1], w[i][0])
		}
		if !w[i][1].After(w[i-1][1]) {
			t.Errorf("window %d %v does not move on from %v", i, w[i], w[i-1][1])
		}
	}
	if last := w[len(w)-1][1]; last.Before(end.Add(-10 * time.Minute)) {
		t.Errorf("last window ends %v, long before %v", last, end)
	}
	st := s.Status()["zzz-fast"]
	if st.LateRuns == 0 || st.Lag <= time.Minute.Milliseconds() || st.LastLate.IsZero() || st.Unsearched != 0 || !behind {
		t.Errorf("lateness not reported: %+v, behind %v", st, behind)
	}
	if !st.SearchedTo.Equal(w[len(w)-1][1]) {
		t.Errorf("searched to %v, want %v", st.SearchedTo, w[len(w)-1][1])
	}

	// Further behind than the catch-up limit (an hour, for a one-minute
	// lookback), a run searches back to the limit and counts the gap.
	fast, _ := lib.Get("zzz-fast")
	clock.Add(3 * time.Hour)
	if _, err := s.Run(context.Background(), fast); err != nil {
		t.Fatal(err)
	}
	last := run.windows[len(run.windows)-1]
	if want := clock.Now().Add(-time.Hour); !last[0].Equal(want) {
		t.Errorf("catch-up window starts %v, want %v", last[0], want)
	}
	if got, want := s.Status()["zzz-fast"].Unsearched, last[0].Sub(st.SearchedTo).Milliseconds(); got != want || got <= 0 {
		t.Errorf("unsearched %dms, want %dms", got, want)
	}

	// On time again, a run searches its lookback, as it always did.
	clock.Add(time.Minute)
	if _, err := s.Run(context.Background(), fast); err != nil {
		t.Fatal(err)
	}
	last = run.windows[len(run.windows)-1]
	if want := clock.Now().Add(-time.Minute); !last[0].Equal(want) {
		t.Errorf("on-time window starts %v, want %v", last[0], want)
	}

	// Turned off, it forgets where it stopped, so it does not catch up on
	// the time it was off.
	fast.Enabled = false
	if err := lib.Put(fast); err != nil {
		t.Fatal(err)
	}
	s.RunDue(context.Background())
	if st := s.Status()["zzz-fast"]; !st.SearchedTo.IsZero() {
		t.Errorf("a detection turned off keeps its checkpoint: %v", st.SearchedTo)
	}
}

func TestCatchUp(t *testing.T) {
	for lb, want := range map[time.Duration]time.Duration{
		time.Minute: time.Hour, 15 * time.Minute: 150 * time.Minute, 6 * time.Hour: 24 * time.Hour, 7 * 24 * time.Hour: 7 * 24 * time.Hour,
	} {
		if got := CatchUp(lb); got != want {
			t.Errorf("lookback %v: catch-up %v, want %v", lb, got, want)
		}
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
