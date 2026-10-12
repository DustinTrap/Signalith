package detect

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Runner executes parsed queries; *search.Engine implements it.
type Runner interface {
	Execute(ctx context.Context, q *query.Query) (*search.Result, error)
}

// Scheduler runs enabled detections on their schedules.
type Scheduler struct {
	Library  *Library
	Engine   Runner
	Findings findings.Store
	// Risk stores risk events; nil disables risk.
	Risk RiskStore
	// Assets adds business context and scales risk; nil means none.
	Assets *assets.Store
	Log    *slog.Logger
	// MaxFindingsPerRun caps the findings one run can raise (default 100),
	// so a noisy rule cannot flood the queue.
	MaxFindingsPerRun int
	// Tick is how often the scheduler checks for due detections (default 15s).
	Tick time.Duration
	Now  func() time.Time
	// Workers is how many detections run at once (default 4), so one slow
	// detection cannot hold up the others.
	Workers int
	// Timeout caps one run. Zero gives each detection its schedule
	// interval, between MinRunTimeout and MaxRunTimeout, so a run cannot
	// last into its next one.
	Timeout time.Duration

	mu    sync.Mutex
	state map[string]*RunState
	slots chan struct{}
}

// Bounds of the default run timeout.
const (
	MinRunTimeout = time.Minute
	MaxRunTimeout = 5 * time.Minute
)

// RunState is what the UI shows about a detection's last run.
type RunState struct {
	LastRun      time.Time `json:"last_run,omitzero"`
	NextRun      time.Time `json:"next_run,omitzero"`
	LastDuration int64     `json:"last_duration_ms"`
	LastResults  int       `json:"last_results"`
	LastFindings int       `json:"last_findings"`
	LastError    string    `json:"last_error,omitempty"`
	// TimedOut says the last run was stopped for taking longer than its
	// timeout; LastError says how long that was.
	TimedOut bool `json:"timed_out,omitempty"`
	Running  bool `json:"running,omitempty"`

	queued bool // waiting for a worker
}

// RunResult reports one run.
type RunResult struct {
	Results   int                 `json:"results"`
	Findings  []*findings.Finding `json:"findings"`
	Risk      int                 `json:"risk_events"`
	Throttled int                 `json:"throttled"`
	Capped    bool                `json:"capped,omitempty"`
	Earliest  time.Time           `json:"earliest"`
	Latest    time.Time           `json:"latest"`
}

func (s *Scheduler) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Scheduler) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

// SetMaxFindingsPerRun changes the cap on findings, for runs that start
// after it returns.
func (s *Scheduler) SetMaxFindingsPerRun(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.MaxFindingsPerRun = n
}

// Status returns the run state of every detection that has run.
func (s *Scheduler) Status() map[string]RunState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]RunState, len(s.state))
	for id, st := range s.state {
		out[id] = *st
	}
	return out
}

func (s *Scheduler) stateFor(id string) *RunState {
	if s.state == nil {
		s.state = map[string]*RunState{}
	}
	st, ok := s.state[id]
	if !ok {
		st = &RunState{}
		s.state[id] = st
	}
	return st
}

// Start runs due detections until ctx is cancelled, at most Workers at a
// time so a burst of schedules cannot overload OpenSearch, while a slow
// one leaves the other workers free. It returns once the runs it started
// have stopped.
func (s *Scheduler) Start(ctx context.Context) {
	tick := s.Tick
	if tick <= 0 {
		tick = 15 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		s.dispatch(ctx, &wg)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue runs every enabled detection whose next run time has passed, at
// most Workers at a time, and waits for them.
func (s *Scheduler) RunDue(ctx context.Context) {
	var wg sync.WaitGroup
	s.dispatch(ctx, &wg)
	wg.Wait()
}

// dispatch starts every due detection that is not already running or
// waiting; each waits for a free worker.
func (s *Scheduler) dispatch(ctx context.Context, wg *sync.WaitGroup) {
	now := s.now()
	var due []*Detection
	s.mu.Lock()
	if s.slots == nil {
		n := s.Workers
		if n <= 0 {
			n = 4
		}
		s.slots = make(chan struct{}, n)
	}
	slots := s.slots
	for _, d := range s.Library.List() {
		if !d.Enabled {
			continue
		}
		st := s.stateFor(d.ID)
		if st.Running || st.queued || (!st.NextRun.IsZero() && now.Before(st.NextRun)) {
			continue
		}
		st.queued = true
		due = append(due, d)
	}
	s.mu.Unlock()
	sort.Slice(due, func(i, j int) bool { return due[i].ID < due[j].ID })
	for _, d := range due {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				s.mu.Lock()
				s.stateFor(d.ID).queued = false
				s.mu.Unlock()
			}()
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-slots }()
			if ctx.Err() != nil {
				return
			}
			// The scheduler bounds its own searches, so they do not wait
			// behind analysts' searches.
			if _, err := s.Run(search.Background(ctx), d); err != nil {
				s.log().Warn("detection failed", "detection", d.ID, "err", err)
			}
		}()
	}
}

// RunTimeout is how long one run of d may take.
func (s *Scheduler) RunTimeout(d *Detection) time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	sched, err := ParseDuration(d.Schedule)
	if err != nil {
		return MaxRunTimeout
	}
	return min(max(sched, MinRunTimeout), MaxRunTimeout)
}

// Run executes one detection now and raises findings. It also records
// the run state and schedules the next run. A run that takes longer than
// RunTimeout is stopped and reported as timed out.
func (s *Scheduler) Run(ctx context.Context, d *Detection) (*RunResult, error) {
	start := s.now()
	s.mu.Lock()
	st := s.stateFor(d.ID)
	st.Running = true
	s.mu.Unlock()

	timeout := s.RunTimeout(d)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	res, err := s.run(rctx, d, start)
	// Failed after its own deadline passed (not the caller's): however the
	// error reads, the run ran out of time.
	timedOut := err != nil && errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil
	cancel()
	if timedOut {
		err = fmt.Errorf("timed out after %s, so this run was stopped; narrow the query or shorten its lookback so it finishes in time", timeout)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	st.Running = false
	st.LastRun = start
	st.LastDuration = s.now().Sub(start).Milliseconds()
	st.TimedOut = timedOut
	if sched, perr := ParseDuration(d.Schedule); perr == nil {
		st.NextRun = start.Add(sched)
	}
	if err != nil {
		st.LastError = err.Error()
		return nil, err
	}
	st.LastError = ""
	st.LastResults = res.Results
	st.LastFindings = len(res.Findings)
	if len(res.Findings) > 0 || res.Risk > 0 {
		s.log().Info("detection fired", "detection", d.ID, "findings", len(res.Findings), "risk_events", res.Risk, "throttled", res.Throttled)
	}
	return res, nil
}

// Window returns the time range a run at now searches.
func Window(d *Detection, now time.Time) (time.Time, time.Time, error) {
	lb, err := ParseDuration(d.Lookback)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return now.Add(-lb), now, nil
}

// Preview runs a detection's query over its lookback window without
// raising findings, for "Test" in the UI.
func (s *Scheduler) Preview(ctx context.Context, d *Detection) (*search.Result, error) {
	q, _, _, err := s.prepare(d, s.now())
	if err != nil {
		return nil, err
	}
	return s.Engine.Execute(ctx, q)
}

func (s *Scheduler) prepare(d *Detection, now time.Time) (*query.Query, time.Time, time.Time, error) {
	q, err := query.Parse(d.Query)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	earliest, latest, err := Window(d, now)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	q.Earliest = earliest.UTC().Format(time.RFC3339)
	q.Latest = latest.UTC().Format(time.RFC3339)
	return q, earliest, latest, nil
}

func (s *Scheduler) run(ctx context.Context, d *Detection, now time.Time) (*RunResult, error) {
	q, earliest, latest, err := s.prepare(d, now)
	if err != nil {
		return nil, err
	}
	res, err := s.Engine.Execute(ctx, q)
	if err != nil {
		return nil, err
	}
	out := &RunResult{Results: len(res.Rows), Earliest: earliest, Latest: latest, Findings: []*findings.Finding{}}
	s.mu.Lock()
	maxF := s.MaxFindingsPerRun
	s.mu.Unlock()
	if maxF <= 0 {
		maxF = 100
	}
	window := time.Duration(0)
	if d.Throttle.Window != "" {
		window, _ = ParseDuration(d.Throttle.Window)
	}
	seen := map[string]bool{}
	for _, row := range res.Rows {
		key := GroupKey(d, row)
		if seen[key] {
			out.Throttled++
			continue
		}
		seen[key] = true
		riskOnly := d.Risk != nil && d.Risk.Only
		if window > 0 {
			var dup bool
			var err error
			if riskOnly {
				if s.Risk != nil {
					dup, err = s.Risk.Exists(ctx, d.ID, key, now.Add(-window))
				}
			} else {
				dup, err = s.Findings.Exists(ctx, d.ID, key, now.Add(-window))
			}
			if err != nil {
				return nil, err
			}
			if dup {
				out.Throttled++
				continue
			}
		}
		if len(out.Findings) >= maxF || out.Risk >= maxF*4 {
			out.Capped = true
			break
		}
		if d.Risk != nil && s.Risk != nil {
			evs := RiskEvents(d, row, key, s.Assets, now)
			if err := s.Risk.Write(ctx, evs); err != nil {
				return nil, err
			}
			out.Risk += len(evs)
		}
		if riskOnly {
			continue
		}
		f := NewFinding(d, q, row, key, earliest, latest, now)
		f.Context = EntityContext(s.Assets, f.Entities)
		f.Urgency = Urgency(f.Severity, f.Context)
		if err := s.Findings.Create(ctx, f); err != nil {
			return nil, err
		}
		out.Findings = append(out.Findings, f)
	}
	return out, nil
}

// GroupKey is the throttle key for a result row.
func GroupKey(d *Detection, row map[string]any) string {
	h := sha256.New()
	h.Write([]byte(d.ID))
	if len(d.Throttle.Fields) > 0 {
		for _, f := range d.Throttle.Fields {
			fmt.Fprintf(h, "\x00%s=%v", f, row[f])
		}
	} else {
		// Whole row, minus the time so the same activity seen by two
		// overlapping runs is one finding.
		b, _ := json.Marshal(withoutTime(row))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

func withoutTime(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		if k != "_time" {
			out[k] = v
		}
	}
	return out
}

// EntityFields are the result columns copied into a finding's entities.
var EntityFields = []string{"user", "src_user", "src", "src_host", "dest", "dest_host", "host", "process_name", "object", "member", "risk_object", "risk_object_type"}

func entities(row map[string]any) map[string]any {
	ents := map[string]any{}
	for _, f := range EntityFields {
		if v, ok := row[f]; ok && v != nil && fmt.Sprint(v) != "" {
			ents[f] = v
		}
	}
	return ents
}

// NewFinding builds the finding for one result row.
func NewFinding(d *Detection, q *query.Query, row map[string]any, key string, earliest, latest, now time.Time) *findings.Finding {
	result := make(map[string]any, len(row))
	for k, v := range row {
		if s, ok := v.(string); ok && len(s) > 8192 {
			v = s[:8192] + "…"
		}
		result[k] = v
	}
	ents := entities(row)
	return &findings.Finding{
		ID:          NewID(now),
		DetectionID: d.ID,
		Title:       RenderTitle(d.Title, row),
		Description: d.Description,
		Severity:    d.Severity,
		Urgency:     d.Severity,
		Status:      findings.StatusNew,
		MITRE:       append([]string(nil), d.MITRE...),
		Entities:    ents,
		Result:      result,
		Query:       Drilldown(q, row).String(),
		Earliest:    earliest.UTC().Format(time.RFC3339),
		Latest:      latest.UTC().Format(time.RFC3339),
		GroupKey:    key,
		Created:     now.UTC(),
		Updated:     now.UTC(),
	}
}

// NewID returns a sortable, unique finding ID.
func NewID(now time.Time) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return now.UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func withTerm(q *query.Query, t query.Expr) *query.Query {
	if q.Search == nil {
		q.Search = t
	} else {
		q.Search = &query.And{Children: []query.Expr{q.Search, t}}
	}
	return q
}

// Drilldown returns the search that shows the events behind a result row:
// the detection's filter plus the row's group-by values, without the
// transforming commands. Event queries drill down to themselves.
func Drilldown(q *query.Query, row map[string]any) *query.Query {
	var by []string
	if len(q.Commands) > 0 {
		switch c := q.Commands[0].(type) {
		case *query.Stats:
			by = c.By
		case *query.Top:
			by = append(append(by, c.Fields...), c.By...)
		case *query.ThreatMatch:
			// The events behind a threat match are those with the matched value.
			out := &query.Query{Search: q.Search, Datamodel: q.Datamodel, Index: q.Index}
			f, _ := row["threat_match_field"].(string)
			if v, ok := row["threat_match_value"]; ok && v != nil && f != "" {
				return withTerm(out, &query.Compare{Field: f, Op: "=", Value: fmt.Sprint(v)})
			}
			return out
		default:
			return &query.Query{Search: q.Search, Datamodel: q.Datamodel, Index: q.Index}
		}
	}
	out := &query.Query{Datamodel: q.Datamodel, Index: q.Index}
	var parts []query.Expr
	if q.Search != nil {
		parts = append(parts, q.Search)
	}
	for _, f := range by {
		if v, ok := row[f]; ok && v != nil {
			parts = append(parts, &query.Compare{Field: f, Op: "=", Value: fmt.Sprint(v)})
		}
	}
	switch len(parts) {
	case 0:
	case 1:
		out.Search = parts[0]
	default:
		out.Search = &query.And{Children: parts}
	}
	return out
}
