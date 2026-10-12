package retention

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
)

// Defaults for the schedule.
const (
	DefaultInterval = time.Hour
	// DefaultRestoreDays is how long a restored day stays searchable when
	// the restore does not say.
	DefaultRestoreDays = 14
	MaxRestoreDays     = 365

	firstRunDelay = 2 * time.Minute
	diskCheck     = 5 * time.Minute
	importBatch   = 500
	importBytes   = 8 << 20
)

// Errors for jobs that cannot start.
var (
	ErrBusy      = errors.New("a retention run is already in progress; try again when it finishes")
	ErrRestoring = errors.New("archived days are being restored; try again when that finishes")
)

// Manager plans and enforces retention, and serves the Data retention
// page: overview, previews, settings changes and restores.
type Manager struct {
	Cluster Cluster
	Prefix  string
	// Config is what signalith.yaml says; Store holds what the page saved.
	Config  Config
	Store   *Store
	Archive *Archive
	// HistoryFile keeps the last run and recent actions.
	HistoryFile string
	// Interval is how often Start enforces policies; default 1h.
	Interval time.Duration
	Log      *slog.Logger
	// Now returns the current time; tests set it.
	Now func() time.Time

	initOnce sync.Once
	hist     *history
	// job is held by a run or a restore, so they never overlap.
	job sync.Mutex

	mu        sync.Mutex
	automatic bool
	current   string // "run" or "restore" while a job holds job
	nextRun   time.Time
	baseCtx   context.Context
	restores  []*RestoreStatus
	lastShort time.Time
}

func (m *Manager) init() {
	m.initOnce.Do(func() {
		m.hist = loadHistory(m.HistoryFile)
		if m.Log == nil {
			m.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
		}
		if m.Archive == nil {
			m.Archive = &Archive{}
		}
	})
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Manager) interval() time.Duration {
	if m.Interval > 0 {
		return m.Interval
	}
	return DefaultInterval
}

func (m *Manager) ctx() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.baseCtx != nil {
		return m.baseCtx
	}
	return context.Background()
}

func (m *Manager) setCurrent(what string) {
	m.mu.Lock()
	m.current = what
	m.mu.Unlock()
}

func (m *Manager) busy() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == "restore" {
		return ErrRestoring
	}
	return ErrBusy
}

// Settings returns the settings in effect. When the page's settings file
// has errors it is returned too, and runs do nothing until it is fixed.
func (m *Manager) Settings() (Settings, error) {
	var saved Saved
	var err error
	if m.Store != nil {
		saved, err = m.Store.Get()
	}
	return Effective(m.Config, saved), err
}

// state is a snapshot plus what the overview needs besides the plan.
type state struct {
	snap     Snapshot
	records  map[string]IndexInfo
	diskErr  string
	archives []Manifest
	archErr  string
	archProb []string
}

func (m *Manager) snapshot(ctx context.Context) (*state, error) {
	m.init()
	st := &state{snap: Snapshot{Now: m.now(), Prefix: m.Prefix}, records: map[string]IndexInfo{}}
	all, err := m.Cluster.Indices(ctx, m.Prefix+"-*,"+m.Prefix+"_*")
	if err != nil {
		return nil, fmt.Errorf("could not list indices in OpenSearch: %w", err)
	}
	for _, ix := range all {
		if strings.HasPrefix(ix.Name, m.Prefix+"-") {
			st.snap.Indices = append(st.snap.Indices, ix)
		} else {
			st.records[ix.Name] = ix
		}
	}
	if d, err := m.Cluster.Disk(ctx); err != nil {
		st.diskErr = err.Error()
	} else {
		st.snap.Disk = d
	}
	list, problems, err := m.Archive.List()
	if err != nil {
		st.archErr = err.Error()
	}
	st.archives, st.archProb = list, problems
	st.snap.Archived = archivedDocs(list)
	return st, nil
}

// planRecords counts the findings and cases the policies would delete.
// Findings in open cases are kept with their case.
func (m *Manager) planRecords(ctx context.Context, s Settings, now time.Time) ([]RecordStep, error) {
	out := []RecordStep{}
	for _, id := range []string{Findings, Cases} {
		pol, src := s.For(id)
		if pol.KeepDays <= 0 {
			continue
		}
		step := RecordStep{
			Category: id, Index: RecordIndex(m.Prefix, id), KeepDays: pol.KeepDays, Source: src,
			Before: now.Add(-time.Duration(pol.KeepDays) * 24 * time.Hour),
			Reason: fmt.Sprintf("Resolved or closed, and unchanged for more than %s", days(pol.KeepDays)),
		}
		if id == Findings {
			open, err := m.Cluster.OpenCases(ctx, RecordIndex(m.Prefix, Cases))
			if err != nil {
				return out, fmt.Errorf("could not list open investigations, so no findings are deleted: %w", err)
			}
			step.keepCases = open
		}
		n, err := m.Cluster.CountClosed(ctx, step.Index, step.Before, step.keepCases)
		if err != nil {
			return out, fmt.Errorf("could not count closed %s: %w", id, err)
		}
		if n > 0 {
			step.Count = n
			out = append(out, step)
		}
	}
	return out, nil
}

// plan plans indices and records. An error means findings or cases could
// not be checked; the plan still covers everything else.
func (m *Manager) plan(ctx context.Context, s Settings, st *state) (*Plan, error) {
	p := PlanIndices(st.snap, s)
	recs, err := m.planRecords(ctx, s, st.snap.Now)
	p.Records = recs
	return p, err
}

// Run plans and enforces retention once. It returns ErrBusy or
// ErrRestoring when another job is going.
func (m *Manager) Run(ctx context.Context, trigger, by string) (*Run, error) {
	m.init()
	if !m.job.TryLock() {
		return nil, m.busy()
	}
	defer m.job.Unlock()
	return m.run(ctx, trigger, by)
}

// RunAsync starts a run in the background, for "Run now".
func (m *Manager) RunAsync(trigger, by string) error {
	m.init()
	if !m.job.TryLock() {
		return m.busy()
	}
	go func() {
		defer m.job.Unlock()
		_, _ = m.run(m.ctx(), trigger, by)
	}()
	return nil
}

// run does one run; the caller holds m.job.
func (m *Manager) run(ctx context.Context, trigger, by string) (*Run, error) {
	m.setCurrent("run")
	defer m.setCurrent("")
	run := &Run{Started: m.now(), Trigger: trigger, By: by, Errors: []string{}}
	finish := func(err error) (*Run, error) {
		if err != nil {
			run.Errors = append(run.Errors, err.Error())
			m.Log.Warn("retention run failed", "err", err)
		}
		run.Finished = m.now()
		if err := m.hist.add(run); err != nil {
			m.Log.Warn("could not save the retention history", "file", m.HistoryFile, "err", err)
		}
		return run, err
	}
	s, err := m.Settings()
	if err != nil {
		return finish(fmt.Errorf("retention is paused until the settings file is fixed: %w", err))
	}
	st, err := m.snapshot(ctx)
	if err != nil {
		return finish(err)
	}
	plan, err := m.plan(ctx, s, st)
	if err != nil {
		run.Errors = append(run.Errors, err.Error())
	}
	g := plan.Guard
	run.Guard = &g
	switch g.State {
	case GuardOver:
		m.Log.Warn("retention: disk is above the guard limit; deleting the oldest days",
			"percent", g.Percent, "limit", g.Threshold, "days", g.PlannedDays, "bytes", g.PlannedBytes)
	case GuardShort:
		m.Log.Error("retention: disk is above the guard limit and only protected days are left; add disk space",
			"percent", g.Percent, "limit", g.Threshold, "min_days", g.MinDays)
		m.mu.Lock()
		m.lastShort = m.now()
		m.mu.Unlock()
	}
	today := startOfDay(st.snap.Now)
	for _, d := range plan.Steps() {
		if ctx.Err() != nil {
			break
		}
		act := m.apply(ctx, d, today)
		m.record(run, act)
		if act.Error != "" {
			run.Errors = append(run.Errors, act.Index+": "+act.Error)
			continue
		}
		run.FreedBytes += act.Freed
		switch act.Action {
		case ActionCompact:
			run.Compacted++
		case ActionArchive:
			run.Archived++
		case ActionDelete:
			run.Deleted++
		}
	}
	for _, r := range plan.Records {
		if ctx.Err() != nil {
			break
		}
		n, err := m.Cluster.DeleteClosed(ctx, r.Index, r.Before, r.keepCases)
		act := Action{Time: m.now(), Action: ActionDeleteRecords, Category: r.Category, Docs: n, Rule: RuleRecords, Reason: r.Reason}
		if err != nil {
			act.Error = err.Error()
			run.Errors = append(run.Errors, r.Category+": "+err.Error())
		}
		run.DeletedRecords += n
		m.record(run, act)
	}
	if err := ctx.Err(); err != nil {
		return finish(fmt.Errorf("the run was stopped: %w", err))
	}
	if run.Compacted+run.Archived+run.Deleted > 0 || run.DeletedRecords > 0 {
		m.Log.Info("retention run finished", "compacted", run.Compacted, "archived", run.Archived,
			"deleted", run.Deleted, "records", run.DeletedRecords, "freed_bytes", run.FreedBytes, "errors", len(run.Errors))
	}
	return finish(nil)
}

// record logs an action and adds it to the history.
func (m *Manager) record(run *Run, act Action) {
	if act.Error != "" {
		m.Log.Warn("retention action failed", "action", act.Action, "index", act.Index, "category", act.Category, "err", act.Error)
	} else {
		m.Log.Info("retention: "+act.Action, "index", act.Index, "category", act.Category, "reason", act.Reason,
			"bytes", act.Bytes, "docs", act.Docs, "file", act.File)
	}
	if run != nil && run.Trigger != "" && act.By == "" {
		act.By = run.By
	}
	if err := m.hist.add(nil, act); err != nil {
		m.Log.Warn("could not save the retention history", "file", m.HistoryFile, "err", err)
	}
}

// apply carries out one decision. It re-checks the index name and day,
// so a planner bug can never delete today's data or another prefix's.
func (m *Manager) apply(ctx context.Context, d Decision, today time.Time) Action {
	act := Action{Time: m.now(), Action: d.Action, Category: d.Category, Index: d.Index, Day: d.Day,
		Bytes: d.Bytes, Rule: d.Rule, Reason: d.Reason}
	cat, day, ok := ParseIndex(m.Prefix, d.Index)
	switch {
	case !ok || cat != d.Category:
		act.Error = "refused: not a Signalith daily index"
		return act
	case d.Removes() && !day.Before(today):
		act.Error = "refused: today's and future days are never deleted"
		return act
	case d.Action == ActionCompact && !day.Before(today.AddDate(0, 0, -1)):
		act.Error = "refused: today and yesterday are never compacted"
		return act
	}
	var err error
	switch d.Action {
	case ActionCompact:
		err = m.compact(ctx, d, &act)
	case ActionArchive:
		err = m.archiveAndDelete(ctx, d, &act)
	case ActionDelete:
		act.Docs = d.Docs
		if err = m.Cluster.DeleteIndex(ctx, d.Index); err == nil {
			act.Freed = d.Bytes
		}
	}
	if err != nil {
		act.Error = err.Error()
	}
	act.Time = m.now()
	return act
}

func (m *Manager) compact(ctx context.Context, d Decision, act *Action) error {
	if err := m.Cluster.BlockWrites(ctx, d.Index, true); err != nil {
		return fmt.Errorf("could not make the index read-only: %w", err)
	}
	if err := m.Cluster.ForceMerge(ctx, d.Index); err != nil {
		return fmt.Errorf("could not merge the index: %w", err)
	}
	if after, err := m.Cluster.Indices(ctx, d.Index); err == nil && len(after) == 1 {
		act.Freed = max(d.Bytes-after[0].Bytes, 0)
	}
	return nil
}

func (m *Manager) archiveAndDelete(ctx context.Context, d Decision, act *Action) error {
	// Writes are blocked first so the archive holds exactly what is deleted.
	// An index under OpenSearch's flood-stage block takes no writes and
	// refuses setting changes, so it is archived as it is.
	if !d.writesBlocked {
		if err := m.Cluster.BlockWrites(ctx, d.Index, true); err != nil {
			return fmt.Errorf("could not make the index read-only before archiving it, so it was kept: %w", err)
		}
	}
	n, err := m.Cluster.Count(ctx, d.Index)
	if err != nil {
		return fmt.Errorf("could not count its events, so it was kept: %w", err)
	}
	man, err := m.Archive.Write(ctx, m.Cluster, d.Index, d.Category, d.Day, d.Bytes, n)
	if err != nil {
		return fmt.Errorf("archiving failed, so the index was kept: %w", err)
	}
	act.File, act.Docs = man.File, man.Docs
	if err := m.Cluster.DeleteIndex(ctx, d.Index); err != nil {
		return fmt.Errorf("archived to %s, but deleting the index failed: %w", man.File, err)
	}
	act.Freed = d.Bytes
	return nil
}

// Start enforces retention every Interval until ctx ends, and checks the
// disk every few minutes so the guard can act between runs. Only the
// server that runs the detection scheduler calls it.
func (m *Manager) Start(ctx context.Context) {
	m.init()
	interval := m.interval()
	m.mu.Lock()
	m.automatic, m.baseCtx, m.nextRun = true, ctx, m.now().Add(firstRunDelay)
	m.mu.Unlock()
	timer := time.NewTimer(firstRunDelay)
	defer timer.Stop()
	check := time.NewTicker(diskCheck)
	defer check.Stop()
	scheduled := func(trigger string) {
		if _, err := m.Run(ctx, trigger, ""); errors.Is(err, ErrBusy) || errors.Is(err, ErrRestoring) {
			m.Log.Info("retention run skipped; another job is in progress", "trigger", trigger)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			scheduled(TriggerSchedule)
			m.mu.Lock()
			m.nextRun = m.now().Add(interval)
			m.mu.Unlock()
			timer.Reset(interval)
		case <-check.C:
			if m.guardTripped(ctx) {
				scheduled(TriggerGuard)
			}
		}
	}
}

// guardTripped reports whether the disk is over the guard's limit. After
// a run found nothing more it may delete, it waits for the next scheduled
// run instead of retrying every few minutes.
func (m *Manager) guardTripped(ctx context.Context) bool {
	s, err := m.Settings()
	if err != nil || !s.Guard.IsEnabled() {
		return false
	}
	m.mu.Lock()
	recent := !m.lastShort.IsZero() && m.now().Sub(m.lastShort) < m.interval()
	m.mu.Unlock()
	if recent {
		return false
	}
	d, err := m.Cluster.Disk(ctx)
	return err == nil && d.Percent() > float64(s.Guard.MaxDiskPercent)
}

// ---- settings changes ----

// SetPolicy saves a category's own policy, or with nil goes back to the
// default.
func (m *Manager) SetPolicy(id string, p *Policy) error {
	return m.change(Change{Category: id, Policy: p}, func(sv *Saved) {
		if p == nil {
			delete(sv.Policies, id)
			return
		}
		if sv.Policies == nil {
			sv.Policies = map[string]Policy{}
		}
		sv.Policies[id] = *p
	})
}

// SetDefault saves the default policy for event categories.
func (m *Manager) SetDefault(p Policy) error {
	return m.change(Change{Default: &p}, func(sv *Saved) { sv.Default = &p })
}

// SetGuard saves the disk guard settings.
func (m *Manager) SetGuard(g Guard) error {
	g = g.Normalized()
	return m.change(Change{Guard: &g}, func(sv *Saved) { sv.Guard = &g })
}

func (m *Manager) change(ch Change, save func(*Saved)) error {
	if m.Store == nil {
		return errors.New("retention settings cannot be saved on this server")
	}
	cur, err := m.Settings()
	if err != nil {
		return err
	}
	if _, err := cur.apply(ch); err != nil {
		return err
	}
	return m.Store.Update(save)
}

// ---- previews ----

// Preview is what a settings change would do at the next run, beyond what
// the current settings already do.
type Preview struct {
	Summary     Summary      `json:"summary"`
	Steps       []Decision   `json:"steps"`
	Records     []RecordStep `json:"records"`
	DeletesData bool         `json:"deletes_data"`
	Guard       GuardStatus  `json:"guard"`
	Notes       []string     `json:"notes"`
}

// Preview plans a change without saving it.
func (m *Manager) Preview(ctx context.Context, ch Change) (*Preview, error) {
	cur, err := m.Settings()
	if err != nil {
		return nil, err
	}
	next, err := cur.apply(ch)
	if err != nil {
		return nil, err
	}
	st, err := m.snapshot(ctx)
	if err != nil {
		return nil, err
	}
	before, _ := m.plan(ctx, cur, st)
	after, err := m.plan(ctx, next, st)
	if err != nil {
		after.Notes = append(after.Notes, err.Error())
	}
	was := map[string]string{}
	for _, d := range before.Steps() {
		was[d.Index] = d.Action
	}
	steps := []Decision{}
	for _, d := range after.Steps() {
		if was[d.Index] != d.Action {
			steps = append(steps, d)
		}
	}
	recs := []RecordStep{}
	for _, r := range after.Records {
		for _, b := range before.Records {
			if b.Category == r.Category {
				r.Count -= b.Count
			}
		}
		if r.Count > 0 {
			recs = append(recs, r)
		}
	}
	sum := Summarize(steps, recs)
	return &Preview{Summary: sum, Steps: steps, Records: recs, DeletesData: sum.DeletesData(), Guard: after.Guard, Notes: after.Notes}, nil
}

// ---- overview ----

// Overview is everything the Data retention page shows.
type Overview struct {
	Categories []CategoryView `json:"categories"`
	Default    DefaultView    `json:"default"`
	Guard      GuardView      `json:"guard"`
	// Disk is the fullest OpenSearch data disk; nil when it could not be read.
	Disk      *Disk  `json:"disk"`
	DiskError string `json:"disk_error,omitempty"`
	// TotalBytes and TotalDocs add up every category.
	TotalBytes int64 `json:"total_bytes"`
	TotalDocs  int64 `json:"total_docs"`
	// DiskBlocked counts indices OpenSearch made read-only because the
	// disk passed its flood-stage watermark.
	DiskBlocked int            `json:"disk_blocked"`
	Archive     ArchiveSummary `json:"archive"`
	Schedule    ScheduleView   `json:"schedule"`
	// Pending is what the next run would do with the current settings.
	Pending Summary  `json:"pending"`
	Notes   []string `json:"notes"`
	LastRun *Run     `json:"last_run"`
	Recent  []Action `json:"recent"`
	// Unmanaged lists indices under the prefix that are not daily indices
	// of a known category; retention leaves them alone.
	Unmanaged []IndexInfo `json:"unmanaged"`
	// Error says OpenSearch could not be read; sizes are then missing.
	Error string `json:"error,omitempty"`
	// SettingsError says retention.yaml has errors; runs are paused.
	SettingsError string `json:"settings_error,omitempty"`
}

// CategoryView is one row of the page's table.
type CategoryView struct {
	Category
	Bytes int64 `json:"bytes"`
	Docs  int64 `json:"docs"`
	// Days counts daily indices; OldestDay and NewestDay are YYYY-MM-DD,
	// empty when there is no data (for findings and cases: when the
	// oldest and newest were created).
	Days          int    `json:"days"`
	OldestDay     string `json:"oldest_day"`
	NewestDay     string `json:"newest_day"`
	CompactedDays int    `json:"compacted_days"`
	RestoredDays  int    `json:"restored_days"`
	Policy        Policy `json:"policy"`
	// Source is default, ui, config or feeds; Editable is false for
	// policies from signalith.yaml and for threat intel.
	Source   string  `json:"source"`
	Editable bool    `json:"editable"`
	Note     string  `json:"note,omitempty"`
	Pending  Summary `json:"pending"`
}

// DefaultView is the default policy for event categories.
type DefaultView struct {
	Policy   Policy `json:"policy"`
	Source   string `json:"source"` // days, ui or config
	Editable bool   `json:"editable"`
	Note     string `json:"note,omitempty"`
}

// GuardView is the disk guard's settings and what it sees.
type GuardView struct {
	Enabled        bool        `json:"enabled"`
	MaxDiskPercent int         `json:"max_disk_percent"`
	MinDays        int         `json:"min_days"`
	Source         string      `json:"source"` // builtin, ui or config
	Editable       bool        `json:"editable"`
	Note           string      `json:"note,omitempty"`
	Status         GuardStatus `json:"status"`
}

// ArchiveSummary describes the archive folder.
type ArchiveSummary struct {
	Dir      string   `json:"dir"`
	Files    int      `json:"files"`
	Bytes    int64    `json:"bytes"`
	Error    string   `json:"error,omitempty"`
	Problems []string `json:"problems"`
}

// ScheduleView says when retention runs.
type ScheduleView struct {
	Interval        string `json:"interval"`
	IntervalSeconds int64  `json:"interval_seconds"`
	// Automatic is false on servers that do not run the detection
	// scheduler; they only run when asked.
	Automatic bool       `json:"automatic"`
	Running   bool       `json:"running"`
	Current   string     `json:"current,omitempty"` // run or restore
	NextRun   *time.Time `json:"next_run"`
}

const fromConfig = "From signalith.yaml"

// shortDuration prints 1h rather than 1h0m0s.
func shortDuration(d time.Duration) string {
	out := d.String()
	if strings.HasSuffix(out, "m0s") {
		out = strings.TrimSuffix(out, "0s")
	}
	if strings.HasSuffix(out, "h0m") {
		out = strings.TrimSuffix(out, "0m")
	}
	return out
}

// Overview gathers the page's data. It always returns something: when
// OpenSearch cannot be read, Error says so and sizes are missing.
func (m *Manager) Overview(ctx context.Context) *Overview {
	m.init()
	s, serr := m.Settings()
	ov := &Overview{Categories: []CategoryView{}, Notes: []string{}, Recent: []Action{}, Unmanaged: []IndexInfo{},
		Pending: Summary{Categories: []string{}}}
	if serr != nil {
		ov.SettingsError = serr.Error()
	}
	ov.Default = DefaultView{Policy: s.Default, Source: s.DefaultSource, Editable: s.DefaultSource != SourceConfig && m.Store != nil}
	if s.DefaultSource == SourceConfig {
		ov.Default.Note = fromConfig
	}
	ov.Guard = GuardView{Enabled: s.Guard.IsEnabled(), MaxDiskPercent: s.Guard.MaxDiskPercent, MinDays: s.Guard.MinDays,
		Source: s.GuardSource, Editable: s.GuardSource != SourceConfig && m.Store != nil}
	if s.GuardSource == SourceConfig {
		ov.Guard.Note = fromConfig
	}
	ov.LastRun, ov.Recent = m.hist.get()
	ov.Archive = ArchiveSummary{Dir: m.Archive.Dir, Problems: []string{}}
	iv := m.interval()
	m.mu.Lock()
	ov.Schedule = ScheduleView{Interval: shortDuration(iv), IntervalSeconds: int64(iv / time.Second),
		Automatic: m.automatic, Running: m.current != "", Current: m.current}
	if m.automatic && !m.nextRun.IsZero() {
		next := m.nextRun
		ov.Schedule.NextRun = &next
	}
	m.mu.Unlock()

	st, err := m.snapshot(ctx)
	var plan *Plan
	if err != nil {
		ov.Error = err.Error()
		st = &state{snap: Snapshot{Now: m.now(), Prefix: m.Prefix}, records: map[string]IndexInfo{}}
		plan = PlanIndices(st.snap, s)
		ov.Guard.Status = GuardStatus{State: GuardUnknown, Threshold: s.Guard.MaxDiskPercent, MinDays: s.Guard.MinDays,
			Message: "OpenSearch could not be read."}
		if !s.Guard.IsEnabled() {
			ov.Guard.Status.State, ov.Guard.Status.Message = GuardOff, "The disk guard is off."
		}
	} else {
		plan, err = m.plan(ctx, s, st)
		if err != nil {
			ov.Notes = append(ov.Notes, err.Error())
		}
		ov.Guard.Status = plan.Guard
		ov.Disk, ov.DiskError = st.snap.Disk, st.diskErr
		ov.Notes = append(ov.Notes, plan.Notes...)
		for _, ma := range st.archives {
			ov.Archive.Files++
			ov.Archive.Bytes += ma.Bytes
		}
		ov.Archive.Error = st.archErr
		if st.archProb != nil {
			ov.Archive.Problems = st.archProb
		}
	}
	steps := plan.Steps()
	ov.Pending = Summarize(steps, plan.Records)

	byCat := map[string]*CategoryView{}
	for _, c := range Categories() {
		pol, src := s.For(c.ID)
		cv := &CategoryView{Category: c, Policy: pol, Source: src,
			Editable: c.Kind != KindManaged && src != SourceConfig && m.Store != nil}
		switch {
		case src == SourceConfig:
			cv.Note = fromConfig
		case c.Kind == KindManaged:
			cv.Note = "Managed by feeds"
		}
		var cs []Decision
		for _, d := range steps {
			if d.Category == c.ID {
				cs = append(cs, d)
			}
		}
		var cr []RecordStep
		for _, r := range plan.Records {
			if r.Category == c.ID {
				cr = append(cr, r)
			}
		}
		cv.Pending = Summarize(cs, cr)
		byCat[c.ID] = cv
	}
	for _, ix := range st.snap.Indices {
		cat, day, ok := ParseIndex(m.Prefix, ix.Name)
		if !ok {
			ov.Unmanaged = append(ov.Unmanaged, ix)
			continue
		}
		cv := byCat[cat]
		cv.Bytes += ix.Bytes
		cv.Docs += ix.Docs
		cv.Days++
		ds := day.Format(time.DateOnly)
		if cv.OldestDay == "" || ds < cv.OldestDay {
			cv.OldestDay = ds
		}
		if ds > cv.NewestDay {
			cv.NewestDay = ds
		}
		if ix.Compacted() {
			cv.CompactedDays++
		}
		if ix.RestoredUntil != "" && ix.RestoredUntil >= plan.Today {
			cv.RestoredDays++
		}
		if ix.DiskBlocked {
			ov.DiskBlocked++
		}
	}
	for _, id := range []string{Findings, Cases, Intel} {
		cv := byCat[id]
		if ix, ok := st.records[RecordIndex(m.Prefix, id)]; ok {
			cv.Bytes, cv.Docs = ix.Bytes, ix.Docs
			if ix.DiskBlocked {
				ov.DiskBlocked++
			}
			if id != Intel && ov.Error == "" {
				if lo, hi, err := m.Cluster.RecordRange(ctx, ix.Name); err == nil && !lo.IsZero() {
					cv.OldestDay, cv.NewestDay = lo.Format(time.DateOnly), hi.Format(time.DateOnly)
				}
			}
		}
	}
	for _, c := range Categories() {
		cv := byCat[c.ID]
		// "Other events" only shows once there are some, or a policy for them.
		if c.ID == "other" && cv.Days == 0 && cv.Source == SourceDefault {
			continue
		}
		ov.TotalBytes += cv.Bytes
		ov.TotalDocs += cv.Docs
		ov.Categories = append(ov.Categories, *cv)
	}
	return ov
}

// ---- archive and restore ----

// RestoreStatus follows one restore.
type RestoreStatus struct {
	ID       string `json:"id"`
	Index    string `json:"index"`
	Category string `json:"category"`
	Day      string `json:"day"`
	// State is queued, running, done or failed.
	State     string     `json:"state"`
	Docs      int64      `json:"docs"`
	Restored  int64      `json:"restored"`
	KeepUntil string     `json:"keep_until"`
	Error     string     `json:"error,omitempty"`
	By        string     `json:"by,omitempty"`
	Queued    time.Time  `json:"queued"`
	Finished  *time.Time `json:"finished,omitempty"`
}

// Restore states.
const (
	RestoreQueued  = "queued"
	RestoreRunning = "running"
	RestoreDone    = "done"
	RestoreFailed  = "failed"
)

// ArchiveView is one archived day.
type ArchiveView struct {
	Manifest
	CategoryName string `json:"category_name"`
	// Searchable is true while the day is in OpenSearch, for example
	// after a restore; RestoredUntil is how long a restored day stays.
	Searchable    bool           `json:"searchable"`
	RestoredUntil string         `json:"restored_until,omitempty"`
	Restore       *RestoreStatus `json:"restore,omitempty"`
}

// ArchiveList is the archive tab's data.
type ArchiveList struct {
	Dir             string          `json:"dir"`
	Archives        []ArchiveView   `json:"archives"`
	Bytes           int64           `json:"bytes"`
	Docs            int64           `json:"docs"`
	Problems        []string        `json:"problems"`
	Restores        []RestoreStatus `json:"restores"`
	DefaultKeepDays int             `json:"default_keep_days"`
	MaxKeepDays     int             `json:"max_keep_days"`
	Error           string          `json:"error,omitempty"`
}

// Archives lists archived days with whether each is searchable now.
func (m *Manager) Archives(ctx context.Context) (*ArchiveList, error) {
	m.init()
	list, problems, err := m.Archive.List()
	if err != nil {
		return nil, fmt.Errorf("could not read the archive folder %s: %w", m.Archive.Dir, err)
	}
	out := &ArchiveList{Dir: m.Archive.Dir, Archives: []ArchiveView{}, Problems: []string{}, Restores: m.restoreStatuses(),
		DefaultKeepDays: DefaultRestoreDays, MaxKeepDays: MaxRestoreDays}
	if problems != nil {
		out.Problems = problems
	}
	live := map[string]IndexInfo{}
	if ixs, err := m.Cluster.Indices(ctx, m.Prefix+"-*"); err != nil {
		out.Error = "could not check OpenSearch for restored days: " + err.Error()
	} else {
		for _, ix := range ixs {
			live[ix.Name] = ix
		}
	}
	latest := map[string]RestoreStatus{}
	for _, r := range out.Restores {
		if _, ok := latest[r.ID]; !ok {
			latest[r.ID] = r
		}
	}
	for _, man := range list {
		v := ArchiveView{Manifest: man}
		if c, ok := CategoryByID(man.Category); ok {
			v.CategoryName = c.Name
		}
		if ix, ok := live[man.Index]; ok {
			v.Searchable = true
			v.RestoredUntil = ix.RestoredUntil
		}
		if r, ok := latest[man.ID]; ok {
			v.Restore = &r
		}
		out.Bytes += man.Bytes
		out.Docs += man.Docs
		out.Archives = append(out.Archives, v)
	}
	return out, nil
}

// restoreStatuses returns recent restores, newest first.
func (m *Manager) restoreStatuses() []RestoreStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RestoreStatus, 0, len(m.restores))
	for i := len(m.restores) - 1; i >= 0; i-- {
		out = append(out, *m.restores[i])
	}
	return out
}

func (m *Manager) updateRestore(st *RestoreStatus, change func(*RestoreStatus)) {
	m.mu.Lock()
	change(st)
	m.mu.Unlock()
}

// Restore queues archived days to be restored in the background, one
// after another and never during a run. Each stays searchable for
// keepDays (0 means DefaultRestoreDays) before retention may delete it
// again.
func (m *Manager) Restore(ids []string, keepDays int, by string) ([]RestoreStatus, error) {
	m.init()
	if keepDays == 0 {
		keepDays = DefaultRestoreDays
	}
	if keepDays < 1 || keepDays > MaxRestoreDays {
		return nil, &PolicyError{Problems: []string{fmt.Sprintf("keep_days must be between 1 and %d", MaxRestoreDays)}}
	}
	if len(ids) == 0 {
		return nil, &PolicyError{Problems: []string{"choose at least one archived day to restore"}}
	}
	var mans []Manifest
	for _, id := range slices.Compact(slices.Sorted(slices.Values(ids))) {
		man, err := m.Archive.Get(id)
		if err != nil {
			if errors.Is(err, ErrArchiveNotFound) {
				return nil, fmt.Errorf("%w: %s", ErrArchiveNotFound, id)
			}
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		if cat, _, ok := ParseIndex(m.Prefix, man.Index); !ok || cat != man.Category {
			return nil, &PolicyError{Problems: []string{fmt.Sprintf("%s was archived from %s, which is not a %s-* daily index on this server",
				id, man.Index, m.Prefix)}}
		}
		mans = append(mans, man)
	}
	m.mu.Lock()
	for _, r := range m.restores {
		if (r.State == RestoreQueued || r.State == RestoreRunning) && slices.ContainsFunc(mans, func(x Manifest) bool { return x.ID == r.ID }) {
			m.mu.Unlock()
			return nil, fmt.Errorf("%s is already being restored", r.ID)
		}
	}
	until := startOfDay(m.now()).AddDate(0, 0, keepDays).Format(time.DateOnly)
	var sts []*RestoreStatus
	for _, man := range mans {
		st := &RestoreStatus{ID: man.ID, Index: man.Index, Category: man.Category, Day: man.Day, State: RestoreQueued,
			Docs: man.Docs, KeepUntil: until, By: by, Queued: m.now()}
		sts = append(sts, st)
		m.restores = append(m.restores, st)
	}
	if n := len(m.restores) - MaxActions; n > 0 {
		m.restores = slices.Delete(m.restores, 0, n)
	}
	out := make([]RestoreStatus, len(sts))
	for i, st := range sts {
		out[i] = *st
	}
	m.mu.Unlock()

	go func() {
		m.job.Lock()
		defer m.job.Unlock()
		m.setCurrent("restore")
		defer m.setCurrent("")
		ctx := m.ctx()
		for i, man := range mans {
			st := sts[i]
			m.updateRestore(st, func(r *RestoreStatus) { r.State = RestoreRunning })
			n, err := m.RestoreArchive(ctx, man, until, func(done int64) {
				m.updateRestore(st, func(r *RestoreStatus) { r.Restored = done })
			})
			act := Action{Time: m.now(), Action: ActionRestore, Category: man.Category, Index: man.Index, Day: man.Day,
				Docs: n, File: man.File, By: by, Reason: "Restored from the archive; searchable until " + until}
			m.updateRestore(st, func(r *RestoreStatus) {
				now := m.now()
				r.Finished, r.Restored = &now, n
				r.State = RestoreDone
				if err != nil {
					r.State, r.Error = RestoreFailed, err.Error()
				}
			})
			if err != nil {
				act.Error = err.Error()
			}
			m.record(nil, act)
		}
	}()
	return out, nil
}

// RestoreArchive writes one archived day back into its index, which makes
// it searchable again, and marks the index so retention keeps it until
// the day given (YYYY-MM-DD). The file is checked in full first, so a
// damaged archive restores nothing. Restoring twice does not duplicate
// events. progress, when set, is called with the events restored so far.
func (m *Manager) RestoreArchive(ctx context.Context, man Manifest, until string, progress func(int64)) (int64, error) {
	m.init()
	if err := m.Archive.Verify(man); err != nil {
		return 0, fmt.Errorf("the archive file failed its check, so nothing was restored: %w", err)
	}
	if err := m.Cluster.CreateIndex(ctx, man.Index); err != nil {
		return 0, fmt.Errorf("could not create %s: %w", man.Index, err)
	}
	// A compacted index that came back with late events is read-only.
	if err := m.Cluster.BlockWrites(ctx, man.Index, false); err != nil {
		return 0, fmt.Errorf("could not make %s writable: %w", man.Index, err)
	}
	// Mark first, so a run that starts meanwhile keeps the index.
	if err := m.Cluster.MarkRestored(ctx, man.Index, until); err != nil {
		return 0, fmt.Errorf("could not mark %s as restored: %w", man.Index, err)
	}
	var done, size int64
	batch := make([]Doc, 0, importBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		if err := m.Cluster.Import(ctx, man.Index, batch); err != nil {
			return err
		}
		done += int64(len(batch))
		batch, size = batch[:0], 0
		if progress != nil {
			progress(done)
		}
		return nil
	}
	err := m.Archive.Read(man, func(d Doc) error {
		batch = append(batch, d)
		size += int64(len(d.Source))
		if len(batch) >= importBatch || size >= importBytes {
			return flush()
		}
		return ctx.Err()
	})
	if err == nil {
		err = flush()
	}
	if err != nil {
		return done, fmt.Errorf("restored %d of %d events, then: %w; restoring again finishes the job without duplicates", done, man.Docs, err)
	}
	if err := m.Cluster.Refresh(ctx, man.Index); err != nil {
		return done, err
	}
	return done, nil
}
