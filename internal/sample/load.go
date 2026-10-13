package sample

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/search"
)

var (
	// ErrAlreadyLoaded means a sample set is already loaded; Remove it first.
	ErrAlreadyLoaded = errors.New("sample data is already loaded; remove it before loading again")
	// ErrPartial means an earlier load stopped part way; Remove what it
	// loaded before loading again.
	ErrPartial = errors.New("the last sample-data load did not finish; remove what it loaded before loading again")
	// ErrNothingWritten means OpenSearch accepted none of the sample events.
	ErrNothingWritten = errors.New("OpenSearch did not accept any of the sample events")
)

// OSClient is the bit of the OpenSearch client the loader needs beyond the
// stores: refresh, searches, delete-by-query and index settings.
// *store.Client has it.
type OSClient interface {
	Do(ctx context.Context, method, path string, body any, out any) error
}

// IntelStore is the threat-intel operations the loader uses. A store that
// can also Sync (reload what another process changed) is synced before
// Remove deletes the sample indicators.
type IntelStore interface {
	Add(ctx context.Context, inds []intel.Indicator) error
	DeleteSource(ctx context.Context, source string) (int, error)
}

type intelSyncer interface {
	Sync(ctx context.Context) (bool, error)
}

// Loader loads and removes the sample data. One load exists at a time,
// recorded in a small state file (written before anything else, so even a
// load that stops part way can be removed), and one load or removal runs
// at a time, across processes, under a lock file next to it.
type Loader struct {
	Prefix string
	// Bulk writes the sample events (the OpenSearch client). The loader
	// writes through its own ingest pipeline, which takes the sample's
	// week-old events whatever the server's maximum event age is.
	Bulk     ingest.Bulker
	OS       OSClient
	Intel    IntelStore
	Assets   *assets.Store
	Library  *detect.Library
	Engine   *search.Engine
	Findings findings.Store
	Cases    cases.Store
	Risk     detect.RiskStore
	StateDir string // where the sample.json bookkeeping file and the lock live
	Now      func() time.Time
	Log      *slog.Logger
}

// State is the bookkeeping for a loaded sample set, written to sample.json.
type State struct {
	ID   string `json:"id"`
	Size Size   `json:"size"`
	// Partial is set from the moment a load starts writing until it has
	// finished: a state that keeps it was stopped part way (an error, a
	// restart, Ctrl-C) and should be removed.
	Partial  bool      `json:"partial,omitempty"`
	Started  time.Time `json:"started"`
	LoadedAt time.Time `json:"loaded_at,omitzero"`
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Events   int       `json:"events"`
	// Skipped counts events OpenSearch turned away, for example on days
	// retention has made read-only.
	Skipped    int      `json:"skipped,omitempty"`
	Findings   int      `json:"findings"`
	RiskEvents int      `json:"risk_events"`
	Indicators int      `json:"indicators"`
	Assets     int      `json:"assets"`
	Identities int      `json:"identities"`
	Cases      []string `json:"cases,omitempty"`
	Stories    []Story  `json:"stories,omitempty"`
}

// Progress reports how far a load or remove has got: the plain-English
// step and the share of the whole job done, 0 to 100.
type Progress struct {
	Op      string `json:"op"`    // "load" or "remove"
	Phase   string `json:"phase"` // human-readable step
	Percent int    `json:"percent"`
}

// ProgressFn receives progress updates; it may be nil.
type ProgressFn func(Progress)

func (l *Loader) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *Loader) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.Default()
}

func (l *Loader) stateFile() string { return filepath.Join(l.StateDir, "sample.json") }

// Status returns the sample's state, or nil when none is loaded. A state
// with Partial set is a load that did not finish.
func (l *Loader) Status() (*State, error) {
	b, err := os.ReadFile(l.stateFile())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// reporter turns each step's own progress into one figure for the whole
// job, so a progress bar only ever moves forward, and passes it to the
// caller and to the lock (for other processes to show).
type reporter struct {
	op   string
	fn   ProgressFn
	lock *jobLock
	last int
}

// step reports a step reaching pct of the whole job.
func (r *reporter) step(phase string, pct int) {
	pct = max(min(pct, 100), r.last)
	r.last = pct
	if r.lock != nil {
		r.lock.set(phase, pct)
	}
	if r.fn != nil {
		r.fn(Progress{Op: r.op, Phase: phase, Percent: pct})
	}
}

// within reports done of total for a step spanning [from, to] of the job.
func (r *reporter) within(phase string, from, to, done, total int) {
	pct := from
	if total > 0 {
		pct = from + (to-from)*done/total
	}
	r.step(phase, pct)
}

// Load generates and writes the sample set, runs the detections over it and
// records what it wrote. It refuses while a set (or a partial one) is
// loaded, and while another load or removal runs. The state file is
// written first, so whatever happens part way, Remove can take out what
// was written.
func (l *Loader) Load(ctx context.Context, size Size, prog ProgressFn) (*State, error) {
	if err := l.checkFree(); err != nil {
		return nil, err
	}
	lk, err := l.acquire("load")
	if err != nil {
		return nil, err
	}
	defer lk.release()
	// Another process may have loaded between the check and the lock.
	if err := l.checkFree(); err != nil {
		return nil, err
	}
	r := &reporter{op: "load", fn: prog, lock: lk}
	r.step("Generating a week of activity", 0)
	d := Generate(Options{Now: l.now(), Size: size})
	st := &State{ID: d.ID, Size: d.Size, Partial: true, Started: l.now().UTC(), Start: d.Start, End: d.End, Stories: d.Stories}
	if err := l.writeState(st); err != nil {
		return nil, err
	}
	r.step("Generating a week of activity", 2)

	// Events, through a pipeline of the loader's own: the sample reaches
	// back six days, and the server's maximum event age may be shorter.
	pipe := &ingest.Pipeline{Store: l.Bulk, Prefix: l.Prefix, MaxEventAge: MaxEventAge, Now: l.now, Log: l.Log}
	const chunk = 2000
	total := len(d.Events)
	var firstErr string
	for i := 0; i < total; i += chunk {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(i+chunk, total)
		res, err := pipe.IngestEvents(ctx, d.Events[i:end])
		if err != nil {
			return nil, fmt.Errorf("writing sample events: %w", err)
		}
		st.Events += res.Indexed
		st.Skipped += res.Rejected
		if firstErr == "" && len(res.Errors) > 0 {
			firstErr = res.Errors[0].Reason
		}
		r.within("Writing events", 2, 25, end, total)
	}
	if st.Events == 0 && total > 0 {
		return nil, fmt.Errorf("%w: %s", ErrNothingWritten, firstErr)
	}
	if st.Skipped > 0 {
		l.log().Warn("some sample events were not written; their days may be read-only after retention compacted them",
			"skipped", st.Skipped, "reason", firstErr)
	}
	if err := l.refresh(ctx, l.Prefix+"-*"); err != nil {
		return nil, err
	}
	_ = l.writeState(st)

	r.step("Adding threat intel", 25)
	if l.Intel != nil {
		if err := l.Intel.Add(ctx, d.Indicators); err != nil {
			return nil, fmt.Errorf("adding sample threat intel: %w", err)
		}
		st.Indicators = len(d.Indicators)
	}

	// Asset and identity context, in the store's overlay: the user's own
	// files are never rewritten, and their rows always win a lookup.
	r.step("Adding asset and identity context", 26)
	if l.Assets != nil {
		if err := l.Assets.SetOverlay(d.Assets, d.Identities); err != nil {
			return nil, fmt.Errorf("adding sample asset and identity context: %w", err)
		}
		st.Assets, st.Identities = len(d.Assets), len(d.Identities)
	}
	_ = l.writeState(st)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Backfill the detections so findings and risk appear at once.
	if l.Library != nil && l.Engine != nil {
		nf, nr, err := l.backfill(ctx, d, r)
		st.Findings, st.RiskEvents = nf, nr
		if err != nil {
			_ = l.writeState(st)
			return nil, err
		}
	}

	// A sample investigation to open and practise on.
	r.step("Building a sample investigation", 97)
	st.Cases = l.buildCase(ctx, d)
	if err := ctx.Err(); err != nil {
		_ = l.writeState(st)
		return nil, err
	}

	st.Partial = false
	st.LoadedAt = l.now().UTC()
	if err := l.writeState(st); err != nil {
		return nil, err
	}
	r.step("Done", 100)
	l.log().Info("sample data loaded", "id", d.ID, "events", st.Events, "findings", st.Findings, "risk_events", st.RiskEvents, "audit", true)
	return st, nil
}

// checkFree refuses a load while a set, complete or partial, is loaded.
func (l *Loader) checkFree() error {
	st, err := l.Status()
	switch {
	case err != nil:
		return err
	case st == nil:
		return nil
	case st.Partial:
		return ErrPartial
	}
	return ErrAlreadyLoaded
}

// isRiskModel reports whether a detection searches the Risk data model (the
// two risk-incident rules), which must run after the component detections
// have written their risk events.
func isRiskModel(d *detect.Detection) bool {
	q := strings.ToLower(strings.ReplaceAll(d.Query, " ", ""))
	return strings.Contains(q, "datamodel="+strings.ToLower(datamodel.RiskModel))
}

// backfill runs every enabled detection over the sample's own documents at
// the sample's run times, marking the findings and risk events it raises.
// Component detections run first (they write risk), then the risk-incident
// rules. Its runs read only this load's documents (detect.ScopeSample), so
// real activity is never marked as sample data.
func (l *Loader) backfill(ctx context.Context, d *Data, r *reporter) (findingsN, riskN int, err error) {
	bf := &detect.Scheduler{
		Library: l.Library, Engine: l.Engine, Findings: l.Findings,
		Risk: l.Risk, Assets: l.Assets, SampleMark: d.ID, Log: l.Log,
		MaxFindingsPerRun: 500,
	}
	var normal, riskModel []*detect.Detection
	for _, det := range l.Library.List() {
		if !det.Enabled {
			continue
		}
		if isRiskModel(det) {
			riskModel = append(riskModel, det)
		} else {
			normal = append(normal, det)
		}
	}
	total := len(d.RunTimes) * (len(normal) + len(riskModel))
	done := 0
	riskIndices := l.Prefix + "-" + strings.ToLower(datamodel.RiskModel) + "-*"
	run := func(det *detect.Detection, at time.Time) {
		res, rerr := bf.RunAt(ctx, det, at)
		done++
		r.within("Running detections", 27, 97, done, total)
		if rerr != nil {
			// One detection failing must not stop the load; log and go on
			// (unless the whole load is stopping).
			if ctx.Err() == nil {
				l.log().Warn("sample backfill: detection run failed", "detection", det.ID, "err", rerr)
			}
			return
		}
		findingsN += len(res.Findings)
		riskN += res.Risk
	}
	for _, at := range d.RunTimes {
		for _, det := range normal {
			if err := ctx.Err(); err != nil {
				return findingsN, riskN, err
			}
			run(det, at)
		}
		// Risk-only detections throttle on the risk events they wrote,
		// which are searchable only after a refresh; without one, the next
		// run time a minute later would write the same risk again.
		if err := l.refresh(ctx, riskIndices); err != nil {
			return findingsN, riskN, err
		}
	}
	for _, at := range d.RunTimes {
		for _, det := range riskModel {
			if err := ctx.Err(); err != nil {
				return findingsN, riskN, err
			}
			run(det, at)
		}
	}
	return findingsN, riskN, nil
}

// CaseTitle is the sample investigation's title.
const CaseTitle = "Sample: phishing intrusion on ws-fin-07"

// buildCase opens one investigation holding the phishing story's findings,
// in the order they fired, so the evaluator has a case to walk through.
func (l *Loader) buildCase(ctx context.Context, d *Data) []string {
	if l.Cases == nil || l.Findings == nil || len(d.CaseFocus) == 0 {
		return nil
	}
	fs, _, err := l.Findings.Search(ctx, findings.Filter{Sample: d.ID, EntityValues: d.CaseFocus, Limit: 100})
	if err != nil || len(fs) == 0 {
		return nil
	}
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Created.Before(fs[j].Created) })
	now := l.now().UTC()
	c := &cases.Case{
		ID: cases.NewID(now), Title: CaseTitle,
		Description: "Created with the sample data. A finance workstation was phished: walk through the linked findings in the order they fired, add notes, and close the case when you are done. Removing the sample data removes this case too.",
		Severity:    "high", Status: findings.StatusInProgress,
		Sample: d.ID, CreatedBy: "sample-data", Created: now, Updated: now,
	}
	// Each save waits for the index to refresh, so save them side by side.
	var wg sync.WaitGroup
	for _, f := range fs {
		if _, err := c.AddFinding(f, "sample-data", now); err == nil {
			f.CaseID = c.ID
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = l.Findings.Save(ctx, f)
			}()
		}
	}
	wg.Wait()
	if err := l.Cases.Create(ctx, c); err != nil {
		l.log().Warn("sample: could not create the investigation", "err", err)
		return nil
	}
	return []string{c.ID}
}

// Remove deletes exactly the sample data, found by its marker: events,
// risk events, findings, the sample investigation, the sample threat intel
// and the asset and identity overlay. It works on a partial load too. A
// case of the user's own that holds sample findings is kept, with them
// unlinked. Nothing else is touched.
func (l *Loader) Remove(ctx context.Context, prog ProgressFn) (*State, error) {
	st, err := l.Status()
	if err != nil || st == nil {
		return nil, err
	}
	lk, err := l.acquire("remove")
	if err != nil {
		return nil, err
	}
	defer lk.release()
	if st, err = l.Status(); err != nil || st == nil {
		return nil, err
	}
	r := &reporter{op: "remove", fn: prog, lock: lk}

	r.step("Deleting events and risk", 0)
	if err := l.deleteBySample(ctx, st.ID, r); err != nil {
		return nil, err
	}

	r.step("Removing the sample investigation", 60)
	ids, err := l.sampleFindingIDs(ctx, st.ID)
	if err != nil {
		return nil, err
	}
	if err := l.removeCases(ctx, st.ID, ids); err != nil {
		return nil, err
	}

	r.step("Removing findings", 70)
	if err := l.removeFindings(ctx, st.ID, ids); err != nil {
		return nil, err
	}

	r.step("Removing threat intel", 88)
	if l.Intel != nil {
		if s, ok := l.Intel.(intelSyncer); ok {
			// A load from another process added them; see them first.
			if _, err := s.Sync(ctx); err != nil {
				return nil, fmt.Errorf("reading threat intel: %w", err)
			}
		}
		if _, err := l.Intel.DeleteSource(ctx, SampleIntelSource); err != nil {
			return nil, fmt.Errorf("removing sample threat intel: %w", err)
		}
	}

	r.step("Removing asset and identity context", 95)
	if l.Assets != nil {
		if err := l.Assets.SetOverlay(nil, nil); err != nil {
			return nil, fmt.Errorf("removing sample asset and identity context: %w", err)
		}
	}

	if err := os.Remove(l.stateFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	r.step("Done", 100)
	l.log().Info("sample data removed", "id", st.ID, "audit", true)
	return st, nil
}

// sampleFindingIDs returns the IDs of the findings carrying the marker.
// Only the backfill marks findings, and it reads only sample documents, so
// these are exactly the findings the sample raised; the live scheduler
// never raises any from sample data.
func (l *Loader) sampleFindingIDs(ctx context.Context, id string) (map[string]bool, error) {
	ids := map[string]bool{}
	if l.Findings == nil {
		return ids, nil
	}
	marked, _, err := l.Findings.Search(ctx, findings.Filter{Sample: id, Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, f := range marked {
		ids[f.ID] = true
	}
	return ids, nil
}

// removeFindings deletes the sample findings, then searches again until
// none carry the marker, in case there were more than one search returns.
func (l *Loader) removeFindings(ctx context.Context, id string, ids map[string]bool) error {
	if l.Findings == nil {
		return nil
	}
	for range 100 {
		if err := l.deleteFindings(ctx, ids); err != nil {
			return err
		}
		more, err := l.sampleFindingIDs(ctx, id)
		if err != nil {
			return err
		}
		if len(more) == 0 {
			return nil
		}
		ids = more
	}
	return errors.New("sample findings keep reappearing; try removing again")
}

// deleteFindings deletes findings a few at a time side by side: each
// delete waits for the index to refresh, and one after another that adds
// up to a second per finding.
func (l *Loader) deleteFindings(ctx context.Context, ids map[string]bool) error {
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		first error
	)
	sem := make(chan struct{}, 8)
	for fid := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			if err := l.Findings.Delete(ctx, fid); err != nil && !errors.Is(err, findings.ErrNotFound) {
				mu.Lock()
				if first == nil {
					first = fmt.Errorf("deleting sample finding: %w", err)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return first
}

// removeCases deletes the sample's own investigation and unlinks sample
// findings from the user's own cases. A user's case is never deleted, even
// when it held only sample findings: its notes and timeline are theirs.
func (l *Loader) removeCases(ctx context.Context, id string, sampleFindings map[string]bool) error {
	if l.Cases == nil {
		return nil
	}
	own, _, err := l.Cases.Search(ctx, cases.Filter{Sample: id, Limit: 1000})
	if err != nil {
		return err
	}
	done := map[string]bool{}
	for _, c := range own {
		if err := l.Cases.Delete(ctx, c.ID); err != nil {
			return err
		}
		done[c.ID] = true
	}
	for fid := range sampleFindings {
		linked, _, err := l.Cases.Search(ctx, cases.Filter{FindingID: fid, Limit: 1000})
		if err != nil {
			return err
		}
		for _, c := range linked {
			if done[c.ID] {
				continue
			}
			done[c.ID] = true
			full, err := l.Cases.Get(ctx, c.ID)
			if err != nil {
				continue
			}
			changed := false
			for _, f := range append([]string(nil), full.Findings...) {
				if sampleFindings[f] && full.RemoveFinding(f, "sample-data", l.now().UTC()) {
					changed = true
				}
			}
			if changed {
				if err := l.Cases.Save(ctx, full); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// deleteBySample deletes the marked documents, index by index. Retention
// compaction makes past days read-only; such an index is made writable
// for the delete and read-only again after, so removal still works.
func (l *Loader) deleteBySample(ctx context.Context, id string, r *reporter) error {
	indices, err := l.sampleIndices(ctx, id)
	if err != nil {
		return err
	}
	var failed []string
	var firstErr error
	for i, ix := range indices {
		if err := l.deleteIn(ctx, ix, id); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			failed = append(failed, ix)
			if firstErr == nil {
				firstErr = err
			}
			l.log().Warn("sample: could not delete the sample events from an index", "index", ix, "err", err)
		}
		r.within("Deleting events and risk", 2, 60, i+1, len(indices))
	}
	if len(failed) > 0 {
		return fmt.Errorf("could not delete the sample events from %s: %w", strings.Join(failed, ", "), firstErr)
	}
	return nil
}

func sampleQuery(id string) map[string]any {
	return map[string]any{"term": map[string]any{datamodel.SampleField: id}}
}

// sampleIndices lists the indices that hold documents with the marker.
func (l *Loader) sampleIndices(ctx context.Context, id string) ([]string, error) {
	var out struct {
		Aggregations struct {
			Idx struct {
				Buckets []struct {
					Key string `json:"key"`
				} `json:"buckets"`
			} `json:"idx"`
		} `json:"aggregations"`
	}
	body := map[string]any{
		"size": 0, "query": sampleQuery(id),
		"aggs": map[string]any{"idx": map[string]any{"terms": map[string]any{"field": "_index", "size": 5000}}},
	}
	path := "/" + url.PathEscape(l.Prefix+"-*") + "/_search?ignore_unavailable=true&allow_no_indices=true"
	if err := l.OS.Do(ctx, "POST", path, body, &out); err != nil {
		return nil, fmt.Errorf("finding the sample events: %w", err)
	}
	var names []string
	for _, b := range out.Aggregations.Idx.Buckets {
		names = append(names, b.Key)
	}
	sort.Strings(names)
	return names, nil
}

func (l *Loader) deleteIn(ctx context.Context, index, id string) error {
	path := "/" + url.PathEscape(index) + "/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true"
	body := map[string]any{"query": sampleQuery(id)}
	err := l.OS.Do(ctx, "POST", path, body, nil)
	if err == nil || !l.writeBlocked(ctx, index) {
		return err
	}
	// Read-only after compaction: lift the block for the delete, then put
	// it back whatever happens.
	settings := "/" + url.PathEscape(index) + "/_settings"
	if err := l.OS.Do(ctx, "PUT", settings, map[string]any{"index.blocks.write": nil}, nil); err != nil {
		return err
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := l.OS.Do(rctx, "PUT", settings, map[string]any{"index.blocks.write": true}, nil); err != nil {
			l.log().Warn("sample: could not make an index read-only again", "index", index, "err", err)
		}
	}()
	return l.OS.Do(ctx, "POST", path, body, nil)
}

// writeBlocked reports whether retention has made an index read-only.
func (l *Loader) writeBlocked(ctx context.Context, index string) bool {
	var out map[string]struct {
		Settings map[string]any `json:"settings"`
	}
	path := "/" + url.PathEscape(index) + "/_settings/index.blocks.write?flat_settings=true"
	if err := l.OS.Do(ctx, "GET", path, nil, &out); err != nil {
		return false
	}
	for _, s := range out {
		if fmt.Sprint(s.Settings["index.blocks.write"]) == "true" {
			return true
		}
	}
	return false
}

func (l *Loader) refresh(ctx context.Context, pattern string) error {
	return l.OS.Do(ctx, "POST", "/"+url.PathEscape(pattern)+"/_refresh?ignore_unavailable=true&allow_no_indices=true", nil, nil)
}

func (l *Loader) writeState(st *State) error {
	if err := os.MkdirAll(l.StateDir, 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := l.stateFile() + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, l.stateFile())
}

// EventsSince counts the events (sample or not) in the last d, so the web
// page can point a new admin at the sample data when there are none. It
// returns -1 when the count cannot be made.
func (l *Loader) EventsSince(ctx context.Context, d time.Duration) int {
	if l.OS == nil {
		return -1
	}
	var out struct {
		Count int `json:"count"`
	}
	body := map[string]any{"query": map[string]any{"range": map[string]any{"@timestamp": map[string]any{
		"gte": l.now().Add(-d).UTC().Format(time.RFC3339)}}}}
	path := "/" + url.PathEscape(l.Prefix+"-*") + "/_count?ignore_unavailable=true&allow_no_indices=true"
	if err := l.OS.Do(ctx, "POST", path, body, &out); err != nil {
		return -1
	}
	return out.Count
}

// CannotFire lists the built-in detections the load did not run (both are
// off by default) and what to do to see them fire, for the status reply.
func (l *Loader) CannotFire() map[string]string {
	out := map[string]string{}
	if l.Library == nil {
		return out
	}
	for _, d := range l.Library.List() {
		if !d.Enabled {
			out[d.ID] = "Off by default. The sample has data for it: turn it on, then remove and load the sample data again to see it fire."
		}
	}
	return out
}
