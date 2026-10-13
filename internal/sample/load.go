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
	"strings"
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

// ErrAlreadyLoaded means a sample set is already loaded; Remove it first.
var ErrAlreadyLoaded = errors.New("sample data is already loaded; remove it before loading again")

// OSClient is the bit of the OpenSearch client the loader needs beyond the
// stores: refresh, delete-by-query and listing indices. *store.Client has it.
type OSClient interface {
	Do(ctx context.Context, method, path string, body any, out any) error
	ListIndices(ctx context.Context, pattern string) ([]string, error)
}

// IntelStore is the threat-intel operations the loader uses.
type IntelStore interface {
	Add(ctx context.Context, inds []intel.Indicator) error
	DeleteSource(ctx context.Context, source string) (int, error)
}

// Loader loads and removes the sample data. One load exists at a time,
// recorded in a small state file so a second load refuses and Remove knows
// what to delete.
type Loader struct {
	Prefix   string
	Pipeline *ingest.Pipeline
	OS       OSClient
	Intel    IntelStore
	Assets   *assets.Store
	Library  *detect.Library
	Engine   *search.Engine
	Findings findings.Store
	Cases    cases.Store
	Risk     detect.RiskStore
	StateDir string // where the sample.json bookkeeping file lives
	Now      func() time.Time
	Log      *slog.Logger
}

// State is the bookkeeping for a loaded sample set, written to sample.json.
type State struct {
	ID         string    `json:"id"`
	Size       Size      `json:"size"`
	LoadedAt   time.Time `json:"loaded_at"`
	Start      time.Time `json:"start"`
	End        time.Time `json:"end"`
	Events     int       `json:"events"`
	Findings   int       `json:"findings"`
	RiskEvents int       `json:"risk_events"`
	Indicators int       `json:"indicators"`
	Assets     int       `json:"assets"`
	Identities int       `json:"identities"`
	Cases      []string  `json:"cases,omitempty"`
	Anchors    []string  `json:"anchors,omitempty"`
	Stories    []Story   `json:"stories,omitempty"`
}

// Progress reports how far a load or remove has got.
type Progress struct {
	Op    string `json:"op"`    // "load" or "remove"
	Phase string `json:"phase"` // human-readable step
	Done  int    `json:"done"`
	Total int    `json:"total"`
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

// Status returns the loaded sample's state, or nil when none is loaded.
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

// Loaded reports whether a sample set is loaded.
func (l *Loader) Loaded() bool {
	st, _ := l.Status()
	return st != nil
}

func report(p ProgressFn, op, phase string, done, total int) {
	if p != nil {
		p(Progress{Op: op, Phase: phase, Done: done, Total: total})
	}
}

// Load generates and writes the sample set, runs the detections over it and
// records what it wrote. It refuses when a set is already loaded.
func (l *Loader) Load(ctx context.Context, size Size, prog ProgressFn) (*State, error) {
	if l.Loaded() {
		return nil, ErrAlreadyLoaded
	}
	report(prog, "load", "Generating a week of activity", 0, 0)
	d := Generate(Options{Now: l.now(), Size: size})

	// Write the events through the ingest pipeline in chunks.
	const chunk = 2000
	total := len(d.Events)
	for i := 0; i < total; i += chunk {
		end := min(i+chunk, total)
		if _, err := l.Pipeline.IngestEvents(ctx, d.Events[i:end]); err != nil {
			return nil, fmt.Errorf("writing sample events: %w", err)
		}
		report(prog, "load", "Writing events", end, total)
	}
	if err := l.refresh(ctx, l.Prefix+"-*"); err != nil {
		return nil, err
	}

	// Threat intel.
	report(prog, "load", "Adding threat intel", 0, 0)
	if l.Intel != nil {
		if err := l.Intel.Add(ctx, d.Indicators); err != nil {
			return nil, fmt.Errorf("adding sample threat intel: %w", err)
		}
	}

	// Asset and identity overlay (merge; the user's entries win).
	report(prog, "load", "Adding asset and identity context", 0, 0)
	if err := l.addLists(d); err != nil {
		return nil, fmt.Errorf("adding sample lists: %w", err)
	}

	// Backfill the detections so findings and risk appear at once.
	nf, nr, err := l.backfill(ctx, d, prog)
	if err != nil {
		return nil, err
	}

	// A sample investigation to open and practise on.
	report(prog, "load", "Building a sample investigation", 0, 0)
	caseIDs := l.buildCase(ctx, d)

	st := &State{
		ID: d.ID, Size: d.Size, LoadedAt: l.now().UTC(), Start: d.Start, End: d.End,
		Events: total, Findings: nf, RiskEvents: nr, Indicators: len(d.Indicators),
		Assets: len(d.Assets), Identities: len(d.Identities), Cases: caseIDs,
		Anchors: d.Anchors, Stories: d.Stories,
	}
	if err := l.writeState(st); err != nil {
		return nil, err
	}
	report(prog, "load", "Done", total, total)
	l.log().Info("sample data loaded", "id", d.ID, "events", total, "findings", nf, "risk_events", nr, "audit", true)
	return st, nil
}

// isRiskModel reports whether a detection searches the Risk data model (the
// two risk-incident rules), which must run after the component detections
// have written their risk events.
func isRiskModel(d *detect.Detection) bool {
	q := strings.ToLower(strings.ReplaceAll(d.Query, " ", ""))
	return strings.Contains(q, "datamodel="+strings.ToLower(datamodel.RiskModel))
}

// backfill runs every enabled detection over the loaded time range, marking
// the findings and risk events it raises so they can be removed. Component
// detections run first (they write risk), then the risk-incident rules.
func (l *Loader) backfill(ctx context.Context, d *Data, prog ProgressFn) (findingsN, riskN int, err error) {
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
	runAt := func(det *detect.Detection, at time.Time) error {
		res, rerr := bf.RunAt(ctx, det, at)
		done++
		report(prog, "load", "Running detections", done, total)
		if rerr != nil {
			// One detection failing must not stop the load; log and go on.
			l.log().Warn("sample backfill: detection run failed", "detection", det.ID, "err", rerr)
			return nil
		}
		findingsN += len(res.Findings)
		riskN += res.Risk
		return nil
	}
	for _, at := range d.RunTimes {
		for _, det := range normal {
			if err := ctx.Err(); err != nil {
				return findingsN, riskN, err
			}
			_ = runAt(det, at)
		}
	}
	// The risk events just written are not searchable until the index
	// refreshes, so refresh before the risk-incident rules read them.
	if err := l.refresh(ctx, l.Prefix+"-"+strings.ToLower(datamodel.RiskModel)+"-*"); err != nil {
		return findingsN, riskN, err
	}
	for _, at := range d.RunTimes {
		for _, det := range riskModel {
			if err := ctx.Err(); err != nil {
				return findingsN, riskN, err
			}
			_ = runAt(det, at)
		}
	}
	return findingsN, riskN, nil
}

// buildCase opens one investigation grouping the sample's most serious
// findings, so the evaluator has a case to open and practise on.
func (l *Loader) buildCase(ctx context.Context, d *Data) []string {
	if l.Cases == nil || l.Findings == nil {
		return nil
	}
	fs, _, err := l.Findings.Search(ctx, findings.Filter{Sample: d.ID, Severity: []string{"critical", "high"}, Limit: 4})
	if err != nil || len(fs) == 0 {
		return nil
	}
	now := l.now().UTC()
	c := &cases.Case{
		ID: cases.NewID(now), Title: "Sample: intrusion on ws-fin-07",
		Description: "Auto-created with the sample data. Walk through the linked findings, add notes, and close it when you are done — then remove the sample data.",
		Severity:    "high", Status: findings.StatusInProgress, Owner: "",
		Sample: d.ID, CreatedBy: "sample-data", Created: now, Updated: now,
	}
	for _, f := range fs {
		if _, err := c.AddFinding(f, "sample-data", now); err == nil {
			f.CaseID = c.ID
			_ = l.Findings.Save(ctx, f)
		}
	}
	if err := l.Cases.Create(ctx, c); err != nil {
		l.log().Warn("sample: could not create the investigation", "err", err)
		return nil
	}
	return []string{c.ID}
}

// addLists merges the sample asset and identity entries into the user's
// lists, skipping any key the user already has, so nothing is overwritten.
func (l *Loader) addLists(d *Data) error {
	if l.Assets == nil {
		return nil
	}
	haveHost := map[string]bool{}
	cur := l.Assets.Assets()
	for _, a := range cur {
		for _, h := range a.Host {
			haveHost[strings.ToLower(h)] = true
		}
	}
	for _, a := range d.Assets {
		skip := false
		for _, h := range a.Host {
			if haveHost[strings.ToLower(h)] {
				skip = true
			}
		}
		if !skip {
			cur = append(cur, a)
		}
	}
	if _, err := l.Assets.SetAssets(assets.MarshalAssets(cur)); err != nil {
		return err
	}

	haveID := map[string]bool{}
	curID := l.Assets.Identities()
	for _, id := range curID {
		for _, u := range id.Identity {
			haveID[strings.ToLower(u)] = true
		}
	}
	for _, id := range d.Identities {
		skip := false
		for _, u := range id.Identity {
			if haveID[strings.ToLower(u)] {
				skip = true
			}
		}
		if !skip {
			curID = append(curID, id)
		}
	}
	_, err := l.Assets.SetIdentities(assets.MarshalIdentities(curID))
	return err
}

// Remove deletes exactly the sample data: events, risk events, findings,
// risk-notable findings the live scheduler raised from sample entities,
// the sample investigation (and sample findings from any analyst case),
// the sample threat intel and the sample list entries. It leaves
// everything else untouched.
func (l *Loader) Remove(ctx context.Context, prog ProgressFn) (*State, error) {
	st, err := l.Status()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, nil // nothing loaded
	}

	report(prog, "remove", "Deleting events and risk", 0, 0)
	if err := l.deleteBySample(ctx, l.Prefix+"-*", st.ID); err != nil {
		return nil, fmt.Errorf("deleting sample events: %w", err)
	}

	report(prog, "remove", "Removing investigations", 0, 0)
	sampleFindings, err := l.sampleFindingIDs(ctx, st)
	if err != nil {
		return nil, err
	}
	if err := l.removeCases(ctx, st, sampleFindings); err != nil {
		return nil, err
	}

	report(prog, "remove", "Removing findings", 0, 0)
	for id := range sampleFindings {
		if err := l.Findings.Delete(ctx, id); err != nil {
			return nil, fmt.Errorf("deleting sample finding: %w", err)
		}
	}

	report(prog, "remove", "Removing threat intel", 0, 0)
	if l.Intel != nil {
		if _, err := l.Intel.DeleteSource(ctx, SampleIntelSource); err != nil {
			return nil, fmt.Errorf("removing sample threat intel: %w", err)
		}
	}

	report(prog, "remove", "Removing asset and identity context", 0, 0)
	if err := l.removeLists(); err != nil {
		return nil, fmt.Errorf("removing sample lists: %w", err)
	}

	_ = l.refresh(ctx, l.Prefix+"-*")
	if err := os.Remove(l.stateFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	report(prog, "remove", "Done", 1, 1)
	l.log().Info("sample data removed", "id", st.ID, "audit", true)
	return st, nil
}

// sampleFindingIDs returns the IDs of every finding to delete: those marked
// with the sample ID, plus the risk-incident findings the live scheduler
// raised from sample entities (which carry no marker).
func (l *Loader) sampleFindingIDs(ctx context.Context, st *State) (map[string]bool, error) {
	ids := map[string]bool{}
	marked, _, err := l.Findings.Search(ctx, findings.Filter{Sample: st.ID, Limit: 10000})
	if err != nil {
		return nil, err
	}
	for _, f := range marked {
		ids[f.ID] = true
	}
	if len(st.Anchors) > 0 {
		anchored, _, err := l.Findings.Search(ctx, findings.Filter{EntityValues: st.Anchors, Limit: 10000})
		if err != nil {
			return nil, err
		}
		for _, f := range anchored {
			// Only the two risk-incident rules raise unmarked findings from
			// sample entities; a real finding about a sample host is left
			// alone. Bound it to the sample's time range as well.
			if f.Sample == st.ID || (riskIncident(f.DetectionID) && inRange(f.Created, st)) {
				ids[f.ID] = true
			}
		}
	}
	return ids, nil
}

func riskIncident(id string) bool {
	return id == "risk-threshold-exceeded" || id == "risk-multiple-tactics"
}

func inRange(t time.Time, st *State) bool {
	return !t.Before(st.Start) && !t.After(st.LoadedAt.Add(time.Hour))
}

// removeCases deletes the sample's own investigation and unlinks sample
// findings from any analyst case, deleting a case that ends up holding only
// sample findings.
func (l *Loader) removeCases(ctx context.Context, st *State, sampleFindings map[string]bool) error {
	if l.Cases == nil {
		return nil
	}
	// The loader's own cases, by marker.
	own, _, err := l.Cases.Search(ctx, cases.Filter{Sample: st.ID, Limit: 1000})
	if err != nil {
		return err
	}
	deleted := map[string]bool{}
	for _, c := range own {
		if err := l.Cases.Delete(ctx, c.ID); err != nil {
			return err
		}
		deleted[c.ID] = true
	}
	// Analyst cases that reference a sample finding.
	for fid := range sampleFindings {
		linked, _, err := l.Cases.Search(ctx, cases.Filter{FindingID: fid, Limit: 1000})
		if err != nil {
			return err
		}
		for _, c := range linked {
			if deleted[c.ID] {
				continue
			}
			full, err := l.Cases.Get(ctx, c.ID)
			if err != nil {
				continue
			}
			allSample := true
			for _, id := range full.Findings {
				if !sampleFindings[id] {
					allSample = false
					break
				}
			}
			if allSample {
				if err := l.Cases.Delete(ctx, full.ID); err != nil {
					return err
				}
				deleted[full.ID] = true
				continue
			}
			changed := false
			for id := range sampleFindings {
				if full.RemoveFinding(id, "sample-data", l.now().UTC()) {
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

// removeLists drops the sample rows (tagged with the sample business unit)
// from the user's asset and identity lists, keeping everything else.
func (l *Loader) removeLists() error {
	if l.Assets == nil {
		return nil
	}
	var as []assets.Asset
	for _, a := range l.Assets.Assets() {
		if a.BUnit != SampleBUnit {
			as = append(as, a)
		}
	}
	if _, err := l.Assets.SetAssets(assets.MarshalAssets(as)); err != nil {
		return err
	}
	var ids []assets.Identity
	for _, id := range l.Assets.Identities() {
		if id.BUnit != SampleBUnit {
			ids = append(ids, id)
		}
	}
	_, err := l.Assets.SetIdentities(assets.MarshalIdentities(ids))
	return err
}

// deleteBySample runs a delete-by-query over a pattern for the marker.
func (l *Loader) deleteBySample(ctx context.Context, pattern, id string) error {
	body := map[string]any{"query": map[string]any{"term": map[string]any{ingest.SampleField: id}}}
	path := "/" + url.PathEscape(pattern) + "/_delete_by_query?conflicts=proceed&refresh=true&wait_for_completion=true&ignore_unavailable=true&allow_no_indices=true"
	return l.OS.Do(ctx, "POST", path, body, nil)
}

func (l *Loader) refresh(ctx context.Context, pattern string) error {
	return l.OS.Do(ctx, "POST", "/"+url.PathEscape(pattern)+"/_refresh?ignore_unavailable=true&allow_no_indices=true", nil, nil)
}

func (l *Loader) writeState(st *State) error {
	if err := os.MkdirAll(l.StateDir, 0o750); err != nil {
		return err
	}
	// json.Marshal (not Encode) so file paths, if ever added, stay intact.
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

// DetectionTitles returns a map of built-in detection ID to its title, for
// the status reply and docs.
func (l *Loader) DetectionTitles() map[string]string {
	out := map[string]string{}
	if l.Library == nil {
		return out
	}
	for _, d := range l.Library.List() {
		out[d.ID] = d.Title
	}
	return out
}

// CannotFire lists the built-in detections that cannot fire from the sample
// and why (both are off by default), for the status reply and docs.
func (l *Loader) CannotFire() map[string]string {
	out := map[string]string{}
	if l.Library == nil {
		return out
	}
	for _, d := range l.Library.List() {
		if !d.Enabled {
			out[d.ID] = "off by default; the sample includes data that would fire it if you turn it on"
		}
	}
	return out
}
