package sample

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/intel"
)

// fakeOS is a no-op OSClient: Remove's delete-by-query and refresh against
// OpenSearch are exercised by the integration test; here we test the
// store-level bookkeeping (findings, cases, intel, lists).
type fakeOS struct{ calls int }

func (f *fakeOS) Do(_ context.Context, _, _ string, _, _ any) error         { f.calls++; return nil }
func (f *fakeOS) ListIndices(_ context.Context, _ string) ([]string, error) { return nil, nil }

// fakeIntel is an in-memory IntelStore.
type fakeIntel struct{ inds []intel.Indicator }

func (f *fakeIntel) Add(_ context.Context, inds []intel.Indicator) error {
	f.inds = append(f.inds, inds...)
	return nil
}
func (f *fakeIntel) DeleteSource(_ context.Context, source string) (int, error) {
	var kept []intel.Indicator
	n := 0
	for _, ind := range f.inds {
		if ind.Source == source {
			n++
			continue
		}
		kept = append(kept, ind)
	}
	f.inds = kept
	return n, nil
}

// TestRemoveDeletesExactlyTheSampleData seeds findings, cases, intel and
// lists by hand — some sample, some not — and checks Remove deletes exactly
// the sample ones and leaves everything else untouched.
func TestRemoveDeletesExactlyTheSampleData(t *testing.T) {
	ctx := context.Background()
	id := "sample-20261013-120000"
	start := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)
	loadedAt := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	inWindow := loadedAt.Add(-time.Hour)
	beforeWindow := start.Add(-48 * time.Hour)

	fs := findings.NewMemory()
	cs := cases.NewMemory()
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fi := &fakeIntel{}

	// Findings: sample (marked), an anchored risk-incident finding in the
	// window (unmarked, must go), a risk-incident finding before the window
	// (must stay), a real finding on a sample host (must stay), and an
	// unrelated real finding (must stay).
	mk := func(fid, det, sample string, created time.Time, entity string) *findings.Finding {
		f := &findings.Finding{ID: fid, DetectionID: det, Sample: sample, Severity: "high",
			Status: findings.StatusNew, Created: created, Updated: created,
			Entities: map[string]any{"user": entity}}
		if err := fs.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	mk("S1", "endpoint-credential-dumping", id, inWindow, "dan.sato")
	mk("S2", "auth-brute-force", id, inWindow, "bob.okafor")
	mk("S3", "endpoint-shadow-copy-delete", id, inWindow, "dan.sato")
	mk("R1", "risk-threshold-exceeded", "", inWindow, "dan.sato")     // anchored, in window
	mk("R2", "risk-threshold-exceeded", "", beforeWindow, "dan.sato") // anchored, before window
	mk("RF", "auth-brute-force", "", inWindow, "dan.sato")            // real, on anchor
	mk("P1", "auth-password-spray", "", inWindow, "someone.else")     // unrelated real

	// Cases: own sample case; an analyst case holding a sample finding and a
	// real one; an analyst case holding only a sample finding.
	own := &cases.Case{ID: "C1", Title: "Sample case", Sample: id, Status: findings.StatusInProgress,
		Findings: []string{"S1"}, Created: loadedAt, Updated: loadedAt}
	mixed := &cases.Case{ID: "C2", Title: "Analyst case", Status: findings.StatusInProgress,
		Findings: []string{"S2", "P1"}, Created: loadedAt, Updated: loadedAt}
	allSample := &cases.Case{ID: "C3", Title: "All sample", Status: findings.StatusInProgress,
		Findings: []string{"S3"}, Created: loadedAt, Updated: loadedAt}
	for _, c := range []*cases.Case{own, mixed, allSample} {
		if err := cs.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	// Intel: two sample indicators, one manual.
	fi.Add(ctx, []intel.Indicator{
		{ID: "i1", Source: SampleIntelSource, Type: intel.TypeIP, Value: "203.0.113.45"},
		{ID: "i2", Source: SampleIntelSource, Type: intel.TypeDomain, Value: "updates.corp-sync.example"},
		{ID: "i3", Source: intel.ManualSource, Type: intel.TypeIP, Value: "203.0.113.9"},
	})

	// Lists: a sample asset/identity and the user's own.
	lists.SetAssets(assets.MarshalAssets([]assets.Asset{
		{Host: []string{"ws-fin-07"}, BUnit: SampleBUnit},
		{Host: []string{"my-server"}, BUnit: "Production"},
	}))
	lists.SetIdentities(assets.MarshalIdentities([]assets.Identity{
		{Identity: []string{"dan.sato"}, BUnit: SampleBUnit},
		{Identity: []string{"real.person"}, BUnit: "Staff"},
	}))

	l := &Loader{
		Prefix: "signalith", OS: &fakeOS{}, Intel: fi, Assets: lists,
		Findings: fs, Cases: cs, StateDir: t.TempDir(),
		Now: func() time.Time { return loadedAt },
	}
	st := &State{ID: id, Size: SizeSmall, LoadedAt: loadedAt, Start: start, End: loadedAt.Add(-5 * time.Minute),
		Anchors: []string{"dan.sato", "bob.okafor", "ws-fin-07"}, Cases: []string{"C1"}}
	if err := l.writeState(st); err != nil {
		t.Fatal(err)
	}
	if !l.Loaded() {
		t.Fatal("state not written")
	}

	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Findings: the sample ones and the anchored in-window risk finding go;
	// the rest stay.
	left := map[string]bool{}
	all, _, _ := fs.Search(ctx, findings.Filter{Limit: 100})
	for _, f := range all {
		left[f.ID] = true
	}
	wantGone := []string{"S1", "S2", "S3", "R1"}
	wantKept := []string{"R2", "RF", "P1"}
	for _, id := range wantGone {
		if left[id] {
			t.Errorf("finding %s should have been removed", id)
		}
	}
	for _, id := range wantKept {
		if !left[id] {
			t.Errorf("finding %s should have been kept", id)
		}
	}

	// Cases: own and all-sample cases gone; the mixed one kept with only its
	// real finding.
	if _, err := cs.Get(ctx, "C1"); err == nil {
		t.Error("own sample case C1 should have been deleted")
	}
	if _, err := cs.Get(ctx, "C3"); err == nil {
		t.Error("all-sample case C3 should have been deleted")
	}
	c2, err := cs.Get(ctx, "C2")
	if err != nil {
		t.Fatalf("mixed case C2 should have been kept: %v", err)
	}
	if len(c2.Findings) != 1 || c2.Findings[0] != "P1" {
		t.Errorf("C2 findings = %v, want [P1]", c2.Findings)
	}

	// Intel: sample source gone, manual kept.
	for _, ind := range fi.inds {
		if ind.Source == SampleIntelSource {
			t.Errorf("sample indicator %s should have been removed", ind.ID)
		}
	}
	if len(fi.inds) != 1 || fi.inds[0].ID != "i3" {
		t.Errorf("intel left = %v, want only manual i3", fi.inds)
	}

	// Lists: sample entries gone, the user's kept.
	for _, a := range lists.Assets() {
		if a.BUnit == SampleBUnit {
			t.Errorf("sample asset %v should have been removed", a.Host)
		}
	}
	if len(lists.Assets()) != 1 {
		t.Errorf("assets left = %d, want 1", len(lists.Assets()))
	}
	for _, i := range lists.Identities() {
		if i.BUnit == SampleBUnit {
			t.Errorf("sample identity %v should have been removed", i.Identity)
		}
	}
	if len(lists.Identities()) != 1 {
		t.Errorf("identities left = %d, want 1", len(lists.Identities()))
	}

	// The state file is gone, so a fresh load would be allowed.
	if l.Loaded() {
		t.Error("state file should have been removed after Remove")
	}
}
