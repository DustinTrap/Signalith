//go:build integration

package integration

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/sample"
)

// TestSampleDataEndToEnd loads the small sample set against a real
// OpenSearch, backfills the detections, and checks that every detection that
// raises findings did, that threat intel matched, that risk accumulated into
// the risk-incident findings, and that a sample investigation was created.
// It then removes the sample data and checks that nothing sample is left and
// that pre-existing documents are untouched.
func TestSampleDataEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Stores.
	pipeline := &ingest.Pipeline{Store: cl, Prefix: prefix, MaxEventAge: 8 * 24 * time.Hour, Log: log}
	fstore := findings.NewOpenSearch(cl, prefix)
	cstore := cases.NewOpenSearch(cl, prefix)
	ibackend := intel.NewOpenSearch(cl, prefix)
	indicators := intel.NewStore(ibackend)
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	lib, _, err := detect.NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []func(context.Context) error{fstore.EnsureIndex, cstore.EnsureIndex, ibackend.EnsureIndex} {
		if err := e(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := indicators.Load(ctx); err != nil {
		t.Fatal(err)
	}
	eng.Assets = lists
	eng.Intel = indicators
	riskStore := &risk.Store{Client: cl, Prefix: prefix}

	refresh := func() {
		t.Helper()
		if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Pre-existing data that must survive removal.
	now := time.Now()
	if _, err := pipeline.IngestEvents(ctx, []ingest.Event{{
		Time: now.Add(-2 * time.Hour), Model: "Authentication",
		Fields: map[string]any{"action": "success", "user": "real.user", "host": "real-host", "app": "sshd"},
	}}); err != nil {
		t.Fatal(err)
	}
	refresh()
	preFinding := &findings.Finding{ID: "pre-existing", DetectionID: "auth-brute-force", Severity: "high",
		Status: findings.StatusNew, Created: now, Updated: now, Entities: map[string]any{"user": "real.user"}}
	if err := fstore.Create(ctx, preFinding); err != nil {
		t.Fatal(err)
	}
	if err := indicators.Add(ctx, []intel.Indicator{{ID: "pre-ind", Source: intel.ManualSource, Type: intel.TypeIP, Value: "203.0.113.200"}}); err != nil {
		t.Fatal(err)
	}

	loader := &sample.Loader{
		Prefix: prefix, Pipeline: pipeline, OS: cl, Intel: indicators, Assets: lists,
		Library: lib, Engine: eng, Findings: fstore, Cases: cstore, Risk: riskStore,
		StateDir: t.TempDir(), Log: log,
	}

	// Load.
	st, err := loader.Load(ctx, sample.SizeSmall, nil)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Events == 0 || st.Findings == 0 {
		t.Fatalf("load wrote %d events and %d findings", st.Events, st.Findings)
	}
	refresh()

	// Every enabled detection that raises findings must have raised at least
	// one, by detection_id.
	sampleFindings, _, err := fstore.Search(ctx, findings.Filter{Sample: st.ID, Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	fired := map[string]int{}
	for _, f := range sampleFindings {
		fired[f.DetectionID]++
	}
	dets, _ := detect.Builtin()
	for _, d := range dets {
		producesFinding := d.Enabled && (d.Risk == nil || !d.Risk.Only)
		if producesFinding && fired[d.ID] == 0 {
			t.Errorf("detection %s produced no finding", d.ID)
		}
	}
	if fired["threat-activity"] == 0 {
		t.Error("threatmatch produced no findings")
	}
	if fired["risk-threshold-exceeded"] == 0 && fired["risk-multiple-tactics"] == 0 {
		t.Error("accumulated risk produced no risk-incident findings")
	}

	// Risk events were written and marked.
	riskRes, err := eng.Execute(ctx, mustParse(t, "datamodel=Risk sample="+st.ID+" | stats count"))
	if err != nil {
		t.Fatal(err)
	}
	if riskRes.Matched == 0 {
		t.Error("no sample risk events")
	}

	// A sample investigation exists.
	if len(st.Cases) == 0 {
		t.Error("no sample investigation created")
	} else if _, err := cstore.Get(ctx, st.Cases[0]); err != nil {
		t.Errorf("sample case missing: %v", err)
	}

	// Loading again is refused.
	if _, err := loader.Load(ctx, sample.SizeSmall, nil); err == nil {
		t.Error("second load should have been refused")
	}

	// Remove.
	if _, err := loader.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	refresh()

	// No sample events, findings, risk or intel remain.
	for _, q := range []string{"sample=" + st.ID + " | stats count", "datamodel=Risk sample=" + st.ID + " | stats count"} {
		res, err := eng.Execute(ctx, mustParse(t, q))
		if err != nil {
			t.Fatal(err)
		}
		if res.Matched != 0 {
			t.Errorf("%q: %d sample docs remain", q, res.Matched)
		}
	}
	leftover, _, err := fstore.Search(ctx, findings.Filter{Sample: st.ID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(leftover) != 0 {
		t.Errorf("%d sample findings remain", len(leftover))
	}
	indicators.Load(ctx)
	allInds, _ := indicators.List(intel.Filter{})
	for _, ind := range allInds {
		if ind.Source == sample.SampleIntelSource {
			t.Errorf("sample indicator %s remains", ind.ID)
		}
	}
	for _, a := range lists.Assets() {
		if a.BUnit == sample.SampleBUnit {
			t.Errorf("sample asset remains: %v", a.Host)
		}
	}

	// Pre-existing documents are untouched.
	if _, err := fstore.Get(ctx, "pre-existing"); err != nil {
		t.Errorf("pre-existing finding was removed: %v", err)
	}
	preRes, err := eng.Execute(ctx, mustParse(t, "datamodel=Authentication user=real.user | stats count"))
	if err != nil {
		t.Fatal(err)
	}
	if preRes.Matched == 0 {
		t.Error("pre-existing event was removed")
	}
	// The store rewrites an indicator's ID to a deterministic hash of its
	// source, type and value, so look the pre-existing one up by value.
	found := false
	indicators.Load(ctx)
	allInds, _ = indicators.List(intel.Filter{})
	for _, ind := range allInds {
		if ind.Source == intel.ManualSource && ind.Value == "203.0.113.200" {
			found = true
		}
	}
	if !found {
		t.Error("pre-existing manual indicator was removed")
	}

	// The state file is gone, so a fresh load would be allowed.
	if loader.Loaded() {
		t.Error("state remained after removal")
	}
}

func mustParse(t *testing.T, s string) *query.Query {
	t.Helper()
	q, err := query.Parse(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return q
}
