//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// addDay writes n events to one daily index, as ingest would.
func addDay(t *testing.T, cl *store.Client, index string, n int) {
	t.Helper()
	docs := make([]store.IndexedDoc, n)
	for i := range docs {
		docs[i] = store.IndexedDoc{Index: index, Doc: map[string]any{
			"@timestamp": time.Now().UTC().Format(time.RFC3339), "datamodel": "Endpoint",
			"user": fmt.Sprintf("user%d", i%7), "process_id": i, "message": fmt.Sprintf("event %d\nsecond line", i),
		}}
	}
	if errs, err := cl.Bulk(context.Background(), docs); err != nil || len(errs) > 0 {
		t.Fatalf("bulk: %v %v", err, errs)
	}
	if err := cl.Do(context.Background(), http.MethodPost, "/"+index+"/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func infoOf(t *testing.T, os *retention.OpenSearch, index string) retention.IndexInfo {
	t.Helper()
	ixs, err := os.Indices(context.Background(), index)
	if err != nil || len(ixs) != 1 {
		t.Fatalf("indices %s: %v %v", index, ixs, err)
	}
	return ixs[0]
}

func TestRetentionEndToEnd(t *testing.T) {
	cl, _, prefix := setup(t)
	ctx := context.Background()
	os := retention.NewOpenSearch(cl)
	os.Poll = 200 * time.Millisecond
	os.PageSize = 400 // several scroll pages
	now := time.Now().UTC()
	old := retention.IndexName(prefix, "endpoint", now.AddDate(0, 0, -40))
	warm := retention.IndexName(prefix, "endpoint", now.AddDate(0, 0, -10))
	today := retention.IndexName(prefix, "endpoint", now)
	addDay(t, cl, old, 1203)
	addDay(t, cl, warm, 50)
	addDay(t, cl, today, 5)
	// Several small segments, so merging has something to do.
	for i := 0; i < 3; i++ {
		addDay(t, cl, warm, 5)
	}

	t.Run("list with sizes", func(t *testing.T) {
		ixs, err := os.Indices(ctx, prefix+"-*,"+prefix+"_*")
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, ix := range ixs {
			names = append(names, ix.Name)
			if ix.Bytes <= 0 || ix.PrimaryBytes <= 0 || ix.Copies != 1 || ix.Segments < 1 || ix.WriteBlocked || ix.RestoredUntil != "" {
				t.Errorf("%+v", ix)
			}
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{old, warm, today}) {
			t.Errorf("names = %v", names)
		}
		if ix := infoOf(t, os, old); ix.Docs != 1203 {
			t.Errorf("old = %+v", ix)
		}
		if ixs, err := os.Indices(ctx, prefix+"-nothing-*"); err != nil || len(ixs) != 0 {
			t.Errorf("no match = %v %v", ixs, err)
		}
		d, err := os.Disk(ctx)
		if err != nil || d.Total <= 0 || d.Available <= 0 || d.Available > d.Total || d.Node == "" {
			t.Errorf("disk = %+v %v", d, err)
		}
	})

	t.Run("read-only and force merge", func(t *testing.T) {
		if ix := infoOf(t, os, warm); ix.Segments < 2 {
			t.Logf("warm index has %d segments before merging", ix.Segments)
		}
		if err := os.BlockWrites(ctx, warm, true); err != nil {
			t.Fatal(err)
		}
		if errs, err := cl.Bulk(ctx, []store.IndexedDoc{{Index: warm, Doc: map[string]any{"user": "late"}}}); err == nil && len(errs) == 0 {
			t.Error("wrote to a read-only index")
		}
		if err := os.ForceMerge(ctx, warm); err != nil {
			t.Fatal(err)
		}
		ix := infoOf(t, os, warm)
		if !ix.WriteBlocked || ix.Segments != 1 || !ix.Compacted() || ix.Docs != 65 {
			t.Errorf("after merge = %+v", ix)
		}
		if err := os.BlockWrites(ctx, warm, false); err != nil {
			t.Fatal(err)
		}
		if ix := infoOf(t, os, warm); ix.WriteBlocked {
			t.Errorf("still read-only: %+v", ix)
		}
	})

	t.Run("archive, delete and restore", func(t *testing.T) {
		off := false
		mgr := &retention.Manager{
			Cluster: os, Prefix: prefix,
			// The guard is off: how full the test machine's disk is does not matter here.
			Config: retention.Config{Days: 90, Guard: &retention.Guard{Enabled: &off},
				Policies: map[string]retention.Policy{"endpoint": {KeepDays: 30, CompactAfterDays: 7, Archive: true}}},
			Store:       retention.NewStore(filepath.Join(t.TempDir(), "retention.yaml")),
			Archive:     &retention.Archive{Dir: filepath.Join(t.TempDir(), "archive")},
			HistoryFile: filepath.Join(t.TempDir(), "history.json"),
			Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		if ov := mgr.Overview(ctx); ov.Error != "" || ov.Disk == nil || ov.Pending.ArchiveDays != 1 || ov.Pending.CompactDays != 1 {
			t.Fatalf("overview = %+v", ov)
		}
		run, err := mgr.Run(ctx, retention.TriggerManual, "test")
		if err != nil || run.Archived != 1 || run.Compacted != 1 || len(run.Errors) != 0 {
			t.Fatalf("run = %+v %v", run, err)
		}
		if ixs, _ := os.Indices(ctx, old); len(ixs) != 0 {
			t.Errorf("archived index still there: %v", ixs)
		}
		if ix := infoOf(t, os, warm); !ix.Compacted() {
			t.Errorf("warm = %+v", ix)
		}
		if ix := infoOf(t, os, today); ix.WriteBlocked || ix.Docs != 5 {
			t.Errorf("today = %+v", ix)
		}
		man, err := mgr.Archive.Get(old)
		if err != nil || man.Docs != 1203 || mgr.Archive.Verify(man) != nil {
			t.Fatalf("archive = %+v %v", man, err)
		}
		// Deleting a missing index is not an error.
		if err := os.DeleteIndex(ctx, old); err != nil {
			t.Error(err)
		}

		until := now.AddDate(0, 0, 3).Format(time.DateOnly)
		for i := 0; i < 2; i++ { // twice: no duplicates
			n, err := mgr.RestoreArchive(ctx, man, until, nil)
			if err != nil || n != 1203 {
				t.Fatalf("restore %d: %d %v", i, n, err)
			}
		}
		if n, _ := os.Count(ctx, old); n != 1203 {
			t.Errorf("restored count = %d", n)
		}
		if ix := infoOf(t, os, old); ix.RestoredUntil != until {
			t.Errorf("restored = %+v", ix)
		}
		var out struct {
			Hits struct {
				Hits []struct {
					Source map[string]any `json:"_source"`
				} `json:"hits"`
			} `json:"hits"`
		}
		err = cl.Do(ctx, http.MethodPost, "/"+old+"/_search", map[string]any{"query": map[string]any{"term": map[string]any{"process_id": 77}}}, &out)
		if err != nil || len(out.Hits.Hits) != 1 || out.Hits.Hits[0].Source["message"] != "event 77\nsecond line" {
			t.Errorf("search restored = %+v %v", out, err)
		}
		// The next run keeps the restored day.
		if run, err := mgr.Run(ctx, retention.TriggerSchedule, ""); err != nil || run.Deleted+run.Archived != 0 {
			t.Errorf("run after restore = %+v %v", run, err)
		}
		// Restoring into a compacted (read-only) index works too.
		if _, err := mgr.RestoreArchive(ctx, man, until, nil); err != nil {
			t.Error(err)
		}
		if err := os.BlockWrites(ctx, old, true); err != nil {
			t.Fatal(err)
		}
		if n, err := mgr.RestoreArchive(ctx, man, until, nil); err != nil || n != 1203 {
			t.Errorf("restore into read-only index: %d %v", n, err)
		}
	})

	t.Run("archive an index under the flood-stage block", func(t *testing.T) {
		// OpenSearch puts this block on every index when its disk passes
		// the flood stage: reads and deletes still work, setting changes
		// and merges do not.
		flooded := retention.IndexName(prefix, "endpoint", now.AddDate(0, 0, -50))
		addDay(t, cl, flooded, 30)
		err := cl.Do(ctx, http.MethodPut, "/"+flooded+"/_settings", map[string]any{"index.blocks.read_only_allow_delete": true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if ix := infoOf(t, os, flooded); !ix.DiskBlocked {
			t.Fatalf("not reported as blocked: %+v", ix)
		}
		if err := os.BlockWrites(ctx, flooded, true); err == nil {
			t.Error("OpenSearch now accepts setting changes on blocked indices; the workaround can go")
		}
		off := false
		mgr := &retention.Manager{
			Cluster: os, Prefix: prefix,
			Config: retention.Config{Guard: &retention.Guard{Enabled: &off},
				Policies: map[string]retention.Policy{"endpoint": {KeepDays: 45, Archive: true}}},
			Archive:     &retention.Archive{Dir: filepath.Join(t.TempDir(), "archive")},
			HistoryFile: filepath.Join(t.TempDir(), "history.json"),
			Log:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		}
		run, err := mgr.Run(ctx, retention.TriggerGuard, "")
		if err != nil || run.Archived != 1 || len(run.Errors) != 0 {
			t.Fatalf("run = %+v %v", run, err)
		}
		if ixs, _ := os.Indices(ctx, flooded); len(ixs) != 0 {
			t.Errorf("still there: %v", ixs)
		}
		if man, err := mgr.Archive.Get(flooded); err != nil || man.Docs != 30 {
			t.Errorf("archive = %+v %v", man, err)
		}
	})
}

func TestRetentionRecordsEndToEnd(t *testing.T) {
	cl, _, prefix := setup(t)
	ctx := context.Background()
	fs := findings.NewOpenSearch(cl, prefix)
	cs := cases.NewOpenSearch(cl, prefix)
	if err := fs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if err := cs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old, recent := now.AddDate(-2, 0, 0), now.AddDate(0, 0, -10)
	for _, c := range []*cases.Case{
		{ID: "CASE-open", Title: "open", Status: findings.StatusInProgress, Severity: "high", Created: old, Updated: old},
		{ID: "CASE-closed", Title: "closed", Status: findings.StatusClosed, Severity: "low", Created: old, Updated: old},
		{ID: "CASE-recent", Title: "recent", Status: findings.StatusResolved, Severity: "low", Created: recent, Updated: recent},
	} {
		if err := cs.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []*findings.Finding{
		{ID: "f-open", Status: findings.StatusNew, Created: old, Updated: old},
		{ID: "f-closed", Status: findings.StatusClosed, Created: old, Updated: old},
		{ID: "f-resolved", Status: findings.StatusResolved, Created: old, Updated: old},
		{ID: "f-recent", Status: findings.StatusClosed, Created: recent, Updated: recent},
		{ID: "f-open-case", Status: findings.StatusClosed, CaseID: "CASE-open", Created: old, Updated: old},
		{ID: "f-closed-case", Status: findings.StatusClosed, CaseID: "CASE-closed", Created: old, Updated: old},
	} {
		f.Title, f.Severity, f.DetectionID = f.ID, "low", "test"
		if err := fs.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	os := retention.NewOpenSearch(cl)
	os.Poll = 200 * time.Millisecond
	fi, ci := retention.RecordIndex(prefix, retention.Findings), retention.RecordIndex(prefix, retention.Cases)
	open, err := os.OpenCases(ctx, ci)
	if err != nil || !slices.Equal(open, []string{"CASE-open"}) {
		t.Fatalf("open cases = %v %v", open, err)
	}
	before := now.AddDate(-1, 0, 0)
	if n, err := os.CountClosed(ctx, fi, before, open); err != nil || n != 3 {
		t.Errorf("count findings = %d %v", n, err)
	}
	if n, err := os.DeleteClosed(ctx, fi, before, open); err != nil || n != 3 {
		t.Errorf("delete findings = %d %v", n, err)
	}
	left, _, err := fs.Search(ctx, findings.Filter{})
	var ids []string
	for _, f := range left {
		ids = append(ids, f.ID)
	}
	slices.Sort(ids)
	if err != nil || !slices.Equal(ids, []string{"f-open", "f-open-case", "f-recent"}) {
		t.Errorf("findings left = %v %v", ids, err)
	}
	if n, err := os.DeleteClosed(ctx, ci, before, nil); err != nil || n != 1 {
		t.Errorf("delete cases = %d %v", n, err)
	}
	if _, err := cs.Get(ctx, "CASE-closed"); err != cases.ErrNotFound {
		t.Errorf("closed case: %v", err)
	}
	lo, hi, err := os.RecordRange(ctx, ci)
	if err != nil || lo.Format(time.DateOnly) != old.Format(time.DateOnly) || hi.Format(time.DateOnly) != recent.Format(time.DateOnly) {
		t.Errorf("range = %v %v %v", lo, hi, err)
	}
	// Missing indices are empty, not errors.
	if n, err := os.CountClosed(ctx, prefix+"_nothing", before, nil); err != nil || n != 0 {
		t.Errorf("missing index = %d %v", n, err)
	}
	if lo, _, err := os.RecordRange(ctx, prefix+"_nothing"); err != nil || !lo.IsZero() {
		t.Errorf("missing range = %v %v", lo, err)
	}
}
