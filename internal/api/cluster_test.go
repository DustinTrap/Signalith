package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// fakeCluster is two servers, siem-a and siem-b; this one is siem-b.
type fakeCluster struct {
	mu     sync.Mutex
	runs   bool
	holder string
}

func (f *fakeCluster) RunsJobs() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.runs
}

func (f *fakeCluster) JobHolder() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.holder
}

func (f *fakeCluster) set(runs bool, holder string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.runs, f.holder = runs, holder
}

func (f *fakeCluster) Status() cluster.Status {
	off := int64(-12)
	started := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	a := &cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", Version: "1.5.0", OS: "linux", Arch: "amd64",
		NodeURL: "https://10.0.0.5:8443", Listen: "0.0.0.0:8443", LeaderEligible: true, ClockOffsetMS: &off,
		OpenSearch: cluster.OSInfo{OK: true, Endpoint: "https://os1:9200", LatencyMS: 3}, Problems: []string{}}
	b := &cluster.Heartbeat{NodeID: "n_b", Name: "siem-b", Version: "1.5.0", OS: "windows", Arch: "amd64",
		NodeURL: "https://10.0.0.6:8443", Listen: "0.0.0.0:8443", LeaderEligible: true, Problems: []string{}}
	acq := started.Add(time.Minute)
	return cluster.Status{Self: "n_b",
		Servers: []cluster.ServerStatus{
			{NodeID: "n_a", Name: "siem-a", State: cluster.StateReady, Version: "1.5.0", Jobs: "runs", StartedAt: started, HeartbeatAt: started, Detail: a},
			{NodeID: "n_b", Name: "siem-b", Self: true, State: cluster.StateReady, Version: "1.5.0", Jobs: "standby", StartedAt: started,
				HeartbeatAt: started, Detail: b, CannotTakeOver: "its retention policies differ from siem-a's"},
		},
		Jobs:     cluster.JobsStatus{Holder: "n_a", HolderName: "siem-a", Epoch: 17, AcquiredAt: &acq, RenewedAt: &acq},
		Warnings: []cluster.Warning{{Level: "amber", Text: "siem-b cannot take over the background jobs if siem-a stops: its retention policies differ from siem-a's."}},
	}
}

func TestClusterViewersSeeNamesAndStates(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Cluster = &fakeCluster{holder: "siem-a"}
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	code, out := doAs(t, ts, "vera", "role-password", "GET", "/api/cluster", "")
	if code != 200 {
		t.Fatalf("viewer: %d %v", code, out)
	}
	servers := out["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("servers %v", servers)
	}
	for _, raw := range servers {
		sv := raw.(map[string]any)
		if sv["name"] == "" || sv["state"] != "ready" || sv["jobs"] == "" || sv["version"] != "1.5.0" {
			t.Errorf("viewer row %v", sv)
		}
		for _, hidden := range []string{"node_id", "node_url", "listen", "syslog", "opensearch", "clock_offset_ms", "cannot_take_over", "files_fingerprint", "problems"} {
			if _, ok := sv[hidden]; ok {
				t.Errorf("a viewer sees %s: %v", hidden, sv)
			}
		}
	}
	lease := out["lease"].(map[string]any)
	if lease["holder_name"] != "siem-a" || lease["frozen"] != false || lease["holder"] != nil || lease["epoch"] != nil {
		t.Errorf("viewer lease %v", lease)
	}
	if out["writes_refused"] != false {
		t.Errorf("viewer writes_refused %v", out["writes_refused"])
	}
	for _, hidden := range []string{"warnings", "self"} {
		if _, ok := out[hidden]; ok {
			t.Errorf("a viewer sees %s", hidden)
		}
	}
	if osInfo := out["opensearch"].(map[string]any); osInfo["url"] != nil {
		t.Errorf("a viewer sees where OpenSearch is: %v", osInfo)
	}

	code, out = do(t, ts, "GET", "/api/cluster", "", true)
	if code != 200 {
		t.Fatalf("admin: %d %v", code, out)
	}
	a := out["servers"].([]any)[0].(map[string]any)
	if a["node_url"] != "https://10.0.0.5:8443" || a["clock_offset_ms"] != float64(-12) || a["opensearch"].(map[string]any)["latency_ms"] != float64(3) {
		t.Errorf("admin row %v", a)
	}
	b := out["servers"].([]any)[1].(map[string]any)
	if b["self"] != true || !strings.Contains(b["cannot_take_over"].(string), "retention policies") {
		t.Errorf("admin self row %v", b)
	}
	lease = out["lease"].(map[string]any)
	if lease["holder"] != "n_a" || lease["epoch"] != float64(17) || lease["mine"] != false {
		t.Errorf("admin lease %v", lease)
	}
	if w := out["warnings"].([]any); len(w) != 1 || out["self"] != "n_b" {
		t.Errorf("admin warnings %v self %v", w, out["self"])
	}
}

func TestClusterNeedsTheCluster(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/cluster", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("without a cluster: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/cluster", "", false); code != http.StatusUnauthorized {
		t.Errorf("signed out: %d", code)
	}
}

// Of the servers that share one OpenSearch, only the one that runs the
// background jobs downloads feeds, so only its page changes them.
func TestFeedsChangeOnlyWhereTheyDownload(t *testing.T) {
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	feeds := &intel.Feeds{Store: store, AllowLoopback: true, File: filepath.Join(t.TempDir(), "intel_feeds.yaml")}
	cl := &fakeCluster{holder: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel, s.Feeds, s.Cluster = store, feeds, cl
	})
	code, raw := feedCall(t, ts, "GET", "/api/intel", "")
	if out := asMap(t, raw); code != 200 || out["manage"] != false || out["downloads"] != false ||
		!strings.HasPrefix(out["downloads_why"].(string), "This server does not download feeds right now: siem-a does") {
		t.Errorf("overview = %d %v", code, out)
	}
	add := `{"name":"x-feed","url":"https://feeds.example/x"}`
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds", add); code != 409 || !strings.Contains(raw, "siem-a does") {
		t.Errorf("standby add = %d %s", code, raw)
	}
	cl.set(false, "")
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds", add); code != 409 || !strings.Contains(raw, "no server runs the background jobs") {
		t.Errorf("no holder add = %d %s", code, raw)
	}
	cl.set(true, "")
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds", add); code != 201 && code != 200 {
		t.Errorf("holder add = %d %s", code, raw)
	}
	if out := asMap(t, getRaw(t, ts, "/api/intel")); out["manage"] != true || out["downloads_why"] != nil {
		t.Errorf("holder overview %v", out)
	}
}
