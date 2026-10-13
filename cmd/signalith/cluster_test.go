package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// eventually waits up to 20 seconds for ok.
func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// An in-process restart keeps the job lease and its epoch, restarts the
// jobs under it, and never locks the state folder again.
func TestRestartKeepsTheJobLease(t *testing.T) {
	rs := startRunnerWith(t, runOptions{scheduler: true})
	node := rs.r.node
	eventually(t, "this server runs the jobs", node.RunsJobs)
	epoch := node.Lease().Epoch()
	eventually(t, "the detection scheduler starts", func() bool {
		return strings.Count(rs.logs.String(), `msg="detection scheduler started"`) == 1
	})
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	eventually(t, "the jobs start again", func() bool {
		return strings.Count(rs.logs.String(), `msg="detection scheduler started"`) == 2
	})
	if !node.RunsJobs() || node.Lease().Epoch() != epoch || rs.r.node != node {
		t.Errorf("after the restart: runs %v epoch %d (was %d)", node.RunsJobs(), node.Lease().Epoch(), epoch)
	}
	lease := rs.os.Source("signalith_runtime", "lease:jobs")
	if lease["holder"] != node.ID() || fmt.Sprint(lease["epoch"]) != strconv.FormatInt(epoch, 10) {
		t.Errorf("lease %v", lease)
	}
	if l := rs.logs.String(); strings.Contains(l, "gave up the background jobs") || strings.Count(l, "now runs the background jobs") != 1 {
		t.Errorf("the lease changed hands:\n%s", l)
	}
	// The process still holds the state folder's lock, from its start.
	if _, err := cluster.OpenLocal(filepath.Dir(rs.r.path), cluster.LocalOptions{}); err == nil || !strings.Contains(err.Error(), "another Signalith process uses") {
		t.Errorf("open the state folder again: %v", err)
	}
}

// Stopping the server hands the jobs over at once and says it stopped.
func TestStopReleasesTheJobLease(t *testing.T) {
	rs := startRunnerWith(t, runOptions{scheduler: true})
	node := rs.r.node
	eventually(t, "this server runs the jobs", node.RunsJobs)
	rs.stop()
	lease := rs.os.Source("signalith_runtime", "lease:jobs")
	if lease["holder"] != "" || lease["released_by"] != node.ID() || lease["release_reason"] != "the server is stopping" {
		t.Errorf("lease after stop %v", lease)
	}
	if hb := rs.os.Source("signalith_runtime", "node:"+node.ID()); hb["state"] != cluster.StateStopped || hb["name"] != "siem-test" {
		t.Errorf("heartbeat after stop %v", hb)
	}
}

// A server with detections.scheduler off never takes the jobs.
func TestSchedulerOffNeverRunsTheJobs(t *testing.T) {
	rs := startRunner(t, nil, nil)
	eventually(t, "the first heartbeat", func() bool {
		return rs.os.Source("signalith_runtime", "node:"+rs.r.node.ID()) != nil
	})
	time.Sleep(300 * time.Millisecond)
	if rs.r.node.RunsJobs() || rs.os.Source("signalith_runtime", "lease:jobs") != nil {
		t.Error("a server with detections.scheduler off took the jobs")
	}
	if l := rs.logs.String(); strings.Contains(l, "detection scheduler started") {
		t.Errorf("the scheduler started:\n%s", l)
	}
	code, out, _ := rs.call("", "GET", "/api/cluster", "")
	servers, _ := out["servers"].([]any)
	if code != 200 || len(servers) != 1 {
		t.Fatalf("api/cluster %d %v", code, out)
	}
	if s := servers[0].(map[string]any); s["name"] != "siem-test" || s["jobs"] != "not_eligible" || s["self"] != true ||
		!strings.Contains(s["not_eligible"].(string), "detections.scheduler is off") {
		t.Errorf("this server %v", s)
	}
}

// /livez and /readyz answer without signing in, and say nothing more than
// whether this server is alive and ready.
func TestProbes(t *testing.T) {
	rs := startRunner(t, nil, nil)
	get := func(path string) (int, map[string]any, http.Header) {
		resp, err := http.Get("http://" + rs.addr + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %s", path, raw)
		}
		return resp.StatusCode, out, resp.Header
	}
	if code, out, h := get("/livez"); code != 200 || out["live"] != true || len(out) != 1 || h.Get("Cache-Control") != "no-store" {
		t.Errorf("livez %d %v", code, out)
	}
	eventually(t, "ready", func() bool { code, _, _ := get("/readyz"); return code == 200 })
	if code, out, _ := get("/readyz"); code != 200 || out["ready"] != true || len(out) != 1 {
		t.Errorf("readyz %d %v", code, out)
	}
	resp, err := http.Post("http://"+rs.addr+"/readyz", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /readyz = %d", resp.StatusCode)
	}
}

// With HTTPS on, /livez and /readyz answer over HTTPS and over plain HTTP
// on the same port, where everything else is sent to HTTPS: a load
// balancer that checks over plain HTTP learns whether the server is ready
// instead of getting a redirect.
func TestProbesWithHTTPS(t *testing.T) {
	rs := startRunnerWith(t, runOptions{})
	if rs.scheme != "https" {
		t.Fatalf("HTTPS is off: %s", rs.scheme)
	}
	for _, c := range []struct {
		name   string
		client *http.Client
		base   string
	}{{"https", rs.client, "https://" + rs.addr}, {"plain", noFollow, "http://" + rs.addr}} {
		for _, path := range []string{"/livez", "/readyz"} {
			eventually(t, c.name+path, func() bool {
				resp, err := c.client.Get(c.base + path)
				if err != nil {
					t.Fatal(err)
				}
				raw, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				return resp.StatusCode == 200 && strings.Contains(string(raw), "true")
			})
		}
	}
	// Anything else over plain HTTP is still sent to HTTPS.
	resp, err := noFollow.Get("http://" + rs.addr + "/livez/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("plain /livez/x = %d", resp.StatusCode)
	}
}

func TestReadiness(t *testing.T) {
	f := &front{}
	if ok, why := f.readiness(); ok || why != "starting" {
		t.Errorf("before start: %v %s", ok, why)
	}
	f.resume(http.NotFoundHandler(), http.NotFoundHandler())
	if ok, why := f.readiness(); !ok || why != "" {
		t.Errorf("running: %v %s", ok, why)
	}
	f.ready = func() (bool, string) { return false, cluster.NotReadyOpenSearch }
	if ok, why := f.readiness(); ok || why != "opensearch" {
		t.Errorf("without OpenSearch: %v %s", ok, why)
	}
	f.pause(time.Millisecond)
	if ok, why := f.readiness(); ok || why != "restarting" {
		t.Errorf("restarting: %v %s", ok, why)
	}
	f.resume(downHandler, downHandler)
	if ok, why := f.readiness(); ok || why != "down" {
		t.Errorf("down: %v %s", ok, why)
	}
}

// The same detections copied to Windows, with CRLF line ends and a byte
// order mark, have the same fingerprint; a real change does not.
func TestDetectionsFingerprintIgnoresLineEnds(t *testing.T) {
	unix, win := t.TempDir(), t.TempDir()
	rule := "id: brute\ntitle: Brute force\nquery: event.action=failed | stats count by user\n"
	if err := os.WriteFile(filepath.Join(unix, "brute.yaml"), []byte(rule), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(win, "brute.yaml"), []byte("\ufeff"+strings.ReplaceAll(rule, "\n", "\r\n")), 0o666); err != nil {
		t.Fatal(err)
	}
	if a, b := detectionsFingerprint(unix), detectionsFingerprint(win); a != b {
		t.Errorf("line ends change the fingerprint: %s %s", a, b)
	}
	if err := os.WriteFile(filepath.Join(win, "brute.yaml"), []byte(strings.Replace(rule, "Brute", "Brutal", 1)), 0o666); err != nil {
		t.Fatal(err)
	}
	if detectionsFingerprint(unix) == detectionsFingerprint(win) {
		t.Error("a changed rule has the same fingerprint")
	}
}
