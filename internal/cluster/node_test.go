package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fast is a timing for tests on the real clock.
var fast = Timing{
	Heartbeat: 200 * time.Millisecond, Offline: 600 * time.Millisecond, IdentityWatch: 800 * time.Millisecond,
	Renew: 200 * time.Millisecond, Retry: 50 * time.Millisecond, Fence: time.Second, Takeover: 1500 * time.Millisecond,
	Watch: 50 * time.Millisecond, ReleaseWait: 3 * time.Second, PreferWait: 200 * time.Millisecond,
	ClockCheck: time.Second, FilesCheck: time.Second,
}

func testOptions(name string) LocalOptions {
	return LocalOptions{
		Hostname:  func() (string, error) { return name, nil },
		MachineID: func() string { return "machine-1" },
	}
}

func TestOpenLocal(t *testing.T) {
	dir := t.TempDir()
	l, err := OpenLocal(dir, testOptions("siem-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(l.Identity.NodeID, "n_") || l.Identity.Name != "siem-a" || l.LastBoot != "" || !strings.HasPrefix(l.BootID, "b_") {
		t.Fatalf("identity %+v boot %q last %q", l.Identity, l.BootID, l.LastBoot)
	}
	// A second process (or a second open in this one) is refused.
	if _, err := OpenLocal(dir, testOptions("siem-a")); err == nil || !strings.Contains(err.Error(), "another Signalith process uses the state folder") {
		t.Fatalf("second open: %v", err)
	}
	if err := l.WriteLastBoot(); err != nil {
		t.Fatal(err)
	}
	l.Close()
	// The next start keeps the identity and knows the last boot; a name
	// set in signalith.yaml wins and is kept.
	o := testOptions("other-host")
	o.Name = "siem-1"
	l2, err := OpenLocal(dir, o)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Identity.NodeID != l.Identity.NodeID || l2.Identity.Name != "siem-1" || l2.LastBoot != l.BootID || l2.BootID == l.BootID {
		t.Fatalf("reopened %+v last %q", l2.Identity, l2.LastBoot)
	}
	l2.Close()
	l3, err := OpenLocal(dir, testOptions("other-host"))
	if err != nil {
		t.Fatal(err)
	}
	if l3.Identity.Name != "siem-1" || l3.Moved {
		t.Errorf("name %q moved %v", l3.Identity.Name, l3.Moved)
	}
	l3.Close()
	// The folder restored on another computer: a warning, same identity.
	moved := testOptions("x")
	moved.MachineID = func() string { return "machine-2" }
	l4, err := OpenLocal(dir, moved)
	if err != nil {
		t.Fatal(err)
	}
	if !l4.Moved || len(l4.Warnings) == 0 || l4.Identity.NodeID != l.Identity.NodeID {
		t.Errorf("moved %v warnings %v", l4.Moved, l4.Warnings)
	}
	l4.Close()
	// A damaged identity is never replaced silently.
	if err := os.WriteFile(filepath.Join(dir, nodeFile), []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenLocal(dir, testOptions("x")); err == nil || !strings.Contains(err.Error(), "damaged") {
		t.Errorf("damaged: %v", err)
	}
}

func TestNamesInContainers(t *testing.T) {
	for host, want := range map[string]string{
		"4f2a91c07b3e": "signalith-1", // a random container id
		"siem-b":       "siem-b",      // a fixed hostname: in the compose file
		"":             "signalith-1",
	} {
		o := LocalOptions{InContainer: true, Hostname: func() (string, error) { return host, nil }}
		if got := hostName(o); got != want {
			t.Errorf("%q: %q, want %q", host, got, want)
		}
	}
	if got := hostName(LocalOptions{Hostname: func() (string, error) { return "WIN SERVER/1", nil }}); got != "WIN-SERVER-1" {
		t.Errorf("odd name: %q", got)
	}
	dir := t.TempDir()
	l, err := OpenLocal(dir, LocalOptions{InContainer: true, Hostname: func() (string, error) { return "4f2a91c07b3e", nil },
		MachineID: func() string { return "m" }})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.Identity.MachineID != "" || l.Identity.Name != "signalith-1" {
		t.Errorf("container identity %+v", l.Identity)
	}
}

func TestLockFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	unlock, err := lockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(path); !errors.Is(err, errLocked) {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	unlock2, err := lockFile(path)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}

// testNode starts a node on a state folder with a fake OpenSearch.
func testNode(t *testing.T, dir string, c *store.Client, eligible bool) *Node {
	t.Helper()
	l, err := OpenLocal(dir, testOptions("host-"+filepath.Base(dir)))
	if err != nil {
		t.Fatal(err)
	}
	n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
	ctx, cancel := context.WithCancel(context.Background())
	n.Start(ctx)
	n.Use(c, "s", Settings{Eligible: eligible, Listen: "0.0.0.0:8080"})
	t.Cleanup(func() {
		cancel()
		n.Close()
	})
	return n
}

// crash stops a node the way a killed process stops: no release, no last
// heartbeat, and its lock released.
func crash(n *Node) {
	n.mu.Lock()
	cancel, done := n.cancel, n.loopDone
	n.mu.Unlock()
	cancel()
	<-done
	n.lease.Abandon("crashed")
	n.Close()
}

func waitReady(t *testing.T, n *Node, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if ok, _ := n.Ready(); ok {
			return
		}
		if time.Now().After(deadline) {
			_, why := n.Ready()
			t.Fatalf("%s not ready after %v: %s", n.Name(), within, why)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func heartbeatOf(t *testing.T, os *ostest.Server, id string) Heartbeat {
	t.Helper()
	b, _ := json.Marshal(os.Source("s_runtime", nodeDocID(id)))
	var hb Heartbeat
	_ = json.Unmarshal(b, &hb)
	return hb
}

func TestCrashRestartWithinASecondPassesTheIdentityCheck(t *testing.T) {
	os := ostest.New(t)
	c := store.New(store.Config{URL: os.URL})
	dir := t.TempDir()
	a := testNode(t, dir, c, true)
	waitReady(t, a, 5*time.Second)
	crash(a)
	// The same folder starts again at once. The heartbeat it finds was
	// written by this folder's last process, so it does not wait.
	l, err := OpenLocal(dir, testOptions("host"))
	if err != nil {
		t.Fatal(err)
	}
	if l.LastBoot != a.local.BootID {
		t.Fatalf("last boot %q, want %q", l.LastBoot, a.local.BootID)
	}
	timing := fast
	timing.IdentityWatch = 12 * time.Second
	b := New(Options{Local: l, Version: "1.0.0", Timing: timing})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer l.Close()
	start := time.Now()
	b.Start(ctx)
	b.Use(c, "s", Settings{Eligible: true})
	waitReady(t, b, time.Second)
	if took := time.Since(start); took > time.Second {
		t.Errorf("the identity check took %v", took)
	}
	if hb := heartbeatOf(t, os, b.ID()); hb.BootID != l.BootID {
		t.Errorf("heartbeat boot %q", hb.BootID)
	}
	select {
	case err := <-b.Fatal():
		t.Fatalf("refused: %v", err)
	default:
	}
}

// copyIdentity copies node.id into a new state folder, as a cloned
// computer or a copied folder would.
func copyIdentity(t *testing.T, from string) string {
	t.Helper()
	to := t.TempDir()
	b, err := os.ReadFile(filepath.Join(from, nodeFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(to, nodeFile), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return to
}

func TestForeignAdvancingHeartbeatRefusesStart(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	dir := t.TempDir()
	a := testNode(t, dir, c, true)
	waitReady(t, a, 5*time.Second)
	b := testNode(t, copyIdentity(t, dir), c, true)
	if b.ID() != a.ID() {
		t.Fatal("not a copy")
	}
	select {
	case err := <-b.Fatal():
		if !strings.Contains(err.Error(), "is using this server's identity") || !strings.Contains(err.Error(), nodeFile) {
			t.Errorf("message: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a copy of a live server's identity started")
	}
	if ok, why := b.Ready(); ok || why != NotReadyIdentity {
		t.Errorf("ready %v %s", ok, why)
	}
	// It never wrote over the live server's heartbeat, and never ran the
	// jobs.
	if hb := heartbeatOf(t, fos, a.ID()); hb.BootID != a.local.BootID {
		t.Errorf("heartbeat boot %q", hb.BootID)
	}
	if b.lease.Holding() {
		t.Error("the copy holds the lease")
	}
}

func TestStaleCopyOfAnIdentityStarts(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	dir := t.TempDir()
	a := testNode(t, dir, c, true)
	waitReady(t, a, 5*time.Second)
	crash(a)
	// The folder restored from a backup elsewhere, with its old server
	// gone: the heartbeat does not change, so it is a stale copy.
	b := testNode(t, copyIdentity(t, dir), c, true)
	waitReady(t, b, 5*time.Second)
	if hb := heartbeatOf(t, fos, b.ID()); hb.BootID != b.local.BootID {
		t.Errorf("heartbeat boot %q", hb.BootID)
	}
}

func TestTwoServersOneRunsTheJobs(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	b := testNode(t, t.TempDir(), c, false)
	waitReady(t, a, 5*time.Second)
	waitReady(t, b, 5*time.Second)
	var st Status
	deadline := time.Now().Add(5 * time.Second)
	for {
		st = b.Status()
		if len(st.Servers) == 2 && st.Jobs.HolderName == a.Name() && st.Servers[0].State == StateReady && st.Servers[1].State == StateReady {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
	for _, s := range st.Servers {
		want := map[string]string{a.ID(): "runs", b.ID(): "not_eligible"}[s.NodeID]
		if s.Jobs != want || s.State != StateReady {
			t.Errorf("%s: jobs %q state %q", s.Name, s.Jobs, s.State)
		}
	}
	if !a.RunsJobs() || b.RunsJobs() || b.JobHolder() != a.Name() {
		t.Error("jobs on the wrong server")
	}
	// a stops: b sees it stopped at once, and the warning that nobody runs
	// the jobs.
	a.Stop()
	if d := heartbeatOf(t, fos, a.ID()); d.State != StateStopped {
		t.Errorf("last heartbeat %q", d.State)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		st = b.Status()
		stopped := false
		for _, s := range st.Servers {
			stopped = stopped || s.NodeID == a.ID() && s.State == StateStopped && s.OfflineSince != nil
		}
		if stopped && len(st.Warnings) > 0 && strings.Contains(st.Warnings[0].Text, "No server is running") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %+v", st)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestCrashedServerShowsOffline(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	b := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	waitReady(t, b, 5*time.Second)
	// Whoever holds the jobs crashes; the other takes over and shows it
	// offline.
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() && !b.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("nobody took the jobs")
		}
		time.Sleep(10 * time.Millisecond)
	}
	holder, other := a, b
	if b.RunsJobs() {
		holder, other = b, a
	}
	crash(holder)
	deadline = time.Now().Add(10 * time.Second)
	for {
		st := other.Status()
		offline := false
		for _, s := range st.Servers {
			offline = offline || s.NodeID == holder.ID() && s.State == StateOffline
		}
		if offline && other.RunsJobs() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("status %+v runs %v", st, other.RunsJobs())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestClockFarOffMayNotHoldTheJobs(t *testing.T) {
	fos := ostest.New(t)
	fos.Offset = 45 * time.Second
	c := store.New(store.Config{URL: fos.URL})
	a := testNode(t, t.TempDir(), c, true)
	waitReady(t, a, 5*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		hb := heartbeatOf(t, fos, a.ID())
		if hb.ClockOffsetMS != nil && strings.Contains(hb.NotEligible, "clock is 45s off") {
			if *hb.ClockOffsetMS < 44000 || *hb.ClockOffsetMS > 46000 {
				t.Errorf("offset %d ms", *hb.ClockOffsetMS)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("heartbeat %+v", hb)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if a.RunsJobs() {
		t.Error("a server with a wrong clock runs the jobs")
	}
}

func TestUseAnotherOpenSearchMovesTheLease(t *testing.T) {
	os1, os2 := ostest.New(t), ostest.New(t)
	c1, c2 := store.New(store.Config{URL: os1.URL}), store.New(store.Config{URL: os2.URL})
	a := testNode(t, t.TempDir(), c1, true)
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("no lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.Use(c2, "s", Settings{Eligible: true})
	if d := os1.Source("s_runtime", leaseID); d["holder"] != "" || d["released_by"] != a.ID() {
		t.Errorf("old lease %v", d)
	}
	deadline = time.Now().Add(5 * time.Second)
	for os2.Source("s_runtime", leaseID)["holder"] != a.ID() {
		if time.Now().After(deadline) {
			t.Fatal("no lease on the new OpenSearch")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Turning detections.scheduler off gives the lease up.
	a.Use(c2, "s", Settings{Eligible: false})
	deadline = time.Now().Add(5 * time.Second)
	for os2.Source("s_runtime", leaseID)["holder"] != "" {
		if time.Now().After(deadline) {
			t.Fatal("still holding with the scheduler off")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestReadyNeedsOpenSearch(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	fos.SetFault(func(m, p string) *ostest.Fault { return &ostest.Fault{Status: 503, Type: "unavailable"} })
	a := testNode(t, t.TempDir(), c, true)
	time.Sleep(200 * time.Millisecond)
	if ok, why := a.Ready(); ok || why != NotReadyOpenSearch {
		t.Errorf("ready %v %q", ok, why)
	}
	fos.SetFault(nil)
	waitReady(t, a, 5*time.Second)
	// A full disk still answers: the server stays ready.
	fos.Block(true)
	time.Sleep(3 * fast.Heartbeat)
	if ok, why := a.Ready(); !ok {
		t.Errorf("not ready with a full disk: %s", why)
	}
	if st := a.Status(); !st.WritesRefused {
		t.Errorf("status %+v", st)
	}
}

// Every server's list shows a server whose files differ from the job
// holder's, and says how to fix it: the holder's own list too, not only
// the list of the server that would not take over.
func TestEveryServerShowsWhoCannotTakeOver(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	start := func(retention string) *Node {
		l, err := OpenLocal(t.TempDir(), testOptions("host-"+retention))
		if err != nil {
			t.Fatal(err)
		}
		n := New(Options{Local: l, Version: "1.0.0", Timing: fast})
		ctx, cancel := context.WithCancel(context.Background())
		n.Start(ctx)
		n.Use(c, "s", Settings{Eligible: true, Fingerprints: func() Fingerprints {
			return Fingerprints{Retention: retention, Feeds: "f", Detections: "d"}
		}})
		t.Cleanup(func() {
			cancel()
			n.Close()
		})
		return n
	}
	a := start("r1")
	deadline := time.Now().Add(5 * time.Second)
	for !a.RunsJobs() {
		if time.Now().After(deadline) {
			t.Fatal("no lease")
		}
		time.Sleep(10 * time.Millisecond)
	}
	b := start("r2")
	waitReady(t, b, 5*time.Second)
	check := func(n *Node) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			st := n.Status()
			var row ServerStatus
			for _, s := range st.Servers {
				if s.NodeID == b.ID() {
					row = s
				}
			}
			text := ""
			for _, w := range st.Warnings {
				text += w.Level + ": " + w.Text + "\n"
			}
			if row.Jobs == "standby" && row.CannotTakeOver == "its retention policies differ from "+a.Name()+"'s" &&
				strings.Contains(text, "amber: "+b.Name()+" would not take the background jobs over if "+a.Name()+" stopped.") &&
				strings.Contains(text, "Make "+b.Name()+"'s retention policies (retention.yaml in the lookups folder, and retention in signalith.yaml) the same as "+a.Name()+"'s, then restart "+b.Name()+".") {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: row %+v warnings:\n%s", n.Name(), row, text)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	check(a)
	check(b)
	// The holder crashes: b does not take over, and says why in red.
	crash(a)
	deadline = time.Now().Add(10 * time.Second)
	for {
		st := b.Status()
		if len(st.Warnings) > 0 && st.Warnings[0].Level == "red" && strings.HasPrefix(st.Warnings[0].Text, "No server is running detections") &&
			strings.Contains(st.Warnings[0].Text, "because its retention policies differ") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("warnings %+v", st.Warnings)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if b.RunsJobs() {
		t.Error("b took the jobs over with different retention policies")
	}
}

func TestFixFiles(t *testing.T) {
	for _, tc := range []struct {
		parts []string
		want  string
	}{
		{[]string{"detections folder"}, "Make siem-b's detections folder the same as siem-a's, then restart siem-b."},
		{[]string{"threat intel feeds", "detections folder"}, "Make siem-b's threat intel feeds (intel_feeds.yaml in the lookups folder, and intel in signalith.yaml) and detections folder the same as siem-a's, then restart siem-b."},
		{[]string{"archives"}, "Keep archives in one shared folder: set retention.archive_dir to the same folder on every server, then restart them."},
		{nil, "Make the files the jobs use the same on siem-b as on siem-a, then restart siem-b."},
	} {
		if got := fixFiles(tc.parts, "siem-b", "siem-a"); got != tc.want {
			t.Errorf("%v:\n got %s\nwant %s", tc.parts, got, tc.want)
		}
	}
}
