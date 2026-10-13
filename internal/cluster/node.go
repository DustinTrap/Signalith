package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Options are what a Node needs.
type Options struct {
	Local   *Local
	Version string
	// Deployment says how the server runs: systemd, docker,
	// windows-service, or "".
	Deployment string
	Clock      Clock
	Timing     Timing
	Log        *slog.Logger
}

// Settings are this server's settings the cluster uses; each start of the
// server's components (an in-process restart too) passes them again.
type Settings struct {
	// Eligible is detections.scheduler: this server may run the
	// background jobs.
	Eligible bool
	NodeURL  string
	Listen   string
	Syslog   Syslog
	// Fingerprints works out the files fingerprints; nil has none.
	Fingerprints func() Fingerprints
}

// Node is this server in the cluster. It lives as long as the process:
// an in-process restart keeps it, with its identity, its lock, its
// heartbeat and its lease, and only points it at the new OpenSearch
// client.
type Node struct {
	local  *Local
	opts   Options
	clock  Clock
	timing Timing
	log    *slog.Logger
	lease  *Lease

	// hbMu lets one heartbeat write happen at a time.
	hbMu sync.Mutex

	mu       sync.Mutex
	client   *store.Client
	prefix   string
	endpoint string
	settings Settings
	// firstTarget is true until the identity check passed on the first
	// OpenSearch this process used: a conflict there stops the process.
	firstTarget bool
	hb          heartbeatState
	members     map[string]*member
	offset      *time.Duration
	offsetNext  time.Duration
	fp          Fingerprints
	fpNext      time.Duration
	fpSet       bool
	leaseNext   time.Duration
	started     time.Time
	stopping    bool
	conflict    string
	// writesRefused is true while OpenSearch refuses writes (a full disk).
	writesRefused bool
	// lastContact is when OpenSearch last answered a heartbeat or a read,
	// on the monotonic clock; contacted is false until it first did.
	lastContact time.Duration
	contacted   bool
	osLatency   time.Duration
	lastErr     string
	releasing   bool
	// paused says why this server's components are not running, so it
	// must not hold the jobs; Use clears it.
	paused string

	wake     chan struct{}
	fatal    chan error
	cancel   context.CancelFunc
	loopDone chan struct{}
	stopOnce sync.Once
}

// heartbeatState is this server's heartbeat on the current OpenSearch.
type heartbeatState struct {
	// checked is true once the identity check passed and the first
	// heartbeat was written.
	checked bool
	ver     store.Version
	next    time.Duration
}

// member is another server's heartbeat as this one last saw it.
type member struct {
	hb  Heartbeat
	ver store.Version
	// since is when this version was first seen, on the monotonic clock.
	since time.Duration
}

// New returns the node for an open state folder. Start starts it.
func New(o Options) *Node {
	if o.Clock == nil {
		o.Clock = NewRealClock()
	}
	if o.Timing == (Timing{}) {
		o.Timing = DefaultTiming
	}
	if o.Log == nil {
		o.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	n := &Node{local: o.Local, opts: o, clock: o.Clock, timing: o.Timing, log: o.Log, firstTarget: true,
		members: map[string]*member{}, wake: make(chan struct{}, 1), fatal: make(chan error, 1), started: o.Clock.Now().UTC()}
	n.lease = &Lease{
		Self: Self{NodeID: o.Local.Identity.NodeID, Name: o.Local.Identity.Name, Version: o.Version,
			BootID: o.Local.BootID, LastBoot: o.Local.LastBoot},
		Clock: o.Clock, Timing: o.Timing, Log: o.Log,
		Target:       n.leaseTarget,
		Eligible:     n.eligible,
		Fingerprints: n.fingerprints,
		OnChange:     n.poke,
	}
	return n
}

// ID and Name are this server's.
func (n *Node) ID() string   { return n.local.Identity.NodeID }
func (n *Node) Name() string { return n.local.Identity.Name }

// Lease returns the job lease, for the fence check before destructive
// steps.
func (n *Node) Lease() *Lease { return n.lease }

// Fatal receives an error when this server must not run at all: another
// running process uses its identity.
func (n *Node) Fatal() <-chan error { return n.fatal }

func (n *Node) leaseTarget() (*store.Client, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.client == nil || !n.hb.checked {
		return nil, ""
	}
	return n.client, RuntimeIndex(n.prefix)
}

// poke wakes the loop, to write the heartbeat soon after a change.
func (n *Node) poke() {
	n.mu.Lock()
	n.hb.next = 0
	n.mu.Unlock()
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

// Start starts the heartbeat and lease loop; it ends when ctx does or at
// Stop. The jobs run under ctx.
func (n *Node) Start(ctx context.Context) {
	n.mu.Lock()
	if n.loopDone != nil {
		n.mu.Unlock()
		return
	}
	ctx, n.cancel = context.WithCancel(ctx)
	n.loopDone = make(chan struct{})
	n.mu.Unlock()
	n.lease.SetBase(ctx)
	go n.loop(ctx)
}

// Use points the node at an OpenSearch client and index prefix, with this
// server's settings, at each start of its components. When the OpenSearch
// or the prefix changed, the lease held on the old one is given up first,
// and the identity is checked again on the new one.
func (n *Node) Use(c *store.Client, prefix string, s Settings) {
	n.mu.Lock()
	same := n.client != nil && n.prefix == prefix && n.endpoint == c.Endpoint()
	had := n.client != nil
	n.settings, n.paused = s, ""
	if same {
		n.client = c
		n.fpNext = 0
		n.mu.Unlock()
		if !s.Eligible {
			n.releaseAsync("detections.scheduler was turned off on this server")
		}
		n.poke()
		return
	}
	n.mu.Unlock()
	if had {
		n.lease.Release("this server moved to another OpenSearch or index prefix")
	}
	n.hbMu.Lock()
	n.mu.Lock()
	n.client, n.prefix, n.endpoint = c, prefix, c.Endpoint()
	n.hb, n.members, n.fpNext, n.offsetNext, n.leaseNext = heartbeatState{}, map[string]*member{}, 0, 0, 0
	n.contacted, n.writesRefused, n.offset = false, false, nil
	if n.conflict != "" && !n.firstTarget {
		// A conflict on the old OpenSearch says nothing about the new one.
		n.conflict = ""
	}
	n.mu.Unlock()
	n.hbMu.Unlock()
	n.lease.Reset()
	n.poke()
}

// Pause gives the background jobs up, and keeps this server from taking
// them again until the next Use: its components could not start.
func (n *Node) Pause(why string) {
	n.mu.Lock()
	n.paused = why
	n.mu.Unlock()
	n.releaseAsync(why)
	n.poke()
}

// releaseAsync gives the lease up in the background, once.
func (n *Node) releaseAsync(reason string) {
	n.mu.Lock()
	if n.releasing || !n.lease.Holding() {
		n.mu.Unlock()
		return
	}
	n.releasing = true
	n.mu.Unlock()
	go func() {
		n.lease.Release(reason)
		n.mu.Lock()
		n.releasing = false
		n.mu.Unlock()
	}()
}

// SetJobs replaces the background jobs this server runs while it holds
// the lease. It waits for the old ones to end. Housekeeping is added.
func (n *Node) SetJobs(jobs []Job) {
	if jobs != nil {
		jobs = append(jobs, Job{Name: "housekeeping", Run: n.housekeeping})
	}
	n.lease.SetJobs(jobs)
}

// Stop gives the lease up gracefully (waiting for the jobs, at most a
// minute), writes a last heartbeat saying this server stopped, and stops
// the loop.
func (n *Node) Stop() {
	n.stopOnce.Do(func() {
		n.mu.Lock()
		n.stopping = true
		n.mu.Unlock()
		n.lease.Release("the server is stopping")
		n.mu.Lock()
		cancel, done := n.cancel, n.loopDone
		n.mu.Unlock()
		if cancel != nil {
			cancel()
			<-done
		}
		n.mu.Lock()
		ok := n.hb.checked && n.conflict == ""
		n.mu.Unlock()
		if ok {
			ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
			n.writeHeartbeat(ctx, StateStopped)
			cancel()
		}
	})
}

// Close releases the state folder's lock. Call it last, after Stop.
func (n *Node) Close() { n.local.Close() }

func (n *Node) loop(ctx context.Context) {
	defer close(n.loopDone)
	for {
		wait := n.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-n.clock.After(wait):
		case <-n.wake:
		}
	}
}

// tick does what is due and returns when the next thing is.
func (n *Node) tick(ctx context.Context) time.Duration {
	n.mu.Lock()
	c, prefix, hb, conflict := n.client, n.prefix, n.hb, n.conflict
	n.mu.Unlock()
	if c == nil {
		return time.Hour
	}
	now := n.clock.Mono()
	if conflict != "" {
		return n.timing.Heartbeat
	}
	if !hb.checked {
		if now < hb.next {
			return hb.next - now
		}
		if err := n.firstHeartbeat(ctx, c, prefix); err != nil {
			var ic *identityConflictError
			if errors.As(err, &ic) {
				return n.timing.Heartbeat
			}
			if ctx.Err() == nil {
				n.mu.Lock()
				n.lastErr = err.Error()
				n.hb.next = n.clock.Mono() + n.timing.Retry
				n.mu.Unlock()
				n.log.Warn("could not write this server's heartbeat to OpenSearch; trying again", "err", err)
			}
			return n.timing.Retry
		}
	}
	n.mu.Lock()
	due := now >= n.hb.next
	offsetDue := now >= n.offsetNext
	fpDue := now >= n.fpNext
	n.mu.Unlock()
	if fpDue {
		n.fingerprints(true)
	}
	if offsetDue {
		n.measureOffset(ctx, c)
	}
	if due {
		state := StateReady
		n.mu.Lock()
		if n.stopping {
			state = StateStopping
		}
		n.mu.Unlock()
		n.writeHeartbeat(ctx, state)
		n.observe(ctx, c, prefix)
	}
	// Give the lease up when this server may no longer hold it.
	if ok, why := n.eligible(); !ok && n.lease.Holding() {
		n.mu.Lock()
		stopping, conflicted := n.stopping, n.conflict != ""
		n.mu.Unlock()
		if !stopping && !conflicted {
			n.releaseAsync(why)
		}
	}
	n.mu.Lock()
	leaseDue := n.clock.Mono() >= n.leaseNext
	n.mu.Unlock()
	if leaseDue {
		wait := n.lease.Step(ctx)
		n.mu.Lock()
		n.leaseNext = n.clock.Mono() + wait
		n.mu.Unlock()
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now = n.clock.Mono()
	next := min(n.hb.next, n.offsetNext, n.fpNext, n.leaseNext) - now
	return max(next, 10*time.Millisecond)
}

// identityConflictError is another live process using this server's
// identity.
type identityConflictError struct{ msg string }

func (e *identityConflictError) Error() string { return e.msg }

// firstHeartbeat checks, on an OpenSearch this process has not written
// to yet, that no other live process uses this server's identity, then
// writes the first heartbeat.
func (n *Node) firstHeartbeat(ctx context.Context, c *store.Client, prefix string) error {
	n.hbMu.Lock()
	defer n.hbMu.Unlock()
	if err := ensureRuntime(ctx, c, prefix); err != nil {
		return err
	}
	index := RuntimeIndex(prefix)
	id := nodeDocID(n.ID())
	for range 3 {
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		src, ver, found, err := c.Get(rctx, index, id)
		cancel()
		if err != nil {
			return err
		}
		if found {
			var other Heartbeat
			_ = json.Unmarshal(src, &other)
			if other.BootID != "" && other.BootID != n.local.BootID && other.BootID != n.local.LastBoot {
				// Written by a process that was not this folder's last: a
				// copy of the folder, alive or not. Watch it.
				live, err := n.watchIdentity(ctx, c, index, id, ver)
				if err != nil {
					return err
				}
				if live != nil {
					return n.identityConflict(live)
				}
				n.log.Warn("found a heartbeat of this server's identity from another process; it no longer changes, so it was a stale copy",
					"other_boot", other.BootID, "other_name", other.Name)
			}
		}
		if err := n.local.WriteLastBoot(); err != nil {
			n.log.Warn("could not record this process in the state folder", "err", err)
		}
		doc := n.heartbeatDoc(StateStarting)
		rctx, cancel = context.WithTimeout(ctx, requestTimeout)
		sent := n.clock.Mono()
		var nv store.Version
		if found {
			nv, err = c.PutIf(rctx, index, id, doc, ver, false)
		} else {
			nv, err = c.Create(rctx, index, id, doc, false)
		}
		cancel()
		if store.IsConflict(err) {
			// It changed between the read and the write: look again.
			continue
		}
		if store.IsClusterBlock(err) {
			// OpenSearch's disk is full: nobody can write, so nobody else
			// can be using this identity's heartbeat either.
			n.mu.Lock()
			n.writesRefused, n.contacted, n.lastContact = true, true, n.clock.Mono()
			n.hb = heartbeatState{checked: true, ver: ver, next: n.clock.Mono() + n.timing.Heartbeat}
			n.firstTarget = false
			n.mu.Unlock()
			return nil
		}
		if err != nil {
			return err
		}
		n.mu.Lock()
		// The next heartbeat, at once, says it is ready, and the other
		// servers are read with it.
		n.hb = heartbeatState{checked: true, ver: nv, next: n.clock.Mono()}
		n.contacted, n.lastContact, n.osLatency, n.lastErr, n.writesRefused = true, n.clock.Mono(), n.clock.Mono()-sent, "", false
		n.firstTarget = false
		n.mu.Unlock()
		n.log.Info("this server joined the servers that share its OpenSearch", "node_id", n.ID(), "index", index)
		return nil
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	src, _, _, _ := c.Get(rctx, index, id)
	var other Heartbeat
	_ = json.Unmarshal(src, &other)
	return n.identityConflict(&other)
}

// watchIdentity watches a heartbeat of this identity for IdentityWatch
// and returns it when it changed: another live process writes it.
func (n *Node) watchIdentity(ctx context.Context, c *store.Client, index, id string, ver store.Version) (*Heartbeat, error) {
	end := n.clock.Mono() + n.timing.IdentityWatch
	for {
		left := end - n.clock.Mono()
		if left <= 0 {
			return nil, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-n.clock.After(min(n.timing.Watch, left)):
		}
		rctx, cancel := context.WithTimeout(ctx, requestTimeout)
		src, now, found, err := c.Get(rctx, index, id)
		cancel()
		if err != nil {
			return nil, err
		}
		if found && !now.Same(ver) {
			var hb Heartbeat
			_ = json.Unmarshal(src, &hb)
			if hb.BootID != n.local.BootID {
				return &hb, nil
			}
		}
	}
}

// identityConflict handles another live process with this identity. On
// the first OpenSearch this process uses, it must not start at all;
// later, it stops its jobs and says why until someone fixes it.
func (n *Node) identityConflict(other *Heartbeat) error {
	where := other.Name
	if other.NodeURL != "" {
		where += ", " + other.NodeURL
	}
	msg := fmt.Sprintf("Another server (%s) is using this server's identity: its state folder was copied (a cloned computer?) or is shared. "+
		"To give this server a new identity, stop it, delete %s and start it again.", where, filepath.Join(n.local.Dir, nodeFile))
	n.mu.Lock()
	first := n.firstTarget
	n.conflict = msg
	n.mu.Unlock()
	n.log.Error(msg)
	err := &identityConflictError{msg: msg}
	if first {
		select {
		case n.fatal <- err:
		default:
		}
	}
	n.lease.Abandon("another process uses this server's identity")
	return err
}

// heartbeatDoc is this server's heartbeat as it is now.
func (n *Node) heartbeatDoc(state string) Heartbeat {
	eligible, why := n.eligible()
	view := n.lease.View()
	n.mu.Lock()
	defer n.mu.Unlock()
	hb := Heartbeat{Kind: "node", NodeID: n.ID(), Name: n.Name(), BootID: n.local.BootID, State: state,
		Version: n.opts.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, Deployment: n.opts.Deployment,
		StartedAt: n.started, HeartbeatAt: n.clock.Now().UTC(), NodeURL: n.settings.NodeURL, Listen: n.settings.Listen,
		Syslog: n.settings.Syslog, LeaderEligible: eligible, NotEligible: why, Leader: view.Mine && view.Valid,
		Frozen: view.State == frozen.String(), FilesFingerprint: n.fp, MachineMoved: n.local.Moved, Problems: []string{},
		OpenSearch: OSInfo{OK: n.contacted && n.lastErr == "", Endpoint: n.endpoint, LatencyMS: n.osLatency.Milliseconds()}}
	if view.Mine {
		hb.LeaseEpoch = view.Doc.Epoch
	}
	if n.offset != nil {
		ms := n.offset.Milliseconds()
		hb.ClockOffsetMS = &ms
	}
	hb.Problems = append(hb.Problems, n.local.Warnings...)
	return hb
}

// writeHeartbeat writes the heartbeat on the version written last.
func (n *Node) writeHeartbeat(ctx context.Context, state string) {
	n.hbMu.Lock()
	defer n.hbMu.Unlock()
	n.mu.Lock()
	c, prefix, ver, checked := n.client, n.prefix, n.hb.ver, n.hb.checked
	n.hb.next = n.clock.Mono() + n.timing.Heartbeat
	n.mu.Unlock()
	if c == nil || !checked {
		return
	}
	index, id := RuntimeIndex(prefix), nodeDocID(n.ID())
	doc := n.heartbeatDoc(state)
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	sent := n.clock.Mono()
	var nv store.Version
	var err error
	if ver.IsZero() {
		nv, err = c.Create(rctx, index, id, doc, false)
	} else {
		nv, err = c.PutIf(rctx, index, id, doc, ver, false)
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrExists) {
		nv, err = n.heartbeatConflict(rctx, c, index, id, doc)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case err == nil:
		n.hb.ver, n.contacted, n.lastContact, n.osLatency, n.lastErr, n.writesRefused = nv, true, n.clock.Mono(), n.clock.Mono()-sent, "", false
	case store.IsClusterBlock(err):
		// OpenSearch answers, but its disk is full.
		n.contacted, n.lastContact, n.writesRefused, n.lastErr = true, n.clock.Mono(), true, ""
	case errors.Is(err, errConflicted):
	default:
		n.lastErr = err.Error()
		n.log.Warn("could not write this server's heartbeat to OpenSearch", "err", err)
	}
}

var errConflicted = errors.New("another process uses this identity")

// heartbeatConflict handles a heartbeat that changed since this server
// wrote it: rewritten by this same process (an answer that got lost), gone
// (removed), or written by another process with this identity.
func (n *Node) heartbeatConflict(ctx context.Context, c *store.Client, index, id string, doc Heartbeat) (store.Version, error) {
	src, ver, found, err := c.Get(ctx, index, id)
	if err != nil {
		return store.Version{}, err
	}
	if !found {
		return c.Create(ctx, index, id, doc, false)
	}
	var other Heartbeat
	_ = json.Unmarshal(src, &other)
	if other.BootID == n.local.BootID {
		return c.PutIf(ctx, index, id, doc, ver, false)
	}
	_ = n.identityConflict(&other)
	return store.Version{}, errConflicted
}

// measureOffset measures how far this server's clock is off OpenSearch's:
// OpenSearch's time minus this server's at the middle of the request.
func (n *Node) measureOffset(ctx context.Context, c *store.Client) {
	n.mu.Lock()
	n.offsetNext = n.clock.Mono() + n.timing.ClockCheck
	n.mu.Unlock()
	var out struct {
		Nodes map[string]struct {
			OS struct {
				Timestamp int64 `json:"timestamp"`
			} `json:"os"`
		} `json:"nodes"`
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	t0 := n.clock.Now()
	err := c.Do(rctx, http.MethodGet, "/_nodes/_local/stats/os?filter_path=nodes.*.os.timestamp", nil, &out)
	t1 := n.clock.Now()
	if err != nil {
		n.log.Debug("could not read OpenSearch's clock", "err", err)
		return
	}
	for _, nd := range out.Nodes {
		if nd.OS.Timestamp == 0 {
			continue
		}
		mid := t0.Add(t1.Sub(t0) / 2)
		off := time.UnixMilli(nd.OS.Timestamp).Sub(mid)
		n.mu.Lock()
		n.offset = &off
		n.mu.Unlock()
		if off > 2*time.Second || off < -2*time.Second {
			n.log.Warn("this server's clock is off OpenSearch's; keep both in sync with NTP", "offset", off.Round(time.Millisecond))
		}
		return
	}
}

// fingerprints returns this server's files fingerprints, worked out again
// when fresh is true or they are older than FilesCheck.
func (n *Node) fingerprints(fresh bool) Fingerprints {
	n.mu.Lock()
	f := n.settings.Fingerprints
	now := n.clock.Mono()
	if !fresh && n.fpSet && now < n.fpNext {
		fp := n.fp
		n.mu.Unlock()
		return fp
	}
	n.fpNext = now + n.timing.FilesCheck
	n.mu.Unlock()
	var fp Fingerprints
	if f != nil {
		fp = f()
	}
	n.mu.Lock()
	n.fp, n.fpSet = fp, true
	n.mu.Unlock()
	return fp
}

// eligible says whether this server may hold the job lease now, and why
// not.
func (n *Node) eligible() (bool, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case n.stopping:
		return false, "it is stopping"
	case n.conflict != "":
		return false, "another process uses its identity"
	case n.paused != "":
		return false, n.paused
	case !n.settings.Eligible:
		return false, "detections.scheduler is off on this server"
	case !n.hb.checked:
		return false, "it has not reached OpenSearch yet"
	case n.offset != nil && (*n.offset > MaxClockOffset || *n.offset < -MaxClockOffset):
		return false, fmt.Sprintf("its clock is %s off OpenSearch's (at most %s is allowed)", n.offset.Abs().Round(time.Second), MaxClockOffset)
	}
	return true, ""
}

// observe reads every server's heartbeat.
func (n *Node) observe(ctx context.Context, c *store.Client, prefix string) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	docs, err := c.SearchDocs(rctx, RuntimeIndex(prefix), map[string]any{"term": map[string]any{"kind": "node"}})
	if err != nil {
		n.log.Debug("could not read the other servers' heartbeats", "err", err)
		return
	}
	now := n.clock.Mono()
	n.mu.Lock()
	defer n.mu.Unlock()
	n.contacted, n.lastContact = true, now
	seen := map[string]bool{}
	for _, d := range docs {
		var hb Heartbeat
		if json.Unmarshal(d.Source, &hb) != nil || hb.NodeID == "" {
			continue
		}
		seen[hb.NodeID] = true
		m := n.members[hb.NodeID]
		switch {
		case m == nil:
			// First sight: how old it is can only be told from its own
			// clock, corrected by both servers' offsets when known.
			age := n.clock.Now().Sub(hb.HeartbeatAt)
			if n.offset != nil && hb.ClockOffsetMS != nil {
				age += *n.offset - time.Duration(*hb.ClockOffsetMS)*time.Millisecond
			}
			age = min(max(age, 0), n.timing.Offline)
			n.members[hb.NodeID] = &member{hb: hb, ver: d.Version, since: now - age}
		case !m.ver.Same(d.Version):
			m.hb, m.ver, m.since = hb, d.Version, now
		}
		if n.writesRefused {
			// Nobody can write a heartbeat while OpenSearch refuses
			// writes: keep everyone as they were.
			n.members[hb.NodeID].since = now
		}
	}
	for id := range n.members {
		if !seen[id] {
			delete(n.members, id)
		}
	}
}

// housekeeping is a leader job: every 10 minutes it removes the
// heartbeats of servers gone for a week.
func (n *Node) housekeeping(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-n.clock.After(10 * time.Minute):
		}
		if !n.lease.Valid() {
			continue
		}
		n.mu.Lock()
		c, prefix := n.client, n.prefix
		n.mu.Unlock()
		if c == nil {
			continue
		}
		cutoff := n.clock.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
		index := RuntimeIndex(prefix)
		rctx, cancel := context.WithTimeout(ctx, time.Minute)
		docs, err := c.SearchVersions(rctx, index, map[string]any{"bool": map[string]any{"filter": []any{
			map[string]any{"term": map[string]any{"kind": "node"}},
			map[string]any{"range": map[string]any{"heartbeat_at": map[string]any{"lt": cutoff}}},
		}}})
		for _, d := range docs {
			if d.ID == nodeDocID(n.ID()) || !n.lease.Valid() {
				continue
			}
			if err := c.DeleteIf(rctx, index, d.ID, d.Version, false); err == nil {
				n.log.Info("removed the heartbeat of a server gone for a week", "doc", d.ID)
			}
		}
		cancel()
		if err != nil {
			n.log.Debug("housekeeping could not list old heartbeats", "err", err)
		}
	}
}

// RunsJobs reports whether this server runs the background jobs now.
func (n *Node) RunsJobs() bool { return n.lease.Valid() }

// Check is the fence before a step that changes data: it confirms that
// this server still runs the background jobs.
func (n *Node) Check(ctx context.Context) error { return n.lease.Check(ctx) }

// JobHolder returns the name of another server that runs the background
// jobs, as this server last saw the lease, or "" when none does: the
// lease names nobody, this server, or a server that went offline.
func (n *Node) JobHolder() string {
	v := n.lease.View()
	if !v.Found || v.Doc.Holder == "" || v.Doc.Holder == n.ID() {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if m := n.members[v.Doc.Holder]; m != nil && n.goneLocked(m) {
		return ""
	}
	return v.Doc.HolderName
}

// holderName names the server the lease names, or the one that ran the
// jobs last.
func holderName(d LeaseDoc) string {
	if d.HolderName != "" {
		return d.HolderName
	}
	return "the server that ran them last"
}

// goneLocked reports whether another server is offline or stopped. The
// caller holds n.mu.
func (n *Node) goneLocked(m *member) bool {
	return m.hb.State == StateStopped || (n.clock.Mono()-m.since >= n.timing.Offline && !n.writesRefused)
}

// Readiness reasons.
const (
	NotReadyStarting   = "starting"
	NotReadyOpenSearch = "opensearch"
	NotReadyIdentity   = "identity"
	NotReadyStopping   = "stopping"
)

// Ready reports whether this server should get traffic from a load
// balancer, and if not, why: one of the NotReady reasons.
func (n *Node) Ready() (bool, string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case n.stopping:
		return false, NotReadyStopping
	case n.conflict != "":
		return false, NotReadyIdentity
	case !n.hb.checked && n.lastErr != "":
		return false, NotReadyOpenSearch
	case !n.hb.checked:
		return false, NotReadyStarting
	case !n.contacted || n.clock.Mono()-n.lastContact > n.timing.Offline:
		return false, NotReadyOpenSearch
	}
	return true, ""
}

// Status is the cluster as this server sees it, for GET /api/cluster.
type Status struct {
	Self    string         `json:"self"`
	Servers []ServerStatus `json:"servers"`
	Jobs    JobsStatus     `json:"lease"`
	// WritesRefused is true while OpenSearch refuses writes, as when its
	// disk is full; heartbeats then stand still.
	WritesRefused bool      `json:"writes_refused"`
	Warnings      []Warning `json:"warnings"`
}

// ServerStatus is one server.
type ServerStatus struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Self   bool   `json:"self"`
	// State is starting, ready, stopping, stopped, conflict or offline.
	State string `json:"state"`
	// OfflineSince is when its heartbeat stopped, for an offline or
	// stopped server.
	OfflineSince *time.Time `json:"offline_since,omitempty"`
	Version      string     `json:"version"`
	// Jobs is "runs" for the server that runs the background jobs,
	// "standby" for one that may take them over, "not_eligible" for one
	// that may not.
	Jobs        string     `json:"jobs"`
	StartedAt   time.Time  `json:"started_at"`
	HeartbeatAt time.Time  `json:"heartbeat_at"`
	Detail      *Heartbeat `json:"-"`
	// CannotTakeOver says why this server would not take the jobs over,
	// for this server only.
	CannotTakeOver string `json:"-"`
}

// JobsStatus is the job lease.
type JobsStatus struct {
	Holder     string     `json:"holder,omitempty"`
	HolderName string     `json:"holder_name,omitempty"`
	Epoch      int64      `json:"epoch,omitempty"`
	AcquiredAt *time.Time `json:"acquired_at,omitempty"`
	RenewedAt  *time.Time `json:"renewed_at,omitempty"`
	// Frozen is true while the holder runs only the disk guard, because
	// OpenSearch refuses writes.
	Frozen bool `json:"frozen"`
	// Mine is true when this server holds it.
	Mine bool `json:"mine"`
	// Released names the server that gave the jobs up last, while nobody
	// has taken them.
	ReleasedBy string `json:"released_by,omitempty"`
}

// Warning is something about the servers an admin should know, red for a
// problem and amber for attention.
type Warning struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

// Status returns the cluster as this server last saw it.
func (n *Node) Status() Status {
	view := n.lease.View()
	eligible, notWhy := n.eligible()
	self := n.heartbeatDoc(StateReady)
	ready, reason := n.Ready()
	n.mu.Lock()
	defer n.mu.Unlock()
	st := Status{Self: n.ID(), WritesRefused: n.writesRefused, Warnings: []Warning{}}
	// This server, as it is now rather than as last written.
	self.State = StateReady
	if !ready {
		self.State = map[string]string{NotReadyStopping: StateStopping, NotReadyIdentity: StateConflict}[reason]
		if self.State == "" {
			self.State = StateStarting
		}
	}
	mine := ServerStatus{NodeID: self.NodeID, Name: self.Name, Self: true, State: self.State, Version: self.Version,
		StartedAt: self.StartedAt, HeartbeatAt: self.HeartbeatAt, Detail: &self, CannotTakeOver: view.CannotTake}
	servers := []ServerStatus{mine}
	holderID := ""
	if view.Found {
		holderID = view.Doc.Holder
	}
	for id, m := range n.members {
		if id == n.ID() {
			continue
		}
		hb := m.hb
		s := ServerStatus{NodeID: id, Name: hb.Name, State: hb.State, Version: hb.Version, StartedAt: hb.StartedAt,
			HeartbeatAt: hb.HeartbeatAt, Detail: &hb}
		if hb.State != StateStopped && n.goneLocked(m) {
			s.State = StateOffline
		}
		if s.State == StateOffline || s.State == StateStopped {
			t := hb.HeartbeatAt
			s.OfflineSince = &t
		}
		servers = append(servers, s)
	}
	for i := range servers {
		s := &servers[i]
		switch {
		case s.NodeID == holderID && (s.Self && view.Valid || !s.Self && s.State != StateOffline && s.State != StateStopped):
			s.Jobs = "runs"
		case s.Self && eligible, !s.Self && s.Detail.LeaderEligible && s.State != StateOffline && s.State != StateStopped:
			s.Jobs = "standby"
		default:
			s.Jobs = "not_eligible"
		}
		if s.Self && !eligible {
			s.Detail.NotEligible = notWhy
		}
	}
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Name != servers[j].Name {
			return servers[i].Name < servers[j].Name
		}
		return servers[i].NodeID < servers[j].NodeID
	})
	st.Servers = servers
	if view.Found {
		d := view.Doc
		st.Jobs = JobsStatus{Holder: d.Holder, HolderName: d.HolderName, Epoch: d.Epoch, Mine: view.Mine && view.Valid,
			Frozen: d.Holder != "" && (view.State == frozen.String() || n.writesRefused)}
		if d.Holder == "" {
			st.Jobs.ReleasedBy = d.ReleasedBy
			st.Jobs.Epoch = 0
		} else {
			acq, ren := d.AcquiredAt, d.RenewedAt
			st.Jobs.AcquiredAt, st.Jobs.RenewedAt = &acq, &ren
		}
	}
	st.Warnings = n.warningsLocked(st, view)
	return st
}

// warningsLocked lists what an admin should know. The caller holds n.mu.
func (n *Node) warningsLocked(st Status, view LeaseView) []Warning {
	w := []Warning{}
	if n.conflict != "" {
		w = append(w, Warning{"red", n.conflict})
	}
	if n.writesRefused {
		w = append(w, Warning{"red", "OpenSearch refuses writes, as it does when its disk is full: new events are refused, and only the retention disk guard runs to free space."})
	}
	runs := false
	for _, s := range st.Servers {
		if s.Jobs == "runs" {
			runs = true
		}
	}
	// This server cannot take the jobs over from the server that ran them
	// last, because its files differ.
	blocked := view.CannotTake != "" && !view.Mine && view.Found && view.Doc.Fingerprint != "" && n.settings.Eligible && n.paused == "" && n.conflict == ""
	if !runs && n.hb.checked && view.Seen {
		standby := false
		for _, s := range st.Servers {
			if s.Jobs == "standby" && !(s.Self && blocked) {
				standby = true
			}
		}
		switch {
		case standby:
			w = append(w, Warning{"amber", "No server runs detections, threat intel downloads or retention right now; a server that may run them takes over within a minute."})
		case blocked:
			w = append(w, Warning{"red", fmt.Sprintf("No server is running detections, threat intel or retention: %s, the only one that may, does not take them over from %s by itself, because %s. Copy those files across, so either server can run them.",
				n.Name(), holderName(view.Doc), view.CannotTake)})
			blocked = false
		default:
			w = append(w, Warning{"red", "No server is running detections, threat intel or retention: none that shares this OpenSearch has detections.scheduler on, or none of them is up."})
		}
	}
	if blocked {
		w = append(w, Warning{"amber", fmt.Sprintf("%s would not take the background jobs over from %s by itself if %s stopped, because %s. Copy those files across, so either server can run them.",
			n.Name(), holderName(view.Doc), holderName(view.Doc), view.CannotTake)})
	}
	for _, msg := range n.local.Warnings {
		w = append(w, Warning{"amber", msg})
	}
	for _, s := range st.Servers {
		if s.Detail != nil && s.Detail.ClockOffsetMS != nil && s.State != StateOffline && s.State != StateStopped {
			off := time.Duration(*s.Detail.ClockOffsetMS) * time.Millisecond
			if off.Abs() > 2*time.Second {
				w = append(w, Warning{"amber", fmt.Sprintf("%s's clock is %s off OpenSearch's. Keep every server's clock in sync (NTP or Windows Time): detections are scheduled by the clock.", s.Name, off.Abs().Round(100*time.Millisecond))})
			}
		}
	}
	return w
}
