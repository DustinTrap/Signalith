package cluster

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// The job lease, lease:jobs in the runtime index, names the one server
// that runs the background jobs: detections, threat intel downloads,
// retention and housekeeping.
//
//   - The holder renews it every 10 seconds with a write that names the
//     version it wrote last, so a renewal fails once anyone else changed it.
//     A failed renewal is retried every 2 seconds; only a version conflict
//     means the lease is lost, which stops the jobs at once.
//   - The holder stops its jobs by itself 20 seconds after it sent its last
//     good renewal (self-fencing).
//   - Another server takes the lease only after it has seen the document
//     unchanged for 30 seconds on its own monotonic clock, so there is a gap
//     of at least 10 seconds in which nobody runs the jobs, and a wrong wall
//     clock cannot hand them over.
//   - A server whose files the jobs use (retention policies, feeds,
//     detections, archives) differ from the holder's does not take over by
//     itself (the fingerprint guard).
//   - When OpenSearch refuses writes because its disk is full, nobody can
//     renew or take the lease. The holder keeps it, frozen, as long as a
//     read shows it unchanged, and runs only the jobs that free space
//     (delete-only emergency mode).

// Job is a background job that runs only on the server holding the lease.
type Job struct {
	Name string
	// Emergency jobs keep running while OpenSearch refuses writes, when
	// the others are paused: the retention disk guard frees space.
	Emergency bool
	// Run runs the job until ctx ends, and returns only once its work in
	// progress has stopped.
	Run func(ctx context.Context)
}

// ErrNotHolder is returned by Check when this server does not hold the
// job lease.
var ErrNotHolder = errors.New("this server no longer runs the background jobs")

type leaseState int

const (
	standby leaseState = iota
	holding
	// frozen holds the lease while OpenSearch refuses writes.
	frozen
	// releasing still holds and renews the lease while its jobs finish.
	releasing
)

func (s leaseState) String() string {
	return [...]string{"standby", "holding", "frozen", "releasing"}[s]
}

// Self is who this server is, as the lease records it.
type Self struct {
	NodeID, Name, Version string
	// BootID is this process; LastBoot the previous one that used the same
	// state folder, whose lease this one takes back after the fence time
	// rather than the whole takeover time.
	BootID, LastBoot string
}

// requestTimeout bounds one request about the lease.
const requestTimeout = 5 * time.Second

// Lease takes, renews and gives up lease:jobs, and runs the jobs while it
// holds it. Step does one round of that and says when the next is due.
type Lease struct {
	Self   Self
	Clock  Clock
	Timing Timing
	Log    *slog.Logger
	// Target returns the client and the runtime index to use; a nil
	// client waits.
	Target func() (*store.Client, string)
	// Eligible says whether this server may hold the lease, and why not.
	Eligible func() (bool, string)
	// Fingerprints returns this server's files fingerprints; fresh asks
	// for them worked out again now.
	Fingerprints func(fresh bool) Fingerprints
	// OnChange is called when this server gains or loses the jobs.
	OnChange func()

	// stepMu lets one write to the lease happen at a time.
	stepMu sync.Mutex

	mu    sync.Mutex
	state leaseState
	// ver and doc are what this server wrote last while it holds the
	// lease.
	ver store.Version
	doc LeaseDoc
	// lastGood is when the last good renewal was sent, on the monotonic
	// clock, and lastGoodWall on the wall clock (to notice a computer that
	// was suspended, whose monotonic clock stood still).
	lastGood     time.Duration
	lastGoodWall time.Time
	// confirmed is when a read last showed a frozen lease unchanged.
	confirmed     time.Duration
	confirmedWall time.Time
	obs           observation
	// cannot says why this server does not take the lease over.
	cannot  string
	lastErr string
	base    context.Context
	jobs    []Job
	run     *runSet
	// draining are job sets cancelled whose work has not ended yet; new
	// jobs start only once they have.
	draining []*runSet
}

// observation is the lease as a server that does not hold it last saw it.
type observation struct {
	seen  bool
	found bool
	ver   store.Version
	doc   LeaseDoc
	// since is when this version was first seen, on the monotonic clock.
	since time.Duration
}

func (l *Lease) fingerprints(fresh bool) Fingerprints {
	if l.Fingerprints == nil {
		return Fingerprints{}
	}
	return l.Fingerprints(fresh)
}

func (l *Lease) log() *slog.Logger {
	if l.Log == nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return l.Log
}

// SetBase sets the context the jobs run under; when it ends, they stop.
func (l *Lease) SetBase(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.base = ctx
}

// Step does one round: renews the lease while holding it, else reads it
// and takes it when allowed. It returns when the next round is due.
func (l *Lease) Step(ctx context.Context) time.Duration {
	l.stepMu.Lock()
	defer l.stepMu.Unlock()
	c, index := l.Target()
	if c == nil {
		return l.Timing.Watch
	}
	l.mu.Lock()
	st := l.state
	l.mu.Unlock()
	switch st {
	case holding, releasing:
		return l.renew(ctx, c, index)
	case frozen:
		return l.renewFrozen(ctx, c, index)
	}
	return l.watch(ctx, c, index)
}

// validLocked reports whether the holder may still do work: its last
// good renewal (or, while frozen, its last confirming read) was sent less
// than Fence ago, and the computer was not suspended since. The caller
// holds l.mu.
func (l *Lease) validLocked() bool {
	var mono time.Duration
	var wall time.Time
	switch l.state {
	case holding, releasing:
		mono, wall = l.lastGood, l.lastGoodWall
	case frozen:
		mono, wall = l.confirmed, l.confirmedWall
	default:
		return false
	}
	elapsed := l.Clock.Mono() - mono
	if elapsed >= l.Timing.Fence {
		return false
	}
	// A computer that was suspended (or a VM that was paused) did not
	// move its monotonic clock meanwhile, but its wall clock did: other
	// servers may have taken over.
	wallElapsed := l.Clock.Now().Sub(wall)
	return wallElapsed < l.Timing.Fence || wallElapsed-elapsed < 5*time.Second
}

// Valid reports whether this server holds the lease and may do a unit of
// work now. Jobs check it before each one.
func (l *Lease) Valid() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.validLocked()
}

// Holding reports whether this server holds the lease, frozen or not.
func (l *Lease) Holding() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state != standby
}

// Frozen reports whether this server holds the lease in delete-only
// emergency mode.
func (l *Lease) Frozen() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state == frozen
}

// Epoch returns the epoch of the lease this server holds, or 0.
func (l *Lease) Epoch() int64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == standby {
		return 0
	}
	return l.doc.Epoch
}

// Check confirms, before a step that changes data, that this server still
// holds the lease: it is valid here, and a fresh read of lease:jobs still
// names this process and its epoch.
func (l *Lease) Check(ctx context.Context) error {
	l.mu.Lock()
	valid, epoch := l.validLocked(), l.doc.Epoch
	l.mu.Unlock()
	if !valid {
		return ErrNotHolder
	}
	c, index := l.Target()
	if c == nil {
		return ErrNotHolder
	}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	src, _, found, err := c.Get(rctx, index, leaseID)
	if err != nil {
		return fmt.Errorf("could not confirm that this server still runs the background jobs: %w", err)
	}
	var doc LeaseDoc
	if !found || json.Unmarshal(src, &doc) != nil || doc.Holder != l.Self.NodeID || doc.HolderBoot != l.Self.BootID || doc.Epoch != epoch {
		return ErrNotHolder
	}
	return nil
}

// renew renews a held lease.
func (l *Lease) renew(ctx context.Context, c *store.Client, index string) time.Duration {
	l.mu.Lock()
	if !l.validLocked() {
		l.loseLocked("its last renewal of the job lease is too old (OpenSearch did not answer in time)")
		l.mu.Unlock()
		return l.Timing.Watch
	}
	doc, ver := l.doc, l.ver
	left := l.lastGood + l.Timing.Fence - l.Clock.Mono()
	l.mu.Unlock()
	doc.RenewedAt = l.Clock.Now().UTC()
	doc.Fingerprints = l.fingerprints(false)
	doc.Fingerprint = doc.Fingerprints.Combined()
	rctx, cancel := context.WithTimeout(ctx, min(requestTimeout, left))
	sent, sentWall := l.Clock.Mono(), l.Clock.Now()
	nv, err := c.PutIf(rctx, index, leaseID, doc, ver, false)
	cancel()
	if store.IsClusterBlock(err) {
		return l.blocked(ctx, c, index, err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != holding && l.state != releasing {
		return l.Timing.Watch
	}
	switch {
	case err == nil:
		l.ver, l.doc, l.lastGood, l.lastGoodWall, l.lastErr = nv, doc, sent, sentWall, ""
		return l.Timing.Renew
	case errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound):
		l.loseLocked("another server changed the job lease")
		return l.Timing.Watch
	}
	l.lastErr = err.Error()
	l.log().Warn("could not renew the job lease; trying again", "err", err)
	return l.retryLocked()
}

// retryLocked is when to try a failed renewal again: Retry with jitter,
// and never after the moment the lease runs out here.
func (l *Lease) retryLocked() time.Duration {
	wait := l.Timing.Retry + time.Duration(rand.Int64N(int64(l.Timing.Retry/4)+1))
	var until time.Duration
	if l.state == frozen {
		until = l.confirmed + l.Timing.Fence - l.Clock.Mono()
	} else {
		until = l.lastGood + l.Timing.Fence - l.Clock.Mono()
	}
	return max(min(wait, until), time.Millisecond)
}

// blocked handles a renewal OpenSearch refused with a cluster block: its
// disk is full, so nobody can write the lease. While a read shows it
// unchanged and still naming this server, this server keeps it, frozen.
func (l *Lease) blocked(ctx context.Context, c *store.Client, index string, werr error) time.Duration {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	sent, sentWall := l.Clock.Mono(), l.Clock.Now()
	src, ver, found, err := c.Get(rctx, index, leaseID)
	cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == standby {
		return l.Timing.Watch
	}
	var doc LeaseDoc
	switch {
	case err != nil:
		l.lastErr = err.Error()
		return l.retryLocked()
	case !found || json.Unmarshal(src, &doc) != nil || !ver.Same(l.ver) || doc.Holder != l.Self.NodeID:
		l.loseLocked("another server changed the job lease")
		return l.Timing.Watch
	}
	if l.state == releasing {
		// Its jobs are already stopped; the lease runs out if writes do
		// not come back before the release is written.
		l.lastErr = werr.Error()
		return l.retryLocked()
	}
	l.confirmed, l.confirmedWall = sent, sentWall
	if l.state != frozen {
		l.state = frozen
		l.log().Warn("OpenSearch refuses writes, as it does when its disk is full: this server keeps the background jobs, "+
			"but runs only the retention disk guard until writes work again", "err", werr)
		if l.run != nil {
			l.run.freeze()
		}
		l.changed()
	}
	l.lastErr = werr.Error()
	return l.retryLocked()
}

// renewFrozen tries to renew a frozen lease: once writes work again, the
// paused jobs start again.
func (l *Lease) renewFrozen(ctx context.Context, c *store.Client, index string) time.Duration {
	l.mu.Lock()
	if !l.validLocked() {
		l.loseLocked("OpenSearch could not be read to confirm the job lease")
		l.mu.Unlock()
		return l.Timing.Watch
	}
	doc, ver := l.doc, l.ver
	l.mu.Unlock()
	doc.RenewedAt = l.Clock.Now().UTC()
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	sent, sentWall := l.Clock.Mono(), l.Clock.Now()
	nv, err := c.PutIf(rctx, index, leaseID, doc, ver, false)
	cancel()
	switch {
	case err == nil:
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.state != frozen {
			return l.Timing.Watch
		}
		l.state, l.ver, l.doc, l.lastGood, l.lastGoodWall, l.lastErr = holding, nv, doc, sent, sentWall, ""
		l.log().Info("OpenSearch takes writes again: the background jobs run again")
		if l.run != nil {
			l.run.thaw(l.jobs)
		}
		l.changed()
		return l.Timing.Renew
	case errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound):
		l.mu.Lock()
		defer l.mu.Unlock()
		l.loseLocked("another server changed the job lease")
		return l.Timing.Watch
	}
	// Still refused, or no answer: a read decides.
	return l.blocked(ctx, c, index, err)
}

// watch reads the lease on a server that does not hold it, and takes it
// when it may.
func (l *Lease) watch(ctx context.Context, c *store.Client, index string) time.Duration {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	src, ver, found, err := c.Get(rctx, index, leaseID)
	cancel()
	now := l.Clock.Mono()
	// Asked before taking l.mu: it reads the server's own state.
	ok, why := l.Eligible()
	l.mu.Lock()
	if err != nil {
		l.lastErr = err.Error()
		l.mu.Unlock()
		return l.Timing.Watch
	}
	var doc LeaseDoc
	if found {
		if err := json.Unmarshal(src, &doc); err != nil {
			l.lastErr = "lease:jobs cannot be read: " + err.Error()
		}
	}
	if !l.obs.seen || l.obs.found != found || !l.obs.ver.Same(ver) {
		l.obs = observation{seen: true, found: found, ver: ver, doc: doc, since: now}
	}
	obs := l.obs
	l.lastErr = ""
	if !ok {
		l.cannot = why
		l.mu.Unlock()
		return l.Timing.Watch
	}
	l.cannot = ""
	l.mu.Unlock()

	switch {
	case !found:
		return l.create(ctx, c, index)
	case doc.Holder == "":
		// Released. One that names another server waits for it first.
		if doc.Prefer != "" && doc.Prefer != l.Self.NodeID && now-obs.since < l.Timing.PreferWait {
			return min(l.Timing.Watch, l.Timing.PreferWait-(now-obs.since))
		}
		if doc.ReleasedBy != l.Self.NodeID && !l.guard(doc, true) {
			return l.Timing.Watch
		}
	case doc.Holder == l.Self.NodeID && doc.HolderBoot != "" && doc.HolderBoot == l.Self.BootID:
		// This process's own lease, from before it stopped its jobs:
		// nobody else took it, so it takes it back at once.
	case doc.Holder == l.Self.NodeID && doc.HolderBoot != "" && doc.HolderBoot == l.Self.LastBoot:
		// The lease of the process that used this state folder before,
		// which crashed. It is taken back once unchanged for the fence
		// time rather than the whole takeover time: by then that process
		// has stopped its jobs even if it still runs (a copy of the
		// folder on another computer), and a copy that runs keeps
		// renewing it, so it is never taken from it.
		if wait := l.Timing.Fence - (now - obs.since); wait > 0 {
			return min(l.Timing.Watch, wait)
		}
	default:
		if wait := l.Timing.Takeover - (now - obs.since); wait > 0 {
			// Not yet; but say now whether it could, for the list of
			// servers, from the fingerprints worked out last.
			l.guard(doc, false)
			return min(l.Timing.Watch, wait)
		}
		if !l.guard(doc, true) {
			return l.Timing.Watch
		}
	}
	return l.take(ctx, c, index, ver, doc.Epoch+1)
}

// guard is the fingerprint guard: this server takes the lease over only
// when its files are the holder's. It records why not. fresh works the
// fingerprints out again rather than using the last ones.
func (l *Lease) guard(doc LeaseDoc, fresh bool) bool {
	if doc.Fingerprint == "" {
		return true
	}
	mine := l.fingerprints(fresh)
	if mine.Combined() == doc.Fingerprint {
		return true
	}
	who := doc.HolderName
	if who == "" {
		who = "the server that ran the jobs last"
	}
	parts := mine.Differ(doc.Fingerprints)
	what := "files the jobs use"
	if len(parts) > 0 {
		what = joinWords(parts)
	}
	l.mu.Lock()
	l.cannot = fmt.Sprintf("its %s differ from %s's", what, who)
	l.mu.Unlock()
	return false
}

// create makes a lease where there is none, with an epoch above every
// epoch stored in the runtime index, so work recorded under an earlier
// lease never outranks the new holder.
func (l *Lease) create(ctx context.Context, c *store.Client, index string) time.Duration {
	top, err := maxEpoch(ctx, c, index)
	if err != nil {
		l.mu.Lock()
		l.lastErr = err.Error()
		l.mu.Unlock()
		return l.Timing.Watch
	}
	return l.take(ctx, c, index, store.Version{}, top+1)
}

// take writes the lease for this server with epoch: over version ver, or
// as a new document when ver is zero.
func (l *Lease) take(ctx context.Context, c *store.Client, index string, ver store.Version, epoch int64) time.Duration {
	now := l.Clock.Now().UTC()
	fp := l.fingerprints(true)
	doc := LeaseDoc{Kind: "lease", Job: "jobs", Holder: l.Self.NodeID, HolderName: l.Self.Name, HolderVersion: l.Self.Version,
		HolderBoot: l.Self.BootID, Epoch: epoch, AcquiredAt: now, RenewedAt: now, TTLMS: l.Timing.Takeover.Milliseconds(),
		Fingerprint: fp.Combined(), Fingerprints: fp}
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	sent, sentWall := l.Clock.Mono(), l.Clock.Now()
	var nv store.Version
	var err error
	if ver.IsZero() {
		nv, err = c.Create(rctx, index, leaseID, doc, false)
	} else {
		nv, err = c.PutIf(rctx, index, leaseID, doc, ver, false)
	}
	cancel()
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case err == nil:
		l.gainLocked(nv, doc, sent, sentWall)
		return l.Timing.Renew
	case store.IsClusterBlock(err):
		// Nobody can write it now, not even its holder: wait the whole
		// takeover time again once writes work.
		l.obs.since = l.Clock.Mono()
		l.lastErr = err.Error()
	case store.IsConflict(err) || errors.Is(err, store.ErrNotFound):
		// Someone else was first; read it again.
	default:
		l.lastErr = err.Error()
	}
	return l.Timing.Watch
}

// gainLocked starts holding the lease. The caller holds l.mu.
func (l *Lease) gainLocked(ver store.Version, doc LeaseDoc, sent time.Duration, sentWall time.Time) {
	l.state, l.ver, l.doc, l.lastGood, l.lastGoodWall, l.lastErr, l.cannot = holding, ver, doc, sent, sentWall, "", ""
	l.log().Info("this server now runs the background jobs", "epoch", doc.Epoch)
	l.startLocked()
	l.changed()
}

// startLocked starts the jobs under the current epoch, once jobs
// cancelled earlier have finished. The caller holds l.mu.
func (l *Lease) startLocked() {
	base := l.base
	if base == nil {
		base = context.Background()
	}
	rs := newRunSet(base, l.doc.Epoch)
	l.run = rs
	waitFor := append([]*runSet(nil), l.draining...)
	go func() {
		for _, d := range waitFor {
			d.wait()
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		l.draining = removeSet(l.draining, waitFor)
		if l.run != rs {
			return
		}
		rs.start(l.jobs, l.state == frozen)
	}()
}

// loseLocked stops holding the lease: the jobs are cancelled at once,
// without waiting for them. The caller holds l.mu.
func (l *Lease) loseLocked(why string) {
	if l.state == standby {
		return
	}
	l.log().Warn("this server stopped running the background jobs", "why", why, "epoch", l.doc.Epoch)
	l.stopRunLocked()
	l.state = standby
	l.obs = observation{seen: true, found: true, ver: l.ver, doc: l.doc, since: l.Clock.Mono()}
	l.changed()
}

// stopRunLocked cancels the running jobs. The caller holds l.mu.
func (l *Lease) stopRunLocked() {
	if l.run == nil {
		return
	}
	l.run.cancel()
	l.draining = append(l.draining, l.run)
	l.run = nil
}

func (l *Lease) changed() {
	if l.OnChange != nil {
		go l.OnChange()
	}
}

// SetJobs replaces the jobs. When this server holds the lease, the old
// jobs are cancelled and waited for (renewals go on meanwhile), then the
// new ones start under the same epoch, as an in-process restart needs.
func (l *Lease) SetJobs(jobs []Job) {
	l.mu.Lock()
	l.jobs = jobs
	rs := l.run
	if rs == nil || l.state == releasing {
		l.mu.Unlock()
		l.waitDraining()
		return
	}
	l.stopRunLocked()
	l.mu.Unlock()
	rs.wait()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.run == nil && (l.state == holding || l.state == frozen) {
		l.startLocked()
	}
}

// waitDraining waits for cancelled jobs to finish.
func (l *Lease) waitDraining() {
	l.mu.Lock()
	sets := append([]*runSet(nil), l.draining...)
	l.mu.Unlock()
	for _, rs := range sets {
		rs.wait()
	}
}

// Release gives the lease up gracefully: no new work starts, the jobs
// are cancelled and waited for (at most ReleaseWait, renewing the lease
// meanwhile as long as Step keeps being called), then the lease is
// written with no holder, so another server takes over within seconds.
func (l *Lease) Release(reason string) {
	l.mu.Lock()
	switch l.state {
	case standby:
		l.mu.Unlock()
		l.waitDraining()
		return
	case frozen:
		// Nothing can be written: stop, and let the lease run out.
		l.stopRunLocked()
		l.state = standby
		l.obs = observation{seen: true, found: true, ver: l.ver, doc: l.doc, since: l.Clock.Mono()}
		l.changed()
		l.mu.Unlock()
		l.waitDraining()
		return
	}
	l.state = releasing
	rs := l.run
	l.stopRunLocked()
	l.mu.Unlock()
	if rs != nil {
		done := make(chan struct{})
		go func() { rs.wait(); close(done) }()
		select {
		case <-done:
		case <-l.Clock.After(l.Timing.ReleaseWait):
			l.log().Warn("background jobs did not finish in time; giving up the job lease anyway", "wait", l.Timing.ReleaseWait)
		}
	}
	l.stepMu.Lock()
	defer l.stepMu.Unlock()
	l.mu.Lock()
	if l.state != releasing {
		l.mu.Unlock()
		return
	}
	doc, ver := l.doc, l.ver
	l.mu.Unlock()
	doc.Holder, doc.HolderBoot, doc.ReleasedBy, doc.ReleaseReason, doc.RenewedAt = "", "", l.Self.NodeID, reason, l.Clock.Now().UTC()
	nv, err := store.Version{}, error(nil)
	if c, index := l.Target(); c != nil {
		ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
		nv, err = c.PutIf(ctx, index, leaseID, doc, ver, false)
		cancel()
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		l.log().Warn("could not give up the job lease; another server takes it over once it runs out", "err", err)
		nv, doc = ver, l.doc
	} else {
		l.log().Info("gave up the background jobs", "reason", reason)
	}
	l.state = standby
	l.obs = observation{seen: true, found: true, ver: nv, doc: doc, since: l.Clock.Mono()}
	l.changed()
}

// Abandon stops the jobs without writing anything: another process with
// this server's identity may be the real holder.
func (l *Lease) Abandon(why string) {
	l.mu.Lock()
	l.loseLocked(why)
	l.mu.Unlock()
	l.waitDraining()
}

// Reset forgets what was observed of the lease, for a new OpenSearch.
func (l *Lease) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.obs = observation{}
	l.cannot, l.lastErr = "", ""
}

// LeaseView is the job lease as this server knows it.
type LeaseView struct {
	// Seen is true once this server has read or written the lease.
	Seen       bool
	Found      bool
	Doc        LeaseDoc
	State      string // standby, holding, frozen or releasing
	Mine       bool
	Valid      bool
	Unchanged  time.Duration // how long it was seen unchanged, for a server that does not hold it
	CannotTake string
	Err        string
}

// View returns the lease as this server last saw or wrote it.
func (l *Lease) View() LeaseView {
	l.mu.Lock()
	defer l.mu.Unlock()
	v := LeaseView{State: l.state.String(), CannotTake: l.cannot, Err: l.lastErr, Valid: l.validLocked()}
	if l.state != standby {
		v.Seen, v.Found, v.Doc, v.Mine = true, true, l.doc, true
		return v
	}
	v.Seen, v.Found, v.Doc = l.obs.seen, l.obs.found, l.obs.doc
	if l.obs.seen {
		v.Unchanged = l.Clock.Mono() - l.obs.since
	}
	return v
}

// maxEpoch returns the highest epoch stored in the runtime index, from
// any document: the lease, heartbeats (lease_epoch) and later records.
func maxEpoch(ctx context.Context, c *store.Client, index string) (int64, error) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	out, err := c.Search(rctx, index, map[string]any{
		"size": 0, "query": map[string]any{"match_all": map[string]any{}},
		"aggs": map[string]any{
			"epoch": map[string]any{"max": map[string]any{"field": "epoch"}},
			"lease": map[string]any{"max": map[string]any{"field": "lease_epoch"}},
		},
	})
	if err != nil {
		return 0, fmt.Errorf("could not read the highest job lease epoch: %w", err)
	}
	var top int64
	aggs, _ := out["aggregations"].(map[string]any)
	for _, name := range []string{"epoch", "lease"} {
		a, _ := aggs[name].(map[string]any)
		switch v := a["value"].(type) {
		case json.Number:
			if f, err := v.Float64(); err == nil && int64(f) > top {
				top = int64(f)
			}
		case float64:
			if int64(v) > top {
				top = int64(v)
			}
		}
	}
	return top, nil
}

// runSet is one start of the jobs. Emergency jobs run under all; the
// others under normal, which a frozen lease cancels alone.
type runSet struct {
	epoch     int64
	all       context.Context
	cancelAll context.CancelFunc

	mu           sync.Mutex
	cancelNormal context.CancelFunc
	normalWG     *sync.WaitGroup
	emergencyWG  sync.WaitGroup
	// waiting are normal jobs cancelled by a freeze that may still run.
	waiting []*sync.WaitGroup
}

func newRunSet(base context.Context, epoch int64) *runSet {
	ctx, cancel := context.WithCancel(base)
	return &runSet{epoch: epoch, all: ctx, cancelAll: cancel, normalWG: &sync.WaitGroup{}}
}

// start starts the jobs; frozenNow starts only the emergency ones.
func (rs *runSet) start(jobs []Job, frozenNow bool) {
	for _, j := range jobs {
		if j.Emergency {
			rs.emergencyWG.Go(func() { j.Run(rs.all) })
		}
	}
	if !frozenNow {
		rs.startNormal(jobs)
	}
}

func (rs *runSet) startNormal(jobs []Job) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.all.Err() != nil {
		return
	}
	ctx, cancel := context.WithCancel(rs.all)
	wg := &sync.WaitGroup{}
	rs.cancelNormal, rs.normalWG = cancel, wg
	for _, j := range jobs {
		if !j.Emergency {
			wg.Go(func() { j.Run(ctx) })
		}
	}
}

// freeze cancels the jobs that are not emergency jobs.
func (rs *runSet) freeze() {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.cancelNormal != nil {
		rs.cancelNormal()
		rs.waiting = append(rs.waiting, rs.normalWG)
		rs.cancelNormal, rs.normalWG = nil, &sync.WaitGroup{}
	}
}

// thaw starts the jobs a freeze cancelled again, once they have ended.
func (rs *runSet) thaw(jobs []Job) {
	rs.mu.Lock()
	waiting := rs.waiting
	rs.waiting = nil
	rs.mu.Unlock()
	go func() {
		for _, wg := range waiting {
			wg.Wait()
		}
		rs.startNormal(jobs)
	}()
}

func (rs *runSet) cancel() { rs.cancelAll() }

// wait waits until every job of the set has returned.
func (rs *runSet) wait() {
	rs.emergencyWG.Wait()
	rs.mu.Lock()
	wgs := append([]*sync.WaitGroup{rs.normalWG}, rs.waiting...)
	rs.mu.Unlock()
	for _, wg := range wgs {
		wg.Wait()
	}
}

func removeSet(list, gone []*runSet) []*runSet {
	out := list[:0]
	for _, rs := range list {
		keep := true
		for _, g := range gone {
			if rs == g {
				keep = false
			}
		}
		if keep {
			out = append(out, rs)
		}
	}
	return out
}

// joinWords joins items as "a, b and c".
func joinWords(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
