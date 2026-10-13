package sample

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A load's bookkeeping lives in OpenSearch, in one document of the runtime
// index (<prefix>_runtime, where servers that share one OpenSearch find
// each other), not in a file of one server. Every server, and the signalith
// sample-data command on any computer, sees the same load:
//
//   - The document is created when a load starts, before anything else is
//     written, so even a load that stops part way can be removed. Creating
//     it is also what keeps to one load at a time: a second load, on any
//     server, finds it there and is refused.
//   - While a load or removal runs, the document holds its progress and a
//     heartbeat, so every server shows it and none starts another. A job
//     whose heartbeat stopped (its process ended mid-job) may be taken over
//     by a removal.
//   - A removal deletes the document last, once everything is gone.

var (
	// ErrBusy means another load or removal is running: on this server, on
	// another server that shares the OpenSearch, or in a signalith
	// sample-data command.
	ErrBusy = errors.New("a sample-data load or removal is already running")
	// ErrTakenOver means another server took the job over after this one's
	// heartbeat stopped reaching OpenSearch for a minute.
	ErrTakenOver = errors.New("another server took over this sample-data job after this one lost touch with OpenSearch")
	// errNoDocs means the loader was built without an OpenSearch client.
	errNoDocs = errors.New("sample data needs OpenSearch, which this loader was not given")
)

const (
	stateID   = "sample:data"
	stateKind = "sample_data"
	heartbeat = 5 * time.Second
	// staleJob is how long a job's heartbeat may be quiet before another
	// process takes the job for stopped. The heartbeat is stamped with the
	// writer's clock and judged with the reader's, so this leaves room for
	// servers whose clocks differ by a few seconds.
	staleJob = time.Minute
	// docTimeout bounds one read or write of the document.
	docTimeout = 15 * time.Second
)

// Docs reads and writes a document with its version, so two servers never
// overwrite each other's changes. *store.Client has it.
type Docs interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
	DeleteIf(ctx context.Context, index, id string, v store.Version, refresh bool) error
}

// Activity is a running load or removal, as every server sees it.
type Activity struct {
	Op      string `json:"op"`    // "load" or "remove"
	Phase   string `json:"phase"` // plain-English step
	Percent int    `json:"percent"`
	// Server names where it runs: the server's name, or the computer's
	// when the signalith sample-data command runs it (Command).
	Server  string    `json:"server,omitempty"`
	Command bool      `json:"command,omitempty"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Beat    time.Time `json:"beat"` // last heartbeat
}

func (a *Activity) fresh(now time.Time) bool {
	return a != nil && now.Sub(a.Beat) < staleJob
}

// stateDoc is the document. In OpenSearch its state and job sit under
// "body", which the runtime index stores without indexing: its top-level
// fields have types of their own there (state, for one, is a server's
// state, a keyword).
type stateDoc struct {
	Kind  string
	State *State
	Job   *Activity
}

type stateBody struct {
	State *State    `json:"state"`
	Job   *Activity `json:"job,omitempty"`
}

func (d stateDoc) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Kind string    `json:"kind"`
		Body stateBody `json:"body"`
	}{d.Kind, stateBody{d.State, d.Job}})
}

func (d *stateDoc) UnmarshalJSON(b []byte) error {
	var raw struct {
		Kind string    `json:"kind"`
		Body stateBody `json:"body"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*d = stateDoc{Kind: raw.Kind, State: raw.Body.State, Job: raw.Body.Job}
	return nil
}

func (l *Loader) index() string { return cluster.RuntimeIndex(l.Prefix) }

// read returns the document, or nil when there is none.
func (l *Loader) read(ctx context.Context) (*stateDoc, store.Version, error) {
	if l.Docs == nil {
		return nil, store.Version{}, errNoDocs
	}
	ctx, cancel := context.WithTimeout(ctx, docTimeout)
	defer cancel()
	src, v, found, err := l.Docs.Get(ctx, l.index(), stateID)
	if err != nil || !found {
		return nil, store.Version{}, err
	}
	var d stateDoc
	if err := json.Unmarshal(src, &d); err != nil {
		return nil, store.Version{}, fmt.Errorf("reading the sample-data bookkeeping in %s: %w", l.index(), err)
	}
	if d.State == nil {
		// Never written so; treat it as a load that did not finish, which
		// Remove clears.
		d.State = &State{Partial: true}
	}
	return &d, v, nil
}

// Current returns the sample's state, nil when none is loaded (a state with
// Partial set is a load that did not finish), and the load or removal
// running now in any process, nil when none is.
func (l *Loader) Current(ctx context.Context) (*State, *Activity, error) {
	d, _, err := l.read(ctx)
	if err != nil || d == nil {
		return nil, nil, err
	}
	var act *Activity
	if d.Job.fresh(time.Now()) {
		act = d.Job
	}
	return d.State, act, nil
}

// Status returns the sample's state, or nil when none is loaded. A state
// with Partial set is a load that did not finish.
func (l *Loader) Status(ctx context.Context) (*State, error) {
	st, _, err := l.Current(ctx)
	return st, err
}

// Activity returns the running load or removal, from any process, or nil
// when none is running (or it cannot be told).
func (l *Loader) Activity(ctx context.Context) *Activity {
	_, act, err := l.Current(ctx)
	if err != nil {
		return nil
	}
	return act
}

// refusal says why a load cannot start while the document d exists.
func refusal(d *stateDoc) error {
	switch {
	case d.Job.fresh(time.Now()):
		return ErrBusy
	case d.State.Partial:
		return ErrPartial
	}
	return ErrAlreadyLoaded
}

func (l *Loader) newActivity(op string) *Activity {
	now := time.Now().UTC()
	return &Activity{Op: op, Server: l.Server, Command: l.Command, PID: os.Getpid(), Started: now, Beat: now}
}

// job is a load or removal holding the document. Lock times are wall-clock
// times (never the loader's Now, which tests fix): a heartbeat is about
// whether a process is alive right now.
type job struct {
	l *Loader
	// cancel stops the job's work when another process took it over.
	cancel context.CancelCauseFunc

	mu      sync.Mutex
	doc     stateDoc
	ver     store.Version
	written time.Time
	lost    bool
	stop    chan struct{}
	done    chan struct{}
}

// startLoad creates the document for a new load holding st, or says why
// it cannot: ErrAlreadyLoaded, ErrPartial or ErrBusy.
func (l *Loader) startLoad(ctx context.Context, cancel context.CancelCauseFunc, st *State) (*job, error) {
	if err := cluster.EnsureRuntime(ctx, l.OS, l.Prefix); err != nil {
		return nil, fmt.Errorf("preparing the %s index: %w", l.index(), err)
	}
	cp := *st
	j := &job{l: l, cancel: cancel, doc: stateDoc{Kind: stateKind, State: &cp, Job: l.newActivity("load")}}
	wctx, done := context.WithTimeout(ctx, docTimeout)
	v, err := l.Docs.Create(wctx, l.index(), stateID, j.doc, false)
	done()
	if errors.Is(err, store.ErrExists) {
		d, _, rerr := l.read(ctx)
		switch {
		case rerr != nil:
			return nil, rerr
		case d == nil:
			return nil, ErrBusy // removed just now; the next try will do
		}
		return nil, refusal(d)
	}
	if err != nil {
		return nil, fmt.Errorf("recording the sample-data load in %s: %w", l.index(), err)
	}
	j.ver = v
	j.start()
	return j, nil
}

// startRemove takes the document over for a removal. It returns no job
// when nothing is loaded, and ErrBusy while another job runs.
func (l *Loader) startRemove(ctx context.Context, cancel context.CancelCauseFunc) (*job, error) {
	d, v, err := l.read(ctx)
	if err != nil || d == nil {
		return nil, err
	}
	if d.Job.fresh(time.Now()) {
		return nil, ErrBusy
	}
	j := &job{l: l, cancel: cancel, doc: stateDoc{Kind: stateKind, State: d.State, Job: l.newActivity("remove")}}
	wctx, done := context.WithTimeout(ctx, docTimeout)
	nv, err := l.Docs.PutIf(wctx, l.index(), stateID, j.doc, v, false)
	done()
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, nil // removed meanwhile
	case errors.Is(err, store.ErrConflict):
		return nil, ErrBusy
	case err != nil:
		return nil, fmt.Errorf("recording the sample-data removal in %s: %w", l.index(), err)
	}
	j.ver = nv
	j.start()
	return j, nil
}

// state returns a copy of the state the job holds.
func (j *job) state() *State {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := *j.doc.State
	return &cp
}

func (j *job) start() {
	j.stop, j.done = make(chan struct{}), make(chan struct{})
	j.written = time.Now()
	go j.beat()
}

func (j *job) beat() {
	defer close(j.done)
	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-j.stop:
			return
		case <-t.C:
			j.mu.Lock()
			_ = j.writeLocked()
			j.mu.Unlock()
		}
	}
}

// writeLocked writes the document with a new heartbeat; the caller holds
// j.mu. A write that finds the document changed or gone means another
// process took the job over: the job's work is stopped. Any other failure
// is tried again on the next heartbeat.
func (j *job) writeLocked() error {
	if j.lost {
		return ErrTakenOver
	}
	if j.doc.Job != nil {
		j.doc.Job.Beat = time.Now().UTC()
	}
	ctx, cancel := context.WithTimeout(context.Background(), docTimeout)
	defer cancel()
	v, err := j.l.Docs.PutIf(ctx, j.l.index(), stateID, j.doc, j.ver, false)
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
		j.lost = true
		j.cancel(ErrTakenOver)
		j.l.log().Warn("sample data: another process took this job over; stopping", "index", j.l.index())
		return ErrTakenOver
	}
	if err != nil {
		return err
	}
	j.ver, j.written = v, time.Now()
	return nil
}

// set records the job's progress. It is written out when the step changed
// or a couple of seconds have passed, so the other servers can show it.
func (j *job) set(phase string, pct int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.doc.Job == nil {
		return
	}
	changed := phase != j.doc.Job.Phase
	j.doc.Job.Phase, j.doc.Job.Percent = phase, pct
	if changed || time.Since(j.written) >= 2*time.Second {
		_ = j.writeLocked()
	}
}

// save records the load's state as it is now.
func (j *job) save(st *State) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	cp := *st
	j.doc.State = &cp
	return j.writeLocked()
}

// end stops the heartbeat and settles the document: it keeps st with no
// job running, or, after a finished removal (st nil), is deleted.
func (j *job) end(st *State) error {
	close(j.stop)
	<-j.done
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lost {
		return ErrTakenOver
	}
	// From here no progress is written: the job is over.
	j.doc.Job = nil
	if st != nil {
		cp := *st
		j.doc.State = &cp
		return j.writeLocked()
	}
	ctx, cancel := context.WithTimeout(context.Background(), docTimeout)
	defer cancel()
	err := j.l.Docs.DeleteIf(ctx, j.l.index(), stateID, j.ver, true)
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil
	case errors.Is(err, store.ErrConflict):
		return ErrTakenOver
	}
	return err
}

// takenOver turns the error of a job's work, stopped because another
// process took the job over, into ErrTakenOver.
func takenOver(ctx context.Context, err error) error {
	if err != nil && errors.Is(context.Cause(ctx), ErrTakenOver) {
		return ErrTakenOver
	}
	return err
}
