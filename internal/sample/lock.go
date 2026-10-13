package sample

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrBusy means another load or removal holds the lock: in this process,
// in a `signalith sample-data` command, or in a server instance that was
// restarted in place while its job kept running.
var ErrBusy = errors.New("a sample-data load or removal is already running")

// The lock is a small file in StateDir that a running load or removal
// creates exclusively and refreshes every heartbeat, with its progress.
// A file whose heartbeat stopped (the process ended mid-job) is stale and
// may be taken over. Its content also lets another process show the job's
// progress: the web page shows a load started from the command line.
const (
	lockName  = "sample.lock"
	heartbeat = 5 * time.Second
	staleLock = 30 * time.Second
)

// Activity is what a running load or removal reports through the lock.
type Activity struct {
	Op      string    `json:"op"`    // "load" or "remove"
	Phase   string    `json:"phase"` // plain-English step
	Percent int       `json:"percent"`
	PID     int       `json:"pid"`
	Started time.Time `json:"started"`
	Beat    time.Time `json:"beat"` // last heartbeat
}

func (a *Activity) fresh(now time.Time) bool {
	return a != nil && now.Sub(a.Beat) < staleLock
}

// Lock times are wall-clock times (never the loader's Now, which tests
// fix): a heartbeat is about whether a process is alive right now.
type jobLock struct {
	path string

	mu      sync.Mutex
	act     Activity
	written time.Time
	writeMu sync.Mutex // one write of the file at a time
	stop    chan struct{}
	done    chan struct{}
}

func (l *Loader) lockPath() string { return filepath.Join(l.StateDir, lockName) }

func readActivity(path string) (*Activity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var a Activity
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// Activity returns the running load or removal, from any process, or nil
// when none is running.
func (l *Loader) Activity() *Activity {
	a, err := readActivity(l.lockPath())
	if err != nil || !a.fresh(time.Now()) {
		return nil
	}
	return a
}

// acquire takes the lock for op, or returns ErrBusy while another job
// holds a fresh one. A stale lock (its holder stopped mid-job) is taken
// over.
func (l *Loader) acquire(op string) (*jobLock, error) {
	if err := os.MkdirAll(l.StateDir, 0o750); err != nil {
		return nil, err
	}
	path := l.lockPath()
	now := time.Now()
	jl := &jobLock{path: path, stop: make(chan struct{}), done: make(chan struct{}),
		act: Activity{Op: op, PID: os.Getpid(), Started: now.UTC(), Beat: now.UTC()}}
	for try := 0; try < 2; try++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if err == nil {
			b, _ := json.Marshal(jl.act)
			_, werr := f.Write(b)
			cerr := f.Close()
			if werr != nil || cerr != nil {
				_ = os.Remove(path)
				return nil, errors.Join(werr, cerr)
			}
			go jl.beat()
			return jl, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		// Held. Take it over only if its holder stopped beating; read it
		// twice so a holder that is just rewriting it is not mistaken for
		// a dead one.
		if lockFresh(path, time.Now()) {
			return nil, ErrBusy
		}
		time.Sleep(50 * time.Millisecond)
		if lockFresh(path, time.Now()) {
			return nil, ErrBusy
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return nil, ErrBusy
}

// lockFresh reports whether the lock file at path has a recent heartbeat,
// judged by its content or, when that cannot be read (being rewritten),
// by its modification time.
func lockFresh(path string, now time.Time) bool {
	if a, err := readActivity(path); err == nil {
		return a.fresh(now)
	}
	st, err := os.Stat(path)
	return err == nil && now.Sub(st.ModTime()) < staleLock
}

// set records progress and writes it out when the step changed or a
// second has passed, so other processes can show it.
func (j *jobLock) set(phase string, pct int) {
	j.mu.Lock()
	changed := phase != j.act.Phase
	j.act.Phase, j.act.Percent = phase, pct
	due := changed || time.Since(j.written) >= time.Second
	j.mu.Unlock()
	if due {
		j.write()
	}
}

func (j *jobLock) write() {
	j.writeMu.Lock()
	defer j.writeMu.Unlock()
	j.mu.Lock()
	j.written = time.Now()
	j.act.Beat = j.written.UTC()
	b, _ := json.Marshal(j.act)
	j.mu.Unlock()
	// Write a temporary file and rename it over the lock, so a reader
	// never sees half of it. A failed write is retried on the next beat.
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return
	}
	if err := os.Rename(tmp, j.path); err != nil {
		_ = os.Remove(tmp)
	}
}

func (j *jobLock) beat() {
	defer close(j.done)
	t := time.NewTicker(heartbeat)
	defer t.Stop()
	for {
		select {
		case <-j.stop:
			return
		case <-t.C:
			j.write()
		}
	}
}

// release stops the heartbeat and removes the lock.
func (j *jobLock) release() {
	close(j.stop)
	<-j.done
	_ = os.Remove(j.path)
}
