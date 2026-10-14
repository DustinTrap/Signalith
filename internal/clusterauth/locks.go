package clusterauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/auth"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Sign-in lockouts are counted on each server, with its limits divided by
// the servers that take sign-ins (auth.Limiter.Divisor), and shared once
// they trip: the server where an address, an address and account, or a
// known browser is locked (or where strangers' wait for an account
// reaches its longest) writes a lock document in the runtime index,
// <prefix>_runtime/lock:<hash>, and bumps watch:locks; every server reads
// the locks that have not ended into its limiter (auth.Limiter.External).
// A lock costs one write per key and server, and checking one costs no
// request: Begin only reads memory. Without OpenSearch each server's own
// limits still apply. Keys are digests (auth.LockKey), so no address or
// account name is stored.

// ReloadEvery is how often every server reads the locks again, besides
// whenever watch:locks moves.
const ReloadEvery = 5 * time.Minute

// lockDoc is a lock document.
type lockDoc struct {
	Kind  string `json:"kind"`
	Scope string `json:"scope"`
	// Key is the bucket's auth.LockKey: the document id is a hash of it
	// with the cluster's id, which cannot be read back.
	Key   string `json:"key"`
	Until string `json:"until"`
	Node  string `json:"node"`
	At    string `json:"at"`
}

// Locks shares the sign-in lockouts of the servers of a cluster.
type Locks struct {
	Docs *Docs
	// Client returns the OpenSearch client and index prefix in use now.
	Client func() (*store.Client, string)
	// Node is this server's node id.
	Node    string
	Limiter *auth.Limiter
	// Writable reports whether this server may write to OpenSearch now;
	// while it may not, only its own limits apply.
	Writable func() bool
	Log      *slog.Logger
	Now      func() time.Time

	mu     sync.Mutex
	loaded time.Time
}

func (l *Locks) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// runtimeIndex is cluster.RuntimeIndex, which this package does not
// import.
func runtimeIndex(prefix string) string { return prefix + "_runtime" }

// LockID returns the id of the lock document of a key in scope.
func LockID(clusterID, scope, key string) string {
	sum := sha256.Sum256([]byte(clusterID + "|" + scope + "|" + key))
	return "lock:" + hex.EncodeToString(sum[:])
}

// Listen makes the limiter report its locks here, and reads the locks
// again whenever another server reports one. Call it once per start.
func (l *Locks) Listen() {
	l.Limiter.OnLock = func(scope, key string, until time.Time) {
		// The limiter calls this as a sign-in fails; the write must not
		// hold up the answer.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := l.Write(ctx, scope, key, until); err != nil {
				l.log().Warn("could not tell the other servers about a sign-in lockout", "scope", scope, "err", err)
			}
		}()
	}
	l.Docs.OnLocks(func() {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = l.Reload(ctx)
		}()
	})
}

func (l *Locks) log() *slog.Logger {
	if l.Log != nil {
		return l.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Write records the lock of key in scope until until, keeping a later end
// another server wrote, then bumps watch:locks.
func (l *Locks) Write(ctx context.Context, scope, key string, until time.Time) error {
	if l.Writable != nil && !l.Writable() {
		return nil
	}
	cid := l.Docs.ClusterID()
	if cid == "" {
		return errors.New("this server is not a member of the cluster now")
	}
	cl, prefix := l.Client()
	index, id := runtimeIndex(prefix), LockID(cid, scope, key)
	doc := lockDoc{Kind: "lock", Scope: scope, Key: key, Until: until.UTC().Format(time.RFC3339Nano), Node: l.Node,
		At: l.now().UTC().Format(time.RFC3339Nano)}
	for try := 0; try < store.ModifyTries; try++ {
		src, ver, found, err := cl.Get(ctx, index, id)
		if err != nil {
			return err
		}
		if found {
			var old lockDoc
			if json.Unmarshal(src, &old) == nil {
				if t, err := time.Parse(time.RFC3339Nano, old.Until); err == nil && !t.Before(until) {
					return nil
				}
			}
			_, err = cl.PutIf(ctx, index, id, doc, ver, true)
		} else {
			_, err = cl.Create(ctx, index, id, doc, true)
		}
		if store.IsConflict(err) {
			continue
		}
		if err != nil {
			return err
		}
		if h := l.Docs.Hub(); h != nil {
			if _, err := h.Bump(ctx, LocksWatch); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

// Reload reads the locks that have not ended into the limiter. It runs
// whenever watch:locks moves, and at least every ReloadEvery (Due).
func (l *Locks) Reload(ctx context.Context) error {
	cid := l.Docs.ClusterID()
	cl, prefix := l.Client()
	now := l.now()
	docs, err := cl.SearchDocs(ctx, runtimeIndex(prefix), map[string]any{"bool": map[string]any{"must": []any{
		map[string]any{"term": map[string]any{"kind": "lock"}},
		map[string]any{"range": map[string]any{"until": map[string]any{"gt": now.UTC().Format(time.RFC3339Nano)}}},
	}}})
	if err != nil {
		return err
	}
	locks := map[string]time.Time{}
	for _, d := range docs {
		var ld lockDoc
		if json.Unmarshal(d.Source, &ld) != nil || ld.Key == "" || d.ID != LockID(cid, ld.Scope, ld.Key) {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, ld.Until)
		if err != nil || !t.After(now) {
			continue
		}
		if t.After(locks[ld.Key]) {
			locks[ld.Key] = t
		}
	}
	l.Limiter.External(locks)
	l.mu.Lock()
	l.loaded = now
	l.mu.Unlock()
	return nil
}

// Due reports whether the locks were last read ReloadEvery ago or more.
func (l *Locks) Due() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.loaded.IsZero() || l.now().Sub(l.loaded) >= ReloadEvery
}

// Housekeep deletes the lock documents that have ended.
func (l *Locks) Housekeep(ctx context.Context) (int, error) {
	if l.Writable != nil && !l.Writable() {
		return 0, nil
	}
	cl, prefix := l.Client()
	var out struct {
		Deleted int `json:"deleted"`
	}
	q := map[string]any{"bool": map[string]any{"must": []any{
		map[string]any{"term": map[string]any{"kind": "lock"}},
		map[string]any{"range": map[string]any{"until": map[string]any{"lt": l.now().UTC().Format(time.RFC3339Nano)}}},
	}}}
	err := cl.Do(ctx, http.MethodPost, "/"+url.PathEscape(runtimeIndex(prefix))+"/_delete_by_query?conflicts=proceed&ignore_unavailable=true",
		map[string]any{"query": q}, &out)
	return out.Deleted, err
}
