package clusterauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Last sign-ins are kept apart from the users, in the runtime index, so
// signing in never changes a user document: <prefix>_runtime/
// lastseen:<server>:<user>, one per user and server, written at most once
// a minute by each server without reading it first. The Users page shows
// the newest of a user's, and on which server it was.

// SeenEvery is how often, at most, a server writes a user's last sign-in.
const SeenEvery = time.Minute

// seenCacheFor is how long the list of last sign-ins is used before it
// is read again.
const seenCacheFor = 2 * time.Second

// Seen is a user's last sign-in.
type Seen struct {
	User string    `json:"user"`
	At   time.Time `json:"at"`
	// Node is the name of the server it was on.
	Node string `json:"node"`
	// Method is session (the sign-in page) or basic (HTTP Basic auth).
	Method string `json:"method"`
}

// Sign-in methods in Seen.
const (
	MethodSession = "session"
	MethodBasic   = "basic"
)

type seenDoc struct {
	Kind string `json:"kind"`
	Seen
}

// LastSeen keeps the last sign-ins of the users of a cluster.
type LastSeen struct {
	// Client returns the OpenSearch client and index prefix in use now.
	Client func() (*store.Client, string)
	// Node is this server's name.
	Node string
	// Writable reports whether this server may write to OpenSearch now;
	// while it may not, sign-ins are not recorded.
	Writable func() bool
	Now      func() time.Time

	mu      sync.Mutex
	written map[string]time.Time
	all     map[string]Seen
	allAt   time.Time
}

func (l *LastSeen) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

// LastSeenID returns the id of the document of user's last sign-in on
// server node.
func LastSeenID(node, user string) string { return "lastseen:" + node + ":" + user }

// Record notes that user signed in on this server by method, unless this
// server did less than SeenEvery ago.
func (l *LastSeen) Record(ctx context.Context, user, method string) error {
	if l.Writable != nil && !l.Writable() {
		return nil
	}
	user = strings.ToLower(user)
	now := l.now()
	l.mu.Lock()
	if l.written == nil {
		l.written = map[string]time.Time{}
	}
	if at, ok := l.written[user]; ok && now.Sub(at) < SeenEvery {
		l.mu.Unlock()
		return nil
	}
	l.written[user] = now
	l.mu.Unlock()
	return l.put(ctx, Seen{User: user, At: now.UTC(), Node: l.Node, Method: method}, false)
}

// Import records a last sign-in from before the users were shared, as
// on node, unless one is there already.
func (l *LastSeen) Import(ctx context.Context, s Seen) error {
	s.User = strings.ToLower(s.User)
	err := l.put(ctx, s, true)
	if store.IsConflict(err) {
		return nil
	}
	return err
}

func (l *LastSeen) put(ctx context.Context, s Seen, create bool) error {
	cl, prefix := l.Client()
	index, id := runtimeIndex(prefix), LastSeenID(s.Node, s.User)
	doc := seenDoc{Kind: "lastseen", Seen: s}
	if create {
		_, err := cl.Create(ctx, index, id, doc, false)
		return err
	}
	var out json.RawMessage
	return cl.Do(ctx, http.MethodPut, "/"+url.PathEscape(index)+"/_doc/"+url.PathEscape(id), doc, &out)
}

// All returns each user's newest last sign-in, by user name.
func (l *LastSeen) All(ctx context.Context) (map[string]Seen, error) {
	now := l.now()
	l.mu.Lock()
	if l.all != nil && now.Sub(l.allAt) < seenCacheFor {
		out := l.all
		l.mu.Unlock()
		return out, nil
	}
	l.mu.Unlock()
	cl, prefix := l.Client()
	docs, err := cl.SearchDocs(ctx, runtimeIndex(prefix), map[string]any{"term": map[string]any{"kind": "lastseen"}})
	if err != nil {
		return nil, err
	}
	out := map[string]Seen{}
	for _, d := range docs {
		var sd seenDoc
		if json.Unmarshal(d.Source, &sd) != nil || sd.User == "" {
			continue
		}
		if cur, ok := out[sd.User]; !ok || sd.At.After(cur.At) {
			out[sd.User] = sd.Seen
		}
	}
	l.mu.Lock()
	l.all, l.allAt = out, now
	l.mu.Unlock()
	return out, nil
}
