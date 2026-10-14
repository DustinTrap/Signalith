package shared

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestTokenFollowsWrites(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "settings", "settings", 1)
	NewDoc[testBody](b, "settings", "settings", 1)
	if a.Token() != "" {
		t.Errorf("token before reading: %q", a.Token())
	}
	cycle(t, a)
	cycle(t, b)
	before := b.Token()
	seq, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "x"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	tok := a.TokenAfter(seq)
	if tok != a.Token() || !strings.HasSuffix(tok, "."+strconv.FormatInt(seq, 10)) {
		t.Errorf("token %q, after %q", a.Token(), tok)
	}
	if !b.behind(tok) {
		t.Fatalf("b at %q is not behind %q", before, tok)
	}
	if stale := b.Wait(ctx, tok); stale {
		t.Error("stale after one cycle")
	}
	if b.Token() != tok {
		t.Errorf("b %q a %q", b.Token(), tok)
	}
	// A token ahead of anything any server has: stale, at most Timing.Wait.
	uuid, _, _ := ParseToken(tok)
	start := time.Now()
	if stale := b.Wait(ctx, uuid+".99999"); !stale {
		t.Error("not stale")
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
	// Tokens that cannot be read are not waited for.
	for _, bad := range []string{"", "nonsense", "x.-2", ".5", uuid + ".-1"} {
		if b.Wait(ctx, bad) {
			t.Errorf("stale for %q", bad)
		}
	}
}

// U7: a token from a housekeeping delete never makes a page wait.
func TestTokenAfterHousekeeping(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "jointoken", "tokens", 1)
	NewCollection[testBody](b, "jointoken", "tokens", 1)
	if _, err := ca.Create(ctx, "sam", "t1", &testBody{Name: "t1"}); err != nil {
		t.Fatal(err)
	}
	_, etag, _ := ca.Get("t1")
	if _, err := ca.Delete(ctx, "sam", "t1", etag); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	cycle(t, b)
	e.clock.Advance(TombstoneAge + time.Hour)
	_, seq, err := ca.Housekeep(ctx, e.clock.Now())
	if err != nil || seq == 0 {
		t.Fatalf("housekeeping: %d %v", seq, err)
	}
	tok := a.TokenAfter(seq)
	if !b.behind(tok) {
		t.Fatalf("b %q is not behind %q", b.Token(), tok)
	}
	start := time.Now()
	if stale := b.Wait(ctx, tok); stale {
		t.Errorf("stale: b %q, token %q", b.Token(), tok)
	}
	if time.Since(start) > time.Second {
		t.Errorf("waited %v", time.Since(start))
	}
}

// U9: a token of a config index that was deleted and made again is
// ignored.
func TestTokenOfAnotherIndexIsIgnored(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "settings", "settings", 1)
	NewDoc[testBody](b, "settings", "settings", 1)
	cycle(t, a)
	for range 3 {
		if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name += "x"; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	old := a.Token()
	oldUUID, oldSeq, _ := ParseToken(old)
	if err := e.c.Do(ctx, http.MethodDelete, "/"+testIndex, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfig(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	e.putSigned(e.key, "settings", "settings", 1, 3, `{"name":"xxx"}`, nil)
	cycle(t, b)
	newUUID, newSeq, ok := ParseToken(b.Token())
	if !ok || newUUID == oldUUID || newSeq >= oldSeq {
		t.Fatalf("old %q new %q", old, b.Token())
	}
	start := time.Now()
	if stale := b.Wait(ctx, old); stale {
		t.Error("stale for a token of the old index")
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Errorf("waited %v", time.Since(start))
	}
	// The writer finds the new index too.
	cycle(t, a)
	if u, _, _ := ParseToken(a.Token()); u != newUUID {
		t.Errorf("a %q", a.Token())
	}
}
