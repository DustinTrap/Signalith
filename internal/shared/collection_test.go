package shared

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func names(items []Item[testBody]) []string {
	var out []string
	for _, it := range items {
		out = append(out, it.Name)
	}
	return out
}

func TestCollectionCreateSaveDelete(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "user", "users", 1)
	cb := NewCollection[testBody](b, "user", "users", 1)
	changes := 0
	cb.OnChange(func() { changes++ })
	if _, err := ca.Create(ctx, "sam", "jlee", &testBody{Name: "J. Lee"}); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Create(ctx, "sam", "jlee", &testBody{Name: "again"}); !errors.Is(err, store.ErrExists) {
		t.Errorf("second create: %v", err)
	}
	if _, err := cb.Create(ctx, "bob", "jlee", &testBody{Name: "from b"}); !errors.Is(err, store.ErrExists) {
		t.Errorf("create on b of an item it has not read: %v", err)
	}
	cycle(t, b)
	v, etag, ok := cb.Get("jlee")
	if !ok || v.Name != "J. Lee" || changes == 0 {
		t.Fatalf("b: %+v %v (%d changes)", v, ok, changes)
	}
	if _, err := cb.SaveIf(ctx, "bob", "jlee", &testBody{Name: "Jo Lee"}, etag); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SaveIf(ctx, "sam", "jlee", &testBody{Name: "stale"}, etag); !errors.As(err, new(*StaleError)) {
		t.Errorf("stale save: %v", err)
	}
	cycle(t, a)
	v, etag, _ = ca.Get("jlee")
	if v.Name != "Jo Lee" {
		t.Errorf("a: %+v", v)
	}
	if _, err := ca.Delete(ctx, "sam", "jlee", etag); err != nil {
		t.Fatal(err)
	}
	if src := e.os.Source(testIndex, "user:jlee"); src["deleted"] != true || src["body"] != "" || src["mac"] == nil {
		t.Errorf("tombstone %v", src)
	}
	cycle(t, b)
	if _, _, ok := cb.Get("jlee"); ok || len(cb.List()) != 0 || len(b.Problems()) != 0 {
		t.Errorf("b after delete: %v %+v", cb.List(), b.Problems())
	}
	// A new item of the same name is written over the tombstone, even by a
	// server that never read it.
	c, _ := e.hub("siem-c")
	cc := NewCollection[testBody](c, "user", "users", 1)
	if _, err := cc.Create(ctx, "sam", "jlee", &testBody{Name: "new J. Lee"}); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	if v, _, ok := ca.Get("jlee"); !ok || v.Name != "new J. Lee" {
		t.Errorf("a: %+v %v", v, ok)
	}
}

// U3: an item that disappears without a tombstone is kept from memory and
// reported; one with a tombstone goes, and so does the tombstone once
// housekeeping removes it.
func TestCollectionVanishedItems(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ca := NewCollection[testBody](a, "detection", "detections", 1)
	cb := NewCollection[testBody](b, "detection", "detections", 1)
	for _, n := range []string{"brute-force", "new-admin", "old-rule"} {
		if _, err := ca.Create(ctx, "sam", n, &testBody{Name: n}); err != nil {
			t.Fatal(err)
		}
	}
	cycle(t, b)
	if got := names(cb.List()); !slices.Equal(got, []string{"brute-force", "new-admin", "old-rule"}) {
		t.Fatalf("b: %v", got)
	}
	// Someone removes one in OpenSearch; Signalith deletes another.
	e.os.Delete(testIndex, "detection:new-admin")
	_, etag, _ := ca.Get("old-rule")
	if _, err := ca.Delete(ctx, "sam", "old-rule", etag); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	if got := names(cb.List()); !slices.Equal(got, []string{"brute-force", "new-admin"}) {
		t.Errorf("b: %v", got)
	}
	if !slices.Equal(b.Tamper(), []string{"detection:new-admin"}) {
		t.Errorf("tamper %v", b.Tamper())
	}

	// Housekeeping removes the tombstone after 30 days.
	if n, _, err := ca.Housekeep(ctx, e.clock.Now()); n != 0 || err != nil {
		t.Errorf("early housekeeping: %d %v", n, err)
	}
	e.clock.Advance(TombstoneAge + time.Hour)
	n, seq, err := ca.Housekeep(ctx, e.clock.Now())
	if n != 1 || seq == 0 || err != nil {
		t.Fatalf("housekeeping: %d %d %v", n, seq, err)
	}
	if e.os.Source(testIndex, "detection:old-rule") != nil {
		t.Error("tombstone not removed")
	}
	cycle(t, b)
	if !slices.Equal(b.Tamper(), []string{"detection:new-admin"}) {
		t.Errorf("tamper after housekeeping %v", b.Tamper())
	}
	if got := names(cb.List()); !slices.Equal(got, []string{"brute-force", "new-admin"}) {
		t.Errorf("b: %v", got)
	}
}

func TestCollectionRefusesTamperedItems(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	ca := NewCollection[testBody](a, "user", "users", 1)
	if _, err := ca.Create(ctx, "sam", "jlee", &testBody{Name: "analyst"}); err != nil {
		t.Fatal(err)
	}
	src := e.os.Source(testIndex, "user:jlee")
	src["body"] = `{"name":"admin"}`
	e.os.Put(testIndex, "user:jlee", src)
	// A forged item, never written by Signalith.
	other, _ := NewClusterKey()
	e.putSigned(other, "user:mallory", "user", 1, 1, `{"name":"admin"}`, nil)
	if _, err := a.Bump(ctx, "users"); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	if v, _, _ := ca.Get("jlee"); v.Name != "analyst" {
		t.Errorf("changed item used: %+v", v)
	}
	if _, _, ok := ca.Get("mallory"); ok {
		t.Error("forged item used")
	}
	if got := a.Tamper(); !slices.Equal(got, []string{"user:jlee", "user:mallory"}) {
		t.Errorf("tamper %v", got)
	}
}
