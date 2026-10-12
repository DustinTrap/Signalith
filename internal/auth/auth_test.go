package auth

import (
	"fmt"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func TestSessions(t *testing.T) {
	c := &clock{time.Date(2026, 10, 12, 8, 0, 0, 0, time.UTC)}
	s := NewSessions(time.Hour)
	s.Now = c.now
	tok := s.Create("admin", false)
	if len(tok) < 40 {
		t.Fatalf("token %q is too short", tok)
	}
	if ss, ok := s.Lookup(tok); !ok || ss.User != "admin" {
		t.Fatalf("lookup = %v %v", ss, ok)
	}
	if _, ok := s.Lookup(tok + "x"); ok {
		t.Error("a wrong token was accepted")
	}
	// Use keeps the session alive; an hour idle ends it.
	c.t = c.t.Add(50 * time.Minute)
	if _, ok := s.Lookup(tok); !ok {
		t.Fatal("session ended while in use")
	}
	c.t = c.t.Add(61 * time.Minute)
	if _, ok := s.Lookup(tok); ok || s.Len() != 0 {
		t.Error("idle session still valid")
	}

	// A remembered session survives idle time but not the maximum age.
	keep := s.Create("admin", true)
	c.t = c.t.Add(3 * 24 * time.Hour)
	if _, ok := s.Lookup(keep); !ok {
		t.Error("remembered session ended while idle")
	}
	c.t = c.t.Add(5 * 24 * time.Hour)
	if _, ok := s.Lookup(keep); ok {
		t.Error("remembered session outlived MaxAge")
	}

	other := s.Create("admin", false)
	s.Delete(other)
	if _, ok := s.Lookup(other); ok {
		t.Error("deleted session still valid")
	}
}

func TestSessionLimitEvictsLeastRecentlyUsed(t *testing.T) {
	c := &clock{time.Now()}
	s := NewSessions(time.Hour)
	s.Now, s.Limit = c.now, 2
	a := s.Create("admin", false)
	c.t = c.t.Add(time.Second)
	b := s.Create("admin", false)
	c.t = c.t.Add(time.Second)
	s.Lookup(a)
	c.t = c.t.Add(time.Second)
	s.Create("admin", false)
	if _, ok := s.Lookup(b); ok {
		t.Error("least recently used session was kept")
	}
	if _, ok := s.Lookup(a); !ok {
		t.Error("recently used session was evicted")
	}
}

// fail makes one failed attempt and reports whether it locked anything.
func fail(t *testing.T, l *Limiter, client, account string) bool {
	t.Helper()
	a, ok, wait := l.Begin(client, account)
	if !ok {
		t.Fatalf("%s/%s refused (wait %v) before failing", client, account, wait)
	}
	return a.Fail()
}

func allowed(l *Limiter, client, account string) (bool, time.Duration) {
	a, ok, wait := l.Begin(client, account)
	if ok {
		a.Done()
	}
	return ok, wait
}

func TestLimiter(t *testing.T) {
	c := &clock{time.Now()}
	l := NewLimiter()
	l.Now, l.Max = c.now, 3
	for i := 0; i < 2; i++ {
		if fail(t, l, "10.0.0.1", "admin") {
			t.Fatal("locked out too early")
		}
	}
	if ok, _ := allowed(l, "10.0.0.1", "admin"); !ok {
		t.Fatal("refused before the limit")
	}
	if !fail(t, l, "10.0.0.1", "Admin ") {
		t.Fatal("not locked out at the limit (account names ignore case)")
	}
	if ok, wait := allowed(l, "10.0.0.1", "admin"); ok || wait != 15*time.Minute {
		t.Errorf("allow = %v %v", ok, wait)
	}
	if ok, _ := allowed(l, "10.0.0.2", "admin"); !ok {
		t.Error("another client was refused")
	}
	if ok, _ := allowed(l, "10.0.0.1", "vera"); !ok {
		t.Error("another account from the same client was refused")
	}
	c.t = c.t.Add(16 * time.Minute)
	if ok, _ := allowed(l, "10.0.0.1", "admin"); !ok {
		t.Error("still refused after the lockout")
	}
	// Failures outside the window do not count.
	fail(t, l, "10.0.0.3", "admin")
	fail(t, l, "10.0.0.3", "admin")
	c.t = c.t.Add(16 * time.Minute)
	if fail(t, l, "10.0.0.3", "admin") {
		t.Error("old failures counted")
	}
	a, _, _ := l.Begin("10.0.0.3", "admin")
	a.Succeed()
	fail(t, l, "10.0.0.3", "admin")
	fail(t, l, "10.0.0.3", "admin")
	if ok, _ := allowed(l, "10.0.0.3", "admin"); !ok {
		t.Error("success did not clear its own failures")
	}
}

// A successful sign-in to one account must not reset the count against
// another: otherwise anyone with an account could guess the admin's
// password forever.
func TestLimiterSuccessClearsOnlyItsOwnAccount(t *testing.T) {
	l := NewLimiter()
	for i := 0; i < l.Max-1; i++ {
		fail(t, l, "10.0.0.9", "admin")
	}
	a, ok, _ := l.Begin("10.0.0.9", "vera")
	if !ok {
		t.Fatal("vera refused")
	}
	a.Succeed()
	if !fail(t, l, "10.0.0.9", "admin") {
		t.Error("vera's sign-in reset the failures against admin")
	}
	if ok, _ := allowed(l, "10.0.0.9", "admin"); ok {
		t.Error("admin not locked for this address")
	}
	if ok, _ := allowed(l, "10.0.0.9", "vera"); !ok {
		t.Error("vera locked out by guesses against admin")
	}
}

func TestLimiterPerAddressAndPerAccount(t *testing.T) {
	l := NewLimiter()
	l.Max, l.MaxPerAddress, l.MaxPerAccount = 3, 5, 6
	// One address trying many accounts.
	for i := 0; i < 5; i++ {
		fail(t, l, "10.0.0.1", fmt.Sprintf("user%d", i))
	}
	if ok, _ := allowed(l, "10.0.0.1", "someone-else"); ok {
		t.Error("address not locked after trying many accounts")
	}
	// Many addresses guessing one account: each stays under Max, the
	// account locks at MaxPerAccount, for every address.
	for i := 0; i < 3; i++ {
		fail(t, l, fmt.Sprintf("10.1.0.%d", i), "admin")
		fail(t, l, fmt.Sprintf("10.1.0.%d", i), "admin")
	}
	if ok, _ := allowed(l, "10.2.0.1", "admin"); ok {
		t.Error("account not locked after guesses from many addresses")
	}
	if ok, _ := allowed(l, "10.2.0.1", "vera"); !ok {
		t.Error("another account locked")
	}
}

// Attempts still being checked count, so a burst of parallel guesses
// cannot pass the limit before the first failure is recorded.
func TestLimiterCountsPendingAttempts(t *testing.T) {
	l := NewLimiter()
	var open []*Attempt
	for {
		a, ok, wait := l.Begin("10.0.0.5", "admin")
		if !ok {
			if wait != Busy {
				t.Errorf("wait = %v, want %v", wait, Busy)
			}
			break
		}
		open = append(open, a)
		if len(open) > 100 {
			t.Fatal("no limit on attempts in progress")
		}
	}
	if len(open) != l.Max {
		t.Errorf("%d attempts in progress, want %d", len(open), l.Max)
	}
	for _, a := range open {
		a.Done()
		a.Done() // ending twice does nothing
	}
	if ok, _ := allowed(l, "10.0.0.5", "admin"); !ok {
		t.Error("finished attempts still counted")
	}
}

func TestEndUser(t *testing.T) {
	s := NewSessions(time.Hour)
	a1, a2 := s.Create("ann", false), s.Create("ann", true)
	b := s.Create("ben", false)
	if n := s.EndUser("ANN", a2); n != 1 {
		t.Errorf("ended %d", n)
	}
	if _, ok := s.Lookup(a1); ok {
		t.Error("other session of ann survived")
	}
	if _, ok := s.Lookup(a2); !ok {
		t.Error("kept session ended")
	}
	if got := s.Users(); len(got) != 2 || got[0] != "ann" || got[1] != "ben" {
		t.Errorf("users = %v", got)
	}
	if n := s.EndUser("ann", ""); n != 1 {
		t.Errorf("ended %d", n)
	}
	if _, ok := s.Lookup(b); !ok {
		t.Error("ben's session ended")
	}
}
