// Package auth keeps sign-in sessions for the web UI and limits password
// guessing. Sessions live in memory, so a server restart signs everyone
// out; API clients can keep using HTTP Basic auth.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sort"
	"strings"
	"sync"
	"time"
)

// Session is one signed-in browser.
type Session struct {
	User     string
	Created  time.Time
	LastSeen time.Time
	// Remember keeps the session through idle periods up to MaxAge, for a
	// "keep me signed in" sign-in.
	Remember bool
}

// Sessions stores sessions by a hash of their token, so the tokens
// themselves are never kept.
type Sessions struct {
	// Idle ends a session after this long without a request.
	Idle time.Duration
	// MaxAge ends any session this long after sign-in.
	MaxAge time.Duration
	// Limit bounds how many sessions are kept; the least recently used go
	// first.
	Limit int
	Now   func() time.Time

	mu   sync.Mutex
	byID map[[32]byte]*Session
}

// NewSessions returns a store with the given idle timeout and a 7 day
// maximum age.
func NewSessions(idle time.Duration) *Sessions {
	return &Sessions{Idle: idle, MaxAge: 7 * 24 * time.Hour, Limit: 10000, Now: time.Now, byID: map[[32]byte]*Session{}}
}

func hash(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// Create starts a session and returns its token.
func (s *Sessions) Create(user string, remember bool) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if len(s.byID) >= s.Limit {
		s.evictLocked(len(s.byID) - s.Limit + 1)
	}
	s.byID[hash(token)] = &Session{User: user, Created: now, LastSeen: now, Remember: remember}
	return token
}

// Lookup returns the session for a token and marks it used. Expired
// sessions are removed and not returned.
func (s *Sessions) Lookup(token string) (Session, bool) {
	if token == "" {
		return Session{}, false
	}
	now := s.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	id := hash(token)
	ss, ok := s.byID[id]
	if !ok {
		return Session{}, false
	}
	if s.expired(ss, now) {
		delete(s.byID, id)
		return Session{}, false
	}
	ss.LastSeen = now
	return *ss, true
}

// Delete ends a session.
func (s *Sessions) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byID, hash(token))
}

// EndUser ends every session of a user except the one with token keep
// ("" keeps none), and reports how many ended. Usernames ignore case.
func (s *Sessions) EndUser(user, keep string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	keepID := hash(keep)
	n := 0
	for id, ss := range s.byID {
		if strings.EqualFold(ss.User, user) && (keep == "" || id != keepID) {
			delete(s.byID, id)
			n++
		}
	}
	return n
}

// Len reports how many sessions are stored.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.byID)
}

func (s *Sessions) expired(ss *Session, now time.Time) bool {
	if now.Sub(ss.Created) >= s.MaxAge {
		return true
	}
	return !ss.Remember && now.Sub(ss.LastSeen) >= s.Idle
}

func (s *Sessions) pruneLocked(now time.Time) {
	for id, ss := range s.byID {
		if s.expired(ss, now) {
			delete(s.byID, id)
		}
	}
}

func (s *Sessions) evictLocked(n int) {
	type entry struct {
		id   [32]byte
		seen time.Time
	}
	all := make([]entry, 0, len(s.byID))
	for id, ss := range s.byID {
		all = append(all, entry{id, ss.LastSeen})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seen.Before(all[j].seen) })
	for _, e := range all[:min(n, len(all))] {
		delete(s.byID, e.id)
	}
}

// Limiter slows password guessing: after Max failures from one client
// within Window, that client is refused for Lockout.
type Limiter struct {
	Max     int
	Window  time.Duration
	Lockout time.Duration
	Now     func() time.Time

	mu      sync.Mutex
	clients map[string]*attempts
}

type attempts struct {
	failures    []time.Time
	lockedUntil time.Time
}

// NewLimiter allows 10 failures per 15 minutes, then refuses for 15
// minutes.
func NewLimiter() *Limiter {
	return &Limiter{Max: 10, Window: 15 * time.Minute, Lockout: 15 * time.Minute, Now: time.Now, clients: map[string]*attempts{}}
}

// Allow reports whether a client may try to sign in, and if not, how long
// until it may.
func (l *Limiter) Allow(client string) (bool, time.Duration) {
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.clients[client]
	if !ok {
		return true, 0
	}
	if wait := a.lockedUntil.Sub(now); wait > 0 {
		return false, wait
	}
	return true, 0
}

// Fail records a failed attempt and reports whether the client is now
// locked out.
func (l *Limiter) Fail(client string) bool {
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.clients) > 50000 {
		l.pruneLocked(now)
	}
	a, ok := l.clients[client]
	if !ok {
		a = &attempts{}
		l.clients[client] = a
	}
	keep := a.failures[:0]
	for _, t := range a.failures {
		if now.Sub(t) < l.Window {
			keep = append(keep, t)
		}
	}
	a.failures = append(keep, now)
	if len(a.failures) >= l.Max {
		a.lockedUntil = now.Add(l.Lockout)
		a.failures = nil
		return true
	}
	return false
}

// Succeed clears a client's failures.
func (l *Limiter) Succeed(client string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, client)
}

func (l *Limiter) pruneLocked(now time.Time) {
	for c, a := range l.clients {
		recent := len(a.failures) > 0 && now.Sub(a.failures[len(a.failures)-1]) < l.Window
		if !recent && now.After(a.lockedUntil) {
			delete(l.clients, c)
		}
	}
}
