package ingest

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// maxPlaintextSenders caps the agents NotePlaintext remembers; when full,
// the one heard from longest ago is forgotten.
const maxPlaintextSenders = 1000

// PlaintextSender is an agent that sent events over plain HTTP, which
// anyone on the network path can read and change.
type PlaintextSender struct {
	Address  string    `json:"address"`
	Requests int64     `json:"requests"`
	LastSeen time.Time `json:"last_seen"`
}

type plaintextSenders struct {
	mu sync.Mutex
	m  map[netip.Addr]*PlaintextSender
}

// NotePlaintext records that the agent at from sent a batch over plain
// HTTP, so admins can find the agents to update before they turn
// plain-text ingest off.
func (p *Pipeline) NotePlaintext(from netip.Addr) {
	if !from.IsValid() {
		return
	}
	from = from.Unmap().WithZone("")
	now := p.now().UTC()
	s := &p.plaintext
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[netip.Addr]*PlaintextSender{}
	}
	e, ok := s.m[from]
	if !ok {
		if len(s.m) >= maxPlaintextSenders {
			var oldest netip.Addr
			for a, x := range s.m {
				if !oldest.IsValid() || x.LastSeen.Before(s.m[oldest].LastSeen) {
					oldest = a
				}
			}
			delete(s.m, oldest)
		}
		e = &PlaintextSender{Address: from.String()}
		s.m[from] = e
	}
	e.Requests++
	e.LastSeen = now
}

// PlaintextSenders lists the agents that sent over plain HTTP since
// since, most recent first.
func (p *Pipeline) PlaintextSenders(since time.Time) []PlaintextSender {
	s := &p.plaintext
	s.mu.Lock()
	out := make([]PlaintextSender, 0, len(s.m))
	for _, e := range s.m {
		if !e.LastSeen.Before(since) {
			out = append(out, *e)
		}
	}
	s.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Address < out[j].Address
	})
	return out
}
