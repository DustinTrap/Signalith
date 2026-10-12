package ingest

import (
	"net/netip"
	"testing"
	"time"
)

func TestPlaintextSenders(t *testing.T) {
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	p := &Pipeline{Now: func() time.Time { return now }}
	p.NotePlaintext(netip.MustParseAddr("::ffff:10.0.0.5"))
	now = now.Add(time.Minute)
	p.NotePlaintext(netip.MustParseAddr("10.0.0.7"))
	p.NotePlaintext(netip.MustParseAddr("10.0.0.5"))
	p.NotePlaintext(netip.Addr{})
	got := p.PlaintextSenders(time.Time{})
	if len(got) != 2 || got[0].Address != "10.0.0.5" || got[0].Requests != 2 || got[1].Address != "10.0.0.7" {
		t.Errorf("senders = %+v", got)
	}
	if got := p.PlaintextSenders(now.Add(time.Second)); len(got) != 0 {
		t.Errorf("since filter: %+v", got)
	}
	// The table is capped; the one heard from longest ago goes first.
	for i := 0; i < maxPlaintextSenders+10; i++ {
		now = now.Add(time.Second)
		p.NotePlaintext(netip.AddrFrom4([4]byte{192, 0, 2 + byte(i/250), byte(i % 250)}))
	}
	all := p.PlaintextSenders(time.Time{})
	if len(all) != maxPlaintextSenders {
		t.Errorf("%d senders kept", len(all))
	}
	for _, s := range all {
		if s.Address == "10.0.0.7" {
			t.Error("the oldest sender was kept")
		}
	}
}
