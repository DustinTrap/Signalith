package ingest

import (
	"errors"
	"io"
	"net/netip"
)

// DefaultMaxReceiving is how much memory request bodies may hold at once,
// from their first byte until they have been written, when
// Pipeline.MaxReceiving is not set: room for 16 of the largest requests,
// or over a hundred of Fluent Bit's usual chunks of up to 2 MB.
const DefaultMaxReceiving = 16 * MaxBodyBytes

// receiveStep is the first piece of memory a body is given; it grows by
// doubling as more arrives.
const receiveStep = 64 << 10

// ErrSenderBusy means one sender already has its share of the memory for
// batches being received; it should send again shortly (Fluent Bit does
// on a 503).
var ErrSenderBusy = errors.New("this sender already has too many batches arriving at once; send again in a few seconds")

// ReadBody reads an ingest request body of at most MaxBodyBytes from r.
// sender is what the sender is counted under (see clientaddr.Key), or the
// zero Addr for an address that stands for many senders, such as a
// reverse proxy. sizeHint is the announced length, or -1.
//
// Memory for the body is taken from MaxReceiving as the body arrives,
// never ahead of it, so a sender that announces a large body and then
// sends slowly holds only what it has sent. One sender may hold a quarter
// of MaxReceiving. When there is no room, ReadBody returns ErrBusy or
// ErrSenderBusy. Call release once the body has been written.
//
// Read bodies with ReadBody before taking one of Admit's slots: then a
// slow sender only ever holds its connection and its own bytes, never a
// slot other agents are waiting for.
func (p *Pipeline) ReadBody(r io.Reader, sender netip.Addr, sizeHint int64) (body []byte, release func(), err error) {
	held := int64(0)
	release = func() {
		p.unreserve(sender, held)
		held = 0
	}
	fail := func(err error) ([]byte, func(), error) {
		release()
		return nil, func() {}, err
	}
	const maxRead = MaxBodyBytes + 1 // one byte more shows a body is too large
	var buf []byte
	for {
		if len(buf) == cap(buf) {
			if cap(buf) >= maxRead {
				return fail(tooLarge("the request body is larger than %d MB; send smaller batches", MaxBodyBytes>>20))
			}
			n := min(max(2*cap(buf), receiveStep), maxRead)
			if sizeHint >= 0 && sizeHint < int64(n) && sizeHint >= int64(cap(buf)) {
				// A body of known length needs one byte more, to see its end.
				n = int(sizeHint) + 1
			}
			if err := p.reserve(sender, int64(n-cap(buf))); err != nil {
				return fail(err)
			}
			held += int64(n - cap(buf))
			grown := make([]byte, len(buf), n)
			copy(grown, buf)
			buf = grown
		}
		m, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+m]
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(err)
		}
	}
	if len(buf) > MaxBodyBytes {
		return fail(tooLarge("the request body is larger than %d MB; send smaller batches", MaxBodyBytes>>20))
	}
	return buf, release, nil
}

func (p *Pipeline) maxReceiving() int64 {
	if p.MaxReceiving > 0 {
		return p.MaxReceiving
	}
	return DefaultMaxReceiving
}

// reserve takes n bytes of the receive budget for sender.
func (p *Pipeline) reserve(sender netip.Addr, n int64) error {
	limit := p.maxReceiving()
	p.recvMu.Lock()
	if p.recvUsed+n > limit {
		p.recvMu.Unlock()
		p.warn("receive-full", "agent batches arriving at once fill the memory set aside for them; senders are told to retry (logged at most once a minute)",
			"limit_mb", limit>>20)
		return ErrBusy
	}
	if sender.IsValid() {
		if p.recvBy[sender]+n > limit/4 {
			p.recvMu.Unlock()
			p.warn("receive-sender", "one sender has a quarter of the memory set aside for agent batches arriving; it is told to retry. "+
				"If many agents reach Signalith through this address (a proxy, load balancer or NAT), list it under server.shared_addresses (logged at most once a minute)",
				"sender", sender.String(), "limit_mb", (limit/4)>>20)
			return ErrSenderBusy
		}
		if p.recvBy == nil {
			p.recvBy = map[netip.Addr]int64{}
		}
		p.recvBy[sender] += n
	}
	p.recvUsed += n
	p.recvMu.Unlock()
	return nil
}

func (p *Pipeline) unreserve(sender netip.Addr, n int64) {
	if n == 0 {
		return
	}
	p.recvMu.Lock()
	defer p.recvMu.Unlock()
	p.recvUsed -= n
	if sender.IsValid() {
		if p.recvBy[sender] <= n {
			delete(p.recvBy, sender)
		} else {
			p.recvBy[sender] -= n
		}
	}
}
