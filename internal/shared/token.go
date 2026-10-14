package shared

import (
	"context"
	"strconv"
	"strings"
)

// Behind a load balancer a page may save on one server and read from
// another. Every API answer carries the configuration token,
// "<config index uuid>.<seq>": the highest _seq_no among the tracked
// documents this server has applied. Writers report the _seq_no of the
// tracked document or watch bump they wrote, a number every other
// server's watcher reaches. The page sends the highest token it has seen
// back, and a server that is behind reads the versions once before
// answering (Wait).

// Token returns this server's configuration token, or "" before it has
// read the config index.
func (h *Hub) Token() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.uuid == "" {
		return ""
	}
	return h.uuid + "." + strconv.FormatInt(h.applied, 10)
}

// TokenAfter returns the token for a write that made seq, which this
// server has applied.
func (h *Hub) TokenAfter(seq int64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.uuid == "" {
		return ""
	}
	return h.uuid + "." + strconv.FormatInt(max(seq, h.applied), 10)
}

// ParseToken splits a token into the index uuid and the _seq_no.
func ParseToken(t string) (uuid string, seq int64, ok bool) {
	i := strings.LastIndexByte(t, '.')
	if i <= 0 {
		return "", 0, false
	}
	seq, err := strconv.ParseInt(t[i+1:], 10, 64)
	if err != nil || seq < -1 {
		return "", 0, false
	}
	return t[:i], seq, true
}

// behind reports whether this server has not applied min yet. A token of
// another index (one deleted and made again since) or one that cannot be
// read is never waited for.
func (h *Hub) behind(min string) bool {
	uuid, seq, ok := ParseToken(min)
	if !ok {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return uuid == h.uuid && seq > h.applied
}

// Wait makes sure this server has applied the configuration of token min
// (a page's X-Signalith-Config-Min): when it is behind, it runs one watch
// cycle now, for at most Timing.Wait. It reports stale when it is still
// behind, so the page can try again.
func (h *Hub) Wait(ctx context.Context, min string) (stale bool) {
	if !h.behind(min) {
		return false
	}
	wctx, cancel := context.WithTimeout(ctx, h.opts.Timing.Wait)
	defer cancel()
	// A cycle already running holds the next one up; the wait ends at
	// Timing.Wait all the same.
	done := make(chan struct{})
	go func() {
		_ = h.Kick(wctx)
		close(done)
	}()
	select {
	case <-done:
	case <-wctx.Done():
	}
	return h.behind(min)
}
