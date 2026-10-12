package syslog

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Defaults for the limits in Config.
const (
	DefaultMaxMessageSize = 64 << 10
	DefaultMaxConnections = 1000
	// DefaultIdleTimeout closes TCP connections that sent nothing for this
	// long. It is long because quiet devices (a switch that logs once a
	// day) keep one connection open, and closing it can lose the next
	// message; TCP keepalives find dead senders much sooner.
	DefaultIdleTimeout   = time.Hour
	DefaultBatchSize     = 500
	DefaultFlushInterval = time.Second
	DefaultQueueSize     = 10000
	DefaultQueueBytes    = 64 << 20
	// maxSenders is how many recent senders the stats keep.
	maxSenders = 50
	// maxExtraNamesPerDay caps the distinct cef_* and sd_* field names
	// added per day, well under OpenSearch's 1000 fields per index.
	maxExtraNamesPerDay = 500
	handshakeTimeout    = 10 * time.Second
	writeTimeout        = 30 * time.Second
	finalFlushTimeout   = 10 * time.Second
)

// Config says where the receiver listens and how it treats senders.
type Config struct {
	// UDP, TCP and TLS are host:port listen addresses; empty turns that
	// listener off.
	UDP, TCP, TLS string
	// CertFile and KeyFile are the TLS certificate and key.
	CertFile, KeyFile string
	// Allow lists the senders that may send; empty allows any sender.
	Allow []netip.Prefix
	// Ready, when set, holds back writes until it is closed, so the first
	// syslog indices are created after the index template is in place and
	// get the right field types. Messages wait in the queue meanwhile.
	Ready <-chan struct{}

	// Limits; zero uses the defaults above.
	MaxMessageSize int
	MaxConnections int
	IdleTimeout    time.Duration
	BatchSize      int
	FlushInterval  time.Duration
	QueueSize      int
	QueueBytes     int64
}

// Sink receives batches of events; ingest.Pipeline is one.
type Sink interface {
	IngestEvents(ctx context.Context, events []ingest.Event) (*ingest.Result, error)
}

// Receiver listens for syslog and writes it through a Sink. Network
// readers parse messages and put them on a bounded queue; one writer sends
// them on in batches. UDP readers never wait: when the queue is full the
// message is dropped and counted. TCP readers wait for room instead, which
// slows the sender down rather than losing its messages.
type Receiver struct {
	cfg  Config
	sink Sink
	log  *slog.Logger
	now  func() time.Time

	queue       chan queued
	queuedBytes atomic.Int64

	udp       *net.UDPConn
	lns       []net.Listener
	listeners []Listener
	tlsConf   *tls.Config

	readers  sync.WaitGroup
	done     chan struct{}
	started  bool
	stopOnce sync.Once

	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool

	received, dropped                         atomic.Int64
	notAllowed, tooLarge, badFraming, tooMany atomic.Int64
	lastMessage                               atomic.Int64 // unix nanoseconds
	senders                                   senderTable
	names                                     nameBudget

	warnMu sync.Mutex
	warned map[string]time.Time
}

type queued struct {
	ev   ingest.Event
	size int64
}

// Listener is one address the receiver listens on.
type Listener struct {
	Protocol string `json:"protocol"` // udp, tcp or tls
	Address  string `json:"address"`
}

// Sender is a system that sent syslog recently.
type Sender struct {
	Address  string    `json:"address"`
	Host     string    `json:"host,omitempty"` // host name in its last message
	Protocol string    `json:"protocol"`
	Messages int64     `json:"messages"`
	LastSeen time.Time `json:"last_seen"`
}

// Rejections counts messages and connections turned away.
type Rejections struct {
	NotAllowed         int64 `json:"not_allowed"`          // sender outside syslog.allow
	TooLarge           int64 `json:"too_large"`            // message over the size limit
	BadFraming         int64 `json:"bad_framing"`          // TCP stream with an impossible octet count
	TooManyConnections int64 `json:"too_many_connections"` // TCP connection over the limit
}

// Stats is what the receiver has done since start, for the health page.
type Stats struct {
	Enabled   bool       `json:"enabled"`
	Listeners []Listener `json:"listeners"`
	// Received counts messages accepted from allowed senders.
	Received int64 `json:"received"`
	// Dropped counts received messages lost because the queue was full
	// (OpenSearch slower than the senders) or the server was stopping.
	Dropped    int64      `json:"dropped"`
	Rejected   int64      `json:"rejected"`
	RejectedBy Rejections `json:"rejected_by"`
	Queued     int        `json:"queued"`
	// Connections is the number of open TCP and TLS connections.
	Connections int       `json:"connections"`
	LastMessage time.Time `json:"last_message,omitzero"`
	// Senders are the most recent senders, newest first.
	Senders []Sender `json:"senders"`
}

// New returns a receiver; Start opens its listeners.
func New(cfg Config, sink Sink, log *slog.Logger) *Receiver {
	if cfg.MaxMessageSize <= 0 {
		cfg.MaxMessageSize = DefaultMaxMessageSize
	}
	if cfg.MaxConnections <= 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = DefaultFlushInterval
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.QueueBytes <= 0 {
		cfg.QueueBytes = DefaultQueueBytes
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Receiver{
		cfg:     cfg,
		sink:    sink,
		log:     log,
		now:     time.Now,
		queue:   make(chan queued, cfg.QueueSize),
		done:    make(chan struct{}),
		conns:   map[net.Conn]struct{}{},
		senders: senderTable{max: maxSenders, m: map[netip.Addr]*Sender{}},
		names:   nameBudget{max: maxExtraNamesPerDay, seen: map[string]struct{}{}},
		warned:  map[string]time.Time{},
	}
}

// Start opens every configured listener and starts receiving. It returns
// an error that says what to do when a port cannot be opened. The receiver
// stops when ctx ends; Wait then returns once the queue is written out.
func (r *Receiver) Start(ctx context.Context) error {
	if r.cfg.TLS != "" {
		cert, err := tls.LoadX509KeyPair(r.cfg.CertFile, r.cfg.KeyFile)
		if err != nil {
			return fmt.Errorf("syslog.tls: cannot load the certificate in server.tls_cert and server.tls_key: %w", err)
		}
		r.tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	}
	var lc net.ListenConfig
	if r.cfg.UDP != "" {
		pc, err := lc.ListenPacket(ctx, "udp", r.cfg.UDP)
		if err != nil {
			return bindError("syslog.udp", "udp", r.cfg.UDP, err)
		}
		r.udp = pc.(*net.UDPConn)
		// A bigger socket buffer rides out bursts while a reader is busy.
		_ = r.udp.SetReadBuffer(4 << 20)
		r.listeners = append(r.listeners, Listener{Protocol: "udp", Address: shownAddr(r.cfg.UDP, r.udp.LocalAddr())})
	}
	var protos []string
	for _, l := range []struct{ proto, addr, setting string }{{"tcp", r.cfg.TCP, "syslog.tcp"}, {"tls", r.cfg.TLS, "syslog.tls"}} {
		if l.addr == "" {
			continue
		}
		ln, err := lc.Listen(ctx, "tcp", l.addr)
		if err != nil {
			r.closeListeners()
			return bindError(l.setting, "tcp", l.addr, err)
		}
		r.lns = append(r.lns, ln)
		protos = append(protos, l.proto)
		r.listeners = append(r.listeners, Listener{Protocol: l.proto, Address: shownAddr(l.addr, ln.Addr())})
	}
	for i, ln := range r.lns {
		r.readers.Add(1)
		go r.accept(ctx, ln, protos[i])
	}
	if r.udp != nil {
		for range min(runtime.NumCPU(), 4) {
			r.readers.Add(1)
			go r.readUDP(ctx)
		}
	}
	r.started = true
	go r.write(ctx)
	go func() {
		<-ctx.Done()
		r.stop()
	}()
	return nil
}

// Wait blocks until the receiver has stopped and written out its queue.
// It returns at once if Start was not called or failed.
func (r *Receiver) Wait() {
	if r == nil || !r.started {
		return
	}
	<-r.done
}

// stop closes the listeners and connections, waits for the readers, and
// closes the queue so the writer flushes what is left and finishes.
func (r *Receiver) stop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		r.closing = true
		for c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		r.closeListeners()
		r.readers.Wait()
		close(r.queue)
	})
}

func (r *Receiver) closeListeners() {
	if r.udp != nil {
		r.udp.Close()
	}
	for _, ln := range r.lns {
		ln.Close()
	}
}

// shownAddr is the configured address with the port actually bound, so
// "0.0.0.0:514" stays readable and ":0" in tests shows the real port.
func shownAddr(configured string, actual net.Addr) string {
	host, _, err := net.SplitHostPort(configured)
	if err != nil {
		return actual.String()
	}
	_, port, err := net.SplitHostPort(actual.String())
	if err != nil {
		return actual.String()
	}
	return net.JoinHostPort(host, port)
}

// bindError explains why a listener could not open and what to do.
func bindError(setting, network, addr string, err error) error {
	_, port, _ := net.SplitHostPort(addr)
	p, _ := strconv.Atoi(port)
	other := "a free port"
	switch setting {
	case "syslog.udp", "syslog.tcp":
		other = "another port, such as 0.0.0.0:1514"
	case "syslog.tls":
		other = "another port, such as 0.0.0.0:6515"
	}
	var errno syscall.Errno
	isErrno := errors.As(err, &errno)
	switch {
	case errors.Is(err, syscall.EADDRINUSE) || (isErrno && errno == 10048): // WSAEADDRINUSE
		return fmt.Errorf("%s: cannot listen on %s/%s: the port is already in use, probably by another syslog server such as rsyslog or syslog-ng. Stop that service, or set %s to %s", setting, addr, network, setting, other)
	case isErrno && errno == 10013: // WSAEACCES
		return fmt.Errorf("%s: cannot listen on %s/%s: Windows refused the port; another program may hold it, or it is in a reserved range (see: netsh interface ipv4 show excludedportrange protocol=%s). Set %s to %s", setting, addr, network, network, setting, other)
	case errors.Is(err, os.ErrPermission) && p > 0 && p < 1024:
		return fmt.Errorf("%s: cannot listen on %s/%s: permission denied. Ports below 1024 need extra permission on Linux: run Signalith with the systemd unit from deploy/systemd (it grants CAP_NET_BIND_SERVICE), or grant it once with: sudo setcap cap_net_bind_service=+ep $(command -v signalith); or set %s to a port above 1023, such as 0.0.0.0:1514", setting, addr, network, setting)
	case errors.Is(err, os.ErrPermission):
		return fmt.Errorf("%s: cannot listen on %s/%s: permission denied. Run Signalith as a user that may open this port, or set %s to %s", setting, addr, network, setting, other)
	}
	return fmt.Errorf("%s: cannot listen on %s/%s: %w", setting, addr, network, err)
}

// ---- reading ----

func (r *Receiver) readUDP(ctx context.Context) {
	defer r.readers.Done()
	// Room for the largest datagram, so the size check below sees how
	// big a message really was on every platform.
	buf := make([]byte, max(r.cfg.MaxMessageSize, 65535)+1)
	for {
		n, ap, err := r.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Such as an ICMP error Windows reports on the socket; keep
			// reading, without spinning if it repeats.
			time.Sleep(time.Millisecond)
			continue
		}
		from := ap.Addr().Unmap()
		if !r.allowed(from) {
			r.rejectSender(from)
			continue
		}
		if n > r.cfg.MaxMessageSize {
			r.tooLarge.Add(1)
			continue
		}
		r.handle(ctx, buf[:n], from, "udp", false)
	}
}

func (r *Receiver) accept(ctx context.Context, ln net.Listener, proto string) {
	defer r.readers.Done()
	var delay time.Duration
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return
			}
			// Out of file descriptors and the like: back off and retry.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			r.warn("accept", "syslog listener could not accept a connection; retrying", "protocol", proto, "err", err)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return
			}
			continue
		}
		delay = 0
		from := remoteAddr(c)
		if !r.allowed(from) {
			r.rejectSender(from)
			c.Close()
			continue
		}
		if !r.track(c) {
			r.tooMany.Add(1)
			r.warn("connections", "syslog connection refused: too many open connections", "limit", r.cfg.MaxConnections, "sender", from.String())
			c.Close()
			continue
		}
		r.readers.Add(1)
		go r.serveConn(ctx, c, from, proto)
	}
}

func remoteAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap()
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap.Addr().Unmap()
}

func (r *Receiver) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || len(r.conns) >= r.cfg.MaxConnections {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *Receiver) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
	c.Close()
}

// idleReader closes a connection's read side after a quiet period.
type idleReader struct {
	c    net.Conn
	idle time.Duration
}

func (ir idleReader) Read(p []byte) (int, error) {
	_ = ir.c.SetReadDeadline(time.Now().Add(ir.idle))
	return ir.c.Read(p)
}

func (r *Receiver) serveConn(ctx context.Context, c net.Conn, from netip.Addr, proto string) {
	defer r.readers.Done()
	defer r.untrack(c)
	conn := c
	if proto == "tls" {
		tc := tls.Server(c, r.tlsConf)
		hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			r.warn("handshake", "syslog TLS handshake failed", "sender", from.String(), "err", err)
			return
		}
		conn = tc
	}
	fr := newFramer(idleReader{c: conn, idle: r.cfg.IdleTimeout}, r.cfg.MaxMessageSize)
	for {
		msg, err := fr.Next()
		switch {
		case err == nil:
			r.handle(ctx, msg, from, proto, true)
		case errors.Is(err, errTooLarge):
			r.tooLarge.Add(1)
		case errors.Is(err, errFraming):
			r.badFraming.Add(1)
			r.warn("framing", "closed a syslog connection that sent an impossible octet count", "sender", from.String())
			return
		default:
			return // closed, idle too long, or stopping
		}
	}
}

func (r *Receiver) allowed(a netip.Addr) bool {
	if len(r.cfg.Allow) == 0 {
		return true
	}
	for _, p := range r.cfg.Allow {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// rejectSender counts a sender outside the allow list, logging at most
// once a minute rather than per message.
func (r *Receiver) rejectSender(a netip.Addr) {
	r.notAllowed.Add(1)
	r.warn("allow", "dropped syslog from a sender outside syslog.allow (logged once a minute)", "sender", a.String(), "dropped_so_far", r.notAllowed.Load())
}

// handle parses one message and queues its event. wait says whether to
// wait for room in the queue (TCP) or drop the message when it is full
// (UDP).
func (r *Receiver) handle(ctx context.Context, data []byte, from netip.Addr, proto string, wait bool) {
	now := r.now()
	m := Parse(data, now)
	if m.Raw == "" {
		return
	}
	ev := m.Event(from, now)
	r.names.limit(ev.Fields, now)
	r.received.Add(1)
	r.lastMessage.Store(now.UnixNano())
	r.senders.seen(from, m.Hostname, proto, now)
	if !r.enqueue(ctx, queued{ev: ev, size: int64(2*len(m.Raw) + 512)}, wait) {
		r.dropped.Add(1)
	}
}

// enqueue puts an event on the queue, which is bounded both in events and
// in (estimated) bytes.
func (r *Receiver) enqueue(ctx context.Context, q queued, wait bool) bool {
	for {
		if r.queuedBytes.Add(q.size) <= r.cfg.QueueBytes {
			if wait {
				select {
				case r.queue <- q:
					return true
				case <-ctx.Done():
					r.queuedBytes.Add(-q.size)
					return false
				}
			}
			select {
			case r.queue <- q:
				return true
			default:
				r.queuedBytes.Add(-q.size)
				return false
			}
		}
		r.queuedBytes.Add(-q.size)
		if !wait {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// ---- writing ----

// write sends queued events in batches: when a batch is full or every
// FlushInterval. When the queue closes it sends the rest and finishes.
func (r *Receiver) write(ctx context.Context) {
	defer close(r.done)
	if r.cfg.Ready != nil {
		select {
		case <-r.cfg.Ready:
		case <-ctx.Done():
		}
	}
	tick := time.NewTicker(r.cfg.FlushInterval)
	defer tick.Stop()
	batch := make([]ingest.Event, 0, r.cfg.BatchSize)
	flush := func(timeout time.Duration) {
		if len(batch) == 0 {
			return
		}
		r.send(batch, timeout)
		clear(batch)
		batch = batch[:0]
	}
	for {
		select {
		case q, ok := <-r.queue:
			if !ok {
				flush(finalFlushTimeout)
				return
			}
			r.queuedBytes.Add(-q.size)
			batch = append(batch, q.ev)
			if len(batch) >= r.cfg.BatchSize {
				flush(writeTimeout)
			}
		case <-tick.C:
			flush(writeTimeout)
		}
	}
}

func (r *Receiver) ready() bool {
	if r.cfg.Ready == nil {
		return true
	}
	select {
	case <-r.cfg.Ready:
		return true
	default:
		return false
	}
}

// send writes one batch. Failures are counted by the pipeline (ingest
// stats "failed") and logged at most once a minute; the batch is not
// retried, so a slow or down OpenSearch cannot back up the receiver.
func (r *Receiver) send(batch []ingest.Event, timeout time.Duration) {
	if !r.ready() {
		// Stopping before OpenSearch was ever ready.
		r.dropped.Add(int64(len(batch)))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := r.sink.IngestEvents(ctx, batch)
	if err != nil {
		r.warn("write", "could not write syslog events to OpenSearch; they were dropped", "events", len(batch), "err", err)
		return
	}
	if len(res.Errors) > 0 {
		r.warn("rejected", "OpenSearch rejected some syslog events", "rejected", len(res.Errors), "first", res.Errors[0].Reason)
	}
}

// warn logs a problem at most once a minute per kind.
func (r *Receiver) warn(kind, msg string, args ...any) {
	now := time.Now()
	r.warnMu.Lock()
	last, seen := r.warned[kind]
	if seen && now.Sub(last) < time.Minute {
		r.warnMu.Unlock()
		return
	}
	r.warned[kind] = now
	r.warnMu.Unlock()
	r.log.Warn(msg, args...)
}

// ---- stats ----

// Stats returns the receiver's counters. A nil receiver (syslog off)
// reports enabled false.
func (r *Receiver) Stats() Stats {
	if r == nil {
		return Stats{Listeners: []Listener{}, Senders: []Sender{}}
	}
	s := Stats{
		Enabled:   true,
		Listeners: append([]Listener{}, r.listeners...),
		Received:  r.received.Load(),
		Dropped:   r.dropped.Load(),
		RejectedBy: Rejections{
			NotAllowed:         r.notAllowed.Load(),
			TooLarge:           r.tooLarge.Load(),
			BadFraming:         r.badFraming.Load(),
			TooManyConnections: r.tooMany.Load(),
		},
		Queued:  len(r.queue),
		Senders: r.senders.list(),
	}
	s.Rejected = s.RejectedBy.NotAllowed + s.RejectedBy.TooLarge + s.RejectedBy.BadFraming + s.RejectedBy.TooManyConnections
	if ns := r.lastMessage.Load(); ns > 0 {
		s.LastMessage = time.Unix(0, ns).UTC()
	}
	r.mu.Lock()
	s.Connections = len(r.conns)
	r.mu.Unlock()
	return s
}

// senderTable keeps the most recent senders, evicting the one heard from
// longest ago when full.
type senderTable struct {
	mu  sync.Mutex
	max int
	m   map[netip.Addr]*Sender
}

func (t *senderTable) seen(a netip.Addr, host, proto string, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.m[a]
	if s == nil {
		if len(t.m) >= t.max {
			var oldest netip.Addr
			for k, v := range t.m {
				if !oldest.IsValid() || v.LastSeen.Before(t.m[oldest].LastSeen) {
					oldest = k
				}
			}
			delete(t.m, oldest)
		}
		s = &Sender{Address: a.String()}
		t.m[a] = s
	}
	s.Messages++
	s.LastSeen = at.UTC()
	s.Protocol = proto
	if host != "" {
		s.Host = host
	}
}

func (t *senderTable) list() []Sender {
	t.mu.Lock()
	out := make([]Sender, 0, len(t.m))
	for _, s := range t.m {
		out = append(out, *s)
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		return out[i].Address < out[j].Address
	})
	return out
}

// nameBudget limits how many distinct vendor-specific field names (cef_*,
// sd_*) are added per day, across all senders. Indices are daily, so a
// sender inventing new keys cannot push an index past OpenSearch's field
// limit; names over the budget stay in the raw message.
type nameBudget struct {
	mu   sync.Mutex
	max  int
	day  string
	seen map[string]struct{}
}

func (b *nameBudget) limit(f map[string]any, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if d := now.UTC().Format("2006-01-02"); d != b.day {
		b.day = d
		clear(b.seen)
	}
	for k := range f {
		if !isExtra(k) {
			continue
		}
		if _, ok := b.seen[k]; ok {
			continue
		}
		if len(b.seen) >= b.max {
			delete(f, k)
			continue
		}
		b.seen[k] = struct{}{}
	}
}
