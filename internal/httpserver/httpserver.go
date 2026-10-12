// Package httpserver builds the web server Signalith serves its UI, API
// and agent ingest on, with timeouts and connection limits so slow, idle
// or numerous clients cannot tie it up before anyone has signed in.
package httpserver

import (
	"bytes"
	"crypto/tls"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// Timeouts and limits for every connection. Request bodies have their own
// deadline per request (see the api package), because a server-wide
// ReadTimeout also cancels a request's context when it passes, which would
// stop long searches.
const (
	// ReadHeaderTimeout is how long a client has to send its request line
	// and headers.
	ReadHeaderTimeout = 10 * time.Second
	// IdleTimeout closes a kept-alive connection that sends no new request
	// for this long. Browsers and Fluent Bit open a new one when needed.
	IdleTimeout = 2 * time.Minute
	// WriteTimeout bounds one request from the end of its headers to the
	// last byte of the response. It is well above the slowest API calls
	// (running a detection or downloading a feed by hand may take 5
	// minutes) so they still finish, and it stops a client that never
	// reads its response from holding the connection forever.
	WriteTimeout = 10 * time.Minute
	// MaxHeaderBytes caps the request line and headers.
	MaxHeaderBytes = 64 << 10
	// DefaultMaxConnections caps open connections in total; more clients
	// wait until one closes. Each connection costs a file descriptor and
	// some memory, so this keeps a flood of connections from using up
	// either while leaving room for thousands of agents.
	DefaultMaxConnections = 10000
)

// New returns a server for handler with Signalith's timeouts. Use Serve to
// run it on a listener from Listen.
func New(handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		WriteTimeout:      WriteTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          errorLog(logger),
	}
}

// Serve runs hs on ln until it is shut down, with TLS when certFile is
// set.
func Serve(hs *http.Server, ln net.Listener, certFile, keyFile string) error {
	if certFile != "" {
		return hs.ServeTLS(ln, certFile, keyFile)
	}
	return hs.Serve(ln)
}

// Limits caps a listener's open connections.
type Limits struct {
	// Max is the most connections open at once; zero uses
	// DefaultMaxConnections. Beyond it, new clients wait for a free slot.
	Max int
	// PerClient is the most connections open at once from one address;
	// zero uses a tenth of Max, at least 16. Beyond it, new connections
	// from that address are closed at once, so one client cannot take
	// every slot. Connections from this machine (loopback) are not
	// counted, so a reverse proxy on the same machine is not held back.
	PerClient int
}

func (l Limits) withDefaults() Limits {
	if l.Max <= 0 {
		l.Max = DefaultMaxConnections
	}
	if l.PerClient <= 0 {
		l.PerClient = max(16, l.Max/10)
	}
	return l
}

// Listen opens a TCP listener on addr with lim applied.
func Listen(addr string, lim Limits, logger *slog.Logger) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	return Limit(ln, lim, logger), nil
}

// Limit wraps ln so it holds at most lim connections open.
func Limit(ln net.Listener, lim Limits, logger *slog.Logger) net.Listener {
	lim = lim.withDefaults()
	return &limitListener{
		Listener: ln,
		lim:      lim,
		slots:    make(chan struct{}, lim.Max),
		done:     make(chan struct{}),
		open:     map[netip.Addr]int{},
		log:      logger,
	}
}

type limitListener struct {
	net.Listener
	lim       Limits
	slots     chan struct{}
	done      chan struct{}
	closeOnce sync.Once

	mu   sync.Mutex
	open map[netip.Addr]int

	log                   *slog.Logger
	refused               atomic.Int64
	lastRefused, lastFull atomic.Int64 // unix nanoseconds of the last warning
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		select {
		case l.slots <- struct{}{}:
		default:
			l.warn(&l.lastFull, "every connection slot is in use; new clients wait until one closes (logged at most once a minute)",
				"limit", l.lim.Max)
			select {
			case l.slots <- struct{}{}:
			case <-l.done:
				return nil, net.ErrClosed
			}
		}
		c, err := l.Listener.Accept()
		if err != nil {
			<-l.slots
			return nil, err
		}
		from := remoteAddr(c)
		if l.admit(from) {
			return &limitConn{Conn: c, l: l, from: from}, nil
		}
		<-l.slots
		c.Close()
		n := l.refused.Add(1)
		l.warn(&l.lastRefused, "connection refused: this address has too many connections open (logged at most once a minute)",
			"client", from.String(), "limit", l.lim.PerClient, "refused_so_far", n)
	}
}

func (l *limitListener) Close() error {
	l.closeOnce.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// admit counts a new connection from an address, or reports false when
// that address already has PerClient open.
func (l *limitListener) admit(from netip.Addr) bool {
	if from.IsLoopback() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[from] >= l.lim.PerClient {
		return false
	}
	l.open[from]++
	return true
}

func (l *limitListener) release(from netip.Addr) {
	<-l.slots
	if from.IsLoopback() {
		return
	}
	l.mu.Lock()
	if l.open[from] <= 1 {
		delete(l.open, from)
	} else {
		l.open[from]--
	}
	l.mu.Unlock()
}

// warn logs at most once a minute per kind of message, so a flood of
// connections cannot flood the log too.
func (l *limitListener) warn(last *atomic.Int64, msg string, args ...any) {
	now := time.Now().UnixNano()
	prev := last.Load()
	if l.log == nil || (prev != 0 && now-prev < int64(time.Minute)) || !last.CompareAndSwap(prev, now) {
		return
	}
	l.log.Warn(msg, args...)
}

func remoteAddr(c net.Conn) netip.Addr {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.AddrPort().Addr().Unmap().WithZone("")
	}
	ap, _ := netip.ParseAddrPort(c.RemoteAddr().String())
	return ap.Addr().Unmap().WithZone("")
}

type limitConn struct {
	net.Conn
	l    *limitListener
	from netip.Addr
	once sync.Once
}

func (c *limitConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.l.release(c.from) })
	return err
}

// errorLog sends net/http's own messages (such as "TLS handshake error
// from ...", which any client can cause) to logger, at most a few a
// minute, so they cannot flood the log.
func errorLog(logger *slog.Logger) *log.Logger {
	if logger == nil {
		return nil
	}
	return log.New(&throttledWriter{log: logger}, "", 0)
}

type throttledWriter struct {
	log        *slog.Logger
	mu         sync.Mutex
	window     time.Time
	n          int
	suppressed int
}

// errorLogBurst is how many net/http messages are logged a minute.
const errorLogBurst = 10

func (w *throttledWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	now := time.Now()
	if now.Sub(w.window) >= time.Minute {
		if w.suppressed > 0 {
			w.log.Warn("http server: more messages like the ones above were not logged", "count", w.suppressed)
		}
		w.window, w.n, w.suppressed = now, 0, 0
	}
	w.n++
	logIt := w.n <= errorLogBurst
	if !logIt {
		w.suppressed++
	}
	w.mu.Unlock()
	if logIt {
		w.log.Warn("http server", "detail", string(bytes.TrimSpace(p)))
	}
	return len(p), nil
}
