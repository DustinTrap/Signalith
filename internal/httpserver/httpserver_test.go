package httpserver

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// startServer runs New(handler) on a loopback listener with the given
// timeouts shortened, and returns its address.
func startServer(t *testing.T, handler http.Handler, change func(*http.Server)) string {
	t.Helper()
	hs := New(handler, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if change != nil {
		change(hs)
	}
	ln, err := Listen("127.0.0.1:0", Limits{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go Serve(hs, ln, "", "")
	t.Cleanup(func() { hs.Close() })
	return ln.Addr().String()
}

// closedWithin reports whether the server closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func TestServerSettings(t *testing.T) {
	hs := New(http.NotFoundHandler(), nil)
	if hs.ReadHeaderTimeout != ReadHeaderTimeout || hs.IdleTimeout != IdleTimeout || hs.WriteTimeout != WriteTimeout ||
		hs.MaxHeaderBytes != MaxHeaderBytes || hs.TLSConfig.MinVersion < 0x0303 {
		t.Errorf("server settings: %+v", hs)
	}
	if hs.ReadTimeout != 0 {
		t.Error("ReadTimeout would cancel long searches; request bodies have their own deadline")
	}
}

func TestSlowHeadersAndIdleConnectionsAreClosed(t *testing.T) {
	addr := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }), func(hs *http.Server) {
		hs.ReadHeaderTimeout = 300 * time.Millisecond
		hs.IdleTimeout = 300 * time.Millisecond
	})
	// Headers that never finish.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n")
	if !closedWithin(c, 3*time.Second) {
		t.Error("a connection that never finished its headers was kept open")
	}
	// A kept-alive connection that goes quiet after one request.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	io.WriteString(c2, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c2), nil)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("first request: %v %v", resp, err)
	}
	resp.Body.Close()
	if !closedWithin(c2, 3*time.Second) {
		t.Error("an idle kept-alive connection was kept open")
	}
}

func TestOversizedHeadersRefused(t *testing.T) {
	addr := startServer(t, http.NotFoundHandler(), nil)
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\nX-Big: "+strings.Repeat("a", 2*MaxHeaderBytes)+"\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil || resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversized headers: %v %v", resp, err)
	}
}

// fakeListener hands out in-memory connections from chosen addresses.
type fakeListener struct {
	conns chan net.Conn
	done  chan struct{}
}

type addrConn struct {
	net.Conn
	addr net.Addr
}

func (c addrConn) RemoteAddr() net.Addr { return c.addr }

func (f *fakeListener) Accept() (net.Conn, error) {
	select {
	case c := <-f.conns:
		return c, nil
	case <-f.done:
		return nil, net.ErrClosed
	}
}
func (f *fakeListener) Close() error   { close(f.done); return nil }
func (f *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

func (f *fakeListener) dial(ip string) net.Conn {
	a, b := net.Pipe()
	f.conns <- addrConn{Conn: a, addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 40000}}
	return b
}

func TestPerClientLimit(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	var logs bytes.Buffer
	ln := Limit(fl, Limits{Max: 10, PerClient: 2}, slog.New(slog.NewTextHandler(&logs, nil)))
	defer ln.Close()
	accept := func() net.Conn {
		t.Helper()
		c, err := ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	fl.dial("203.0.113.9")
	fl.dial("203.0.113.9")
	a1, a2 := accept(), accept()
	// The third from the same address is closed at once; another address
	// and this machine still get in.
	third := fl.dial("203.0.113.9")
	fl.dial("198.51.100.7")
	if c := accept(); c.RemoteAddr().String() != "198.51.100.7:40000" {
		t.Fatalf("accepted %v", c.RemoteAddr())
	}
	third.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := third.Read(make([]byte, 1)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("third connection from one address: %v, want it closed", err)
	}
	if !strings.Contains(logs.String(), "too many connections") || strings.Count(logs.String(), "\n") != 1 {
		t.Errorf("log: %s", logs.String())
	}
	for i := 0; i < 3; i++ {
		fl.dial("127.0.0.1")
		accept()
	}
	// Closing one frees its place.
	a1.Close()
	a1.Close() // twice is harmless
	fl.dial("203.0.113.9")
	accept()
	a2.Close()
}

func TestTotalLimitWaits(t *testing.T) {
	fl := &fakeListener{conns: make(chan net.Conn, 10), done: make(chan struct{})}
	ln := Limit(fl, Limits{Max: 2}, nil)
	fl.dial("203.0.113.1")
	fl.dial("203.0.113.2")
	fl.dial("203.0.113.3")
	c1, _ := ln.Accept()
	ln.Accept()
	got := make(chan net.Conn)
	go func() {
		c, _ := ln.Accept()
		got <- c
	}()
	select {
	case <-got:
		t.Fatal("a third connection was accepted while two were open")
	case <-time.After(100 * time.Millisecond):
	}
	c1.Close()
	select {
	case c := <-got:
		if c == nil {
			t.Fatal("no connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closing a connection did not let the next one in")
	}
	ln.Close()
	if _, err := ln.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("accept after close: %v", err)
	}
}

func TestLimitDefaults(t *testing.T) {
	if l := (Limits{}).withDefaults(); l.Max != DefaultMaxConnections || l.PerClient != DefaultMaxConnections/10 {
		t.Errorf("defaults %+v", l)
	}
	if l := (Limits{Max: 50}).withDefaults(); l.PerClient != 16 {
		t.Errorf("small max %+v", l)
	}
}

func TestErrorLogIsThrottled(t *testing.T) {
	var buf syncBuffer
	l := errorLog(slog.New(slog.NewTextHandler(&buf, nil)))
	for i := 0; i < 100; i++ {
		l.Printf("http: TLS handshake error from 203.0.113.9:%d: EOF", i)
	}
	if n := strings.Count(buf.String(), "\n"); n != errorLogBurst {
		t.Errorf("%d lines logged, want %d:\n%s", n, errorLogBurst, buf.String())
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
