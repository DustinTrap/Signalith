package syslog

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// capture is a Bulker that keeps what it is sent. When block is set,
// Bulk waits for it to close first.
type capture struct {
	mu    sync.Mutex
	docs  []store.IndexedDoc
	block chan struct{}
}

func (c *capture) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	if c.block != nil {
		select {
		case <-c.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.docs = append(c.docs, docs...)
	return nil, nil
}

func (c *capture) all() []store.IndexedDoc {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]store.IndexedDoc{}, c.docs...)
}

func (c *capture) count() int { return len(c.all()) }

// start runs a receiver writing to a pipeline backed by bulk, and stops it
// when the test ends.
func start(t *testing.T, cfg Config, bulk *capture) (*Receiver, *ingest.Pipeline, context.CancelFunc) {
	t.Helper()
	p := &ingest.Pipeline{Store: bulk, Prefix: "sig"}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = 20 * time.Millisecond
	}
	r := New(cfg, p, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := r.Start(ctx); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		r.Wait()
	})
	return r, p, cancel
}

// addr returns the address a listener of the receiver is bound to.
func addr(t *testing.T, r *Receiver, proto string) string {
	t.Helper()
	for _, l := range r.Stats().Listeners {
		if l.Protocol == proto {
			return l.Address
		}
	}
	t.Fatalf("no %s listener in %+v", proto, r.Stats().Listeners)
	return ""
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func sendUDP(t *testing.T, to string, msgs ...string) {
	t.Helper()
	c, err := net.Dial("udp", to)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, m := range msgs {
		if _, err := c.Write([]byte(m)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestUDP(t *testing.T) {
	bulk := &capture{}
	r, p, _ := start(t, Config{UDP: "127.0.0.1:0"}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<38>1 2026-10-12T13:59:00Z web1 sshd 811 - - Failed password for root from 192.0.2.4 port 40122 ssh2\n")
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	d := bulk.all()[0]
	if d.Index != "sig-authentication-2026.10.12" {
		t.Errorf("index = %s", d.Index)
	}
	check(t, "udp", d.Doc, map[string]any{"user": "root", "action": "failure", "host": "web1", "dvc": "127.0.0.1", "sourcetype": "syslog", "app": "sshd"})
	s := r.Stats()
	if !s.Enabled || s.Received != 1 || s.Dropped != 0 || s.Rejected != 0 || s.LastMessage.IsZero() {
		t.Errorf("stats = %+v", s)
	}
	if len(s.Senders) != 1 || s.Senders[0].Address != "127.0.0.1" || s.Senders[0].Host != "web1" || s.Senders[0].Protocol != "udp" || s.Senders[0].Messages != 1 {
		t.Errorf("senders = %+v", s.Senders)
	}
	if ps := p.Stats(); ps.Received != 1 || ps.Indexed != 1 {
		t.Errorf("pipeline stats = %+v", ps)
	}
}

func TestTCPFramingOnOneConnection(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{TCP: "127.0.0.1:0"}, bulk)
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	octet := "<13>1 2026-10-12T13:00:00Z h app - - - two\nlines"
	stream := "<13>Oct 12 13:00:00 h app: first\n" + fmt.Sprintf("%d %s", len(octet), octet) + "<13>Oct 12 13:00:01 h app: third\n"
	for i := 0; i < len(stream); i += 7 { // partial writes
		end := min(i+7, len(stream))
		if _, err := c.Write([]byte(stream[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "three events", func() bool { return bulk.count() == 3 })
	docs := bulk.all()
	for i, want := range []string{"<13>Oct 12 13:00:00 h app: first", octet, "<13>Oct 12 13:00:01 h app: third"} {
		if docs[i].Doc["message"] != want {
			t.Errorf("event %d message = %q, want %q", i, docs[i].Doc["message"], want)
		}
	}
	if s := r.Stats(); s.Connections != 1 || s.Senders[0].Protocol != "tcp" {
		t.Errorf("stats = %+v", s)
	}
}

func writeCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signalith test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

func TestTLS(t *testing.T) {
	certFile, keyFile := writeCert(t)
	bulk := &capture{}
	r, _, _ := start(t, Config{TLS: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile}, bulk)
	pemBytes, _ := os.ReadFile(certFile)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemBytes)
	c, err := tls.Dial("tcp", addr(t, r, "tls"), &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	msg := "<86>1 2026-10-12T13:00:00Z web1 useradd 900 - - new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash"
	fmt.Fprintf(c, "%d %s", len(msg), msg)
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
	c.Close()
	d := bulk.all()[0]
	if d.Index != "sig-change-2026.10.12" || d.Doc["object"] != "backdoor" {
		t.Errorf("event = %s %v", d.Index, d.Doc)
	}
	if s := r.Stats(); s.Senders[0].Protocol != "tls" {
		t.Errorf("senders = %+v", s.Senders)
	}

	// Plain text to the TLS port is not syslog.
	plain, err := net.Dial("tcp", addr(t, r, "tls"))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(plain, "<13>Oct 12 13:00:00 h app: not encrypted\n")
	plain.SetReadDeadline(time.Now().Add(5 * time.Second))
	io.Copy(io.Discard, plain) // the server hangs up
	plain.Close()
	if bulk.count() != 1 {
		t.Errorf("plain text over the TLS port was accepted")
	}
}

func TestTLSNeedsCertificate(t *testing.T) {
	r := New(Config{TLS: "127.0.0.1:0", CertFile: "/nonexistent/cert.pem", KeyFile: "/nonexistent/key.pem"}, &ingest.Pipeline{Store: &capture{}}, nil)
	err := r.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "server.tls_cert") {
		t.Errorf("err = %v", err)
	}
}

func TestAllowList(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<13>Oct 12 13:00:00 h app: from outside")
	waitFor(t, "the UDP rejection", func() bool { return r.Stats().RejectedBy.NotAllowed == 1 })
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection from a sender outside the allow list stayed open")
	}
	c.Close()
	s := r.Stats()
	if s.RejectedBy.NotAllowed != 2 || s.Rejected != 2 || s.Received != 0 || len(s.Senders) != 0 || bulk.count() != 0 {
		t.Errorf("stats = %+v, events %d", s, bulk.count())
	}

	bulk2 := &capture{}
	r2, _, _ := start(t, Config{UDP: "127.0.0.1:0", Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}, bulk2)
	sendUDP(t, addr(t, r2, "udp"), "<13>Oct 12 13:00:00 h app: allowed")
	waitFor(t, "the allowed event", func() bool { return bulk2.count() == 1 })
}

func TestFullQueueDropsUDP(t *testing.T) {
	bulk := &capture{block: make(chan struct{})}
	r, p, _ := start(t, Config{UDP: "127.0.0.1:0", QueueSize: 5, BatchSize: 1, FlushInterval: 5 * time.Millisecond}, bulk)
	var msgs []string
	for i := range 50 {
		msgs = append(msgs, fmt.Sprintf("<13>Oct 12 13:00:00 h app: message %d", i))
	}
	sendUDP(t, addr(t, r, "udp"), msgs...)
	waitFor(t, "all 50 to be read", func() bool { return r.Stats().Received == 50 })
	s := r.Stats()
	// One batch is stuck in OpenSearch and five wait in the queue.
	if s.Dropped < 40 || s.Dropped > 45 {
		t.Errorf("dropped = %d", s.Dropped)
	}
	close(bulk.block)
	waitFor(t, "the rest to be written", func() bool { return p.Stats().Indexed == 50-s.Dropped })
}

func TestTCPWaitsWhenQueueIsFull(t *testing.T) {
	bulk := &capture{block: make(chan struct{})}
	r, p, _ := start(t, Config{TCP: "127.0.0.1:0", QueueSize: 2, BatchSize: 1, FlushInterval: 5 * time.Millisecond}, bulk)
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := range 20 {
		fmt.Fprintf(c, "<13>Oct 12 13:00:00 h app: message %d\n", i)
	}
	time.Sleep(100 * time.Millisecond)
	if s := r.Stats(); s.Dropped != 0 || s.Received > 5 {
		t.Errorf("while blocked: %+v", s)
	}
	close(bulk.block)
	waitFor(t, "all 20", func() bool { return p.Stats().Indexed == 20 })
	if s := r.Stats(); s.Dropped != 0 {
		t.Errorf("dropped = %d", s.Dropped)
	}
}

func TestWaitsUntilReady(t *testing.T) {
	ready := make(chan struct{})
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", Ready: ready}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<13>Oct 12 13:00:00 h app: early")
	waitFor(t, "the message", func() bool { return r.Stats().Received == 1 })
	time.Sleep(50 * time.Millisecond)
	if bulk.count() != 0 {
		t.Fatal("written before the index template was ready")
	}
	close(ready)
	waitFor(t, "the event", func() bool { return bulk.count() == 1 })
}

func TestStopFlushesTheQueue(t *testing.T) {
	bulk := &capture{}
	r, _, cancel := start(t, Config{TCP: "127.0.0.1:0", FlushInterval: time.Hour, BatchSize: 1000}, bulk)
	c, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		fmt.Fprintf(c, "<13>Oct 12 13:00:00 h app: message %d\n", i)
	}
	waitFor(t, "three messages", func() bool { return r.Stats().Received == 3 })
	if bulk.count() != 0 {
		t.Fatal("flushed early")
	}
	cancel()
	r.Wait()
	if bulk.count() != 3 {
		t.Errorf("after stop: %d events written", bulk.count())
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Error("connection still open after stop")
	}
	c.Close()
}

func TestLimits(t *testing.T) {
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", MaxMessageSize: 100, MaxConnections: 1, IdleTimeout: 300 * time.Millisecond}, bulk)
	sendUDP(t, addr(t, r, "udp"), "<13>"+strings.Repeat("x", 200))
	waitFor(t, "the too-large UDP message", func() bool { return r.Stats().RejectedBy.TooLarge == 1 })

	a, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	fmt.Fprintf(a, "<13>%s\n<13>Oct 12 13:00:00 h app: fits\n", strings.Repeat("y", 200))
	waitFor(t, "the fitting message", func() bool { return bulk.count() == 1 })
	if s := r.Stats(); s.RejectedBy.TooLarge != 2 || s.Connections != 1 {
		t.Errorf("stats = %+v", s)
	}

	b, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Error("connection over the limit stayed open")
	}
	b.Close()
	if s := r.Stats(); s.RejectedBy.TooManyConnections != 1 {
		t.Errorf("too many connections = %d", s.RejectedBy.TooManyConnections)
	}

	// The idle connection is closed, which frees its slot.
	a.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := a.Read(make([]byte, 1)); err == nil {
		t.Error("idle connection stayed open")
	}
	waitFor(t, "the slot to free", func() bool { return r.Stats().Connections == 0 })

	bad, err := net.Dial("tcp", addr(t, r, "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	fmt.Fprint(bad, "123456789 <13>x")
	waitFor(t, "the framing error", func() bool { return r.Stats().RejectedBy.BadFraming == 1 })
}

func TestBindErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, cfg := range []Config{{TCP: ln.Addr().String()}, {UDP: pc.LocalAddr().String()}, {UDP: "127.0.0.1:0", TCP: ln.Addr().String()}} {
		err := New(cfg, &ingest.Pipeline{Store: &capture{}}, nil).Start(context.Background())
		if err == nil || !strings.Contains(err.Error(), "already in use") || !strings.Contains(err.Error(), "1514") {
			t.Errorf("%+v: err = %v", cfg, err)
		}
	}

	denied := &net.OpError{Op: "listen", Net: "udp", Err: os.NewSyscallError("bind", syscall.EACCES)}
	msg := bindError("syslog.udp", "udp", "0.0.0.0:514", denied).Error()
	for _, want := range []string{"syslog.udp", "0.0.0.0:514", "permission denied", "CAP_NET_BIND_SERVICE", "deploy/systemd", "setcap", "0.0.0.0:1514"} {
		if !strings.Contains(msg, want) {
			t.Errorf("permission error lacks %q: %s", want, msg)
		}
	}
	other := bindError("syslog.tcp", "tcp", "10.9.9.9:514", errors.New("cannot assign requested address")).Error()
	if !strings.Contains(other, "syslog.tcp: cannot listen on 10.9.9.9:514/tcp: cannot assign requested address") {
		t.Errorf("other error = %s", other)
	}
}

func TestNilReceiver(t *testing.T) {
	var r *Receiver
	s := r.Stats()
	if s.Enabled || s.Listeners == nil || s.Senders == nil {
		t.Errorf("stats = %+v", s)
	}
	r.Wait()
}

func TestSenderTableKeepsTheMostRecent(t *testing.T) {
	st := senderTable{max: 3, m: map[netip.Addr]*Sender{}}
	for i := range 5 {
		st.seen(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), "", "udp", now.Add(time.Duration(i)*time.Second))
	}
	st.seen(netip.AddrFrom4([4]byte{10, 0, 0, 2}), "h2", "tcp", now.Add(time.Minute))
	got := st.list()
	if len(got) != 3 || got[0].Address != "10.0.0.2" || got[0].Messages != 2 || got[0].Host != "h2" || got[1].Address != "10.0.0.4" || got[2].Address != "10.0.0.3" {
		t.Errorf("senders = %+v", got)
	}
}

// TestLoggerClient sends with the util-linux logger command, the way a
// Linux server without an agent forwards its logs, in every framing it
// supports.
func TestLoggerClient(t *testing.T) {
	logger, err := exec.LookPath("logger")
	if err != nil {
		t.Skip("logger (util-linux) not installed")
	}
	if out, err := exec.Command(logger, "--help").CombinedOutput(); err != nil || !strings.Contains(string(out), "--server") {
		t.Skip("this logger cannot send to a server")
	}
	bulk := &capture{}
	r, _, _ := start(t, Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0"}, bulk)
	modes := [][]string{
		{"--udp", "--rfc3164"},
		{"--udp", "--rfc5424"},
		{"--tcp", "--rfc3164"},
		{"--tcp", "--rfc5424"},
		{"--tcp", "--rfc5424", "--octet-count"},
	}
	for i, mode := range modes {
		proto := strings.TrimPrefix(mode[0], "--")
		_, port, _ := net.SplitHostPort(addr(t, r, proto))
		args := append([]string{"--server", "127.0.0.1", "--port", port, "-t", "sshd", "--id=4242"}, mode[1:]...)
		args = append(args, mode[0], fmt.Sprintf("Failed password for invalid user oracle%d from 192.0.2.4 port 4022 ssh2", i))
		if out, err := exec.Command(logger, args...).CombinedOutput(); err != nil {
			t.Fatalf("logger %v: %v %s", args, err, out)
		}
		waitFor(t, fmt.Sprintf("logger %v", mode), func() bool { return bulk.count() == i+1 })
		d := bulk.all()[i]
		check(t, strings.Join(mode, " "), d.Doc, map[string]any{
			"datamodel": "Authentication", "action": "failure", "user": fmt.Sprintf("oracle%d", i), "src": "192.0.2.4",
			"app": "sshd", "process_id": int64(4242), "dvc": "127.0.0.1", "facility": "user", "severity": "notice",
		})
		if !strings.HasPrefix(d.Index, "sig-authentication-") {
			t.Errorf("%v: index %s", mode, d.Index)
		}
	}
}
