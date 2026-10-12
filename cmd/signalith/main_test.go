package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
)

func TestPrintSyslogPorts(t *testing.T) {
	out := func(c *config.Config) string {
		t.Helper()
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout := os.Stdout
		os.Stdout = w
		printSyslogPorts(c)
		os.Stdout = stdout
		w.Close()
		b, _ := io.ReadAll(r)
		return string(b)
	}
	c := &config.Config{Syslog: config.Syslog{UDP: "0.0.0.0:514", TLS: "[::]:6514"}}
	if got := out(c); got != "udp 514 any\ntls 6514 any\n" {
		t.Errorf("got %q", got)
	}
	c.Syslog.Allow = []string{"10.0.0.0/8", " 192.0.2.10 "}
	if got := out(c); got != "udp 514 10.0.0.0/8,192.0.2.10/32\ntls 6514 10.0.0.0/8,192.0.2.10/32\n" {
		t.Errorf("got %q", got)
	}
}

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	f()
	os.Stdout = stdout
	w.Close()
	return string(<-done)
}

func TestPasswdKeepsEnvironmentSecretsOutOfTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password"}); err != nil {
			t.Fatal(err)
		}
	})
	before, _ := os.ReadFile(path)
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "OS-SECRET-PW")
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-ant-ENV-ONLY")
	t.Setenv("SIGNALITH_INGEST_TOKEN", "env-token-0123456789abcdef")
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "http://127.0.0.1:9201")
	t.Setenv("SIGNALITH_NEW_PASSWORD", "second password")
	var err error
	out := captureStdout(t, func() { err = cmdPasswd([]string{"-c", path}) })
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "second password") {
		t.Errorf("the password was printed: %s", out)
	}
	after, _ := os.ReadFile(path)
	for _, secret := range []string{"OS-SECRET-PW", "sk-ant-ENV-ONLY", "env-token-0123456789abcdef", "9201"} {
		if strings.Contains(string(after), secret) {
			t.Errorf("%q from the environment was written to the file", secret)
		}
	}
	// Only the hash line changed.
	b, a := strings.Split(string(before), "\n"), strings.Split(string(after), "\n")
	if len(a) != len(b) {
		t.Fatalf("line count %d -> %d", len(b), len(a))
	}
	for i := range a {
		if a[i] != b[i] && !strings.Contains(a[i], "admin_password_hash:") {
			t.Errorf("line %d changed: %q -> %q", i+1, b[i], a[i])
		}
	}
	for _, k := range []string{"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_OPENSEARCH_URL"} {
		os.Unsetenv(k)
	}
	c, err := config.Load(path)
	if err != nil || !c.CheckPassword("admin", "second password") {
		t.Fatalf("new password does not work: %v", err)
	}
}

func TestReadNewPasswordFromAPipe(t *testing.T) {
	r, w, _ := os.Pipe()
	io.WriteString(w, "a pass phrase with spaces\r\n")
	w.Close()
	pw, err := readNewPassword(r, io.Discard)
	if err != nil || pw != "a pass phrase with spaces" {
		t.Errorf("%q %v", pw, err)
	}
	r2, w2, _ := os.Pipe()
	w2.Close()
	if _, err := readNewPassword(r2, io.Discard); err == nil {
		t.Error("empty input accepted")
	}
}

func TestSyslogSummary(t *testing.T) {
	for _, c := range []struct {
		syslog config.Syslog
		want   string
	}{
		{config.Syslog{}, ""},
		{config.Syslog{UDP: "0.0.0.0:514", TCP: "0.0.0.0:514"}, "UDP 0.0.0.0:514, TCP 0.0.0.0:514"},
		{config.Syslog{UDP: "0.0.0.0:5514", TCP: "0.0.0.0:5514", PublicPort: 514}, "UDP 0.0.0.0:5514, TCP 0.0.0.0:5514 (devices send UDP and TCP to port 514)"},
		{config.Syslog{UDP: "0.0.0.0:5514", PublicPort: 514}, "UDP 0.0.0.0:5514 (devices send UDP to port 514)"},
		{config.Syslog{TCP: "0.0.0.0:5514", TLS: "0.0.0.0:6514", PublicPort: 514}, "TCP 0.0.0.0:5514, TLS 0.0.0.0:6514 (devices send TCP to port 514)"},
		{config.Syslog{TLS: "0.0.0.0:6514", PublicPort: 514}, "TLS 0.0.0.0:6514"},
	} {
		if got := syslogSummary(&config.Config{Syslog: c.syslog}); got != c.want {
			t.Errorf("%+v: %q, want %q", c.syslog, got, c.want)
		}
	}
}

// A new config serves HTTPS with Signalith's own certificate, refuses
// agents over plain HTTP and receives syslog over TLS on 6514.
func TestInitTurnsOnHTTPS(t *testing.T) {
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	out := captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password", "-listen", "0.0.0.0:8080"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Web UI:    https://") || !strings.Contains(out, "docs/https.md") {
		t.Errorf("init output does not point to HTTPS:\n%s", out)
	}
	raw, _ := os.ReadFile(path)
	for _, want := range []string{"mode: auto", "plaintext_ingest: deny", "tls: 0.0.0.0:6514"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config lacks %q:\n%s", want, raw)
		}
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.TLSMode() != config.TLSAuto || c.Server.PlaintextIngest() || c.Syslog.TLS != "0.0.0.0:6514" {
		t.Errorf("mode %s, plaintext %v, syslog.tls %q", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Syslog.TLS)
	}
	if got := httpsSummary(c); !strings.Contains(got, "own certificate") || !strings.Contains(got, "Agents must send over HTTPS") {
		t.Errorf("summary %q", got)
	}
	// -syslog-tls "" leaves it off.
	path2 := filepath.Join(t.TempDir(), "signalith.yaml")
	captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path2, "-admin-password", "first-password", "-syslog-tls="}); err != nil {
			t.Fatal(err)
		}
	})
	if c2, err := config.Load(path2); err != nil || c2.Syslog.TLS != "" {
		t.Errorf("syslog.tls %v %v", c2, err)
	}
}
