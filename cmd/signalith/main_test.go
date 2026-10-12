package main

import (
	"io"
	"os"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

func TestSyslogMaxAge(t *testing.T) {
	day := 24 * time.Hour
	for days, want := range map[int]time.Duration{0: 7 * day, 90: 7 * day, 7: 7 * day, 3: 3 * day, 1: day} {
		if got := syslogMaxAge(days); got != want {
			t.Errorf("retention %d days: %v, want %v", days, got, want)
		}
	}
}

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
