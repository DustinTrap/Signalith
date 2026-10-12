package main

import (
	"io"
	"os"
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
