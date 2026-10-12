package agents

import (
	"strings"
	"testing"
)

func TestParseServerURLAccepts(t *testing.T) {
	for _, in := range []string{
		"http://192.168.1.20:8080",
		"http://siem.corp.local:8080/",
		"https://siem.example.com",
		"HTTP://Desktop-7Q2K:8080",
		"http://my_pc:1",
		"http://x:65535",
		"http://[::1]:8080",
		"https://[2001:db8::20]:8443",
		"http://localhost:8080",
		"http://a-b_c.example:8080",
		"http://10.0.0.1",
	} {
		if _, err := ParseServerURL(in); err != nil {
			t.Errorf("ParseServerURL(%q) = %v, want ok", in, err)
		}
	}
}

func TestParseServerURLRejects(t *testing.T) {
	for _, in := range []string{
		"",
		" http://a:8080",
		"http://a:8080 ",
		"http://a b:8080",
		"http://a:8080\n[OUTPUT]\n    Name stdout",
		"http://a:8080\r\n    Header X-Evil 1",
		"http://a\n:8080",
		"\nhttp://a:8080",
		"http://a:8080\t",
		"http://a:8080\x00",
		"http://a:8080\u2028",
		"http://a\u0085b:8080",
		"http://a%0Ab:8080",
		"http://a:8080/%0A",
		"http://a:8080/api/ingest",
		"http://a:8080?x=1",
		"http://a:8080/?",
		"http://a:8080#top",
		"ftp://a:21",
		"javascript:alert(1)",
		"http:a",
		"a:8080",
		"192.168.1.20:8080",
		"//a:8080",
		"http://",
		"http:///x",
		"http://user:pw@a:8080",
		"http://user@a",
		"http://a:0",
		"http://a:65536",
		"http://a:080",
		"http://a:",
		"http://a:-1",
		"http://a:http",
		"http://-a:8080",
		"http://a..b:8080",
		"http://a.:8080",
		"http://évil.example:8080",
		"http://a;b:8080",
		"http://[fe80::1%25eth0]:8080",
		"http://[127.0.0.1]:8080",
		"http://::1:8080",
		"http://127.1:8080",
		"http://256.1.1.1",
		"http://999:8080",
		"http://1.2.3.4.5",
		"http://a-:8080",
		"http://" + strings.Repeat("a.", 200) + "com",
	} {
		if u, err := ParseServerURL(in); err == nil {
			t.Errorf("ParseServerURL(%q) = %v, want an error", in, u)
		}
	}
}

func TestIsLoopback(t *testing.T) {
	for in, want := range map[string]bool{
		"http://localhost:8080":         true,
		"http://LocalHost":              true,
		"http://app.localhost:8080":     true,
		"http://127.0.0.1:8080":         true,
		"http://127.10.20.30":           true,
		"http://[::1]:8080":             true,
		"http://0.0.0.0:8080":           true,
		"http://192.168.1.20:8080":      false,
		"http://siem.corp.local:8080":   false,
		"https://localhost.example.com": false,
		"http://[2001:db8::20]:8080":    false,
		"http://128.0.0.1":              false,
	} {
		u, err := ParseServerURL(in)
		if err != nil {
			t.Fatalf("ParseServerURL(%q): %v", in, err)
		}
		if got := IsLoopback(u); got != want {
			t.Errorf("IsLoopback(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestGenerateUsesServerAddress(t *testing.T) {
	a, err := Generate(Options{OS: "linux", ServerURL: "https://192.168.1.20:8443/", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Host             192.168.1.20\n", "Port             8443\n", "tls              On\n"} {
		if !strings.Contains(a.Config, want) {
			t.Errorf("config missing %q:\n%s", want, a.Config)
		}
	}
	if a.ServerURL != "https://192.168.1.20:8443" || a.ServerLoopback {
		t.Errorf("server_url = %q, loopback = %v", a.ServerURL, a.ServerLoopback)
	}

	a, err = Generate(Options{OS: "linux", ServerURL: "https://[2001:db8::20]:8443", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "Host             2001:db8::20\n") || !strings.Contains(a.Config, "tls              On\n") {
		t.Errorf("IPv6 address:\n%s", a.Config)
	}

	a, err = Generate(Options{OS: "windows", ServerURL: "http://localhost", Token: "tok-0123456789abcdef"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.Config, "Port             80\n") || a.ServerURL != "http://localhost" || !a.ServerLoopback {
		t.Errorf("server_url = %q, loopback = %v:\n%s", a.ServerURL, a.ServerLoopback, a.Config)
	}
}

func TestGenerateRejectsInjectedAddress(t *testing.T) {
	for _, in := range []string{
		"http://a:8080\n[OUTPUT]\n    Name stdout\n    Match *",
		"http://a:8080\r\n    Header Authorization Bearer stolen",
		"http://a%0A[OUTPUT]:8080",
		"",
	} {
		a, err := Generate(Options{OS: "linux", ServerURL: in, Token: "tok-0123456789abcdef"})
		if err == nil {
			t.Errorf("Generate with server %q succeeded:\n%s", in, a.Config)
			continue
		}
		if strings.ContainsAny(err.Error(), "\r\n") {
			t.Errorf("error for %q has a raw line break: %q", in, err.Error())
		}
	}
}
