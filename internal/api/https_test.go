package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// newPlainSide serves the plain-HTTP side of the HTTPS port.
func newPlainSide(t *testing.T, change func(*Server)) (*httptest.Server, *Server) {
	t.Helper()
	var srv *Server
	full, _ := newTestServerWith(t, func(s *Server) {
		withUI(s)
		if change != nil {
			change(s)
		}
		srv = s
	})
	full.Close()
	ts := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	t.Cleanup(ts.Close)
	return ts, srv
}

func plainSend(t *testing.T, method, url, body string, hdr map[string]string, cookies ...*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		}
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestPlainHTTPGoesToHTTPS(t *testing.T) {
	ts, _ := newPlainSide(t, nil)
	host := map[string]string{"Host": "siem.example.com:8080"}

	// Pages and API reads: the same address over HTTPS.
	for path, want := range map[string]string{
		"/":                       "https://siem.example.com:8080/",
		"/login?next=%2Fcases":    "https://siem.example.com:8080/login?next=%2Fcases",
		"/api/tls/ca.pem":         "https://siem.example.com:8080/api/tls/ca.pem",
		"/assets/app.css?v=2#top": "https://siem.example.com:8080/assets/app.css?v=2",
	} {
		resp, _ := plainSend(t, "GET", ts.URL+path, "", host)
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != want {
			t.Errorf("GET %s: %d %q, want %s", path, resp.StatusCode, resp.Header.Get("Location"), want)
		}
		if resp.Header.Get("Strict-Transport-Security") != "" {
			t.Errorf("GET %s: HSTS over plain HTTP", path)
		}
	}
	// A Host header that is not a host is not echoed into the redirect.
	resp, _ := plainSend(t, "GET", ts.URL+"/", "", map[string]string{"Host": "evil.example/x"})
	if loc := resp.Header.Get("Location"); loc != "https://127.0.0.1:8080/" {
		t.Errorf("bad Host: Location %q", loc)
	}

	// Passwords and sessions are never taken over plain HTTP.
	resp, body := plainSend(t, "POST", ts.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, host)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "https://siem.example.com:8080/api/login") || len(resp.Cookies()) != 0 {
		t.Errorf("sign-in over plain HTTP: %d %s %v", resp.StatusCode, body, resp.Cookies())
	}
	basic := map[string]string{"Host": "siem.example.com:8080", "Authorization": "Basic YWRtaW46czNjcmV0LXBhc3M="}
	for _, m := range []string{"GET", "POST"} {
		resp, body = plainSend(t, m, ts.URL+"/api/health", "", basic)
		if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "only accepts passwords over HTTPS") {
			t.Errorf("%s with Basic: %d %s", m, resp.StatusCode, body)
		}
	}
	old := &http.Cookie{Name: sessionCookie, Value: "from-before"}
	resp, body = plainSend(t, "GET", ts.URL+"/api/cases", "", host, old)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "sessions") {
		t.Errorf("API with a session over plain HTTP: %d %s", resp.StatusCode, body)
	}
	// A browser with a cookie from before HTTPS: sent on, and told to
	// forget the cookie.
	resp, _ = plainSend(t, "GET", ts.URL+"/", "", host, old)
	if resp.StatusCode != http.StatusPermanentRedirect || len(resp.Cookies()) != 1 || resp.Cookies()[0].MaxAge >= 0 {
		t.Errorf("page with an old cookie: %d %v", resp.StatusCode, resp.Cookies())
	}
	// Other writes are refused, not redirected.
	resp, body = plainSend(t, "POST", ts.URL+"/api/search", `{"query":"*"}`, host)
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "https://") {
		t.Errorf("POST over plain HTTP: %d %s", resp.StatusCode, body)
	}
}

func TestPlainIngest(t *testing.T) {
	batch := `[{"date":1760000000,"log":"Accepted password for bob from 192.0.2.4 port 22 ssh2"}]`
	bearer := map[string]string{"Authorization": "Bearer tok-0123456789abcdef"}

	// A config from before HTTPS was the default: old agents still send.
	ts, s := newPlainSide(t, nil)
	if !s.Config.Server.PlaintextIngest() {
		t.Fatal("plain-text ingest is off for an old config")
	}
	resp, body := plainSend(t, "POST", ts.URL+"/api/ingest", batch, bearer)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("plain ingest allowed: %d %s", resp.StatusCode, body)
	}
	senders := s.Pipeline.PlaintextSenders(time.Time{})
	if len(senders) != 1 || senders[0].Address != "127.0.0.1" || senders[0].Requests != 1 {
		t.Errorf("senders = %+v", senders)
	}
	// A wrong token is refused and not listed as an agent.
	resp, _ = plainSend(t, "POST", ts.URL+"/api/ingest", batch, map[string]string{"Authorization": "Bearer wrong-token-0123456"})
	if resp.StatusCode != http.StatusUnauthorized || s.Pipeline.PlaintextSenders(time.Time{})[0].Requests != 1 {
		t.Errorf("wrong token: %d", resp.StatusCode)
	}
	// The Health page names the agent and says how to move it.
	code, h := do(t, mustServe(t, s), "GET", "/api/health", "", true)
	warn, _ := json.Marshal(h["warnings"])
	if code != 200 || !strings.Contains(string(warn), "127.0.0.1") || !strings.Contains(string(warn), "plaintext_ingest: deny") || h["plaintext_senders"] == nil {
		t.Errorf("health: %d %v", code, h)
	}

	// Denied: the agent is told what to do, and nothing is stored.
	ts, s = newPlainSide(t, func(s *Server) {
		s.Config.Server.TLS = &config.ServerTLS{Mode: "auto", PlaintextIngest: "deny"}
	})
	resp, body = plainSend(t, "POST", ts.URL+"/api/ingest", batch, bearer)
	if resp.StatusCode != http.StatusUpgradeRequired || !strings.Contains(body, "Add data") {
		t.Errorf("plain ingest denied: %d %s", resp.StatusCode, body)
	}
	if len(s.Pipeline.PlaintextSenders(time.Time{})) != 0 || s.Pipeline.Stats().Received != 0 {
		t.Error("a denied batch was counted")
	}
}

// mustServe serves s's normal handler.
func mustServe(t *testing.T, s *Server) *httptest.Server {
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func TestTrustedProxyIsServed(t *testing.T) {
	ts, _ := newPlainSide(t, func(s *Server) { s.Config.Server.TrustedProxies = []string{"127.0.0.1"} })
	hdr := map[string]string{"X-Forwarded-Proto": "https", "Authorization": "Basic YWRtaW46czNjcmV0LXBhc3M="}
	resp, body := plainSend(t, "GET", ts.URL+"/api/health", "", hdr)
	if resp.StatusCode != 200 || resp.Header.Get("Strict-Transport-Security") == "" {
		t.Errorf("trusted proxy: %d %s", resp.StatusCode, body)
	}
	// Not trusted: the header is ignored.
	ts, _ = newPlainSide(t, func(s *Server) { s.Config.Server.TrustedProxies = []string{"192.0.2.1"} })
	if resp, _ := plainSend(t, "GET", ts.URL+"/api/health", "", hdr); resp.StatusCode != http.StatusForbidden {
		t.Errorf("untrusted proxy: %d", resp.StatusCode)
	}
}

func TestSessionCookieOverHTTPS(t *testing.T) {
	var srv *Server
	plain, _ := newTestServerWith(t, func(s *Server) { srv = s })
	ts := httptest.NewTLSServer(srv.Handler())
	defer ts.Close()
	client := ts.Client()
	client.CheckRedirect = noRedirect.CheckRedirect
	req, _ := http.NewRequest("POST", ts.URL+"/api/login", strings.NewReader(`{"username":"admin","password":"s3cret-pass"}`))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	var c *http.Cookie
	for _, x := range resp.Cookies() {
		if x.Value != "" {
			c = x
		}
	}
	if c == nil || c.Name != "__Host-signalith_session" || !c.Secure || c.Path != "/" || c.Domain != "" || !c.HttpOnly {
		t.Fatalf("cookie over HTTPS: %+v", c)
	}
	me := func(url string, cl *http.Client, cookie *http.Cookie) int {
		req, _ := http.NewRequest("GET", url+"/api/me", nil)
		req.AddCookie(cookie)
		resp, err := cl.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := me(ts.URL, client, c); code != 200 {
		t.Errorf("signed in with the __Host- cookie: %d", code)
	}
	// The same token under the plain name is not a session over HTTPS.
	if code := me(ts.URL, client, &http.Cookie{Name: sessionCookie, Value: c.Value}); code != http.StatusUnauthorized {
		t.Errorf("plain cookie name over HTTPS: %d", code)
	}
	// Over plain HTTP (HTTPS off, or a test): the plain name, not Secure.
	_, _, pc := login(t, plain, "admin", "s3cret-pass")
	if pc == nil || pc.Secure {
		t.Errorf("cookie over plain HTTP: %+v", pc)
	}
	// HTTPS off behind a proxy that adds it (public_url https): Secure.
	off, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Server.TLS = &config.ServerTLS{Mode: "off"}
		s.Config.Server.PublicURL = "https://siem.example.com"
	})
	resp = send(t, "POST", off.URL+"/api/login", `{"username":"admin","password":"s3cret-pass"}`, nil)
	if cs := resp.Cookies(); len(cs) != 1 || cs[0].Name != "__Host-signalith_session" || !cs[0].Secure {
		t.Errorf("mode off, https public_url: %+v", cs)
	}
}

func newCertManager(t *testing.T) *tlsauto.Manager {
	t.Helper()
	m, err := tlsauto.New(tlsauto.Options{Dir: t.TempDir(), Names: []string{"siem.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestCACertificateIsPublic(t *testing.T) {
	m := newCertManager(t)
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	resp, err := http.Get(ts.URL + "/api/tls/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != string(m.CAPEM()) || resp.Header.Get("Content-Type") != "application/x-x509-ca-cert" ||
		!strings.Contains(resp.Header.Get("Content-Disposition"), "signalith-ca.crt") {
		t.Errorf("ca.pem: %d %s %v", resp.StatusCode, b, resp.Header)
	}
	// Without a certificate of its own, there is nothing to download.
	ts, _ = newTestServer(t)
	code, body := do(t, ts, "GET", "/api/tls/ca.pem", "", false)
	if code != http.StatusNotFound || !strings.Contains(body["error"].(string), "server.tls.mode is off") {
		t.Errorf("no certificate: %d %v", code, body)
	}
}

func TestAgentConfigTrustsTheCA(t *testing.T) {
	m := newCertManager(t)
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	q := url.Values{"os": {"linux"}, "server": {"https://192.168.1.77:8080"}}
	code, body := do(t, ts, "GET", "/api/agents/config?"+q.Encode(), "", true)
	cfg, _ := body["config"].(string)
	if code != 200 || !strings.Contains(cfg, "tls.ca_file      /etc/fluent-bit/signalith-ca.pem") || body["ca"] != string(m.CAPEM()) ||
		body["ca_fingerprint"] != m.Fingerprint() || body["ca_step"] != float64(2) || body["config_step"] != float64(3) {
		t.Fatalf("agent config: %d %v", code, body)
	}
	// The certificate now covers the address agents use.
	if !m.Covers("192.168.1.77") {
		t.Error("the agent address was not added to the certificate")
	}
}

// Admins see how HTTPS is served, the names the certificate covers and
// the CA's fingerprint, which the Add data page's syslog setups use.
func TestHealthShowsTLS(t *testing.T) {
	m := newCertManager(t)
	ts, _ := newTestServerWith(t, func(s *Server) { s.TLS = m })
	_, body := do(t, ts, "GET", "/api/health", "", true)
	info, _ := body["tls"].(map[string]any)
	names, _ := info["names"].([]any)
	if info == nil || info["mode"] != config.TLSAuto || info["ca_sha256"] != m.Fingerprint() || info["own_ca"] != true ||
		len(names) == 0 || names[0] != "siem.example.com" {
		t.Errorf("tls = %v", body["tls"])
	}
	// Without a certificate there is no CA to give out.
	ts, _ = newTestServer(t)
	_, body = do(t, ts, "GET", "/api/health", "", true)
	if info, _ := body["tls"].(map[string]any); info == nil || info["ca_sha256"] != nil || info["names"] != nil {
		t.Errorf("no certificate: %v", body["tls"])
	}
}

func TestPlaintextWarning(t *testing.T) {
	one := plaintextWarning([]ingest.PlaintextSender{{Address: "192.0.2.4"}})
	if !strings.HasPrefix(one, "An agent still sends") || !strings.Contains(one, ": 192.0.2.4.") || !strings.Contains(one, "plaintext_ingest: deny") {
		t.Errorf("one: %s", one)
	}
	var many []ingest.PlaintextSender
	for _, a := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5", "192.0.2.6", "192.0.2.7"} {
		many = append(many, ingest.PlaintextSender{Address: a})
	}
	if got := plaintextWarning(many); !strings.HasPrefix(got, "7 agents still send") ||
		!strings.Contains(got, "192.0.2.1, 192.0.2.2, 192.0.2.3, 192.0.2.4, 192.0.2.5 and 2 more.") {
		t.Errorf("many: %s", got)
	}
}
