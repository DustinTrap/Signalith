package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitSaveLoadRoundTrip(t *testing.T) {
	c := Default()
	h, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	c.Auth.AdminPasswordHash = h
	c.Ingest.Tokens = []string{RandomToken(16)}
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.CheckPassword("admin", "correct horse") || got.CheckPassword("admin", "wrong") {
		t.Error("password check failed")
	}
	if got.Server.PublicURL != "http://127.0.0.1:8080" {
		t.Errorf("public url = %s", got.Server.PublicURL)
	}
}

func TestValidationListsEveryProblem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	os.WriteFile(path, []byte("server:\n  listen: nonsense\nopensearch:\n  url: ftp://x\n  index_prefix: Bad Prefix\nretention:\n  days: -1\n"), 0o600)
	_, err := Load(path)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"server.listen", "opensearch.url", "index_prefix", "retention.days", "admin_password_hash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.yaml")
	os.WriteFile(path, []byte("retension:\n  days: 30\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "retension") {
		t.Errorf("typo not reported: %v", err)
	}
}

func TestEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.yaml")
	os.WriteFile(path, []byte("search:\n  max_events: 500\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "from-the-env")
	t.Setenv("SIGNALITH_OPENSEARCH_URL", "https://os.internal:9200")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !c.CheckPassword("admin", "from-the-env") || c.OpenSearch.URL != "https://os.internal:9200" || c.Search.MaxEvents != 500 {
		t.Errorf("env not applied: %+v", c)
	}
}

func TestPublicURL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "url.yaml")
	os.WriteFile(path, []byte("server:\n  listen: 0.0.0.0:8080\n  public_url: http://localhost:8080\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	t.Setenv("SIGNALITH_PUBLIC_URL", "http://192.168.1.20:8080")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.PublicURL != "http://192.168.1.20:8080" {
		t.Errorf("SIGNALITH_PUBLIC_URL not applied: %s", c.Server.PublicURL)
	}
	// The environment value is checked like the file's, so a line break
	// can never reach a generated agent config.
	for _, bad := range []string{"http://192.168.1.20:8080\n[OUTPUT]", "192.168.1.20:8080", "http://192.168.1.20:8080/siem"} {
		t.Setenv("SIGNALITH_PUBLIC_URL", bad)
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_PUBLIC_URL") {
			t.Errorf("SIGNALITH_PUBLIC_URL=%q: want an error naming it, got %v", bad, err)
		}
	}
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	os.WriteFile(path, []byte("server:\n  public_url: \"http://siem:8080\\n[OUTPUT]\"\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "server.public_url") {
		t.Errorf("line break in public_url: want an error, got %v", err)
	}
}

func TestAssistantSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ai.yaml")
	os.WriteFile(path, []byte("assistant:\n  provider: openia\n  url: localhost:11434\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	_, err := Load(path)
	for _, want := range []string{"assistant.provider", "assistant.url"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	os.WriteFile(path, []byte("assistant:\n  provider: anthropic\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "SIGNALITH_ASSISTANT_API_KEY") {
		t.Errorf("missing key not reported: %v", err)
	}
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "sk-test")
	c, err := Load(path)
	if err != nil || c.Assistant.APIKey != "sk-test" {
		t.Errorf("env key: %v %+v", err, c)
	}
}

func TestIntelFeeds(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	good := filepath.Join(dir, "good.yaml")
	os.WriteFile(good, []byte(`intel:
  feeds:
    - name: feodo-tracker
      url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
    - name: urlhaus
      url: https://urlhaus.abuse.ch/downloads/csv_recent/
      format: csv
      column: url
      type: url
      interval: 30m
      weight: 1.5
      enabled: false
`), 0o600)
	c, err := Load(good)
	if err != nil {
		t.Fatal(err)
	}
	f := c.Intel.Feeds[0]
	if f.Format != "lines" || f.Type != "auto" || f.Interval != "1h" || f.MaxAge != "7d" || f.Weight != 1 || !f.IsEnabled() {
		t.Errorf("defaults = %+v", f)
	}
	if c.Intel.Feeds[1].IsEnabled() {
		t.Error("enabled: false ignored")
	}
	if d, err := ParseFeedDuration("2w"); err != nil || d.Hours() != 336 {
		t.Errorf("2w = %v %v", d, err)
	}

	bad := filepath.Join(dir, "bad.yaml")
	os.WriteFile(bad, []byte(`intel:
  feeds:
    - name: Bad Name
      url: ftp://x
      format: xml
      type: ipv4
    - name: csvfeed
      url: https://example.com/a.csv
      format: csv
      interval: 1m
      max_age: 30s
      weight: 20
      headers: {Authorization: "Bearer ${SIGNALITH_TEST_UNSET_KEY}"}
    - name: csvfeed
      url: https://example.com/b
    - name: manual
      url: https://example.com/c
      column: "2"
`), 0o600)
	_, err = Load(bad)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{
		"intel.feeds[0] (Bad Name): name must be", `url "ftp://x"`, `format "xml"`, `type "ipv4"`,
		"csv feeds need a column", "interval must be at least 5m", "max_age:", "weight must be",
		"${SIGNALITH_TEST_UNSET_KEY}", "intel.feeds[2] (csvfeed): name is used", `name "manual" is reserved`,
		"column only applies to format: csv",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestDashboardSettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dash.yaml")
	os.WriteFile(path, []byte("dashboards:\n  dir: \"\"\n  stale_after: soon\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	_, err := Load(path)
	for _, want := range []string{"dashboards.dir", "dashboards.stale_after"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q: %v", want, err)
		}
	}
	os.WriteFile(path, []byte("dashboards:\n  stale_after: 1d\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.DashboardsDir() != filepath.Join(dir, "dashboards") || c.StaleAfter().Hours() != 24 {
		t.Errorf("dir %s stale %v", c.DashboardsDir(), c.StaleAfter())
	}
	other := filepath.Join(t.TempDir(), "dash")
	t.Setenv("SIGNALITH_DASHBOARDS_DIR", other)
	if c, err := Load(path); err != nil || c.DashboardsDir() != other {
		t.Errorf("env dir: %v %v", err, c)
	}
}

func TestSyslogSettings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	path := filepath.Join(dir, "syslog.yaml")

	// Absent means off, so existing configs keep working as before.
	os.WriteFile(path, []byte("search:\n  max_events: 500\n"), 0o600)
	c, err := Load(path)
	if err != nil || c.Syslog.Enabled() {
		t.Fatalf("absent syslog section: %v %+v", err, c.Syslog)
	}

	os.WriteFile(path, []byte(`syslog:
  udp: 0.0.0.0:514
  tcp: 127.0.0.1:1514
  allow: [10.0.0.0/8, 192.0.2.7, "::ffff:198.51.100.0/120", "2001:db8::/32"]
`), 0o600)
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, p := range c.Syslog.AllowList() {
		got = append(got, p.String())
	}
	if !c.Syslog.Enabled() || strings.Join(got, " ") != "10.0.0.0/8 192.0.2.7/32 198.51.100.0/24 2001:db8::/32" {
		t.Errorf("allow = %v, syslog %+v", got, c.Syslog)
	}

	os.WriteFile(path, []byte(`server:
  listen: 0.0.0.0:6514
syslog:
  udp: "514"
  tcp: 0.0.0.0:99999
  tls: 0.0.0.0:6514
  allow: [10.0.0.0/33, not-an-ip]
`), 0o600)
	_, err = Load(path)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{
		`syslog.udp "514" must be host:port`, `syslog.tcp port "99999"`, "server.listen and syslog.tls both use 0.0.0.0:6514",
		"syslog.tls needs server.tls_cert and server.tls_key", `syslog.allow[0] "10.0.0.0/33"`, `syslog.allow[1] "not-an-ip"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}

	// Docker: listen on 5514, devices send to the 514 published for it.
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:5514\n  tcp: 0.0.0.0:5514\n  public_port: 514\n"), 0o600)
	if c, err := Load(path); err != nil || c.Syslog.PublicPort != 514 {
		t.Errorf("public_port: %v %+v", err, c.Syslog)
	}
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:5514\n  public_port: 70000\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "syslog.public_port 70000 must be 1-65535") {
		t.Errorf("public_port 70000: %v", err)
	}

	os.WriteFile(path, []byte("syslog:\n  udp: myhost:514\n  tcp: 0.0.0.0:514\n  tls: :514\n"), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), `syslog.udp host "myhost"`) || !strings.Contains(err.Error(), "syslog.tcp and syslog.tls both use :514") {
		t.Errorf("err = %v", err)
	}
}

func TestSyslogEnvOverrides(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env.yaml")
	os.WriteFile(path, []byte("syslog:\n  udp: 0.0.0.0:514\n  tcp: 0.0.0.0:514\n"), 0o600)
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "long-enough-password")
	t.Setenv("SIGNALITH_SYSLOG_UDP", "0.0.0.0:5514")
	t.Setenv("SIGNALITH_SYSLOG_TCP", "off")
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Syslog.UDP != "0.0.0.0:5514" || c.Syslog.TCP != "" {
		t.Errorf("syslog = %+v", c.Syslog)
	}
}

func TestSavedFileExplainsSyslog(t *testing.T) {
	c := Default()
	h, _ := HashPassword("correct horse")
	c.Auth.AdminPasswordHash = h
	c.Syslog.UDP, c.Syslog.TCP = "0.0.0.0:514", "0.0.0.0:514"
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	text := string(data)
	for _, want := range []string{"# syslog.udp, .tcp", "# appliances, servers). Point them at this server on UDP or TCP port 514.", "sender.\nsyslog:\n", "udp: 0.0.0.0:514"} {
		if !strings.Contains(text, want) {
			t.Errorf("saved file lacks %q:\n%s", want, text)
		}
	}
	got, err := Load(path)
	if err != nil || got.Syslog.UDP != "0.0.0.0:514" || got.Syslog.TCP != "0.0.0.0:514" {
		t.Errorf("reload: %v %+v", err, got.Syslog)
	}
}
