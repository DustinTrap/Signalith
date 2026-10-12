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
