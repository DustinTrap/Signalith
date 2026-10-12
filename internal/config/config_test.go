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

func TestUsersAndDirectorySettings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "from-the-env")
	os.WriteFile(path, []byte("lookups:\n  dir: lists\n"), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.UsersFile() != filepath.Join(dir, "lists", "users.json") || c.DirectoryFile() != filepath.Join(dir, "lists", "directory.json") {
		t.Errorf("users file = %s, directory file = %s", c.UsersFile(), c.DirectoryFile())
	}
	if s, err := c.LDAP(); s != nil || err != nil {
		t.Errorf("no auth.ldap = %v %v", s, err)
	}
	if !c.CheckPassword("ADMIN", "from-the-env") {
		t.Error("the built-in admin's name should ignore case")
	}
	t.Setenv("SIGNALITH_USERS_FILE", filepath.Join(dir, "elsewhere", "people.json"))
	if c, _ := Load(path); c.UsersFile() != filepath.Join(dir, "elsewhere", "people.json") {
		t.Errorf("env users file = %s", c.UsersFile())
	}

	// auth.ldap: problems are listed with their keys.
	os.WriteFile(path, []byte("auth:\n  ldap:\n    type: ad\n    url: http://dc1\n    bind_dn: CN=svc,DC=corp,DC=example,DC=com\n"), 0o600)
	_, err = Load(path)
	for _, want := range []string{"auth.ldap.url", "auth.ldap.bind_password: set auth.ldap.bind_password, or the SIGNALITH_LDAP_BIND_PASSWORD", "auth.ldap.user_base_dn", "auth.ldap.admin_groups"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error missing %q:\n%v", want, err)
		}
	}
	// A complete block: on by default, Active Directory unless type says
	// otherwise, preset defaults filled in, the password from the
	// environment and never written back to the file.
	os.WriteFile(path, []byte(`auth:
  ldap:
    url: ldaps://dc1.corp.example.com
    bind_dn: CN=svc,DC=corp,DC=example,DC=com
    user_base_dn: DC=corp,DC=example,DC=com
    admin_groups:
      - CN=Signalith Admins,OU=Groups,DC=corp,DC=example,DC=com
`), 0o600)
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "bind-secret")
	c, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := c.LDAP()
	if err != nil || !s.IsEnabled() || s.Type != "ad" || s.BindPassword != "bind-secret" || s.UsernameAttribute != "sAMAccountName" || !s.Nested() {
		t.Errorf("ldap = %+v %v", s, err)
	}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "bind-secret") || strings.Contains(string(raw), "sAMAccountName") {
		t.Errorf("saved file has the env password or filled defaults:\n%s", raw)
	}
}
