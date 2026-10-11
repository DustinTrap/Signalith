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
