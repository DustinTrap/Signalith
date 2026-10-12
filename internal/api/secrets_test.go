package api

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// TestHealthWarnsAboutSecrets checks the admin health reply: plain text
// passwords in signalith.yaml, a master key from SIGNALITH_MASTER_KEY,
// and a directory password that cannot be decrypted are all reported.
func TestHealthWarnsAboutSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	h, _ := config.HashPassword("s3cret-pass")
	if err := os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+h+"\nopensearch:\n  password: plain-os-pw\ningest:\n  tokens: [tok-0123456789abcdef]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// directory.json written with another master key.
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal(users.BindPasswordField, "bind-pw")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("SIGNALITH_MASTER_KEY", "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=")
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dirFile := filepath.Join(dir, "directory.json")
	os.WriteFile(dirFile, []byte(`{"version":1,"settings":{"type":"ad","url":"ldaps://dc1.example.com","bind_dn":"CN=svc,DC=example,DC=com","user_base_dn":"DC=example,DC=com","admin_groups":["CN=A,DC=example,DC=com"]},"bind_password":"`+sealed+`"}`), 0o600)
	d, err := users.OpenDirectory(dirFile, nil)
	if err != nil {
		t.Fatal(err)
	}

	ts, _ := newTestServerWith(t, func(s *Server) { s.Config, s.Directory = cfg, d })
	_, body := do(t, ts, "GET", "/api/health", "", true)
	w := fmt.Sprint(body["warnings"])
	for _, want := range []string{
		"2 passwords or keys in signalith.yaml are stored as plain text (opensearch.password, ingest.tokens[0]). Run: signalith secrets encrypt",
		"SIGNALITH_MASTER_KEY",
		"Directory sign-in cannot search for users until the service account password is entered again",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "plain-os-pw") || strings.Contains(w, "bind-pw") {
		t.Errorf("warnings show a secret: %s", w)
	}
	_, view := do(t, ts, "GET", "/api/auth/directory", "", true)
	if !strings.Contains(fmt.Sprint(view["warnings"]), "Directory sign-in cannot search for users") {
		t.Errorf("directory view warnings: %v", view["warnings"])
	}
}
