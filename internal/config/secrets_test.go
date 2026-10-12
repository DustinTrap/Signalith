package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"gopkg.in/yaml.v3"
)

// sealedValues returns every enc: value in a file, decrypted with keys.
func sealedValues(t *testing.T, data []byte, keys *secrets.Keyring) map[string]string {
	t.Helper()
	out := map[string]string{}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, n := range secretNodes(&doc) {
		if secrets.IsSealed(n.node.Value) {
			v, err := keys.Open(n.field, n.node.Value)
			if err != nil {
				t.Fatalf("%s: %v", n.label, err)
			}
			out[n.label] = v
		}
	}
	return out
}

func TestStateDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := validConfig(t).Save(path); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.StateDir() != dir {
		t.Errorf("StateDir = %s, want the folder holding lookups (%s)", c.StateDir(), dir)
	}
	t.Setenv("SIGNALITH_STATE_DIR", "/var/lib/signalith")
	if c.StateDir() != "/var/lib/signalith" {
		t.Errorf("StateDir with SIGNALITH_STATE_DIR = %s", c.StateDir())
	}
}

func TestSaveEncryptsAndLoadDecrypts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("CTI_KEY", "from-env")
	c := validConfig(t)
	c.OpenSearch.URL, c.OpenSearch.Username, c.OpenSearch.Password = "https://os.internal:9200", "signalith", "os-pass-123"
	c.Assistant.Provider, c.Assistant.APIKey = "anthropic", "sk-ant-key"
	c.Ingest.Tokens = []string{"token-0123456789abcdef", "token-fedcba9876543210"}
	c.Intel.Feeds = []IntelFeed{{Name: "otx", URL: "https://otx.example.com/feed.txt",
		Headers: map[string]string{"X-OTX-API-KEY": "otx-key", "X-Ref": "${CTI_KEY}"}, Username: "u", Password: "feed-pw"}}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, plain := range []string{"os-pass-123", "sk-ant-key", "token-0123456789abcdef", "token-fedcba9876543210", "otx-key", "feed-pw"} {
		if strings.Contains(string(raw), plain) {
			t.Errorf("saved file has %q in plain text", plain)
		}
	}
	if n := len(regexp.MustCompile(`: enc:v1:|- enc:v1:`).FindAll(raw, -1)); n != 6 {
		t.Errorf("%d encrypted values, want 6:\n%s", n, raw)
	}
	if !strings.Contains(string(raw), "${CTI_KEY}") {
		t.Error("a ${ENV_VAR} reference should stay as it is")
	}
	if _, err := os.Stat(filepath.Join(dir, "keys")); err != nil {
		t.Errorf("no master key next to the config: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	f := got.Intel.Feeds[0]
	if got.OpenSearch.Password != "os-pass-123" || got.Assistant.APIKey != "sk-ant-key" || got.Ingest.Tokens[1] != "token-fedcba9876543210" ||
		f.Headers["X-OTX-API-KEY"] != "otx-key" || f.Headers["X-Ref"] != "${CTI_KEY}" || f.Password != "feed-pw" {
		t.Errorf("loaded %+v %+v %v %+v", got.OpenSearch, got.Assistant, got.Ingest.Tokens, f)
	}
	if p := got.PlainSecrets(); len(p) != 0 {
		t.Errorf("PlainSecrets = %v", p)
	}
	for _, w := range got.Warnings() {
		if strings.Contains(w, "plain text") {
			t.Errorf("warning: %s", w)
		}
	}
}

// TestSaveNeverWritesEnvironmentValues is the regression test for
// "signalith passwd" copying secrets kept in environment variables into
// signalith.yaml: Save writes only what the file had.
func TestSaveNeverWritesEnvironmentValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte(`# my comment
auth:
  admin_password_hash: `+validConfig(t).Auth.AdminPasswordHash+`
  ldap:
    url: ldaps://dc1.corp.example.com
    bind_dn: CN=svc,DC=corp,DC=example,DC=com
    user_base_dn: DC=corp,DC=example,DC=com
    admin_groups: [CN=Admins,DC=corp,DC=example,DC=com]
ingest:
  tokens: [file-token-0123456789]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"SIGNALITH_OPENSEARCH_PASSWORD": "OS-SECRET-PW",
		"SIGNALITH_ASSISTANT_API_KEY":   "sk-ant-ENV-ONLY",
		"SIGNALITH_INGEST_TOKEN":        "env-token-0123456789abcdef",
		"SIGNALITH_LDAP_BIND_PASSWORD":  "ENV-BIND-PW",
		"SIGNALITH_LOOKUPS_DIR":         filepath.Join(dir, "env-lookups"),
		"SIGNALITH_ADMIN_PASSWORD":      "env admin password",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "OS-SECRET-PW" || len(c.Ingest.Tokens) != 2 {
		t.Fatalf("environment not applied: %+v %v", c.OpenSearch, c.Ingest.Tokens)
	}
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, v := range sealedValues(t, raw, c.Keyring()) {
		for name, ev := range env {
			if v == ev {
				t.Errorf("%s was written into the file (encrypted)", name)
			}
		}
	}
	for name, v := range env {
		if strings.Contains(string(raw), v) {
			t.Errorf("%s was written into the file:\n%s", name, raw)
		}
	}
	if strings.Contains(string(raw), "env-lookups") {
		t.Error("a folder from the environment was written into the file")
	}
	// The LDAP section needs its bind password, so that one stays set.
	for _, k := range []string{"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_ADMIN_PASSWORD"} {
		os.Unsetenv(k)
	}
	back, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if back.OpenSearch.Password != "" || back.Assistant.APIKey != "" || len(back.Ingest.Tokens) != 1 || back.Ingest.Tokens[0] != "file-token-0123456789" {
		t.Errorf("reloaded: %+v %+v %v", back.OpenSearch, back.Assistant, back.Ingest.Tokens)
	}
}

func TestPlainSecretWarnings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("CTI", "x")
	write := func(body string) {
		t.Helper()
		os.WriteFile(path, []byte("auth:\n  admin_password_hash: "+validConfig(t).Auth.AdminPasswordHash+"\n"+body), 0o600)
	}
	write(`opensearch:
  url: https://os.internal:9200
  username: signalith
  password: plain-pw
ingest:
  tokens:
    - token-0123456789abcdef
    - token-fedcba9876543210
intel:
  feeds:
    - name: cti
      url: https://cti.example.com/list.txt
      headers: {X-Key: "${CTI}"}
`)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "3 passwords or keys in signalith.yaml are stored as plain text (opensearch.password, ingest.tokens[0], ingest.tokens[1]). Run: signalith secrets encrypt"
	if !contains(c.Warnings(), want) {
		t.Errorf("warnings %q lack %q", c.Warnings(), want)
	}
	write("ingest:\n  tokens: [token-0123456789abcdef]\n")
	c, _ = Load(path)
	if !contains(c.Warnings(), "1 password or key in signalith.yaml is stored as plain text (ingest.tokens[0]). Run: signalith secrets encrypt") {
		t.Errorf("warnings %q", c.Warnings())
	}
	// A plain value from the environment is not the file's problem.
	write("")
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "env")
	c, _ = Load(path)
	if len(c.Warnings()) != 0 {
		t.Errorf("warnings %q", c.Warnings())
	}
	// A master key from SIGNALITH_MASTER_KEY is flagged.
	t.Setenv("SIGNALITH_MASTER_KEY", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32)))
	c, _ = Load(path)
	if len(c.Warnings()) != 1 || !strings.Contains(c.Warnings()[0], "SIGNALITH_MASTER_KEY_FILE") {
		t.Errorf("warnings %q", c.Warnings())
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func TestLoadMixedAndWrongKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	keys := secrets.NewKeyring(dir)
	sealed, err := keys.Seal("assistant.api_key", "sk-sealed")
	if err != nil {
		t.Fatal(err)
	}
	body := "auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n" +
		"opensearch:\n  url: https://os.internal:9200\n  username: u\n  password: plain-pw\n" +
		"assistant:\n  provider: anthropic\n  api_key: " + sealed + "\n"
	os.WriteFile(path, []byte(body), 0o600)
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "plain-pw" || c.Assistant.APIKey != "sk-sealed" {
		t.Errorf("loaded %q %q", c.OpenSearch.Password, c.Assistant.APIKey)
	}
	if p := c.PlainSecrets(); len(p) != 1 || p[0] != "opensearch.password" {
		t.Errorf("PlainSecrets = %v", p)
	}
	// Another folder's key cannot open it: the error says which setting,
	// which file and what to do.
	other := filepath.Join(t.TempDir(), "signalith.yaml")
	os.WriteFile(other, []byte(body), 0o600)
	if _, err := secrets.NewKeyring(filepath.Dir(other)).Seal("x", "y"); err != nil {
		t.Fatal(err)
	}
	_, err = Load(other)
	for _, want := range []string{other, "assistant.api_key is encrypted with master key " + keys.KeyID(), "signalith secrets set assistant.api_key", "never events"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
	// A value copied into another setting is refused too.
	os.WriteFile(path, []byte(strings.Replace(body, "password: plain-pw", "password: "+sealed, 1)), 0o600)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "opensearch.password cannot be decrypted") {
		t.Errorf("swapped value: %v", err)
	}
	// LoadUnchecked reads it anyway, for the secrets commands.
	if c, err := LoadUnchecked(path); err != nil || c.OpenSearch.Password != sealed {
		t.Errorf("LoadUnchecked: %v", err)
	}
	// A bind password from the environment is used instead of the file's,
	// which then need not decrypt.
	ldap := "auth:\n  admin_password_hash: " + validConfig(t).Auth.AdminPasswordHash + "\n  ldap:\n    url: ldaps://dc1\n    bind_dn: CN=svc\n    bind_password: enc:v1:00000000:AAAA\n    user_base_dn: DC=x\n    admin_groups: [CN=a]\n"
	os.WriteFile(path, []byte(ldap), 0o600)
	if _, err := Load(path); err == nil {
		t.Error("a damaged bind password loaded")
	}
	t.Setenv("SIGNALITH_LDAP_BIND_PASSWORD", "from-env")
	if _, err := Load(path); err != nil {
		t.Errorf("with the environment's bind password: %v", err)
	}
}

const layoutFile = `# Signalith configuration (hand-written).
server:
  listen: 0.0.0.0:8080   # all interfaces

opensearch:
  url: https://os.internal:9200
  username: signalith
  password: "os pass"    # the OpenSearch password
assistant:
  provider: anthropic
  api_key: 'sk-ant-1'
auth:
  admin_password_hash: HASH
ingest:
  # Agents' tokens.
  tokens:
    - token-0123456789abcdef   # Windows agents
    - token-fedcba9876543210
intel:
  feeds:
    - name: otx
      url: https://otx.example.com/feed.txt
      headers: {X-OTX-API-KEY: otx-key, X-Env: "${OTX}"}
      username: me
      password: feed-pw
`

func TestResealFileKeepsCommentsAndLayout(t *testing.T) {
	keys := secrets.NewKeyring(t.TempDir())
	data := []byte(strings.Replace(layoutFile, "HASH", validConfig(t).Auth.AdminPasswordHash, 1))
	var seen []string
	out, n, err := ResealFile(data, func(s secrets.Stored) (string, error) {
		seen = append(seen, s.Label)
		return keys.Seal(s.Field, s.Value)
	})
	if err != nil {
		t.Fatal(err)
	}
	wantSeen := []string{"opensearch.password", "assistant.api_key", "ingest.tokens[0]", "ingest.tokens[1]", "intel.feeds[otx].headers.X-OTX-API-KEY", "intel.feeds[otx].password"}
	if n != 6 || strings.Join(seen, ",") != strings.Join(wantSeen, ",") {
		t.Fatalf("changed %d, saw %v", n, seen)
	}
	inLines, outLines := strings.Split(string(data), "\n"), strings.Split(string(out), "\n")
	if len(inLines) != len(outLines) {
		t.Fatalf("line count changed:\n%s", out)
	}
	secretLine := regexp.MustCompile(`os pass|sk-ant-1|token-|otx-key|feed-pw`)
	for i := range inLines {
		if secretLine.MatchString(inLines[i]) {
			if !strings.Contains(outLines[i], "enc:v1:") {
				t.Errorf("line %d not encrypted: %s", i+1, outLines[i])
			}
			continue
		}
		if inLines[i] != outLines[i] {
			t.Errorf("line %d changed:\n  %s\n  %s", i+1, inLines[i], outLines[i])
		}
	}
	for _, keep := range []string{"# the OpenSearch password", "# Windows agents", `X-Env: "${OTX}"`} {
		if !strings.Contains(string(out), keep) {
			t.Errorf("lost %q", keep)
		}
	}
	got := sealedValues(t, out, keys)
	want := map[string]string{"opensearch.password": "os pass", "assistant.api_key": "sk-ant-1", "ingest.tokens[0]": "token-0123456789abcdef",
		"ingest.tokens[1]": "token-fedcba9876543210", "intel.feeds[otx].headers.X-OTX-API-KEY": "otx-key", "intel.feeds[otx].password": "feed-pw"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// Running it again finds nothing to do.
	if again, n, err := ResealFile(out, func(s secrets.Stored) (string, error) { return keys.Seal(s.Field, s.Value) }); err != nil || n != 0 || !bytes.Equal(again, out) {
		t.Errorf("second run changed %d: %v", n, err)
	}
	// The file loads with the encrypted values.
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, out, 0o600)
	c, err := LoadUnchecked(path)
	if err != nil {
		t.Fatal(err)
	}
	c.keys = keys
	if err := c.openSecrets(); err != nil || c.OpenSearch.Password != "os pass" || c.Intel.Feeds[0].Headers["X-OTX-API-KEY"] != "otx-key" {
		t.Errorf("open: %v %+v", err, c.OpenSearch)
	}
}

func TestResealFileFallsBackForBlockValues(t *testing.T) {
	keys := secrets.NewKeyring(t.TempDir())
	data := []byte("# keep me\nopensearch:\n  url: https://os:9200\n  password: |\n    multi\n    line\nassistant:\n  api_key: k1 # key\n")
	out, n, err := ResealFile(data, func(s secrets.Stored) (string, error) { return keys.Seal(s.Field, s.Value) })
	if err != nil || n != 2 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got := sealedValues(t, out, keys)
	if got["opensearch.password"] != "multi\nline\n" || got["assistant.api_key"] != "k1" || !strings.Contains(string(out), "# keep me") {
		t.Errorf("got %q from:\n%s", got, out)
	}
}

func TestSetSecret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	keys := secrets.NewKeyring(dir)
	base := strings.Replace(layoutFile, "HASH", validConfig(t).Auth.AdminPasswordHash, 1)
	os.WriteFile(path, []byte(base), 0o600)
	t.Setenv("SIGNALITH_ASSISTANT_API_KEY", "ENV-KEY")
	if err := SetSecret(path, "opensearch.password", "new pass", keys); err != nil {
		t.Fatal(err)
	}
	if err := SetSecret(path, "ingest.tokens", "added-token-0123456789", keys); err != nil {
		t.Fatal(err)
	}
	out, _ := os.ReadFile(path)
	inLines, outLines := strings.Split(base, "\n"), strings.Split(string(out), "\n")
	if len(outLines) != len(inLines)+1 {
		t.Fatalf("expected one added line:\n%s", out)
	}
	if !strings.Contains(outLines[18], `    - "enc:v1:`) {
		t.Errorf("new token line: %q", outLines[18])
	}
	if !strings.Contains(string(out), "# the OpenSearch password") || strings.Contains(string(out), "ENV-KEY") {
		t.Errorf("file:\n%s", out)
	}
	got := sealedValues(t, out, keys)
	if got["opensearch.password"] != "new pass" || got["ingest.tokens[2]"] != "added-token-0123456789" {
		t.Errorf("values %v", got)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Errorf("mode %v", st.Mode().Perm())
		}
	}
	// A missing key, a flow list and a missing list are added.
	os.WriteFile(path, []byte("server:\n  listen: 127.0.0.1:8080\ningest:\n  tokens: [a-token-0123456789abc]\n"), 0o600)
	if err := SetSecret(path, "assistant.api_key", "sk-1", keys); err != nil {
		t.Fatal(err)
	}
	if err := SetSecret(path, "ingest.tokens", "b-token-0123456789abc", keys); err != nil {
		t.Fatal(err)
	}
	out, _ = os.ReadFile(path)
	if toks := tokenList(out); len(toks) != 2 || toks[0] != "a-token-0123456789abc" {
		t.Errorf("tokens %v in:\n%s", toks, out)
	}
	if got := sealedValues(t, out, keys); got["assistant.api_key"] != "sk-1" || got["ingest.tokens[1]"] != "b-token-0123456789abc" {
		t.Errorf("values %v", got)
	}
	os.WriteFile(path, []byte("server:\n  listen: 127.0.0.1:8080\n"), 0o600)
	if err := SetSecret(path, "ingest.tokens", "c-token-0123456789abc", keys); err != nil {
		t.Fatal(err)
	}
	if out, _ = os.ReadFile(path); len(tokenList(out)) != 1 {
		t.Errorf("no tokens list made:\n%s", out)
	}
	// Refusals.
	if err := SetSecret(path, "auth.ldap.bind_password", "x", keys); err == nil || !strings.Contains(err.Error(), "Users page") {
		t.Errorf("bind password without auth.ldap: %v", err)
	}
	if err := SetSecret(path, "opensearch.username", "x", keys); err == nil || !strings.Contains(err.Error(), strings.Join(SettableSecrets, ", ")) {
		t.Errorf("unknown setting: %v", err)
	}
	if err := SetSecret(path, "ingest.tokens", "short", keys); err == nil || !strings.Contains(err.Error(), "16") {
		t.Errorf("short token: %v", err)
	}
}

func TestPlainScalar(t *testing.T) {
	for v, want := range map[string]bool{
		"enc:v1:0a1b2c3d:AbC-_xyz": true, "$2a$10$abc/def.ghi": true, "token-0123": true,
		"true": false, "123": false, "null": false, "a b": false, "x #y": false, "key:": false, "'q'": false, "": false, "-x": false,
	} {
		if got := plainScalar(v); got != want {
			t.Errorf("plainScalar(%q) = %v", v, got)
		}
	}
}
