package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// TestMain keeps the tests away from this computer's own Signalith: no
// systemd service settings, master key variables or state folder.
func TestMain(m *testing.M) {
	readServiceSettings = func() *serviceSettings { return nil }
	for _, k := range []string{"SIGNALITH_STATE_DIR", "SIGNALITH_MASTER_KEY", "SIGNALITH_MASTER_KEY_FILE", "CREDENTIALS_DIRECTORY",
		"SIGNALITH_OPENSEARCH_PASSWORD", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_INGEST_TOKEN", "SIGNALITH_LDAP_BIND_PASSWORD", "SIGNALITH_LOOKUPS_DIR"} {
		os.Unsetenv(k)
	}
	os.Exit(m.Run())
}

const commentedConfig = `# Signalith for the SOC lab.
# Keep this file in Git, without secrets.
server:
  listen: 0.0.0.0:8080   # all interfaces
opensearch:
  url: https://os.lab.example.com:9200
  username: signalith
  password: "lab OpenSearch pass"   # rotate every quarter
auth:
  admin_user: admin
ingest:
  tokens:
    - lab-ingest-token-0001
assistant:
  provider: anthropic
  api_key: sk-ant-lab-key
intel:
  feeds:
    - name: cti
      url: https://cti.example.com/list.txt
      headers:
        X-Key: ${CTI_KEY}
`

// secretsSetup writes a config with plain secrets, a directory.json and a
// feeds file, and returns the config path and the lookups folder.
func secretsSetup(t *testing.T) (string, string) {
	t.Helper()
	// The file has no admin password hash, and a feed reads its key from
	// the environment.
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "admin password from the environment")
	t.Setenv("CTI_KEY", "cti-key-from-the-environment")
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte(commentedConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	lookups := filepath.Join(dir, "lookups")
	os.MkdirAll(lookups, 0o750)
	os.WriteFile(filepath.Join(lookups, "directory.json"), []byte(`{
  "version": 1,
  "settings": {"type": "ad", "url": "ldaps://dc1.example.com", "bind_dn": "CN=svc,DC=example,DC=com", "user_base_dn": "DC=example,DC=com"},
  "bind_password": "plain-bind-pw"
}
`), 0o600)
	os.WriteFile(filepath.Join(lookups, "intel_feeds.yaml"), []byte(`feeds:
  - name: otx
    url: https://otx.example.com/feed.txt
    headers:
      X-OTX-API-KEY: plain-otx-key
`), 0o600)
	return path, lookups
}

// runCmd runs "signalith secrets args..." with input and returns what it
// printed.
func runCmd(t *testing.T, input string, args ...string) (string, error) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(w, input)
	w.Close()
	defer r.Close()
	var out bytes.Buffer
	err = runSecrets(args, r, &out)
	return out.String(), err
}

var plainSecrets = []string{"lab OpenSearch pass", "lab-ingest-token-0001", "sk-ant-lab-key", "plain-bind-pw", "plain-otx-key"}

// allFiles returns the three files' text.
func allFiles(t *testing.T, path, lookups string) string {
	t.Helper()
	var b strings.Builder
	for _, f := range []string{path, filepath.Join(lookups, "directory.json"), filepath.Join(lookups, "intel_feeds.yaml")} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

func TestSecretsStatusAndEncrypt(t *testing.T) {
	path, lookups := secretsSetup(t)
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "ENV-ONLY-PASSWORD")
	out, err := runCmd(t, "", "status", "-c", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Master key:    none yet. Signalith makes one in " + filepath.Join(filepath.Dir(path), "keys"),
		"  opensearch.password  plain text",
		"  ingest.tokens[0]     plain text",
		"  bind_password (service account password)  plain text",
		"  feeds[otx] header X-OTX-API-KEY  plain text",
		"SIGNALITH_OPENSEARCH_PASSWORD",
		"0 encrypted, 5 plain text.\nRun: signalith secrets encrypt",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "${CTI_KEY}") || strings.Contains(out, "X-Key") {
		t.Errorf("a ${ENV_VAR} reference is not a stored secret:\n%s", out)
	}

	out, err = runCmd(t, "", "encrypt", "-c", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Made a new master key:", "Encrypted 3 values in " + path, "Encrypted 1 value in " + filepath.Join(lookups, "directory.json"),
		"Encrypted 1 value in " + filepath.Join(lookups, "intel_feeds.yaml")} {
		if !strings.Contains(out, want) {
			t.Errorf("encrypt output lacks %q:\n%s", want, out)
		}
	}
	text := allFiles(t, path, lookups)
	for _, p := range append(plainSecrets, "ENV-ONLY-PASSWORD", "admin password from the environment", "cti-key-from-the-environment") {
		if strings.Contains(text, p) {
			t.Errorf("%q is still in the files", p)
		}
	}
	// Only the values changed: comments, order and the mode stay.
	data, _ := os.ReadFile(path)
	sealed := regexp.MustCompile(`enc:v1:[0-9a-f]{8}:[A-Za-z0-9_-]+`)
	want := strings.NewReplacer(`lab OpenSearch pass`, "X", "lab-ingest-token-0001", "X", "sk-ant-lab-key", "X").Replace(commentedConfig)
	if got := sealed.ReplaceAllString(string(data), "X"); got != want {
		t.Errorf("layout changed:\n%s\nwant\n%s", got, want)
	}
	if st, _ := os.Stat(path); runtime.GOOS != "windows" && st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v, want the file's own 0640", st.Mode().Perm())
	}
	c, err := config.Load(path)
	if err != nil || c.OpenSearch.Password != "ENV-ONLY-PASSWORD" {
		t.Fatalf("load: %v", err)
	}
	t.Setenv("SIGNALITH_OPENSEARCH_PASSWORD", "")
	if c, err = config.Load(path); err != nil || c.OpenSearch.Password != "lab OpenSearch pass" || c.Assistant.APIKey != "sk-ant-lab-key" {
		t.Fatalf("load without the environment: %v", err)
	}

	out, err = runCmd(t, "", "status", "-c", path)
	if err != nil || !strings.Contains(out, "5 encrypted, 0 plain text.") || strings.Contains(out, "Run:") {
		t.Errorf("status after encrypt (%v):\n%s", err, out)
	}
	if out, _ := runCmd(t, "", "encrypt", "-c", path); !strings.Contains(out, "Nothing to encrypt") {
		t.Errorf("second encrypt:\n%s", out)
	}
}

func TestSecretsSet(t *testing.T) {
	path, _ := secretsSetup(t)
	if _, err := runCmd(t, "", "set", "server.listen", "-c", path); err == nil ||
		!strings.Contains(err.Error(), "opensearch.password, assistant.api_key, auth.ldap.bind_password, ingest.tokens") {
		t.Errorf("unknown setting: %v", err)
	}
	if _, err := runCmd(t, "", "set", "-c", path); err == nil {
		t.Error("no setting named")
	}
	out, err := runCmd(t, "new OpenSearch pass\n", "set", "opensearch.password", "-c", path)
	if err != nil || !strings.Contains(out, "Saved opensearch.password, encrypted, in "+path) {
		t.Fatalf("set (%v):\n%s", err, out)
	}
	if _, err := runCmd(t, "another-token-0123456789\n", "set", "-c", path, "ingest.tokens"); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, "", "set", "assistant.api_key", "-c", path); err == nil || !strings.Contains(err.Error(), "nothing entered") {
		t.Errorf("empty input: %v", err)
	}
	if _, err := runCmd(t, "pw\n", "set", "auth.ldap.bind_password", "-c", path); err == nil || !strings.Contains(err.Error(), "no auth.ldap section") {
		t.Errorf("no ldap section: %v", err)
	}
	if _, err := runCmd(t, "enc:v1:00000000:AAAA\n", "set", "assistant.api_key", "-c", path); err == nil || !strings.Contains(err.Error(), "how encrypted values look") {
		t.Errorf("a value that looks encrypted: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "new OpenSearch pass") || strings.Contains(string(data), "another-token") ||
		!strings.Contains(string(data), "# rotate every quarter") {
		t.Errorf("file after set:\n%s", data)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.OpenSearch.Password != "new OpenSearch pass" || len(c.Ingest.Tokens) != 2 || c.Ingest.Tokens[1] != "another-token-0123456789" {
		t.Errorf("loaded %q %q", c.OpenSearch.Password, c.Ingest.Tokens)
	}
}

func TestSecretsRotateAndPrune(t *testing.T) {
	path, lookups := secretsSetup(t)
	if _, err := runCmd(t, "", "rotate-master", "-c", path); err == nil || !strings.Contains(err.Error(), "no master key yet") {
		t.Errorf("rotate without a key: %v", err)
	}
	if _, err := runCmd(t, "", "encrypt", "-c", path); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(filepath.Dir(path), "keys", "master.key")
	if runtime.GOOS == "windows" {
		keyFile += ".dpapi"
	}
	oldKey, _ := os.ReadFile(keyFile)
	dirFile := filepath.Join(lookups, "directory.json")
	beforeDir, _ := os.ReadFile(dirFile)
	oldID := secrets.KeyID(regexp.MustCompile(`enc:v1:[^"]+`).FindString(string(beforeDir)))

	out, err := runCmd(t, "", "rotate-master", "-c", path)
	if err != nil {
		t.Fatalf("rotate (%v):\n%s", err, out)
	}
	newID := regexp.MustCompile(`New master key ([0-9a-f]{8}) in `).FindStringSubmatch(out)
	if newID == nil || newID[1] == oldID || !strings.Contains(out, "Encrypted 3 values again in "+path) || !strings.Contains(out, keyFile+".old") {
		t.Fatalf("rotate output:\n%s", out)
	}
	if kept, _ := os.ReadFile(keyFile + ".old"); !bytes.Equal(kept, oldKey) {
		t.Error("the previous key was not kept")
	}
	text := allFiles(t, path, lookups)
	if strings.Contains(text, "enc:v1:"+oldID) || strings.Count(text, "enc:v1:"+newID[1]) != 5 {
		t.Errorf("values after rotation:\n%s", text)
	}
	if _, err := runCmd(t, "", "rotate-master", "-c", path); err == nil || !strings.Contains(err.Error(), "-prune") {
		t.Errorf("second rotation: %v", err)
	}

	// A file put back from a backup still needs the previous key, so
	// prune waits for encrypt.
	os.WriteFile(dirFile, beforeDir, 0o600)
	out, _ = runCmd(t, "", "status", "-c", path)
	if !strings.Contains(out, "encrypted with the previous master key") || !strings.Contains(out, "Previous key:  "+keyFile+".old, key id "+oldID) {
		t.Errorf("status with an old value:\n%s", out)
	}
	if _, err := runCmd(t, "", "rotate-master", "-prune", "-c", path); err == nil || !strings.Contains(err.Error(), "bind_password") {
		t.Errorf("prune with an old value: %v", err)
	}
	if out, err := runCmd(t, "", "encrypt", "-c", path); err != nil || !strings.Contains(out, "Encrypted 1 value in "+dirFile) {
		t.Fatalf("encrypt after restore (%v):\n%s", err, out)
	}
	out, err = runCmd(t, "", "rotate-master", "-c", path, "-prune")
	if err != nil || !strings.Contains(out, "Removed the previous master key "+keyFile+".old (key id "+oldID+")") {
		t.Fatalf("prune (%v):\n%s", err, out)
	}
	if _, err := os.Stat(keyFile + ".old"); !os.IsNotExist(err) {
		t.Error(".old is still there")
	}
	if out, _ := runCmd(t, "", "rotate-master", "-prune", "-c", path); !strings.Contains(out, "no previous master key") {
		t.Errorf("second prune:\n%s", out)
	}
	if c, err := config.Load(path); err != nil || c.Assistant.APIKey != "sk-ant-lab-key" {
		t.Errorf("load after rotation: %v", err)
	}
}

// TestSecretsRotateFailureChangesNothing makes writing a file fail, before
// and after the new key is in place, and checks that everything is as it
// was.
func TestSecretsRotateFailureChangesNothing(t *testing.T) {
	path, lookups := secretsSetup(t)
	if _, err := runCmd(t, "", "encrypt", "-c", path); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(filepath.Dir(path), "keys", "master.key")
	if runtime.GOOS == "windows" {
		keyFile += ".dpapi"
	}
	key, _ := os.ReadFile(keyFile)
	files := allFiles(t, path, lookups)
	feedsFile := filepath.Join(lookups, "intel_feeds.yaml")
	defer func() { prepareFile, commitFile = securefile.Prepare, (*securefile.Pending).Commit }()
	same := func(when string) {
		t.Helper()
		if now, _ := os.ReadFile(keyFile); !bytes.Equal(now, key) {
			t.Errorf("%s: the master key changed", when)
		}
		if _, err := os.Stat(keyFile + ".old"); !os.IsNotExist(err) {
			t.Errorf("%s: .old was left", when)
		}
		if allFiles(t, path, lookups) != files {
			t.Errorf("%s: the files changed", when)
		}
		left, _ := filepath.Glob(filepath.Join(lookups, ".*.tmp"))
		more, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".*.tmp"))
		if len(left)+len(more) > 0 {
			t.Errorf("%s: temporary files left: %v %v", when, left, more)
		}
	}

	prepareFile = func(p string, data []byte) (*securefile.Pending, error) {
		if p == feedsFile {
			return nil, errors.New("disk full")
		}
		return securefile.Prepare(p, data)
	}
	if _, err := runCmd(t, "", "rotate-master", "-c", path); err == nil || !strings.Contains(err.Error(), "disk full. Nothing was changed") {
		t.Errorf("prepare failure: %v", err)
	}
	same("prepare failure")

	prepareFile = securefile.Prepare
	commitFile = func(p *securefile.Pending) error {
		if p.Path() == feedsFile {
			p.Discard()
			return errors.New("access denied")
		}
		return p.Commit()
	}
	if _, err := runCmd(t, "", "rotate-master", "-c", path); err == nil || !strings.Contains(err.Error(), "access denied. Nothing was changed") {
		t.Errorf("commit failure: %v", err)
	}
	same("commit failure")
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "lab OpenSearch pass" {
		t.Errorf("load after the failed rotation: %v", err)
	}
}

// TestEncryptStoresAtStartup checks that the server encrypts the plain
// values in the files it writes, logs it once, and leaves signalith.yaml
// alone.
func TestEncryptStoresAtStartup(t *testing.T) {
	path, lookups := secretsSetup(t)
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	useKeys(c, log)
	encryptStores(c, log)
	dir, _ := os.ReadFile(filepath.Join(lookups, "directory.json"))
	feeds, _ := os.ReadFile(filepath.Join(lookups, "intel_feeds.yaml"))
	cfg, _ := os.ReadFile(path)
	if strings.Contains(string(dir), "plain-bind-pw") || strings.Contains(string(feeds), "plain-otx-key") || string(cfg) != commentedConfig {
		t.Errorf("after startup:\n%s\n%s\n%s", dir, feeds, cfg)
	}
	if n := strings.Count(logs.String(), "encrypted the passwords and keys stored in a file"); n != 2 || !strings.Contains(logs.String(), "made a new master key") {
		t.Errorf("log:\n%s", logs.String())
	}
	logs.Reset()
	encryptStores(c, log)
	if logs.Len() != 0 {
		t.Errorf("second start logged:\n%s", logs.String())
	}
	d, err := users.OpenDirectory(filepath.Join(lookups, "directory.json"), nil)
	if err != nil || d.Settings().BindPassword != "plain-bind-pw" {
		t.Errorf("directory after startup: %v", err)
	}
}

func TestInitWritesEncryptedValues(t *testing.T) {
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	out := captureStdout(t, func() {
		if err := cmdInit([]string{"-c", path, "-admin-password", "first-password"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Master key:  "+filepath.Join(filepath.Dir(path), "keys")) || !strings.Contains(out, "Back it up") {
		t.Errorf("init output:\n%s", out)
	}
	data, _ := os.ReadFile(path)
	if !regexp.MustCompile(`tokens:\n\s+- enc:v1:`).Match(data) {
		t.Errorf("the ingest token is not encrypted:\n%s", data)
	}
	if c, err := config.Load(path); err != nil || len(c.Ingest.Tokens[0]) < 16 || len(c.PlainSecrets()) != 0 {
		t.Errorf("load: %v", err)
	}
}

func TestServiceEnv(t *testing.T) {
	envFile := filepath.Join(t.TempDir(), "signalith.env")
	os.WriteFile(envFile, []byte("# secrets for the service\nSIGNALITH_MASTER_KEY_FILE=\"/srv/keys/signalith.key\"\nSIGNALITH_OPENSEARCH_PASSWORD=never-taken\n"), 0o600)
	show := []byte(`ExecStart={ path=/usr/local/bin/signalith ; argv[]=/usr/local/bin/signalith serve -c /etc/signalith/signalith.yaml ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
Environment=SIGNALITH_STATE_DIR=/var/lib/signalith SIGNALITH_LOOKUPS_DIR=/var/lib/signalith/lookups "SIGNALITH_ARCHIVE_DIR=/mnt/arch ive" SIGNALITH_OPENSEARCH_PASSWORD=secret GOTRACEBACK=none
EnvironmentFiles=` + envFile + ` (ignore_errors=yes)
EnvironmentFiles=/nonexistent/other.env (ignore_errors=yes)
`)
	s := parseSystemctlShow(show, os.ReadFile)
	got := s.envFor("/etc/signalith/signalith.yaml")
	want := map[string]string{
		"SIGNALITH_STATE_DIR": "/var/lib/signalith", "SIGNALITH_LOOKUPS_DIR": "/var/lib/signalith/lookups",
		"SIGNALITH_ARCHIVE_DIR": "/mnt/arch ive", "SIGNALITH_MASTER_KEY_FILE": "/srv/keys/signalith.key",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// A key passed as a systemd credential is the file the service reads.
	cred := parseSystemctlShow(append(show, "LoadCredential=master.key:/etc/credstore/signalith-master.key\n"...), os.ReadFile)
	if cred.cred != "/etc/credstore/signalith-master.key" || cred.envFor("/etc/signalith/signalith.yaml")["SIGNALITH_MASTER_KEY_FILE"] != "/etc/credstore/signalith-master.key" {
		t.Errorf("credential: %+v", cred)
	}
	if got := s.envFor("/srv/other/signalith.yaml"); got != nil {
		t.Errorf("another config file: %v", got)
	}
	if s := parseSystemctlShow([]byte("ExecStart=\nEnvironment=\n"), os.ReadFile); s.envFor("/etc/signalith/signalith.yaml") != nil {
		t.Errorf("no service: %+v", s)
	}
	// The Windows service's settings, as read from the registry.
	win := &serviceSettings{args: []string{"-c", `C:\ProgramData\Signalith\signalith.yaml`},
		env: map[string]string{"SIGNALITH_MASTER_KEY_FILE": `C:\ProgramData\Signalith\keys\master.key`, "SIGNALITH_ADMIN_PASSWORD": "x"}}
	if runtime.GOOS == "windows" {
		if got := win.envFor(`c:\programdata\signalith\SIGNALITH.yaml`); len(got) != 1 || got["SIGNALITH_MASTER_KEY_FILE"] == "" {
			t.Errorf("Windows service: %v", got)
		}
	}
}

func TestParseEnvFile(t *testing.T) {
	got := parseEnvFile([]byte("# comment\n; another\nA=1\n B = two words \nC=\"quoted value\"\nexport D='x'\nnot a setting\n"))
	want := map[string]string{"A": "1", "B": "two words", "C": "quoted value", "D": "x"}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

// keyFileOf returns where the CLI keeps the master key for a test config.
func keyFileOf(path string) string {
	f := filepath.Join(filepath.Dir(path), "keys", "master.key")
	if runtime.GOOS == "windows" {
		f += ".dpapi"
	}
	return f
}

// Prune keeps the previous key while it cannot be read, while a value
// that cannot be decrypted may need it, and, with a systemd credential,
// until the service has restarted with the new key.
func TestPruneKeepsAKeyThatMayBeNeeded(t *testing.T) {
	path, lookups := secretsSetup(t)
	if _, err := runCmd(t, "", "encrypt", "-c", path); err != nil {
		t.Fatal(err)
	}
	if _, err := runCmd(t, "", "rotate-master", "-c", path); err != nil {
		t.Fatal(err)
	}
	old := keyFileOf(path) + ".old"
	kept, _ := os.ReadFile(old)

	// The previous key cannot be read.
	os.WriteFile(old, []byte("damaged"), 0o600)
	if _, err := runCmd(t, "", "rotate-master", "-prune", "-c", path); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("prune with an unreadable previous key: %v", err)
	}
	if _, err := os.Stat(old); err != nil {
		t.Fatal("the unreadable previous key was removed")
	}
	os.WriteFile(old, kept, 0o600)

	// A value encrypted with a third key cannot be decrypted; it might be
	// the previous key's, so the key stays.
	stranger := secrets.NewKeyring(t.TempDir())
	sealed, err := stranger.Seal(users.BindPasswordField, "from another key")
	if err != nil {
		t.Fatal(err)
	}
	dirFile := filepath.Join(lookups, "directory.json")
	good, _ := os.ReadFile(dirFile)
	os.WriteFile(dirFile, regexp.MustCompile(`enc:v1:[^"]+`).ReplaceAll(good, []byte(sealed)), 0o600)
	if _, err := runCmd(t, "", "rotate-master", "-prune", "-c", path); err == nil || !strings.Contains(err.Error(), "bind_password") || !strings.Contains(err.Error(), "may need it") {
		t.Errorf("prune with an undecryptable value: %v", err)
	}
	os.WriteFile(dirFile, good, 0o600)

	// With the key as a systemd credential, the service must have
	// restarted since the rotation.
	defer func() { keyIsCredential, serviceRestarted = false, serviceStartedAfter }()
	keyIsCredential = true
	serviceRestarted = func(time.Time) (bool, error) { return false, nil }
	if _, err := runCmd(t, "", "rotate-master", "-prune", "-c", path); err == nil || !strings.Contains(err.Error(), "systemctl restart signalith") {
		t.Errorf("prune before the service restarted: %v", err)
	}
	serviceRestarted = func(time.Time) (bool, error) { return true, nil }
	if out, err := runCmd(t, "", "rotate-master", "-prune", "-c", path); err != nil || !strings.Contains(out, "Removed the previous master key") {
		t.Errorf("prune after the restart (%v):\n%s", err, out)
	}
}

// With no master key here but values encrypted with one, encrypt and set
// stop instead of making a second key, unless told to with -new-key.
func TestNoSecondKeyWithoutAsking(t *testing.T) {
	path, _ := secretsSetup(t)
	elsewhere := filepath.Join(t.TempDir(), "service.key")
	os.WriteFile(elsewhere, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x81}, 32))+"\n"), 0o600)
	t.Setenv("SIGNALITH_MASTER_KEY_FILE", elsewhere)
	if _, err := runCmd(t, "", "encrypt", "-c", path); err != nil {
		t.Fatal(err)
	}
	// The same commands run without the service's variable.
	t.Setenv("SIGNALITH_MASTER_KEY_FILE", "")
	before, _ := os.ReadFile(path)
	for _, args := range [][]string{{"encrypt"}, {"set", "opensearch.password"}} {
		_, err := runCmd(t, "pw\n", append(args, "-c", path)...)
		if err == nil || !strings.Contains(err.Error(), "SIGNALITH_MASTER_KEY_FILE") || !strings.Contains(err.Error(), "-new-key") {
			t.Errorf("%v without the key: %v", args, err)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), "keys")); !os.IsNotExist(err) {
		t.Errorf("a key folder was made: %v", err)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, before) {
		t.Error("the config changed")
	}
	// The key is lost: -new-key makes one and stores the value with it.
	out, err := runCmd(t, "new pw\n", "set", "opensearch.password", "-new-key", "-c", path)
	if err != nil || !strings.Contains(out, "Made a new master key") {
		t.Fatalf("set -new-key (%v):\n%s", err, out)
	}
	if _, err := os.Stat(keyFileOf(path)); err != nil {
		t.Error(err)
	}
}

// When a file cannot be written, no master key is left behind either.
func TestNoKeyWhenNothingCanBeWritten(t *testing.T) {
	path, _ := secretsSetup(t)
	defer func() { prepareFile = securefile.Prepare }()
	prepareFile = func(p string, data []byte) (*securefile.Pending, error) {
		if p == path {
			return nil, errors.New("read-only file system")
		}
		return securefile.Prepare(p, data)
	}
	for _, args := range [][]string{{"encrypt"}, {"set", "opensearch.password"}} {
		out, err := runCmd(t, "pw\n", append(args, "-c", path)...)
		if err == nil || !strings.Contains(err.Error(), "read-only file system") || strings.Contains(out, "Made a new master key") {
			t.Errorf("%v (%v):\n%s", args, err, out)
		}
		if _, err := os.Stat(filepath.Join(filepath.Dir(path), "keys")); !os.IsNotExist(err) {
			t.Errorf("%v left a key folder: %v", args, err)
		}
	}
}

// decrypt writes everything back as plain text, for going back to an
// older version.
func TestSecretsDecrypt(t *testing.T) {
	path, lookups := secretsSetup(t)
	before := allFiles(t, path, lookups)
	if _, err := runCmd(t, "", "encrypt", "-c", path); err != nil {
		t.Fatal(err)
	}
	out, err := runCmd(t, "", "decrypt", "-c", path)
	if err != nil || !strings.Contains(out, "Decrypted 3 values in "+path) || !strings.Contains(out, "plain text") {
		t.Fatalf("decrypt (%v):\n%s", err, out)
	}
	text := allFiles(t, path, lookups)
	if strings.Contains(text, "enc:v1:") {
		t.Errorf("still encrypted:\n%s", text)
	}
	for _, p := range plainSecrets {
		if !strings.Contains(text, p) {
			t.Errorf("%q is not back", p)
		}
	}
	// signalith.yaml is as it was, comments and all.
	if data, _ := os.ReadFile(path); !strings.Contains(before, string(data)) {
		t.Errorf("signalith.yaml after decrypt:\n%s", data)
	}
}

// A password written into opensearch.url is moved to opensearch.password
// and encrypted there.
func TestEncryptMovesTheURLPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	t.Setenv("SIGNALITH_ADMIN_PASSWORD", "admin password from the environment")
	os.WriteFile(path, []byte("opensearch:\n  url: https://admin:Plain%20OS%20pw%231@127.0.0.1:18810   # lab\n"), 0o600)
	out, err := runCmd(t, "", "status", "-c", path)
	if !strings.Contains(out, "opensearch.url  plain text") || !strings.Contains(out, "0 encrypted, 1 plain text") {
		t.Errorf("status (%v):\n%s", err, out)
	}
	out, err = runCmd(t, "", "encrypt", "-c", path)
	if err != nil || !strings.Contains(out, "now opensearch.password, encrypted") {
		t.Fatalf("encrypt (%v):\n%s", err, out)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "Plain") || !strings.Contains(string(data), "url: https://127.0.0.1:18810   # lab") {
		t.Errorf("file:\n%s", data)
	}
	c, err := config.Load(path)
	if err != nil || c.OpenSearch.Username != "admin" || c.OpenSearch.Password != "Plain OS pw#1" || len(c.PlainSecrets()) != 0 {
		t.Errorf("load: %v %+v %v", err, c.OpenSearch, c.PlainSecrets())
	}
}
