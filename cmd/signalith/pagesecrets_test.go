package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// useTestKeyring makes k the keyring secrets.Seal uses for the rest of the
// test, as the server and the commands make their config's.
func useTestKeyring(t *testing.T, k *secrets.Keyring) {
	t.Helper()
	before := secrets.Default()
	secrets.SetDefault(k)
	t.Cleanup(func() { secrets.SetDefault(before) })
}

// The secrets commands find the Settings page's settings.yaml with the
// other files the server writes: status lists it, encrypt and
// rotate-master encrypt its values, and a link put in its place is
// replaced, as the server replaces it, not followed.
func TestSecretsCommandsCoverTheSettingsPage(t *testing.T) {
	path, lookups := secretsSetup(t)
	file := filepath.Join(lookups, "settings.yaml")
	page := "settings:\n  opensearch.password:\n    secret: page-plain-pw\n    sent_to: https://os.lab.example.com:9200\n    changed_by: ann\n"
	if err := os.WriteFile(file, []byte(page), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := runCmd(t, "", "status", "-c", path)
	if err != nil || !strings.Contains(out, file+"\n  opensearch.password  plain text\n") || !strings.Contains(out, "0 encrypted, 6 plain text.") {
		t.Fatalf("status (%v):\n%s", err, out)
	}
	out, err = runCmd(t, "", "encrypt", "-c", path)
	if err != nil || !strings.Contains(out, "Encrypted 1 value in "+file) {
		t.Fatalf("encrypt (%v):\n%s", err, out)
	}
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), "page-plain-pw") || !regexp.MustCompile(`secret: enc:v1:[0-9a-f]{8}:`).Match(data) ||
		!strings.Contains(string(data), "sent_to: https://os.lab.example.com:9200") || !strings.Contains(string(data), "changed_by: ann") {
		t.Fatalf("settings.yaml after encrypt:\n%s", data)
	}
	if st, _ := os.Stat(file); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	// The page's password replaces the one in signalith.yaml.
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "page-plain-pw" || len(c.PageUnreadable()) != 0 {
		t.Fatalf("load: %v", err)
	}
	out, err = runCmd(t, "", "status", "-c", path)
	if err != nil || !strings.Contains(out, "6 encrypted, 0 plain text.") {
		t.Errorf("status after encrypt (%v):\n%s", err, out)
	}

	out, err = runCmd(t, "", "rotate-master", "-c", path)
	newID := regexp.MustCompile(`New master key ([0-9a-f]{8}) in `).FindStringSubmatch(out)
	if err != nil || newID == nil || !strings.Contains(out, "Encrypted 1 value again in "+file) {
		t.Fatalf("rotate (%v):\n%s", err, out)
	}
	data, _ = os.ReadFile(file)
	if !strings.Contains(string(data), "secret: enc:v1:"+newID[1]+":") {
		t.Errorf("settings.yaml after rotate:\n%s", data)
	}
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "page-plain-pw" {
		t.Errorf("load after rotate: %v", err)
	}

	// A link in place of settings.yaml is replaced; the file it points to
	// is left as it is.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.yaml")
	os.WriteFile(elsewhere, []byte(page), 0o644)
	os.Remove(file)
	if err := os.Symlink(elsewhere, file); err != nil {
		t.Skip("cannot make links here:", err)
	}
	if out, err := runCmd(t, "", "encrypt", "-c", path); err != nil || !strings.Contains(out, "Encrypted 1 value in "+file) {
		t.Fatalf("encrypt through a link (%v):\n%s", err, out)
	}
	if fi, err := os.Lstat(file); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		t.Errorf("the link is still there: %v", err)
	}
	if b, _ := os.ReadFile(elsewhere); string(b) != page {
		t.Errorf("the file the link pointed to changed:\n%s", b)
	}
}

// The server encrypts a plain value in settings.yaml, such as one written
// by hand or by a version from before, when it starts.
func TestStartupEncryptsPageSecrets(t *testing.T) {
	path, lookups := secretsSetup(t)
	file := filepath.Join(lookups, "settings.yaml")
	os.WriteFile(file, []byte("settings:\n  opensearch.password:\n    secret: by-hand-pw\n    sent_to: https://os.lab.example.com:9200\n"), 0o600)
	c, err := config.Load(path)
	if err != nil || c.OpenSearch.Password != "by-hand-pw" {
		t.Fatalf("load: %v", err)
	}
	logs := &syncBuffer{}
	log := newLogger(logs)
	useKeys(c, log)
	encryptStores(c, log)
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), "by-hand-pw") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Errorf("settings.yaml after startup:\n%s", data)
	}
	if !strings.Contains(logs.String(), `msg="encrypted the passwords and keys stored in a file" file=`+file+" values=1") {
		t.Errorf("log:\n%s", logs.String())
	}
	if c, err := config.Load(path); err != nil || c.OpenSearch.Password != "by-hand-pw" {
		t.Errorf("load after: %v", err)
	}
}

// "signalith validate" says when a password saved on the Settings page
// cannot be decrypted, and the config is still valid.
func TestValidateReportsUnreadablePageSecret(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	fos := newFakeOpenSearch(t)
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(path, []byte("opensearch:\n  url: "+fos.URL+"\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	other := secrets.NewKeyring(t.TempDir())
	sealed, err := other.Seal("settings.opensearch.password", "lost-pw")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "lookups", "settings.yaml")
	os.MkdirAll(filepath.Dir(file), 0o750)
	os.WriteFile(file, []byte("settings:\n  opensearch.password:\n    secret: "+sealed+"\n    sent_to: "+fos.URL+"\n"), 0o600)
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	for _, want := range []string{
		path + " is valid.",
		"Warning: 1 password or key saved on the Settings page cannot be decrypted, so Signalith runs without it",
		"Warning: On the Settings page (" + file + "), opensearch.password is encrypted with master key " + other.KeyID(),
		"signalith settings reset opensearch.password",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q (%v):\n%s", want, err, out)
		}
	}
	if strings.Contains(out, "lost-pw") {
		t.Errorf("validate shows the password:\n%s", out)
	}
}

// The settings commands and validate read the signalith service's unit,
// as the secrets commands do, and so find the file the service keeps;
// a unit for another config file is not used, and only pointed to.
func TestSettingsCommandsReadTheUnit(t *testing.T) {
	t.Setenv("SIGNALITH_SETTINGS_FILE", "")
	t.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	t.Setenv("SIGNALITH_STATE_DIR", "")
	fos := newFakeOpenSearch(t)
	dir := t.TempDir()
	h, _ := config.HashPassword("s3cret-pass")
	path := filepath.Join(dir, "etc", "signalith.yaml")
	os.MkdirAll(filepath.Dir(path), 0o750)
	os.WriteFile(path, []byte("opensearch:\n  url: "+fos.URL+"\nauth:\n  admin_password_hash: "+h+"\n"), 0o600)
	svcLookups := filepath.Join(dir, "var", "lookups")
	svcFile := filepath.Join(svcLookups, "settings.yaml")
	page := &config.PageSettings{}
	page.Set("search.max_events", 4321, "alice", time.Now())
	if err := config.WritePageSettings(svcFile, page); err != nil {
		t.Fatal(err)
	}
	served := path
	saved := readServiceSettings
	readServiceSettings = func() *serviceSettings {
		return &serviceSettings{where: "the test unit", args: []string{"serve", "-c", served},
			env: map[string]string{"SIGNALITH_LOOKUPS_DIR": svcLookups, "SIGNALITH_OPENSEARCH_PASSWORD": "never-taken"}}
	}
	t.Cleanup(func() { readServiceSettings = saved })

	out, err := capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) })
	if err != nil || !strings.Contains(out, "Using the settings the signalith service is given (the test unit):\n  SIGNALITH_LOOKUPS_DIR="+svcLookups) ||
		!strings.Contains(out, "Changed on the Settings page ("+svcFile+"):") || !strings.Contains(out, "4321") || strings.Contains(out, "never-taken") {
		t.Errorf("list: %v\n%s", err, out)
	}
	os.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil || !strings.Contains(out, "Changed on the Settings page ("+svcFile+"): search.max_events.") || strings.Contains(out, "Note: The Signalith service keeps") {
		t.Errorf("validate: %v\n%s", err, out)
	}

	// The service runs another config file: its folders are not used, and
	// on Linux the commands point to the file it keeps.
	served = filepath.Join(dir, "other", "signalith.yaml")
	os.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	own := filepath.Join(dir, "etc", "lookups", "settings.yaml")
	out, err = capture(t, func() error { return cmdSettings([]string{"list", "-c", path}) })
	if err != nil || strings.Contains(out, "Using the settings") || !strings.Contains(out, "There is no settings file at "+own) {
		t.Errorf("list for another config: %v\n%s", err, out)
	}
	if runtime.GOOS == "linux" && !strings.Contains(out, "The Signalith service keeps its settings in "+svcFile) {
		t.Errorf("list for another config, no pointer to the service's file:\n%s", out)
	}
	if got := serviceSettingsPath(); got != svcFile {
		t.Errorf("serviceSettingsPath() = %q", got)
	}
	// A unit that moves neither folder: the service keeps the file where
	// the commands look already.
	readServiceSettings = func() *serviceSettings {
		return &serviceSettings{where: "the test unit", args: []string{"serve", "-c", path}, env: map[string]string{}}
	}
	if got := serviceSettingsPath(); got != "" {
		t.Errorf("serviceSettingsPath() without folders = %q", got)
	}
}

// A restart in place sets the master key up again from the config it
// loads, logs where it comes from only when that changed, and encrypts a
// plain value written in the meantime.
func TestRestartSetsUpTheMasterKey(t *testing.T) {
	rs := startRunner(t, nil, nil)
	dir := filepath.Dir(rs.r.path)
	file := filepath.Join(dir, "lookups", "settings.yaml")
	if got := secrets.Default().DefaultPath(); got != filepath.Join(dir, "keys", "master.key") {
		t.Errorf("the default keyring is not the config's: %s", got)
	}
	rs.save(`{"opensearch.password":"page-pw"}`)
	data, _ := os.ReadFile(file)
	if strings.Contains(string(data), "page-pw") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Fatalf("settings.yaml:\n%s", data)
	}
	if st, _ := os.Stat(file); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	count := func(s string) int { return strings.Count(rs.logs.String(), s) }
	if count("no master key yet") != 1 || count("made a new master key") != 1 || count(`msg="master key for stored passwords and keys"`) != 0 {
		t.Errorf("log before the restart:\n%s", rs.logs.String())
	}
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("restart %+v\n%s", res, rs.logs.String())
	}
	if count(`msg="master key for stored passwords and keys"`) != 1 || count("no master key yet") != 1 {
		t.Errorf("log after the restart:\n%s", rs.logs.String())
	}
	if c, err := config.Load(rs.r.path); err != nil || c.OpenSearch.Password != "page-pw" {
		t.Errorf("load: %v", err)
	}
	// Written by hand in the meantime.
	p, err := config.ReadPageSettings(file)
	if err != nil {
		t.Fatal(err)
	}
	plain := "by-hand-pw"
	p.Settings["opensearch.password"].Secret = &plain
	if err := config.WritePageSettings(file, p); err != nil {
		t.Fatal(err)
	}
	if _, res := rs.restart(); !res.OK {
		t.Fatalf("second restart %+v\n%s", res, rs.logs.String())
	}
	data, _ = os.ReadFile(file)
	if strings.Contains(string(data), "by-hand-pw") || !strings.Contains(string(data), "secret: enc:v1:") {
		t.Errorf("settings.yaml after the second restart:\n%s", data)
	}
	if count(`msg="master key for stored passwords and keys"`) != 1 || count("encrypted the passwords and keys stored in a file") != 1 {
		t.Errorf("log after the second restart:\n%s", rs.logs.String())
	}
	if !rs.signedIn("") {
		t.Error("signed out by the restarts")
	}
}
