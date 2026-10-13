package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// badFolders makes the state folder check fail for the folders listed,
// as on a network share or a folder the service's user cannot write.
func badFolders(t *testing.T, bad ...string) {
	t.Helper()
	forgetStateDirs()
	saved := stateDirProblem
	stateDirProblem = func(dir string) string {
		for _, b := range bad {
			if samePath(dir, b) {
				return "this user cannot write in " + dir
			}
		}
		return ""
	}
	t.Cleanup(func() {
		stateDirProblem = saved
		forgetStateDirs()
	})
}

// A usable folder that holds lookups.dir is the state folder.
func TestStateDirIsNextToLookups(t *testing.T) {
	badFolders(t)
	def, fallback := t.TempDir(), t.TempDir()
	if dir, why := pickStateDir(def, []string{fallback}); dir != def || why != "" {
		t.Errorf("usable folder: %q %q", dir, why)
	}
	if _, err := os.Stat(filepath.Join(fallback, insteadOfFile)); err == nil {
		t.Error("the fallback was marked")
	}
}

// When the folder that holds lookups.dir cannot be used and holds none of
// Signalith's files, a local fallback is used, says why, and stays the
// state folder after the usual one can be used again, also for commands
// run by hand (as another user, for whom it may be writable).
func TestStateDirFallback(t *testing.T) {
	def, other, fallback := t.TempDir(), t.TempDir(), t.TempDir()
	badFolders(t, def, other)
	dir, why := pickStateDir(def, []string{other, fallback})
	if dir != fallback || !strings.Contains(why, "cannot write in") || !strings.Contains(why, "SIGNALITH_STATE_DIR") {
		t.Fatalf("fallback: %q %q", dir, why)
	}
	// Kept for the life of the process.
	if again, _ := pickStateDir(def, []string{other, fallback}); again != fallback {
		t.Errorf("second answer %q", again)
	}
	// A later start, or a command run as root, for whom def is fine.
	badFolders(t)
	dir, why = pickStateDir(def, []string{other, fallback})
	if dir != fallback || !strings.Contains(why, "used instead of "+def) {
		t.Errorf("after def works again: %q %q", dir, why)
	}
	// Another config's folder is not taken for this one's.
	if dir, _ := pickStateDir(t.TempDir(), []string{fallback}); dir == fallback {
		t.Error("a fallback used for another folder was taken")
	}
}

// An install whose master key, HTTPS certificate or admin password file is
// already in the folder that holds lookups.dir keeps that folder, even
// where a fallback would now be chosen: an upgrade leaves nothing behind.
func TestStateDirKeepsExistingFiles(t *testing.T) {
	for _, f := range []string{"keys", "tls", "admin-password-hash", "node.id"} {
		t.Run(f, func(t *testing.T) {
			def, fallback := t.TempDir(), t.TempDir()
			badFolders(t, def)
			if f == "keys" || f == "tls" {
				os.MkdirAll(filepath.Join(def, f), 0o700)
			} else if err := os.WriteFile(filepath.Join(def, f), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if !HoldsState(def) {
				t.Fatal("HoldsState is false")
			}
			if dir, why := pickStateDir(def, []string{fallback}); dir != def || why != "" {
				t.Errorf("got %q %q", dir, why)
			}
		})
	}
}

// With nowhere better, the usual folder is kept, and using it says what
// is wrong.
func TestStateDirNoFallback(t *testing.T) {
	def, fallback := t.TempDir(), t.TempDir()
	badFolders(t, def, fallback)
	if dir, why := pickStateDir(def, []string{fallback}); dir != def || why != "" {
		t.Errorf("got %q %q", dir, why)
	}
}

// SIGNALITH_STATE_DIR always wins, and the master key, the HTTPS
// certificate, the admin password file and StateDirFor all use the one
// folder StateDir picks.
func TestStateDirOneFolder(t *testing.T) {
	badFolders(t)
	t.Setenv("SIGNALITH_LOOKUPS_DIR", "")
	t.Setenv("SIGNALITH_STATE_DIR", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "signalith.yaml")
	if err := os.WriteFile(path, []byte("lookups:\n  dir: data/lookups\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := Default()
	c.path = path
	c.Lookups.Dir = "data/lookups"
	want := filepath.Join(dir, "data")
	if got := c.StateDir(); got != want {
		t.Fatalf("StateDir = %q, want %q", got, want)
	}
	if got := StateDirFor(path); got != want {
		t.Errorf("StateDirFor = %q", got)
	}
	if got := c.TLSDir(); got != filepath.Join(want, "tls") {
		t.Errorf("TLSDir = %q", got)
	}
	if got := c.AdminHashFile(); got != filepath.Join(want, "admin-password-hash") {
		t.Errorf("AdminHashFile = %q", got)
	}
	if got := c.Keyring().DefaultPath(); !strings.HasPrefix(got, filepath.Join(want, "keys")+string(filepath.Separator)) {
		t.Errorf("master key %q", got)
	}
	env := t.TempDir()
	t.Setenv("SIGNALITH_STATE_DIR", env)
	if got, why := c.StateDirChoice(); got != env || why != "" {
		t.Errorf("SIGNALITH_STATE_DIR: %q %q", got, why)
	}
	if got := StateDirFor(path); got != env {
		t.Errorf("StateDirFor with SIGNALITH_STATE_DIR = %q", got)
	}
}

// The real check: a folder below a file cannot be made, so it cannot be a
// state folder; a temporary folder can.
func TestStateDirProblem(t *testing.T) {
	if p := StateDirProblem(t.TempDir()); p != "" {
		t.Errorf("a usable folder: %s", p)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if p := StateDirProblem(filepath.Join(file, "state")); !strings.Contains(p, "cannot write in") {
		t.Errorf("below a file: %q", p)
	}
	// A config whose usual folder is below a file falls back to the
	// platform's folder.
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		return
	}
	forgetStateDirs()
	t.Cleanup(forgetStateDirs)
	fallback := t.TempDir()
	if runtime.GOOS == "linux" {
		t.Setenv("STATE_DIRECTORY", fallback)
	} else {
		t.Setenv("ProgramData", fallback)
		fallback = filepath.Join(fallback, "Signalith")
	}
	t.Setenv("SIGNALITH_STATE_DIR", "")
	c := Default()
	c.Lookups.Dir = filepath.Join(file, "state", "lookups")
	if dir, why := c.StateDirChoice(); dir != fallback || !strings.Contains(why, "cannot write in") {
		t.Errorf("fallback: %q %q", dir, why)
	}
}
