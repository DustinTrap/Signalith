package securefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestServiceSID(t *testing.T) {
	// Windows' own TrustedInstaller service has this well-known SID.
	if got := ServiceSID("TrustedInstaller"); got != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
		t.Errorf("ServiceSID(TrustedInstaller) = %s", got)
	}
	if ServiceSID("signalith") != ServiceSID("Signalith") {
		t.Error("service names ignore case")
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "store.json")
	if err := WriteFile(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatalf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("new file mode %v", st.Mode().Perm())
		}
		// A replaced file keeps its mode.
		os.Chmod(p, 0o640)
		if err := WriteFile(p, []byte("two")); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
			t.Errorf("replaced file mode %v, want 0640", st.Mode().Perm())
		}
	}
	// Prepare writes nothing in place until Commit; Discard leaves nothing.
	pend, err := Prepare(p, []byte("three"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) == "three" {
		t.Error("Prepare replaced the file")
	}
	pend.Discard()
	if left, _ := filepath.Glob(filepath.Join(dir, "sub", ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	// CommitNew refuses to replace a file.
	pend, err = Prepare(p, []byte("four"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pend.CommitNew(); !errors.Is(err, fs.ErrExist) {
		t.Errorf("CommitNew over a file: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) == "four" {
		t.Error("CommitNew replaced the file")
	}
	n := filepath.Join(dir, "sub", "new")
	pend, _ = Prepare(n, []byte("five"))
	if err := pend.CommitNew(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(n); string(b) != "five" {
		t.Errorf("CommitNew wrote %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "sub", ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestMkdirPrivate(t *testing.T) {
	d := filepath.Join(t.TempDir(), "a", "keys")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(d); err != nil {
		t.Fatalf("an existing folder: %v", err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
			t.Errorf("mode %v, want 0700", st.Mode().Perm())
		}
	}
}
