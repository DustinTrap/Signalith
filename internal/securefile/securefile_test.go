package securefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
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

// A file that can only be written in place (a Docker bind mount of one
// file) gets the content given to Prepare, even when the caller cleared
// its own copy right after, as a key's bytes are.
func TestCommitInPlaceUsesItsOwnCopy(t *testing.T) {
	if !isBusy(&os.LinkError{Op: "rename", Err: syscall.EBUSY}) {
		t.Skip("no in-place writes on this system")
	}
	p := filepath.Join(t.TempDir(), "master.key")
	os.WriteFile(p, []byte("old key"), 0o600)
	defer func() { rename = os.Rename }()
	rename = func(oldpath, newpath string) error {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EBUSY}
	}
	data := []byte("the new key")
	pend, err := Prepare(p, data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if err := pend.Commit(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "the new key" {
		t.Errorf("written in place: %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

// Writing through a link replaces the file it points to and keeps the
// link, so no copy with the old content is left behind.
func TestWriteFileFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real", "signalith.yaml")
	os.MkdirAll(filepath.Dir(real), 0o750)
	os.WriteFile(real, []byte("password: plain"), 0o640)
	link := filepath.Join(dir, "signalith.yaml")
	if err := os.Symlink(filepath.Join("real", "signalith.yaml"), link); err != nil {
		t.Skip("cannot make links here:", err)
	}
	if err := WriteFile(link, []byte("password: enc:v1:...")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v %v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(real); string(b) != "password: enc:v1:..." {
		t.Errorf("the file the link points to holds %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(real); st.Mode().Perm() != 0o640 {
			t.Errorf("mode %v, want the old file's 0640", st.Mode().Perm())
		}
	}
	// A link to nothing is an error, not a new file in place of the link.
	dangling := filepath.Join(dir, "gone.yaml")
	os.Symlink(filepath.Join(dir, "missing", "x.yaml"), dangling)
	if err := WriteFile(dangling, []byte("x")); err == nil {
		t.Error("writing through a link to nothing worked")
	}
}

func TestPreparePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not apply on Windows; see access_windows_test.go")
	}
	p := filepath.Join(t.TempDir(), "master.key")
	os.WriteFile(p, []byte("old"), 0o644)
	pend, err := PreparePrivate(p, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pend.Commit(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600 whatever the old file had", st.Mode().Perm())
	}
}

func TestOtherLinks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(p, []byte("x"), 0o600)
	if n := OtherLinks(p); n != 0 {
		t.Errorf("OtherLinks = %d for a file with one name", n)
	}
	if err := os.Link(p, filepath.Join(dir, "backup.yaml")); err != nil {
		t.Skip("no hard links here:", err)
	}
	want := 1
	if runtime.GOOS == "windows" {
		want = 0
	}
	if n := OtherLinks(p); n != want {
		t.Errorf("OtherLinks = %d, want %d", n, want)
	}
}

// A folder that is a link is not followed: a link someone else planted
// could otherwise have another folder's permissions changed.
func TestMkdirPrivateRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.Mkdir(victim, 0o755)
	keys := filepath.Join(dir, "state", "keys")
	os.MkdirAll(filepath.Dir(keys), 0o750)
	if err := os.Symlink(victim, keys); err != nil {
		t.Skip("cannot make links here:", err)
	}
	if err := MkdirPrivate(keys); err == nil {
		t.Fatal("MkdirPrivate followed a link")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(victim); st.Mode().Perm() != 0o755 {
			t.Errorf("the folder the link points to became %v", st.Mode().Perm())
		}
	}
}
