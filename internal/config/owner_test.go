//go:build !windows

package config

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestSettingsFileKeepsItsOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files away")
	}
	dir := filepath.Join(t.TempDir(), "lookups")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	// The service's account owns the folder; root runs the command line.
	if err := os.Chown(dir, 4242, 4343); err != nil {
		t.Skip("cannot change owners here:", err)
	}
	path := filepath.Join(dir, "settings.yaml")
	p := &PageSettings{}
	p.Set("search.max_events", 10, "root", time.Now())
	owner := func() (uint32, uint32) {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		st := fi.Sys().(*syscall.Stat_t)
		return st.Uid, st.Gid
	}
	if err := WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(); u != 4242 || g != 4343 {
		t.Errorf("new file owned by %d:%d", u, g)
	}
	// Rewriting keeps the file's own owner.
	if err := os.Chown(path, 5151, 5252); err != nil {
		t.Fatal(err)
	}
	p.Set("search.max_events", 20, "root", time.Now())
	if err := WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}
	if u, g := owner(); u != 5151 || g != 5252 {
		t.Errorf("rewritten file owned by %d:%d", u, g)
	}
}

// A link put in place of the settings file must not get its target given
// away: the new file replaces the link, and the target keeps its owner.
func TestSettingsFileOwnerIgnoresALink(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to give files away")
	}
	dir := filepath.Join(t.TempDir(), "lookups")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 4242, 4343); err != nil {
		t.Skip("cannot change owners here:", err)
	}
	target := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "settings.yaml")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	p := &PageSettings{}
	p.Set("search.max_events", 10, "root", time.Now())
	if err := WritePageSettings(path, p); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 0 || st.Gid != 0 {
		t.Errorf("the link's target was given to %d:%d", st.Uid, st.Gid)
	}
	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("the settings file is still a link")
	}
	if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4242 || st.Gid != 4343 {
		t.Errorf("new file owned by %d:%d, want the folder's owner", st.Uid, st.Gid)
	}
}
