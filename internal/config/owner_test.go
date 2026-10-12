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
