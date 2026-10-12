//go:build !windows

package config

import (
	"os"
	"syscall"
)

// fileOwner is the account that owns a file.
type fileOwner struct {
	uid, gid int
	ok       bool
}

// ownerOf returns the owner of the first of paths that exists. A link is
// skipped: its owner says nothing about who should own the file.
func ownerOf(paths ...string) fileOwner {
	for _, p := range paths {
		fi, err := os.Lstat(p)
		if err != nil || fi.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			return fileOwner{uid: int(st.Uid), gid: int(st.Gid), ok: true}
		}
	}
	return fileOwner{}
}

// apply gives the new file f to the owner, when running as root: the
// command line is often run with sudo while the service runs as its own
// account, which must still be able to read the file. It works on the
// open file, before it is renamed into place, so nothing can swap the
// path for a link to another file in between.
func (o fileOwner) apply(f *os.File) error {
	if o.ok && os.Geteuid() == 0 {
		return f.Chown(o.uid, o.gid)
	}
	return nil
}
