//go:build unix

package main

import (
	"os"
	"syscall"
)

// chownLike gives path the owner of dir when running as root, so a file
// root writes into a server's folder stays readable by the server's user.
func chownLike(path, dir string) error {
	if os.Geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	return os.Chown(path, int(st.Uid), int(st.Gid))
}
