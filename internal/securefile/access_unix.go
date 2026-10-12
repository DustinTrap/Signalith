//go:build unix

package securefile

import (
	"errors"
	"os"
	"syscall"
)

// keepAccess gives tmp the mode and owner of the file it replaces. A
// command run as root (sudo signalith secrets encrypt) thus leaves the
// service's files owned by the service.
func keepAccess(_ string, old os.FileInfo, tmp *os.File) error {
	if err := tmp.Chmod(old.Mode().Perm()); err != nil {
		return err
	}
	st, ok := old.Sys().(*syscall.Stat_t)
	if ok && (int(st.Uid) != os.Geteuid() || int(st.Gid) != os.Getegid()) {
		// Only root, or an owner changing the group to one of its own,
		// may do this; otherwise the new file stays this account's.
		_ = tmp.Chown(int(st.Uid), int(st.Gid))
	}
	return nil
}

// newFileAccess keeps a new file at mode 0600 (os.CreateTemp's) and, when
// running as root, gives it the owner of the folder it is in: the
// service's own folder stays the service's.
func newFileAccess(tmp *os.File, dir string) error {
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if os.Geteuid() == 0 {
		if st, err := os.Stat(dir); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (sys.Uid != 0 || sys.Gid != 0) {
				return tmp.Chown(int(sys.Uid), int(sys.Gid))
			}
		}
	}
	return nil
}

// privateDir sets dir to mode 0700 and, for a folder root just made, the
// owner of the folder above it.
func privateDir(dir, parent string, created bool) error {
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	if created && os.Geteuid() == 0 {
		if st, err := os.Stat(parent); err == nil {
			if sys, ok := st.Sys().(*syscall.Stat_t); ok && (sys.Uid != 0 || sys.Gid != 0) {
				return os.Chown(dir, int(sys.Uid), int(sys.Gid))
			}
		}
	}
	return nil
}

func isBusy(err error) bool { return errors.Is(err, syscall.EBUSY) }
