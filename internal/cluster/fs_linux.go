//go:build linux

package cluster

import (
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Filesystem types from statfs, as in linux/magic.h and the CIFS client.
const (
	nfsMagic      = 0x6969
	smbMagic      = 0x517B
	cifsMagic     = 0xFF534D42
	smb2Magic     = 0xFE534D42
	fuseMagic     = 0x65735546
	v9fsMagic     = 0x01021997
	virtiofsMagic = 0x6A656A63
)

// folderFilesystem names the filesystem dir is on when it matters: a
// network one (refused), or one that bind mounts from Docker Desktop and
// WSL use (only warned about).
func folderFilesystem(dir string) (network, shared string, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", "", err
	}
	switch uint32(st.Type) {
	case nfsMagic:
		return "NFS", "", nil
	case smbMagic, cifsMagic, smb2Magic:
		return "SMB", "", nil
	case fuseMagic:
		return "", "FUSE", nil
	case v9fsMagic:
		return "", "9p", nil
	case virtiofsMagic:
		return "", "virtiofs", nil
	}
	return "", "", nil
}

// machineID is this computer's id (/etc/machine-id), or "".
func machineID() string {
	for _, f := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(f); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id
			}
		}
	}
	return ""
}
