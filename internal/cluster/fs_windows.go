//go:build windows

package cluster

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// folderFilesystem reports a state folder on a network share: a UNC path
// (\\server\share) or a mapped network drive.
func folderFilesystem(dir string) (network, shared string, err error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", "", err
	}
	if strings.HasPrefix(abs, `\\`) && !strings.HasPrefix(abs, `\\?\`) && !strings.HasPrefix(abs, `\\.\`) {
		return "SMB", "", nil
	}
	vol := filepath.VolumeName(abs)
	if vol == "" {
		return "", "", nil
	}
	root, err := windows.UTF16PtrFromString(vol + `\`)
	if err != nil {
		return "", "", err
	}
	if windows.GetDriveType(root) == windows.DRIVE_REMOTE {
		return "SMB", "", nil
	}
	return "", "", nil
}

// fallbackStateDirs are local folders for the state folder when the one
// that holds lookups.dir cannot be used.
func fallbackStateDirs() []string {
	if d := os.Getenv("ProgramData"); d != "" {
		return []string{filepath.Join(d, "Signalith")}
	}
	return nil
}

// machineID is this computer's id (the MachineGuid in the registry), or "".
func machineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}
