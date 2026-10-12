//go:build windows

package securefile

import (
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// Well-known security identifiers.
const (
	sidSystem = "S-1-5-18"     // NT AUTHORITY\SYSTEM
	sidAdmins = "S-1-5-32-544" // BUILTIN\Administrators
)

// trustees returns who may use Signalith's private files: SYSTEM,
// Administrators, the service account and the account running now (the
// service itself, or the admin running the CLI or a test).
func trustees() []string {
	out := []string{sidSystem, sidAdmins, ServiceSID(ServiceName)}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		self := u.User.Sid.String()
		if self != "" && !contains(out, self) {
			out = append(out, self)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// privateACL returns the protected access list: full control for the
// trustees and nobody else. inherit makes the entries apply to the files
// and folders inside a folder.
func privateACL(inherit bool) (*windows.ACL, error) {
	flags := ""
	if inherit {
		flags = "OICI"
	}
	var b strings.Builder
	b.WriteString("D:P")
	for _, sid := range trustees() {
		b.WriteString("(A;" + flags + ";FA;;;" + sid + ")")
	}
	sd, err := windows.SecurityDescriptorFromString(b.String())
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

// protect gives path the protected access list.
func protect(path string, folder bool) error {
	dacl, err := privateACL(folder)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// keepAccess gives tmp the access list of the file it replaces: the same
// entries, protected or inherited from the folder as that one's are.
func keepAccess(old string, _ os.FileInfo, tmp *os.File) error {
	sd, err := windows.GetNamedSecurityInfo(old, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if ctrl&windows.SE_DACL_PROTECTED != 0 {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(tmp.Name(), windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// newFileAccess gives a new file the protected access list.
func newFileAccess(tmp *os.File, _ string) error { return protect(tmp.Name(), false) }

// privateDir gives a folder the protected access list, inherited by the
// files and folders inside it.
func privateDir(dir, _ string, _ bool) error { return protect(dir, true) }

func isBusy(error) bool { return false }
