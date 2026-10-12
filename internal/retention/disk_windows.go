//go:build windows

package retention

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// diskSpace returns the bytes free for this process and the size of the
// disk that holds dir, or of its nearest existing parent.
func diskSpace(dir string) (free, total int64, err error) {
	p, err := windows.UTF16PtrFromString(existing(dir))
	if err != nil {
		return 0, 0, err
	}
	var f, t, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &f, &t, &totalFree); err != nil {
		return 0, 0, err
	}
	return int64(f), int64(t), nil
}

// restrictDir gives a folder an access list of its own, not inherited
// from the drive or its parent: full control for SYSTEM, Administrators
// and the account the server runs as, and nobody else. Files created in
// it inherit the list. Unix file modes do not do this on Windows.
func restrictDir(dir string) error {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return err
	}
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", user.User.Sid.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
