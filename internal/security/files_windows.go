//go:build windows

package security

import (
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// Account is the account Signalith runs as, whose files are its own.
type Account struct {
	UID, GID int
	SID      string
}

// Access rights that let an account read or change a file.
const (
	readRights  = windows.ACCESS_MASK(0x1 | 0x80000000 | 0x10000000)                           // FILE_READ_DATA, GENERIC_READ, GENERIC_ALL
	writeRights = windows.ACCESS_MASK(0x2 | 0x4 | 0x40000000 | 0x10000000 | 0x40000 | 0x80000) // FILE_WRITE_DATA, FILE_APPEND_DATA, GENERIC_WRITE, GENERIC_ALL, WRITE_DAC, WRITE_OWNER
	inheritOnly = 0x08
)

// everyoneSIDs stand for every account on the computer.
var everyoneSIDs = map[string]bool{
	"S-1-1-0":      true, // Everyone
	"S-1-5-11":     true, // Authenticated Users
	"S-1-5-32-545": true, // Users
	"S-1-5-4":      true, // Interactive
	"S-1-2-0":      true, // Local
}

// trustedSID reports whether sid may use Signalith's files: SYSTEM,
// Administrators, a service account (Signalith's, TrustedInstaller's),
// the file's owner, or acct.
func trustedSID(sid, owner string, acct Account) bool {
	switch {
	case sid == "S-1-5-18", sid == "S-1-5-32-544", sid == "S-1-3-0",
		strings.HasPrefix(sid, "S-1-5-80-"),
		sid == owner, acct.SID != "" && strings.EqualFold(sid, acct.SID):
		return true
	}
	return false
}

// probePerm reads who other than Signalith and administrators may read
// or change path, from its access list. Mode bits are never used here:
// Windows shows every file as 0666.
func probePerm(path string, acct Account) (*Perm, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	p := &Perm{}
	owner := ""
	if o, _, err := sd.Owner(); err == nil && o != nil {
		owner = o.String()
		p.Owner = accountName(o)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return nil, err
	}
	if dacl == nil {
		// No access list at all: everyone may do anything.
		p.OtherRead, p.OtherWrite = true, true
		return p, nil
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&inheritOnly != 0 {
			continue
		}
		sidp := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sid := sidp.String()
		if trustedSID(sid, owner, acct) {
			continue
		}
		read, write := ace.Mask&readRights != 0, ace.Mask&writeRights != 0
		if everyoneSIDs[sid] {
			p.OtherRead = p.OtherRead || read
			p.OtherWrite = p.OtherWrite || write
			continue
		}
		if read || write {
			p.SomeRead = p.SomeRead || read
			p.SomeWrite = p.SomeWrite || write
			if p.Group == "" {
				p.Group = accountName(sidp)
			}
		}
	}
	return p, nil
}

func accountName(sid *windows.SID) string {
	if account, domain, _, err := sid.LookupAccount(""); err == nil {
		if domain != "" {
			return domain + `\` + account
		}
		return account
	}
	return sid.String()
}

// CurrentAccount is the account this process runs as.
func CurrentAccount() Account {
	a := Account{UID: -1, GID: -1}
	if u, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		a.SID = u.User.Sid.String()
	}
	return a
}

// isService reports whether this process runs as a Windows service.
func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}
