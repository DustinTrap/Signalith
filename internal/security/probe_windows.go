//go:build windows

package security

import (
	"context"
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// probeProcess reads how the server's process runs: this process when
// self, else the Signalith service as configured (pid is "service" when
// it exists).
func probeProcess(pid string, self, _ bool) (ProcessFacts, MemoryFacts, string) {
	var p ProcessFacts
	switch {
	case self:
		tok := windows.GetCurrentProcessToken()
		if u, err := tok.GetTokenUser(); err == nil {
			p.SID = u.User.Sid.String()
			if account, domain, _, err := u.User.Sid.LookupAccount(""); err == nil {
				p.UserName = domain + `\` + account
			}
			p.Known = true
		}
		p.Elevated = tok.IsElevated()
		p.Service, _ = svc.IsWindowsService()
	case pid != "":
		p = serviceAccount()
	default:
		p.Why = NoServiceLine
	}
	return p, windowsDumps(), ""
}

// serviceAccount reads the account the Signalith service is set to run
// as.
func serviceAccount() ProcessFacts {
	var p ProcessFacts
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		p.Why = DeniedLine("windows")
		return p
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := syscall.UTF16PtrFromString(securefile.ServiceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		p.Why = "Signalith isn't installed as a service here, so how it runs can't be checked."
		return p
	}
	s := &mgr.Service{Name: securefile.ServiceName, Handle: h}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		p.Why = DeniedLine("windows")
		return p
	}
	p.Known, p.Service = true, true
	p.UserName = cfg.ServiceStartName
	switch {
	case cfg.ServiceStartName == "" || strings.EqualFold(cfg.ServiceStartName, "LocalSystem"):
		p.SID, p.UserName = "S-1-5-18", "Local System"
	default:
		if sid, _, _, err := windows.LookupSID("", cfg.ServiceStartName); err == nil {
			p.SID = sid.String()
		} else if strings.EqualFold(cfg.ServiceStartName, `NT SERVICE\`+securefile.ServiceName) {
			p.SID = securefile.ServiceSID(securefile.ServiceName)
		}
	}
	return p
}

// windowsDumps reads whether Windows Error Reporting keeps full memory
// dumps of crashing programs, or of signalith.exe.
func windowsDumps() MemoryFacts {
	m := MemoryFacts{Known: true}
	const base = `SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`
	read := func(path string) (dumpType uint64, folder string, ok bool) {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return 0, "", false
		}
		defer k.Close()
		dumpType = 1 // a mini dump, unless set
		if v, _, err := k.GetIntegerValue("DumpType"); err == nil {
			dumpType = v
		}
		folder, _, _ = k.GetStringValue("DumpFolder")
		return dumpType, folder, true
	}
	t, folder, ok := read(base)
	where := `HKLM\` + base
	if t2, f2, ok2 := read(base + `\signalith.exe`); ok2 {
		t, folder, ok, where = t2, f2, true, `HKLM\`+base+`\signalith.exe`
	}
	if ok && t == 2 {
		m.FullDumps, m.DumpFolder, m.DumpsRegistry = true, folder, where
	}
	return m
}

// windowsVM reads the BIOS vendor and product.
func windowsVM() vmInfo {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return vmInfo{}
	}
	defer k.Close()
	vendor, _, _ := k.GetStringValue("SystemManufacturer")
	product, _, _ := k.GetStringValue("SystemProductName")
	if p := providerOf(vendor, product); p != "" {
		return vmInfo{Virtual: true, Provider: p}
	}
	return vmInfo{}
}

// probeDisks describes the drives that hold paths, each once, from the
// answer an Administrator's signalith security saved.
func probeDisks(paths []string, inContainer bool, stateDir string) []Disk {
	saved := LoadDisks(stateDir)
	vm := windowsVM()
	var out []Disk
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		d := bitLockerDisk(p, saved, time.Now(), vm)
		key := d.Drive + d.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

// QueryBitLocker asks BitLocker about every volume; it works only as
// Administrator.
func QueryBitLocker(ctx context.Context) ([]BitLockerVolume, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", BitLockerQuery)
	cmd.Stderr = nil
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return ParseBitLocker(out)
}

// Elevated reports whether this process runs as Administrator.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// DefaultGateway is read only on Linux.
func DefaultGateway() (netip.Addr, bool) { return netip.Addr{}, false }

// ServiceAccount is the account the Signalith service is set to run as,
// for the CLI, or this one when there is no service.
func ServiceAccount(pid, _ string) Account {
	if pid != "" {
		if p := serviceAccount(); p.SID != "" {
			return Account{UID: -1, GID: -1, SID: p.SID}
		}
	}
	return CurrentAccount()
}
