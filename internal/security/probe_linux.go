//go:build linux

package security

import (
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// hostFS is the real /proc and /sys.
var hostFS sysFS = osFS{root: "/"}

// probeProcess reads how the server's process runs: this process when
// self, else process pid (the CLI, about the running service). systemd
// says whether it runs under systemd.
func probeProcess(pid string, self, systemd bool) (ProcessFacts, MemoryFacts, string) {
	var p ProcessFacts
	var m MemoryFacts
	cvm := confidentialVM(hostFS)
	if pid == "" {
		p.Why = NoServiceLine
		return p, m, cvm
	}
	if self {
		pid = "self"
	}
	if err := readProcess(hostFS, pid, &p); err != nil {
		p.Known = false
		if os.IsPermission(err) {
			p.Why = DeniedLine("linux")
		} else {
			p.Why = "Signalith couldn't read how its process runs."
		}
		return p, m, cvm
	}
	p.Systemd = systemd
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.UserName = u.Username
	}
	m.Known = true
	if self {
		var lim unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_CORE, &lim); err == nil {
			m.CoreOff = lim.Cur == 0
		}
		if d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil {
			m.NotDumpable = d == 0
		}
	} else {
		// Whether another process is dumpable can't be read from
		// outside, so only its core limit counts.
		off, known := coreLimitOff(hostFS, pid)
		m.CoreOff, m.NotDumpable, m.Known = off, true, known
	}
	swapFacts(hostFS, readText(hostFS, "/proc/"+pid+"/mountinfo"), pid, &m)
	return p, m, cvm
}

// probeDisks finds the filesystems that hold paths, each once.
func probeDisks(paths []string, inContainer bool, _ string) []Disk {
	mountinfo := readText(hostFS, "/proc/self/mountinfo")
	vm := detectVM(hostFS)
	var out []Disk
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" {
			continue
		}
		real := realPath(p)
		var d Disk
		if inContainer {
			d = Disk{Path: p, Kind: DiskContainer}
			if m, ok := mountOf(parseMountinfo(mountinfo), real); ok {
				d.MountPoint, d.FSType, d.Source = m.Point, m.FSType, m.Source
			}
			if found := detectDisk(hostFS, mountinfo, real, vm); found.Kind == DiskNetwork || found.Kind == DiskMemory {
				d = found
			}
		} else {
			d = detectDisk(hostFS, mountinfo, real, vm)
		}
		d.Path = p
		key := d.MountPoint + "\x00" + d.Source
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, d)
	}
	return out
}

// realPath resolves links in p, or in the longest part of it that can
// be read.
func realPath(p string) string {
	p = filepath.Clean(p)
	rest := ""
	for at := p; ; at = filepath.Dir(at) {
		if r, err := filepath.EvalSymlinks(at); err == nil {
			return filepath.Join(r, rest)
		}
		if filepath.Dir(at) == at {
			return p
		}
		rest = filepath.Join(filepath.Base(at), rest)
	}
}

// DefaultGateway is the IPv4 default route's gateway: in a container,
// the address the host's port forwarding makes every sender seem to come
// from.
func DefaultGateway() (netip.Addr, bool) { return defaultGateway(hostFS) }

// ServiceAccount is the account the server runs as, for the CLI: that
// of process pid when it runs, else the owner of its state folder, else
// this one.
func ServiceAccount(pid, stateDir string) Account {
	if pid != "" {
		if a, ok := procAccount(hostFS, pid); ok {
			return a
		}
	}
	if a, ok := ownerOf(stateDir); ok {
		return a
	}
	return CurrentAccount()
}
