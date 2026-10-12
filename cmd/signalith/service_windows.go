//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/safelog"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "Signalith"

func init() {
	// When Windows starts us as a service, run the service handler instead
	// of the CLI.
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		path := defaultConfigPath()
		if len(os.Args) > 2 && os.Args[1] == "-c" {
			path = os.Args[2]
		}
		if err := svc.Run(serviceName, &service{configPath: path}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

type service struct{ configPath string }

func (s *service) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	elog, _ := eventlog.Open(serviceName)
	log := newLogger(os.Stderr)
	// The log file rotates by size (signalith.log.1 and so on), so it
	// cannot fill the disk.
	if f, err := safelog.OpenRotating(filepath.Join(filepath.Dir(s.configPath), "signalith.log"), safelog.DefaultMaxSize, safelog.DefaultBackups); err == nil {
		defer f.Close()
		log = newLogger(f)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, s.configPath, log) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil && elog != nil {
				elog.Error(1, "Signalith stopped: "+err.Error())
			}
			return false, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(15 * time.Second):
				}
				return false, 0
			}
		}
	}
}

func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: signalith service install|uninstall|start|stop [-c file]")
	}
	path := defaultConfigPath()
	if len(args) > 2 && args[1] == "-c" {
		path = args[2]
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	switch args[0] {
	case "install":
		return installService(m, path)
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		_ = eventlog.Remove(serviceName)
		return s.Delete()
	case "start":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		return s.Start()
	case "stop":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		_, err = s.Control(svc.Stop)
		return err
	default:
		return fmt.Errorf("unknown service action %q", args[0])
	}
}

// serviceAccount is the virtual account the service runs as: an account
// of its own that Windows manages, with no password, that can be given
// access to exactly the files it needs (unlike LocalSystem, which can
// read everything).
const serviceAccount = `NT SERVICE\` + serviceName

// modifyAccess is the "Modify" right on files and folders: read, write,
// run and delete, but not change permissions or take ownership.
const modifyAccess windows.ACCESS_MASK = 0x1301BF

// installService installs the service, or updates an existing one (an
// upgrade, or one installed by an older version as LocalSystem), so that
// it runs this program with the config file at path, as its own virtual
// account, and restarts after a failure.
func installService(m *mgr.Mgr, path string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cfg := mgr.Config{
		DisplayName:      "Signalith SIEM",
		Description:      "Signalith security event search and detection server",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: serviceAccount,
		// The service's own SID (NT SERVICE\Signalith) is in its token,
		// so access lists naming it apply.
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	verb := "Installed"
	s, err := m.OpenService(serviceName)
	if err == nil {
		verb = "Updated"
		cur, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		cur.BinaryPathName = syscall.EscapeArg(exe) + " -c " + syscall.EscapeArg(abs)
		cur.DisplayName, cur.Description, cur.StartType = cfg.DisplayName, cfg.Description, cfg.StartType
		cur.ServiceStartName, cur.SidType = cfg.ServiceStartName, cfg.SidType
		// A virtual account has no password; an empty one leaves it unset.
		cur.Password = ""
		if err := s.UpdateConfig(cur); err != nil {
			s.Close()
			return fmt.Errorf("could not update the %s service: %w", serviceName, err)
		}
	} else {
		if s, err = m.CreateService(serviceName, exe, cfg, "-c", abs); err != nil {
			return err
		}
	}
	defer s.Close()
	// Restart after 5 seconds, then 30, then every minute; count failures
	// from zero again after a day without one.
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}
	if err := s.SetRecoveryActions(actions, 24*60*60); err != nil {
		fmt.Printf("Warning: could not set the service to restart after a failure: %v\n", err)
	} else if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		fmt.Printf("Warning: could not set the service to restart after it stops with an error: %v\n", err)
	}
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	dirs := serviceFolders(abs)
	for _, dir := range dirs {
		if err := grantModify(dir, securefile.ServiceSID(serviceName)); err != nil {
			fmt.Printf("Warning: could not give %s access to %s (%v). Run: icacls \"%s\" /grant \"%s:(OI)(CI)M\"\n", serviceAccount, dir, err, dir, serviceAccount)
		}
	}
	fmt.Printf("%s the %s service using %s.\n", verb, serviceName, abs)
	fmt.Printf("It runs as %s, which may change files in: %s\n", serviceAccount, strings.Join(dirs, ", "))
	fmt.Println("Start it with: signalith service start")
	return nil
}

// serviceFolders lists the folders the service writes to: the config
// file's folder, then each data folder (lookups, detections, dashboards,
// archive, state) that exists and is not inside one already listed, such
// as an archive on another disk.
func serviceFolders(configPath string) []string {
	dirs := []string{filepath.Dir(configPath)}
	c, err := config.LoadUnchecked(configPath)
	if err != nil {
		return dirs
	}
	for _, d := range []string{c.StateDir(), c.LookupsDir(), c.DetectionsDir(), c.DashboardsDir(), c.ArchiveDir()} {
		if d == "" {
			continue
		}
		if st, err := os.Stat(d); err != nil || !st.IsDir() {
			continue
		}
		inside := false
		for _, have := range dirs {
			if rel, err := filepath.Rel(have, d); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				inside = true
				break
			}
		}
		if !inside {
			dirs = append(dirs, d)
		}
	}
	return dirs
}

// grantModify adds Modify for sid to the folder's access list, inherited
// by what is in it, keeping the entries already there and whether the
// list is its own or inherited from the folder above.
func grantModify(dir, sid string) error {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
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
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: modifyAccess,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(s),
		},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
}
