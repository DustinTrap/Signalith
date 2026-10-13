//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/jrsamsanchez/signalith/internal/safelog"
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
		asService = true
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
	// PreShutdown gives a stop at reboot the same time as any other stop.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown}
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
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				cancel()
				stopping(status, done)
				return false, 0
			}
		}
	}
}

// stopWait is how long a stop may take: the background jobs get up to a
// minute to finish before this server hands them to another one, then the
// last requests to OpenSearch and the web server's own wait.
const stopWait = 90 * time.Second

// stopping waits for serve to return, at most stopWait, telling Windows
// every few seconds that the stop is still going, so it does not give up
// on the service.
func stopping(status chan<- svc.Status, done <-chan error) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	limit := time.After(stopWait)
	for cp := uint32(1); ; cp++ {
		status <- svc.Status{State: svc.StopPending, CheckPoint: cp, WaitHint: 10000}
		select {
		case <-done:
			return
		case <-limit:
			return
		case <-tick.C:
		}
	}
}

// setPreshutdownTimeout asks Windows to wait up to stopWait for this
// service at reboot (SERVICE_PRESHUTDOWN_INFO).
func setPreshutdownTimeout(s *mgr.Service) error {
	info := struct{ timeout uint32 }{uint32((stopWait + 10*time.Second) / time.Millisecond)}
	return windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_PRESHUTDOWN_INFO, (*byte)(unsafe.Pointer(&info)))
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
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		abs, _ := filepath.Abs(path)
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: "Signalith SIEM",
			Description: "Signalith security event search and detection server",
			StartType:   mgr.StartAutomatic,
		}, "-c", abs)
		if err != nil {
			return err
		}
		defer s.Close()
		_ = setPreshutdownTimeout(s)
		_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
		fmt.Printf("Installed the %s service using %s. Start it with: signalith service start\n", serviceName, abs)
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
	return nil
}
