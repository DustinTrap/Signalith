//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jrsamsanchez/signalith/internal/safelog"
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
