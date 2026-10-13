package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// systemctlShow returns what systemd knows about the signalith service.
// Tests replace it.
var systemctlShow = func(props ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := []string{"show", "signalith.service"}
	for _, p := range props {
		args = append(args, "--property="+p)
	}
	return exec.CommandContext(ctx, "systemctl", args...).Output()
}

func platformServiceSettings() *serviceSettings {
	out, err := systemctlShow("ExecStart", "Environment", "EnvironmentFiles", "LoadCredential")
	if err != nil {
		return nil
	}
	return parseSystemctlShow(out, os.ReadFile)
}

// serviceStartedAfter reports whether the signalith service is running
// and started after t. A service that is not running is reported as
// started after t: it reads its key when it starts again.
func serviceStartedAfter(t time.Time) (bool, error) {
	out, err := systemctlShow("ActiveState", "ExecMainStartTimestampMonotonic")
	if err != nil {
		return false, err
	}
	var state string
	var started uint64
	for _, line := range strings.Split(string(out), "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), "=")
		switch k {
		case "ActiveState":
			state = v
		case "ExecMainStartTimestampMonotonic":
			started, _ = strconv.ParseUint(v, 10, 64)
		}
	}
	if state != "active" && state != "activating" && state != "reloading" {
		return true, nil
	}
	if started == 0 {
		return false, errors.New("systemd does not say when the service started")
	}
	// The start time is on the monotonic clock, in microseconds; turn it
	// into the time of day by its distance from now.
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return false, err
	}
	ago := time.Duration(now.Nano()) - time.Duration(started)*time.Microsecond
	return time.Now().Add(-ago).After(t), nil
}
