//go:build !windows

package main

import "errors"

func cmdService(args []string) error {
	return errors.New("the service command is for Windows; on Linux install deploy/systemd/signalith.service and run: sudo systemctl enable --now signalith")
}
