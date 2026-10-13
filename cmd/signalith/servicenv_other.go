//go:build !linux && !windows

package main

import "time"

func platformServiceSettings() *serviceSettings { return nil }

// serviceStartedAfter is for systemd credentials, which exist only on
// Linux.
func serviceStartedAfter(time.Time) (bool, error) { return true, nil }
