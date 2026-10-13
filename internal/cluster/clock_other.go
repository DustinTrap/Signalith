//go:build !linux

package cluster

import "time"

// bootTime is not read here: Go's monotonic clock already counts the time
// a suspended computer slept on Windows.
func bootTime() (time.Duration, bool) { return 0, false }
