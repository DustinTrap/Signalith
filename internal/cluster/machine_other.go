//go:build !linux && !windows

package cluster

// machineID is unknown here.
func machineID() string { return "" }
