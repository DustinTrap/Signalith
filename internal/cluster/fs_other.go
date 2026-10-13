//go:build !linux && !windows

package cluster

// folderFilesystem cannot tell network filesystems apart here.
func folderFilesystem(string) (network, shared string, err error) { return "", "", nil }

// fallbackStateDirs: none here.
func fallbackStateDirs() []string { return nil }

// machineID is unknown here.
func machineID() string { return "" }
