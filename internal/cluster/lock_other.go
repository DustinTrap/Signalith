//go:build !unix && !windows

package cluster

// lockFile does nothing where files cannot be locked.
func lockFile(string) (func(), error) { return func() {}, nil }
