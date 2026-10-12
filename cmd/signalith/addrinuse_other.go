//go:build !windows

package main

import (
	"errors"
	"syscall"
)

// addrInUse reports whether a listen error is that the address is in use.
func addrInUse(err error) bool { return errors.Is(err, syscall.EADDRINUSE) }
