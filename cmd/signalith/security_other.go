//go:build !windows

package main

import (
	"context"
	"io"
)

// saveBitLocker is for Windows, where the service can't ask BitLocker.
func saveBitLocker(context.Context, string, io.Writer) {}
