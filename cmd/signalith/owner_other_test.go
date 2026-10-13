//go:build !unix

package main

import "os"

// fileOwner reports no owner where files have no Unix owner.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }
