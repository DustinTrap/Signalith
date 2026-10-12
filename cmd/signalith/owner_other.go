//go:build !unix

package main

// chownLike does nothing where files have no Unix owner: on Windows a new
// file takes its folder's access list.
func chownLike(path, dir string) error { return nil }
