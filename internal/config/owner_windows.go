package config

import "os"

// On Windows a new file takes its folder's permissions, which the
// installer sets, so the service can read it whoever wrote it.
type fileOwner struct{}

func ownerOf(paths ...string) fileOwner { return fileOwner{} }

func (fileOwner) apply(*os.File) error { return nil }
