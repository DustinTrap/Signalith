// Package securefile writes files that hold passwords and keys: whole or
// not at all, and readable only by Signalith's own account.
//
// A new file is readable and writable by its owner only (mode 0600), and a
// new private folder only by its owner (0700). Windows ignores those
// modes, so there a new file or private folder gets an access list of its
// own instead, not inherited from the folder above: full control for
// SYSTEM, Administrators, the Signalith service account (NT
// SERVICE\Signalith) and the account that made it, and nobody else. A file
// that is replaced keeps its mode, owner and access list.
package securefile

import (
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf16"
)

// ServiceName is the Windows service, whose virtual account NT
// SERVICE\Signalith the server runs as.
const ServiceName = "Signalith"

// WriteFile replaces path with data, through a temporary file in the same
// folder that is then renamed into place, so a crash never leaves half a
// file. Missing folders above it are created.
func WriteFile(path string, data []byte) error {
	p, err := Prepare(path, data)
	if err != nil {
		return err
	}
	return p.Commit()
}

// Pending is a file written next to its destination but not yet in place,
// so several files can be written before any of them changes: Commit puts
// it in place, Discard throws it away.
type Pending struct {
	path string
	tmp  string
	data []byte
}

// Path returns the file the pending write replaces.
func (p *Pending) Path() string { return p.path }

// Prepare writes data to a temporary file next to path, with the access
// path has (or a new file's), and returns it without replacing path.
func Prepare(path string, data []byte) (*Pending, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*Pending, error) {
		tmp.Close()
		os.Remove(tmp.Name())
		return nil, err
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if st, err := os.Stat(path); err == nil {
		if err := keepAccess(path, st, tmp); err != nil {
			return fail(fmt.Errorf("could not give the new %s the same permissions as the old one: %w", path, err))
		}
	} else if errors.Is(err, os.ErrNotExist) {
		if err := newFileAccess(tmp, dir); err != nil {
			return fail(fmt.Errorf("could not make %s private: %w", path, err))
		}
	} else {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return nil, err
	}
	return &Pending{path: path, tmp: tmp.Name(), data: data}, nil
}

// Commit puts the file in place.
func (p *Pending) Commit() error {
	err := os.Rename(p.tmp, p.path)
	if err != nil && isBusy(err) {
		// A file mounted into a container on its own (a Docker bind mount
		// of one file) cannot be replaced, only written in place.
		err = writeInPlace(p.path, p.data)
		os.Remove(p.tmp)
		return err
	}
	if err != nil {
		os.Remove(p.tmp)
	}
	return err
}

// CommitNew puts the file in place only if nothing is there yet, and
// returns an error wrapping fs.ErrExist otherwise, so two programs making
// the same file at once cannot both win.
func (p *Pending) CommitNew() error {
	defer os.Remove(p.tmp)
	err := os.Link(p.tmp, p.path)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return err
	}
	// The file system has no hard links: check, then rename.
	if _, serr := os.Lstat(p.path); serr == nil {
		return &fs.PathError{Op: "create", Path: p.path, Err: fs.ErrExist}
	}
	return os.Rename(p.tmp, p.path)
}

// Discard removes the temporary file.
func (p *Pending) Discard() { os.Remove(p.tmp) }

func writeInPlace(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// MkdirPrivate creates dir, and any missing folders above it, and makes
// dir private (see the package comment). A dir that already exists is
// made private too when this account may change it.
func MkdirPrivate(dir string) error {
	parent := filepath.Dir(dir)
	if err := os.MkdirAll(parent, 0o750); err != nil {
		return err
	}
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	created := err == nil
	if perr := privateDir(dir, parent, created); perr != nil && created {
		return fmt.Errorf("could not make %s private: %w", dir, perr)
	}
	return nil
}

// ServiceSID returns the security identifier of a Windows service's
// virtual account (NT SERVICE\<name>): S-1-5-80- and the SHA-1 of the
// upper-case service name in UTF-16, as five numbers. Windows works it out
// the same way, so it is known before the service is installed.
func ServiceSID(name string) string {
	u := utf16.Encode([]rune(strings.ToUpper(name)))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	sum := sha1.Sum(b)
	parts := make([]string, 5)
	for i := range parts {
		parts[i] = fmt.Sprint(binary.LittleEndian.Uint32(sum[4*i:]))
	}
	return "S-1-5-80-" + strings.Join(parts, "-")
}
