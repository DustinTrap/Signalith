package intel

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// The feeds added on the Threat intel page are kept in a YAML file
// (default intel_feeds.yaml in the lookups folder), next to the status
// file. Signalith rewrites it whole on each change, through a temporary
// file and a rename, so a crash never leaves half a file. It holds API
// keys, so only the server's own account may read it.

// feedsFile is the file's content.
type feedsFile struct {
	Feeds []FeedSpec `yaml:"feeds"`
	// Kept lists deleted feeds whose indicators were kept to age out, so
	// a restart does not remove them early.
	Kept []KeptFeed `yaml:"kept,omitempty"`
}

// KeptFeed is a deleted feed whose indicators stay until they expire.
type KeptFeed struct {
	Name  string    `yaml:"name"`
	Until time.Time `yaml:"until"`
}

const feedsFileHeader = `# Threat intel feeds added on the Threat intel page of Signalith.
# Signalith rewrites this file when feeds change there; to change a feed,
# use the page. It holds API keys and passwords, so keep it private.
# Feeds in signalith.yaml (intel.feeds) are not listed here.
`

// FileError is a feeds file that cannot be read.
type FileError struct {
	Path string
	Err  error
}

func (e *FileError) Error() string {
	return fmt.Sprintf("The feeds file %s could not be read (%v). Fix or delete it, then reload this page.", e.Path, e.Err)
}

func (e *FileError) Unwrap() error { return e.Err }

// loadFile reads the feeds file once; the caller holds f.mu.
func (f *Feeds) loadFile() {
	if f.fileRead {
		return
	}
	f.fileRead = true
	if f.gen == nil {
		f.gen = map[string]int{}
	}
	if f.File == "" {
		return
	}
	data, err := os.ReadFile(f.File)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		f.fileErr = &FileError{Path: f.File, Err: err}
		return
	}
	var ff feedsFile
	if err := yaml.Unmarshal(data, &ff); err != nil {
		f.fileErr = &FileError{Path: f.File, Err: err}
		return
	}
	for i := range ff.Feeds {
		ff.Feeds[i].Defaults()
	}
	f.ui, f.kept = ff.Feeds, ff.Kept
}

// retryFile reads the feeds file again if it could not be read before, so
// a fixed file takes effect without a restart; the caller holds f.mu.
func (f *Feeds) retryFile() {
	if f.fileRead && f.fileErr != nil {
		f.fileRead, f.fileErr = false, nil
	}
	f.loadFile()
}

// saveFile writes the feeds file; the caller holds f.mu. The caller
// updates f.ui and f.kept only after it succeeds.
func (f *Feeds) saveFile(ui []FeedSpec, kept []KeptFeed) error {
	if f.File == "" {
		return nil
	}
	now := f.now()
	var live []KeptFeed
	for _, k := range kept {
		if k.Until.After(now) {
			live = append(live, k)
		}
	}
	if ui == nil {
		ui = []FeedSpec{}
	}
	var buf bytes.Buffer
	buf.WriteString(feedsFileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(feedsFile{Feeds: ui, Kept: live}); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := writeFileAtomic(f.File, buf.Bytes()); err != nil {
		return fmt.Errorf("could not save %s: %w", f.File, err)
	}
	return nil
}

// writeFileAtomic replaces path with data, readable only by this account.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	// CreateTemp makes the file readable and writable only by its owner
	// (0600), and the rename keeps that.
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}
