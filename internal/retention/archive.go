package retention

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ArchiveFormat names the archive file format in manifests.
const ArchiveFormat = "signalith-archive/1"

// Archive files are <index>.ndjson.gz with a <index>.json manifest beside
// them. When an index was archived before (events that arrived late
// recreated it), the next file is <index>.2.ndjson.gz, and so on.
const (
	dataExt     = ".ndjson.gz"
	manifestExt = ".json"
)

// Archive writes deleted days to a folder and reads them back. Each line
// of an archive file is one document, {"_id":...,"_source":{...}}, so the
// files can also be read with zcat and jq.
type Archive struct {
	Dir string
	// Seal, when set, wraps the file as it is written, for example to
	// encrypt it, and Unseal reverses it when reading; Encryption names
	// the scheme in manifests. When nil, files are plain gzip.
	Seal       func(io.Writer) (io.WriteCloser, error)
	Unseal     func(io.Reader) (io.Reader, error)
	Encryption string
}

// Manifest describes one archive file.
type Manifest struct {
	Format string `json:"format"`
	// ID is the file name without extension; restores name archives by it.
	ID       string `json:"id"`
	Index    string `json:"index"`
	Category string `json:"category"`
	Day      string `json:"day"` // YYYY-MM-DD
	Docs     int64  `json:"docs"`
	File     string `json:"file"`
	// Bytes is the archive file's size and IndexBytes the size the index
	// had in OpenSearch.
	Bytes      int64     `json:"bytes"`
	IndexBytes int64     `json:"index_bytes"`
	SHA256     string    `json:"sha256"`
	Created    time.Time `json:"created"`
	Encryption string    `json:"encryption,omitempty"`
}

var archiveID = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,250}$`)

// ErrArchiveNotFound is returned for unknown archive IDs.
var ErrArchiveNotFound = errors.New("archive not found")

func (a *Archive) path(name string) string { return filepath.Join(a.Dir, name) }

// ensureDir creates the archive folder, readable by its owner only.
func (a *Archive) ensureDir() error {
	if a.Dir == "" {
		return errors.New("no archive folder is set (retention.archive_dir)")
	}
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return fmt.Errorf("cannot create the archive folder %s: %w", a.Dir, err)
	}
	// A folder made by an installer may be more open; tighten it if this
	// server owns it.
	_ = os.Chmod(a.Dir, 0o700)
	return nil
}

// freeID returns the first archive ID for an index whose files do not
// exist yet.
func (a *Archive) freeID(index string) string {
	id := index
	for n := 2; ; n++ {
		_, err1 := os.Lstat(a.path(id + dataExt))
		_, err2 := os.Lstat(a.path(id + manifestExt))
		if errors.Is(err1, os.ErrNotExist) && errors.Is(err2, os.ErrNotExist) {
			return id
		}
		id = index + "." + strconv.Itoa(n)
	}
}

// countingWriter counts bytes written through it.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Exporter reads every document of an index.
type Exporter interface {
	Export(ctx context.Context, index string, fn func(Doc) error) error
}

// Write exports an index into a new archive file and returns its
// manifest. The file is written to a temporary name, synced to disk,
// checked against the expected document count, renamed into place and
// then read back in full before Write returns, so an index is only
// deleted once its archive is known to be complete and readable. On any
// error no archive files are left behind.
func (a *Archive) Write(ctx context.Context, ex Exporter, index, category, day string, indexBytes, expectDocs int64) (*Manifest, error) {
	if !archiveID.MatchString(index) {
		return nil, fmt.Errorf("%q is not an index name that can be archived", index)
	}
	if err := a.ensureDir(); err != nil {
		return nil, err
	}
	tmp, err := os.CreateTemp(a.Dir, ".tmp-"+index+"-*")
	if err != nil {
		return nil, fmt.Errorf("cannot write to the archive folder %s: %w", a.Dir, err)
	}
	keep := false
	defer func() {
		if !keep {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	sum := sha256.New()
	counted := &countingWriter{w: io.MultiWriter(tmp, sum)}
	var sealed io.WriteCloser
	var under io.Writer = counted
	if a.Seal != nil {
		if sealed, err = a.Seal(counted); err != nil {
			return nil, err
		}
		under = sealed
	}
	zw := gzip.NewWriter(under)
	bw := bufio.NewWriterSize(zw, 256<<10)
	var docs int64
	var line bytes.Buffer
	err = ex.Export(ctx, index, func(d Doc) error {
		line.Reset()
		id, _ := json.Marshal(d.ID)
		line.WriteString(`{"_id":`)
		line.Write(id)
		line.WriteString(`,"_source":`)
		if err := json.Compact(&line, d.Source); err != nil {
			return fmt.Errorf("document %s is not valid JSON: %w", d.ID, err)
		}
		line.WriteString("}\n")
		docs++
		_, err := bw.Write(line.Bytes())
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("exporting %s: %w", index, err)
	}
	if err := bw.Flush(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	if sealed != nil {
		if err := sealed.Close(); err != nil {
			return nil, err
		}
	}
	if err := tmp.Sync(); err != nil {
		return nil, fmt.Errorf("syncing the archive file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if docs != expectDocs {
		return nil, fmt.Errorf("the archive of %s has %d events but the index has %d", index, docs, expectDocs)
	}
	enc := ""
	if a.Seal != nil {
		enc = a.Encryption
		if enc == "" {
			enc = "sealed"
		}
	}
	id := a.freeID(index)
	m := &Manifest{
		Format: ArchiveFormat, ID: id, Index: index, Category: category, Day: day,
		Docs: docs, File: id + dataExt, Bytes: counted.n, IndexBytes: indexBytes,
		SHA256: hex.EncodeToString(sum.Sum(nil)), Created: time.Now().UTC(), Encryption: enc,
	}
	if err := os.Rename(tmp.Name(), a.path(m.File)); err != nil {
		return nil, err
	}
	keep = true
	fail := func(err error) (*Manifest, error) {
		os.Remove(a.path(m.File))
		os.Remove(a.path(id + manifestExt))
		return nil, err
	}
	if err := writeFileSynced(a.path(id+manifestExt), m); err != nil {
		return fail(err)
	}
	syncDir(a.Dir)
	if err := a.Verify(*m); err != nil {
		return fail(fmt.Errorf("the archive of %s could not be read back: %w", index, err))
	}
	return m, nil
}

// writeFileSynced writes JSON to a file atomically and syncs it to disk.
func writeFileSynced(name string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+filepath.Base(name)+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), name)
}

// syncDir makes a rename durable. Windows cannot sync folders, and does
// not need to.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}

// List returns every archive, newest day first, and a problem for each
// manifest that cannot be read.
func (a *Archive) List() ([]Manifest, []string, error) {
	if a.Dir == "" {
		return nil, nil, nil
	}
	entries, err := os.ReadDir(a.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var out []Manifest
	var problems []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, manifestExt) {
			continue
		}
		m, err := a.readManifest(strings.TrimSuffix(name, manifestExt))
		if err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Day != out[j].Day {
			return out[i].Day > out[j].Day
		}
		return out[i].ID < out[j].ID
	})
	return out, problems, nil
}

// Get returns one archive's manifest.
func (a *Archive) Get(id string) (Manifest, error) {
	if !archiveID.MatchString(id) {
		return Manifest{}, ErrArchiveNotFound
	}
	m, err := a.readManifest(id)
	if errors.Is(err, os.ErrNotExist) {
		return Manifest{}, ErrArchiveNotFound
	}
	return m, err
}

func (a *Archive) readManifest(id string) (Manifest, error) {
	data, err := os.ReadFile(a.path(id + manifestExt))
	if err != nil {
		return Manifest{}, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("not a valid manifest: %w", err)
	}
	if m.Format != ArchiveFormat {
		return Manifest{}, fmt.Errorf("unknown archive format %q", m.Format)
	}
	if m.ID != id || m.File != id+dataExt || !archiveID.MatchString(m.Index) {
		return Manifest{}, errors.New("the manifest does not match its file name")
	}
	st, err := os.Stat(a.path(m.File))
	if err != nil {
		return Manifest{}, fmt.Errorf("its data file is missing: %w", err)
	}
	if st.Size() != m.Bytes {
		return Manifest{}, fmt.Errorf("its data file is %d bytes, not %d", st.Size(), m.Bytes)
	}
	return m, nil
}

// Read calls fn with every document in an archive file, then checks the
// file's checksum and document count against its manifest. Callers that
// must not act on a damaged file call Verify first.
func (a *Archive) Read(m Manifest, fn func(Doc) error) error {
	f, err := os.Open(a.path(m.File))
	if err != nil {
		return err
	}
	defer f.Close()
	sum := sha256.New()
	var r io.Reader = io.TeeReader(f, sum)
	if m.Encryption != "" {
		if a.Unseal == nil {
			return fmt.Errorf("the archive is encrypted (%s) and this server cannot decrypt it", m.Encryption)
		}
		if r, err = a.Unseal(r); err != nil {
			return err
		}
	}
	zr, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("not a gzip file: %w", err)
	}
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 0, 1<<20), 256<<20)
	var n int64
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var d Doc
		if err := json.Unmarshal(line, &d); err != nil {
			return fmt.Errorf("line %d is not valid JSON: %w", n+1, err)
		}
		if len(d.Source) == 0 {
			return fmt.Errorf("line %d has no _source", n+1)
		}
		n++
		if fn != nil {
			if err := fn(d); err != nil {
				return err
			}
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	// Read to the end so the checksum covers the whole file.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != m.SHA256 {
		return fmt.Errorf("checksum mismatch: the file is damaged or was changed (sha256 %s, expected %s)", got, m.SHA256)
	}
	if n != m.Docs {
		return fmt.Errorf("the file holds %d events, not %d", n, m.Docs)
	}
	return nil
}

// Verify reads an archive file in full and checks its checksum and
// document count.
func (a *Archive) Verify(m Manifest) error { return a.Read(m, nil) }

// archivedDocs maps each index to how many of its documents the archive
// holds.
func archivedDocs(list []Manifest) map[string]int64 {
	out := map[string]int64{}
	for _, m := range list {
		out[m.Index] += m.Docs
	}
	return out
}
