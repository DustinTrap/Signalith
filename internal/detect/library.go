package detect

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Library holds the built-in detections and the custom ones in Dir.
type Library struct {
	Dir string // where custom detections are saved; "" keeps them in memory only

	mu      sync.RWMutex
	builtin map[string]*Detection
	custom  map[string]*Detection
}

// ErrNotFound is returned for unknown detection IDs.
var ErrNotFound = errors.New("detection not found")

// Decode reads one detection from YAML, rejecting unknown keys.
func Decode(data []byte) (*Detection, error) {
	var d Detection
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&d); err != nil {
		return nil, err
	}
	d.Defaults()
	return &d, nil
}

// Encode renders a detection as YAML.
func Encode(d *Detection) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

// Builtin returns the detections shipped in the binary.
func Builtin() ([]*Detection, error) {
	files, err := fs.Glob(builtinFS, "builtin/*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Detection
	for _, f := range files {
		data, err := builtinFS.ReadFile(f)
		if err != nil {
			return nil, err
		}
		d, err := Decode(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := d.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if d.ID+".yaml" != path.Base(f) {
			return nil, fmt.Errorf("%s: id %q does not match the file name", f, d.ID)
		}
		d.Source = "builtin"
		out = append(out, d)
	}
	return out, nil
}

// NewLibrary loads built-in detections and every *.yaml file in dir.
// Invalid custom files are reported in the returned problems but do not
// stop the others from loading.
func NewLibrary(dir string) (*Library, []error, error) {
	l := &Library{Dir: dir, builtin: map[string]*Detection{}, custom: map[string]*Detection{}}
	bs, err := Builtin()
	if err != nil {
		return nil, nil, err
	}
	for _, d := range bs {
		l.builtin[d.ID] = d
	}
	if dir == "" {
		return l, nil, nil
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.yaml"))
	if err != nil {
		return nil, nil, err
	}
	var problems []error
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		d, err := Decode(data)
		if err == nil {
			err = d.Validate()
		}
		if err == nil && d.ID+".yaml" != filepath.Base(f) {
			err = fmt.Errorf("id %q does not match the file name", d.ID)
		}
		if err != nil {
			problems = append(problems, fmt.Errorf("%s: %w", f, err))
			continue
		}
		l.custom[d.ID] = d
	}
	return l, problems, nil
}

func (l *Library) resolve(id string) *Detection {
	if d, ok := l.custom[id]; ok {
		c := *d
		c.Source = "custom"
		if _, ok := l.builtin[id]; ok {
			c.Source = "override"
		}
		return &c
	}
	if d, ok := l.builtin[id]; ok {
		c := *d
		return &c
	}
	return nil
}

// List returns every detection, sorted by ID.
func (l *Library) List() []*Detection {
	l.mu.RLock()
	defer l.mu.RUnlock()
	ids := map[string]bool{}
	for id := range l.builtin {
		ids[id] = true
	}
	for id := range l.custom {
		ids[id] = true
	}
	out := make([]*Detection, 0, len(ids))
	for id := range ids {
		out = append(out, l.resolve(id))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns one detection.
func (l *Library) Get(id string) (*Detection, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if d := l.resolve(id); d != nil {
		return d, nil
	}
	return nil, ErrNotFound
}

// Put validates and saves a detection. Saving a built-in's ID creates an
// override; the built-in comes back when the override is deleted.
func (l *Library) Put(d *Detection) error {
	c := *d
	c.Source = ""
	c.Defaults()
	if err := c.Validate(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.Dir != "" {
		data, err := Encode(&c)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(l.Dir, 0o750); err != nil {
			return err
		}
		if err := writeFileAtomic(filepath.Join(l.Dir, c.ID+".yaml"), data); err != nil {
			return err
		}
	}
	l.custom[c.ID] = &c
	return nil
}

// Delete removes a custom detection or reverts an override to the
// built-in. Built-ins cannot be deleted; disable them instead.
func (l *Library) Delete(id string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.custom[id]; !ok {
		if _, ok := l.builtin[id]; ok {
			return errors.New("built-in detections cannot be deleted; disable it instead")
		}
		return ErrNotFound
	}
	if l.Dir != "" {
		if err := os.Remove(filepath.Join(l.Dir, id+".yaml")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	delete(l.custom, id)
	return nil
}

func writeFileAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-"+strings.TrimSuffix(filepath.Base(name), ".yaml")+"-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
