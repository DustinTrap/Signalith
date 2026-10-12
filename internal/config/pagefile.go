package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/users"
	"gopkg.in/yaml.v3"
)

// The settings changed on the Settings page are kept in settings.yaml in
// the lookups folder (SIGNALITH_SETTINGS_FILE moves it), never in
// signalith.yaml, which is often read-only (Docker mounts it so, and the
// systemd unit protects /etc). The file holds only the settings changed
// on the page, with who changed them and when. Signalith rewrites it whole
// on each save, through a temporary file and a rename, readable only by
// its own account, since it can hold passwords and API keys.
//
// Precedence: environment variable > Settings page > signalith.yaml >
// built-in default.

// PageSettings is the content of settings.yaml.
type PageSettings struct {
	Settings map[string]*PageEntry `yaml:"settings"`
}

// PageEntry is one setting changed on the page.
type PageEntry struct {
	// Value is the setting's value. A secret is kept in Secret instead.
	Value  yaml.Node `yaml:"value,omitempty"`
	Secret *string   `yaml:"secret,omitempty"`
	// SentTo is the only address a secret is sent to: scheme://host:port
	// of the server it was entered for.
	SentTo    string    `yaml:"sent_to,omitempty"`
	ChangedBy string    `yaml:"changed_by,omitempty"`
	ChangedAt time.Time `yaml:"changed_at,omitempty"`
}

const pageFileHeader = `# Settings changed on the Settings page of Signalith. They override
# signalith.yaml; environment variables override both. Signalith rewrites
# this file when settings are saved on the page. To undo a change, use Reset
# on the page, or on the server: signalith settings reset [key...]
# It can hold passwords and API keys, so keep it private.
`

// sealSecret and openSecret are the one place secrets saved on the page
// are written and read. Today they keep the secret as it is, protected by
// the file's permissions; encrypting secrets at rest only changes these.
func sealSecret(s string) string          { return s }
func openSecret(s string) (string, error) { return s, nil }

// Empty reports whether no setting was changed on the page.
func (p *PageSettings) Empty() bool { return p == nil || len(p.Settings) == 0 }

// Keys lists the settings changed on the page, sorted.
func (p *PageSettings) Keys() []string {
	if p == nil {
		return nil
	}
	keys := make([]string, 0, len(p.Settings))
	for k := range p.Settings {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Clone returns a copy that can be changed without changing p.
func (p *PageSettings) Clone() *PageSettings {
	out := &PageSettings{Settings: map[string]*PageEntry{}}
	if p == nil {
		return out
	}
	for k, e := range p.Settings {
		c := *e
		if e.Secret != nil {
			s := *e.Secret
			c.Secret = &s
		}
		out.Settings[k] = &c
	}
	return out
}

// Set records a value changed on the page.
func (p *PageSettings) Set(key string, v any, by string, at time.Time) error {
	var n yaml.Node
	if err := n.Encode(v); err != nil {
		return err
	}
	p.put(key, &PageEntry{Value: n, ChangedBy: by, ChangedAt: at.UTC()})
	return nil
}

// SetSecret records a secret entered on the page and the address it may
// be sent to; an empty secret means none.
func (p *PageSettings) SetSecret(key, secret, sentTo string, by string, at time.Time) {
	sealed := sealSecret(secret)
	if secret == "" {
		sentTo = ""
	}
	p.put(key, &PageEntry{Secret: &sealed, SentTo: sentTo, ChangedBy: by, ChangedAt: at.UTC()})
}

func (p *PageSettings) put(key string, e *PageEntry) {
	if p.Settings == nil {
		p.Settings = map[string]*PageEntry{}
	}
	p.Settings[key] = e
}

// Remove takes a setting off the page, so signalith.yaml or the default
// applies again. It reports whether it was there.
func (p *PageSettings) Remove(key string) bool {
	if p == nil || p.Settings[key] == nil {
		return false
	}
	delete(p.Settings, key)
	return true
}

// PageFileError is a settings file that cannot be read.
type PageFileError struct {
	Path string
	Err  error
}

func (e *PageFileError) Error() string {
	return fmt.Sprintf("the settings file %s cannot be read (%v)", e.Path, e.Err)
}

func (e *PageFileError) Unwrap() error { return e.Err }

// ReadPageSettings reads the settings file. A missing file is no settings.
func ReadPageSettings(path string) (*PageSettings, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &PageSettings{}, nil
	}
	if err != nil {
		return nil, &PageFileError{Path: path, Err: err}
	}
	var p PageSettings
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, &PageFileError{Path: path, Err: err}
	}
	for k, e := range p.Settings {
		if e == nil {
			delete(p.Settings, k)
		}
	}
	return &p, nil
}

// WritePageSettings replaces the settings file; with no settings left it
// removes it.
func WritePageSettings(path string, p *PageSettings) error {
	if p.Empty() {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	var buf bytes.Buffer
	buf.WriteString(pageFileHeader)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(p); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	// The new file keeps the owner of the one it replaces, or of its
	// folder, so "sudo signalith settings reset" does not leave a file the
	// service cannot read.
	owner := ownerOf(path, filepath.Dir(path))
	if err := users.WriteFileAtomic(path, buf.Bytes()); err != nil {
		return err
	}
	owner.apply(path)
	return nil
}

// secretMismatch is a secret that is not used because the address it
// would be sent to is not the one it was entered for.
type secretMismatch struct {
	Key   string
	Bound string // where it may be sent
	Now   string // where it would go now
}

// applyPage applies the page's settings to c, which already has the
// environment applied: a setting set by an environment variable keeps
// that value. base is c without the page's settings. A value of the wrong
// type is an error; an unknown setting is skipped with a warning.
func (c *Config) applyPage(p *PageSettings, base *Config) error {
	l := c.layers
	for _, key := range p.Keys() {
		e := p.Settings[key]
		s, ok := Lookup(key)
		if !ok {
			l.warnings = append(l.warnings, fmt.Sprintf("%s has %s, which is not a setting on the Settings page; it is ignored", l.pageFile, key))
			continue
		}
		if l.env[key] != "" {
			continue
		}
		if s.Type == TypeSecret {
			var v string
			switch {
			case e.Secret != nil:
				var err error
				if v, err = openSecret(*e.Secret); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			case e.Value.Kind != 0:
				if err := e.Value.Decode(&v); err != nil {
					return fmt.Errorf("%s: %w", key, err)
				}
			}
			if err := c.SetValue(key, v); err != nil {
				return err
			}
			l.page[key] = e
			continue
		}
		if e.Value.Kind == 0 {
			return fmt.Errorf("%s has no value", key)
		}
		f, _ := field(c, key)
		nv := reflect.New(f.Type())
		if err := e.Value.Decode(nv.Interface()); err != nil {
			return fmt.Errorf("%s: %w", key, err)
		}
		f.Set(nv.Elem())
		l.page[key] = e
	}
	// A secret is only sent to the address it was entered for: one saved
	// on the page to the address it was saved with, one from signalith.yaml
	// or the environment to the address set there. When the address has
	// moved since, the secret is not used until it is entered again.
	for i := range Registry {
		s := &Registry[i]
		if s.Type != TypeSecret || s.sentTo == nil {
			continue
		}
		v, _ := c.Value(s.Key).(string)
		if v == "" {
			continue
		}
		bound := s.SentTo(base)
		if e, ok := l.page[s.Key]; ok {
			bound = e.SentTo
		}
		if now := s.SentTo(c); now != bound {
			_ = c.SetValue(s.Key, "")
			l.mismatch = append(l.mismatch, secretMismatch{Key: s.Key, Bound: bound, Now: now})
			l.warnings = append(l.warnings, fmt.Sprintf("%s is not used: it is only sent to %s, and the address is now %s. Enter it again on the Settings page", s.Key, orNone(bound), orNone(now)))
		}
	}
	return nil
}

func orNone(origin string) string {
	if origin == "" {
		return "no address"
	}
	return origin
}

// Source says where a setting's value comes from.
type Source struct {
	// Kind is env, page, file or default.
	Kind string `json:"kind"`
	// Env is the environment variable, for env.
	Env string `json:"env,omitempty"`
	// By and At say who changed it on the page, and when.
	By string    `json:"by,omitempty"`
	At time.Time `json:"at,omitzero"`
}

// Where a value comes from.
const (
	FromEnv     = "env"
	FromPage    = "page"
	FromFile    = "file"
	FromDefault = "default"
)

// Source says where the value of a setting in c comes from.
func (c *Config) Source(key string) Source {
	l := c.layers
	if l == nil {
		return Source{Kind: FromDefault}
	}
	if v := l.env[key]; v != "" {
		return Source{Kind: FromEnv, Env: v}
	}
	if e, ok := l.page[key]; ok {
		return Source{Kind: FromPage, By: e.ChangedBy, At: e.ChangedAt}
	}
	if l.file[key] {
		return Source{Kind: FromFile}
	}
	return Source{Kind: FromDefault}
}

// PageKeys lists the settings whose value comes from the Settings page.
func (c *Config) PageKeys() []string {
	keys := []string{}
	if c.layers == nil {
		return keys
	}
	for k := range c.layers.page {
		if c.layers.env[k] == "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// Base returns c without the settings changed on the Settings page:
// signalith.yaml, the environment and the defaults. Reset goes back to
// its values.
func (c *Config) Base() *Config {
	if c.layers == nil || c.layers.base == nil {
		return c
	}
	return c.layers.base
}

// SettingsFile returns where the settings changed on the Settings page
// are kept: settings.yaml in the lookups folder, or the file named by
// SIGNALITH_SETTINGS_FILE.
func (c *Config) SettingsFile() string {
	if c.layers != nil && c.layers.pageFile != "" {
		return c.layers.pageFile
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_SETTINGS_FILE")); v != "" {
		return c.resolve(v)
	}
	return filepath.Join(c.LookupsDir(), "settings.yaml")
}

// SettingsFileFor returns the Settings page's file for the config file at
// path, even when the configuration is not valid.
func SettingsFileFor(path string) (string, error) {
	c, err := readAndEnv(path)
	if err != nil {
		return "", err
	}
	return c.SettingsFile(), nil
}

// SettingsFileFromEnv reports whether SIGNALITH_SETTINGS_FILE set where
// the settings file is.
func (c *Config) SettingsFileFromEnv() bool {
	return c.layers != nil && c.layers.pageFileEnv
}

// SettingsProblem says why the settings changed on the Settings page are
// not in use, or "" when they are (or there are none). Signalith then
// runs with signalith.yaml alone.
func (c *Config) SettingsProblem() string {
	if c.layers == nil {
		return ""
	}
	return c.layers.problem
}

// SettingsWarnings lists settings from the page that are skipped, such as
// a password saved for a server that is no longer the one set.
func (c *Config) SettingsWarnings() []string {
	if c.layers == nil {
		return nil
	}
	return c.layers.warnings
}

// LockedReason says why a setting set by an environment variable cannot
// be changed on the page.
func LockedReason(env string) string {
	return fmt.Sprintf("Set by the %s environment variable, which overrides this page. Change it where Signalith's environment is set, such as docker-compose.yml or the service's settings, then restart Signalith.", env)
}
