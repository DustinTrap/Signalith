package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Servers that share one OpenSearch also share their settings, once every
// one of them can (see internal/clustercfg). The settings every server
// shares (ScopeCluster) are then kept in OpenSearch, one value for all;
// each server's own (ScopeServer) are kept there too, one set per server,
// so they can be changed from any server's Settings page; and only the
// settings a server needs before it can reach OpenSearch (ScopeBootstrap)
// stay in its settings.yaml. This package cannot read OpenSearch: what is
// kept there reaches it as a Shared layer of plain data.
//
// Precedence with a shared layer:
//
//   - shared settings: the shared value, else the default. signalith.yaml
//     and the environment do not set them; a server applies a change made
//     there to the shared value when it sees it (internal/clustercfg),
//     which SourceValues is for.
//   - a server's own settings: environment variable > the server's values
//     in the layer (Shared.Server) > signalith.yaml > default.
//   - settings needed to reach OpenSearch: environment variable >
//     settings.yaml > signalith.yaml > default, as without a layer.

// Shared is the shared layer for one server.
type Shared struct {
	// Cluster holds the shared settings' values by key: those of
	// SharedKeys, and cluster.name.
	Cluster map[string]SharedValue
	// Server holds this server's own settings as changed on a Settings
	// page, by key, as settings.yaml holds them without a layer.
	Server map[string]*PageEntry
	// Refused holds the shared values this server could not use, by key:
	// it keeps the value it ran with until the shared value changes.
	Refused map[string]SharedRefusal
	// Open decrypts a shared password or key sealed for key, sent only to
	// sentTo; Seal encrypts one (see SharedField). Both use the cluster's
	// key; nil leaves shared passwords and keys unreadable, and refuses
	// new ones.
	Open func(key, sealed, sentTo string) (string, error)
	Seal func(key, plain, sentTo string) (string, error)
	// Self is this server's name, recorded with the changes made on its
	// page.
	Self string
	// Hash, when set, replaces SharedHash in matching a refusal to the
	// shared value it refused.
	Hash func(key string, v SharedValue) string

	// explicitMode is PageSettings.explicitMode for Server, while an edit
	// of this server's own settings is checked.
	explicitMode bool
}

// SharedValue is the value of one shared setting.
type SharedValue struct {
	// Value is the value as JSON. A password or key is in Secret instead,
	// sealed (see SharedField), with SentTo, the only address it is sent
	// to; an empty Secret is none.
	Value  json.RawMessage `json:"value,omitempty"`
	Secret string          `json:"secret,omitempty"`
	SentTo string          `json:"sent_to,omitempty"`
	// Rev counts the changes to the value, so a change saved from a page
	// loaded before another one can be refused.
	Rev int64 `json:"rev"`
	// From says where the value came from: Kind is page, yaml, env,
	// import or apply, Node the server it came from, and By and At who
	// changed it and when.
	From Source `json:"from"`
}

// SharedRefusal is a shared value one server could not use.
type SharedRefusal struct {
	// Hash is SharedHash of the shared value refused.
	Hash string `json:"hash"`
	// Kept is the value the server uses instead, as JSON; for a password
	// or key, a SharedValue as JSON. Empty is the default.
	Kept   json.RawMessage `json:"kept,omitempty"`
	Reason string          `json:"reason"`
	At     time.Time       `json:"at"`
}

// SharedKeys lists the settings whose values the servers share in one
// document: every shared setting on the Settings page but cluster.name
// (kept with the cluster itself), and retention.interval and the shared
// agent tokens of older setups (ingest.tokens). The retention policies,
// the threat intel feeds, directory sign-in and the built-in admin have
// documents of their own.
func SharedKeys() []string {
	var out []string
	for _, s := range Registry {
		if s.Scope == ScopeCluster && s.Key != "cluster.name" {
			out = append(out, s.Key)
		}
	}
	return append(out, "retention.interval", "ingest.tokens")
}

// layerKeys are the shared settings a Shared layer gives values to.
func layerKeys() []string { return append(SharedKeys(), "cluster.name") }

// SharedField is the name a shared password or key is sealed for: its
// key and the address it is sent to, so a sealed value cannot pass for
// another setting's, nor follow a change of address.
func SharedField(key, sentTo string) string {
	if sentTo == "" {
		return "settings." + key
	}
	return "settings." + key + "@" + sentTo
}

// SharedHash stands for a shared value, to tell whether a refusal is of
// the value now shared: its key, value, sealed secret and address, not
// who changed it.
func SharedHash(key string, v SharedValue) string {
	h := sha256.New()
	for _, part := range []string{key, string(v.Value), v.Secret, v.SentTo} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func (s *Shared) hash(key string, v SharedValue) string {
	if s.Hash != nil {
		return s.Hash(key, v)
	}
	return SharedHash(key, v)
}

// Clone returns a copy of s that can be changed without changing s.
func (s *Shared) Clone() *Shared {
	out := *s
	out.Cluster = maps.Clone(s.Cluster)
	out.Refused = maps.Clone(s.Refused)
	out.Server = (&PageSettings{Settings: s.Server}).Clone().Settings
	if out.Cluster == nil {
		out.Cluster = map[string]SharedValue{}
	}
	if out.Refused == nil {
		out.Refused = map[string]SharedRefusal{}
	}
	return &out
}

// resetShared takes every shared setting back to its default: with a
// shared layer, signalith.yaml and the environment do not set them.
func (c *Config) resetShared() {
	l := c.layers
	l.sharedOn = true
	l.filesEnv = maps.Clone(l.env)
	def := Default()
	for _, key := range SharedKeys() {
		if l.file[key] || l.env[key] != "" {
			// Through a section the file does not have, the field is a
			// fresh one: nothing to take back.
			dst, _ := walkField(c, key, false)
			src, _ := walkField(def, key, false)
			dst.Set(src)
		}
		delete(l.env, key)
	}
	c.publicURLFromEnv, c.publicURLDerived, c.httpPublicURL = false, false, ""
	c.envTokens = nil
}

// applyShared gives the shared settings their values from sh: the shared
// value, or the value this server kept when it refused that one. A value
// that is not of the setting's type is left out with a warning, so the
// setting keeps its default.
func (c *Config) applyShared(sh *Shared) {
	l := c.layers
	l.shared, l.kept = map[string]SharedValue{}, map[string]SharedRefusal{}
	for _, key := range layerKeys() {
		v, ok := sh.Cluster[key]
		if r, refused := sh.Refused[key]; refused && ok && r.Hash == sh.hash(key, v) {
			kept, err := keptValue(key, r.Kept)
			if err == nil {
				err = c.setShared(key, kept, sh)
			}
			if err != nil {
				l.warnings = append(l.warnings, fmt.Sprintf("%s: the value this server keeps in place of the shared one cannot be read (%v); the default is used", key, err))
			}
			l.kept[key] = r
			continue
		}
		if !ok {
			continue
		}
		if err := c.setShared(key, v, sh); err != nil {
			l.warnings = append(l.warnings, fmt.Sprintf("%s: the shared value cannot be read (%v); the default is used", key, err))
			continue
		}
		l.shared[key] = v
	}
}

// keptValue reads a refusal's kept value.
func keptValue(key string, kept json.RawMessage) (SharedValue, error) {
	if s, ok := Lookup(key); ok && s.Type == TypeSecret {
		var v SharedValue
		if len(kept) > 0 && string(kept) != "null" {
			if err := json.Unmarshal(kept, &v); err != nil {
				return v, err
			}
		}
		return v, nil
	}
	return SharedValue{Value: kept}, nil
}

// setShared sets key in c to a shared value. A password or key that
// cannot be decrypted is left out and reported, as one saved on the page
// is (see PageUnreadable).
func (c *Config) setShared(key string, v SharedValue, sh *Shared) error {
	if s, ok := Lookup(key); ok && s.Type == TypeSecret {
		plain := ""
		if v.Secret != "" {
			var err error
			if plain, err = sh.open(key, v.Secret, v.SentTo); err != nil {
				c.sharedCannotOpen(key, err)
				plain = ""
			}
		}
		return c.SetValue(key, plain)
	}
	if len(v.Value) == 0 || string(v.Value) == "null" {
		return nil
	}
	if key == "ingest.tokens" {
		// Each one sealed on its own: they come from several servers.
		var list []string
		if err := json.Unmarshal(v.Value, &list); err != nil {
			return err
		}
		tokens := []string{}
		for i, t := range list {
			if secrets.IsSealed(t) {
				plain, err := sh.open(key, t, "")
				if err != nil {
					c.layers.warnings = append(c.layers.warnings, fmt.Sprintf("ingest.tokens: shared agent token %d cannot be decrypted with the cluster's key (%v), so it is not accepted", i+1, err))
					continue
				}
				t = plain
			}
			tokens = append(tokens, t)
		}
		c.Ingest.Tokens = tokens
		return nil
	}
	f, ok := field(&Config{}, key)
	if !ok {
		return fmt.Errorf("unknown setting %s", key)
	}
	nv := reflect.New(f.Type())
	if err := json.Unmarshal(v.Value, nv.Interface()); err != nil {
		return err
	}
	return c.SetValue(key, nv.Elem().Interface())
}

func (s *Shared) open(key, sealed, sentTo string) (string, error) {
	if s.Open == nil {
		return "", errors.New("this server does not have the cluster's key")
	}
	return s.Open(key, sealed, sentTo)
}

// sharedCannotOpen records that the shared password or key of key cannot
// be decrypted (err), so it is left out.
func (c *Config) sharedCannotOpen(key string, err error) {
	c.pageUnreadable = append(c.pageUnreadable, pageProblem{key: key,
		text: fmt.Sprintf("%s, shared by the servers, cannot be decrypted with the cluster's key (%v). Enter it again on the Settings page.", key, err)})
	locked := maps.Clone(c.pageLocked)
	if locked == nil {
		locked = map[string]string{}
	}
	locked[key] = "It cannot be decrypted with the cluster's key, so it is not used. Enter it again, or reset it."
	c.pageLocked = locked
}

// pageFor returns the settings that take the place of the page's file
// with the shared layer s: the settings needed to reach OpenSearch from
// the file, and this server's own settings from s. Others in the file are
// no longer used: the servers share them now.
func (s *Shared) pageFor(c *Config, file *PageSettings) *PageSettings {
	l := c.layers
	out := &PageSettings{Settings: map[string]*PageEntry{}, explicitMode: s.explicitMode}
	if file != nil {
		out.explicitMode = out.explicitMode || file.explicitMode
	}
	for _, key := range file.Keys() {
		if sc := ScopeOf(key); sc != ScopeBootstrap && sc != "" {
			l.warnings = append(l.warnings, fmt.Sprintf("%s has %s, which the servers keep in OpenSearch now; it is no longer used here (a copy of the file is kept as settings.yaml.imported-…)", l.pageFile, key))
			continue
		}
		out.Settings[key] = file.Settings[key]
	}
	keys := slices.Sorted(maps.Keys(s.Server))
	for _, key := range keys {
		e := s.Server[key]
		if e == nil {
			continue
		}
		to := key
		if a := alias(key); a != "" && ScopeOf(key) == ScopeServer {
			// Saved under the old name: the new one wins when both are.
			if _, both := s.Server[a]; both {
				continue
			}
			to = "cluster.leader_eligible"
		}
		if ScopeOf(to) != ScopeServer {
			l.warnings = append(l.warnings, fmt.Sprintf("this server's settings in OpenSearch have %s, which is not one of a server's own settings; it is ignored", key))
			continue
		}
		out.Settings[to] = e
	}
	return out
}

// SharedSettings reports whether c was built with a shared layer.
func (c *Config) SharedSettings() bool { return c.layers != nil && c.layers.sharedOn }

// SharedKept returns the refusal of the shared value of key, when this
// server could not use it and keeps the value it ran with instead.
func (c *Config) SharedKept(key string) (SharedRefusal, bool) {
	if c.layers == nil {
		return SharedRefusal{}, false
	}
	r, ok := c.layers.kept[key]
	return r, ok
}

// SourceValue is the value one source gives a setting.
type SourceValue struct {
	// Source is "yaml" (signalith.yaml) or "env" (the environment).
	Source string
	// Value is the setting's value, as Value returns it, with passwords
	// and keys decrypted.
	Value any
	// Env names the environment variable, for env.
	Env string
}

// SourceValues returns the values signalith.yaml and the environment
// each set for key, decrypted, whichever value is in effect: only the
// sources that set it, and not a password or key that cannot be
// decrypted. With a shared layer, a change to one of them is applied to
// the shared value; ingest.tokens gives the tokens of each.
func (c *Config) SourceValues(key string) []SourceValue {
	l := c.layers
	if l == nil {
		return nil
	}
	files, env := l.files, l.filesEnv
	if files == nil {
		files = c.Base()
	}
	if env == nil {
		env = l.env
	}
	var out []SourceValue
	if l.file[key] && c.file != nil {
		if v, ok := c.yamlValue(key); ok {
			out = append(out, SourceValue{Source: "yaml", Value: v})
		}
	}
	if name := env[key]; name != "" {
		v := files.Value(key)
		if key == "ingest.tokens" {
			// The environment's follow those of the file.
			list := files.Ingest.Tokens
			v = slices.Clone(list[max(0, len(list)-len(files.envTokens)):])
		}
		out = append(out, SourceValue{Source: "env", Value: v, Env: name})
	}
	return out
}

// yamlValue returns the value signalith.yaml gives key, decrypted.
func (c *Config) yamlValue(key string) (any, bool) {
	v := c.file.Value(key)
	if key == "ingest.tokens" {
		var out []string
		for _, t := range v.([]string) {
			if secrets.IsSealed(t) {
				plain, err := c.Keyring().Open(key, t)
				if err != nil {
					continue
				}
				t = plain
			}
			out = append(out, t)
		}
		return out, true
	}
	if s, ok := Lookup(key); ok && s.Type == TypeSecret {
		str, _ := v.(string)
		if secrets.IsSealed(str) {
			plain, err := c.Keyring().Open(key, str)
			if err != nil {
				return nil, false
			}
			return plain, true
		}
	}
	return v, true
}

// LoadShared is Load with the shared layer sh. When this server's own
// settings in it, or the settings.yaml ones, do not validate, it starts
// without them, with the shared settings, and SettingsProblem says why.
func LoadShared(path string, sh *Shared) (*Config, error) {
	return loadWith(path, nil, sh)
}

// LoadSetAsideShared is LoadSetAside with the shared layer sh: keys are
// set aside in settings.yaml, among this server's own settings in sh, and
// for shared settings as refused, keeping their default. A caller that
// knows the value the server ran with records a refusal with that value
// in sh itself.
func LoadSetAsideShared(path string, sh *Shared, keys []string, reason string) (*Config, error) {
	now := time.Now()
	sh = sh.Clone()
	for _, k := range keys {
		if e := sh.Server[k]; e != nil && e.Refused == "" {
			e.Refused, e.RefusedAt = reason, now.UTC()
		}
		if v, ok := sh.Cluster[k]; ok {
			if _, done := sh.Refused[k]; !done {
				sh.Refused[k] = SharedRefusal{Hash: sh.hash(k, v), Reason: reason, At: now.UTC()}
			}
		}
	}
	return loadWith(path, func(p *PageSettings) { p.refuse(keys, reason, now) }, sh)
}

// LoadSavedShared is LoadSaved with the shared layer sh.
func LoadSavedShared(path string, sh *Shared) (*Saved, error) {
	return loadSaved(path, nil, sh)
}

// loadFileShared is LoadFile with the shared settings of sh: without the
// settings.yaml ones nor this server's own in sh.
func loadFileShared(path string, sh *Shared) (*Config, error) {
	sh = sh.Clone()
	sh.Server = nil
	c, err := buildWith(path, nil, sh)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// SharedEditResult is an edit of one scope's settings, with a shared
// layer, checked against the whole configuration.
type SharedEditResult struct {
	EditResult
	// Scope is the scope of the settings edited.
	Scope Scope
	// Shared is the layer with the edit: with ScopeCluster, the shared
	// values (Cluster) and this server's refusals of them (Refused);
	// with ScopeServer, this server's own settings (Server). For
	// ScopeBootstrap, the edit is in EditResult.Page, settings.yaml.
	Shared *Shared
	// Touched lists the settings whose entry in Shared the edit changes,
	// sorted.
	Touched []string
}

// CheckEditShared is CheckEdit for a server with the shared layer sh: an
// edit of the settings of one scope. A shared setting's edit lands in the
// shared values, one of a server's own settings in sh.Server, and one
// needed to reach OpenSearch in settings.yaml. A setting of another scope
// is refused at its field. Settings set by an environment variable are
// locked as without a layer, except shared ones, which the environment
// does not set. sh is not changed.
func CheckEditShared(path string, sh *Shared, scope Scope, e Edit) (*SharedEditResult, error) {
	saved, err := LoadSavedShared(path, sh)
	if err != nil {
		return nil, err
	}
	if scope == ScopeBootstrap && saved.PageErr != nil && !e.ResetAll {
		return nil, fmt.Errorf("%w: %v. Reset all settings to start the file again, or fix it on the server", ErrPageFile, saved.PageErr)
	}
	e = renameAliases(e)
	work := sh.Clone()
	if work.Server == nil {
		work.Server = map[string]*PageEntry{}
	}
	var d edits
	var page *PageSettings
	switch scope {
	case ScopeCluster:
		d = &clusterEdits{sh: work, make: func() (*Config, error) { return buildWith(path, saved.Page, work) }}
	case ScopeServer:
		d = &pageEdits{page: &PageSettings{Settings: work.Server}, make: func(p *PageSettings) (*Config, error) {
			work.Server, work.explicitMode = p.Settings, p.explicitMode
			defer func() { work.explicitMode = false }()
			return buildWith(path, saved.Page, work)
		}}
	case ScopeBootstrap:
		page = saved.Page.Clone()
		d = &pageEdits{page: page, make: func(p *PageSettings) (*Config, error) { return buildWith(path, p, work) }}
	default:
		return nil, fmt.Errorf("no settings have the scope %q", scope)
	}
	res, err := checkEdit(saved.Config, e, d, func(key string) string {
		if sc := ScopeOf(key); sc != scope {
			return fmt.Sprintf("This setting is one of %s, not of %s.", scopeWords[sc], scopeWords[scope])
		}
		return ""
	}, true)
	if err != nil {
		return nil, err
	}
	if pe, ok := d.(*pageEdits); ok && scope == ScopeServer {
		work.Server = pe.page.Settings
	}
	out := &SharedEditResult{EditResult: *res, Scope: scope, Shared: work, Touched: touchedKeys(sh, work)}
	out.Page = page
	return out, nil
}

// scopeWords names the scopes for people.
var scopeWords = map[Scope]string{
	ScopeCluster:   "the settings every server shares",
	ScopeServer:    "each server's own settings",
	ScopeBootstrap: "the connection and folder settings each server keeps in its settings.yaml",
}

// renameAliases gives the settings of e under an old name their new one.
func renameAliases(e Edit) Edit {
	const from, to = "detections.scheduler", "cluster.leader_eligible"
	if v, ok := e.Values[from]; ok {
		e.Values = maps.Clone(e.Values)
		delete(e.Values, from)
		if _, both := e.Values[to]; !both {
			e.Values[to] = v
		}
	}
	rename := func(list []string) []string {
		if !slices.Contains(list, from) {
			return list
		}
		out := slices.Clone(list)
		for i := range out {
			if out[i] == from {
				out[i] = to
			}
		}
		return slices.Compact(out)
	}
	e.Clear, e.Reset, e.Retry = rename(e.Clear), rename(e.Reset), rename(e.Retry)
	return e
}

// touchedKeys lists the settings whose entries differ between two layers.
func touchedKeys(a, b *Shared) []string {
	set := map[string]bool{}
	differ(set, a.Cluster, b.Cluster, func(x, y SharedValue) bool { return reflect.DeepEqual(x, y) })
	differ(set, a.Refused, b.Refused, func(x, y SharedRefusal) bool { return reflect.DeepEqual(x, y) })
	differ(set, a.Server, b.Server, func(x, y *PageEntry) bool {
		return x == nil && y == nil || x != nil && y != nil && reflect.DeepEqual(*x, *y)
	})
	return slices.Sorted(maps.Keys(set))
}

// differ adds to set the keys whose entries in a and b differ.
func differ[V any](set map[string]bool, a, b map[string]V, same func(x, y V) bool) {
	for k, va := range a {
		if vb, ok := b[k]; !ok || !same(va, vb) {
			set[k] = true
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			set[k] = true
		}
	}
}

// clusterEdits are edits of the shared settings' values.
type clusterEdits struct {
	sh   *Shared
	make func() (*Config, error)
}

func (d *clusterEdits) refused(key string) bool {
	_, ok := d.sh.Refused[key]
	return ok
}

// dropRefused: a value entered again is tried again on this server.
func (d *clusterEdits) dropRefused(key string) { delete(d.sh.Refused, key) }

func (d *clusterEdits) set(key string, v any, by string, at time.Time) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	d.sh.Cluster[key] = SharedValue{Value: raw, Rev: d.sh.Cluster[key].Rev, From: d.from(by, at)}
	return nil
}

func (d *clusterEdits) setSecret(key, secret, sentTo, by string, at time.Time) error {
	v := SharedValue{Rev: d.sh.Cluster[key].Rev, From: d.from(by, at)}
	if secret != "" {
		if d.sh.Seal == nil {
			return errors.New("this server does not have the cluster's key to encrypt it with")
		}
		sealed, err := d.sh.Seal(key, secret, sentTo)
		if err != nil {
			return err
		}
		v.Secret, v.SentTo = sealed, sentTo
	}
	d.sh.Cluster[key] = v
	return nil
}

// from says the value was changed on this server's page.
func (d *clusterEdits) from(by string, at time.Time) Source {
	return Source{Kind: FromPage, Node: d.sh.Self, By: by, At: at.UTC()}
}

func (d *clusterEdits) remove(key string) { delete(d.sh.Cluster, key) }

func (d *clusterEdits) retry(key string) bool {
	if _, ok := d.sh.Refused[key]; !ok {
		return false
	}
	delete(d.sh.Refused, key)
	return true
}

// clear takes the shared settings on the page back to their defaults;
// retention.interval and the agent tokens are not on it, and stay.
func (d *clusterEdits) clear() {
	for _, s := range Registry {
		if s.Scope == ScopeCluster {
			delete(d.sh.Cluster, s.Key)
		}
	}
}

func (d *clusterEdits) build(bool) (*Config, error) { return d.make() }
