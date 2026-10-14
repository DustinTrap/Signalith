package shared

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// A cluster setting set in signalith.yaml or the environment is applied
// to the shared value when it changes, not at every start, so an
// unchanged file never undoes a change made on a page. Each server
// records, per setting and source, a keyed hash of the value its files
// had at its previous start, in its nodecfg:<node_id> document. The hash
// is an HMAC under the cluster key, so a secret cannot be guessed from it.

// Sources of a setting's value outside the pages.
const (
	SourceYAML = "yaml"
	SourceEnv  = "env"
)

// NodeCfgKind is the kind of nodecfg documents.
const NodeCfgKind = "nodecfg"

// NodeCfgID returns the id of the nodecfg document of server nodeID.
func NodeCfgID(nodeID string) string { return NodeCfgKind + ":" + nodeID }

// NodeCfg is the body of a nodecfg:<node_id> document: what one server
// recorded of its files, and, once settings are shared (level 3), its own
// settings as changed on any server's Settings page, the shared values it
// could not use, and what it runs. The server writes it as a Doc (Local);
// another server reads and changes it with a Remote.
type NodeCfg struct {
	// Seen holds, per setting and source, the hash of the value last
	// applied or recorded.
	Seen map[string]map[string]string `json:"seen"`
	// Applied is when this server first applied (only recorded) its
	// files' values as a member; until then every value is only
	// recorded.
	Applied string `json:"applied,omitempty"`
	// UsersApplied is the same for the settings of the users and
	// directory sign-in (auth.*), which apply only once users are shared:
	// until then they are only recorded.
	UsersApplied string `json:"users_applied,omitempty"`
	// Values holds this server's own settings (server scope) as changed
	// on a Settings page, by key, as settings.yaml holds them in legacy
	// mode.
	Values map[string]PageValue `json:"values,omitempty"`
	// Refused holds, by key, the shared values (cluster scope) this
	// server could not use: it keeps the value it ran with until the
	// shared value changes, or an admin clicks Try again.
	Refused map[string]Refusal `json:"refused,omitempty"`
	// Running holds what this server runs of its own settings, by key, and
	// where each value comes from, written when it changes (RunningAt), so
	// another server's page can show it.
	Running   map[string]RunningValue `json:"running,omitempty"`
	RunningAt time.Time               `json:"running_at,omitzero"`
	// SettingsApplied is Applied for the settings of the Settings page,
	// which apply only once settings are shared: until then they are only
	// recorded.
	SettingsApplied string `json:"settings_applied,omitempty"`
	// SettingsImported is the hash of this server's settings.yaml once its
	// own settings were moved here, so that runs once.
	SettingsImported string `json:"settings_imported,omitempty"`
	// Migrated lists the shared settings whose value on this server's
	// Settings page differed from the shared one when its settings were
	// moved here, for the Servers page.
	Migrated []MigratedValue `json:"migrated,omitempty"`
	Extra    `json:"-"`
}

// From says where a setting's value came from: Source is page, yaml, env,
// import or apply, Node the server it came from, and By and At who changed
// it and when.
type From struct {
	Source string    `json:"source"`
	Node   string    `json:"node,omitempty"`
	By     string    `json:"by,omitempty"`
	At     time.Time `json:"at,omitzero"`
}

// PageValue is one of a server's own settings as changed on a Settings
// page.
type PageValue struct {
	// Value is the value as JSON. A password or key is in Secret instead,
	// sealed, with SentTo, the only address it is sent to.
	Value  json.RawMessage `json:"value,omitempty"`
	Secret string          `json:"secret,omitempty"`
	SentTo string          `json:"sent_to,omitempty"`
	// Rev counts the changes to the value, so a change saved from a page
	// loaded before another one can be refused.
	Rev  int64 `json:"rev"`
	From From  `json:"from"`
	// Refused says why the server did not use this value when it started
	// with it; it is set aside until saved again.
	Refused   string    `json:"refused,omitempty"`
	RefusedAt time.Time `json:"refused_at,omitzero"`
	// CheckedAt is when the server last started with this value after
	// checking it; zero for one saved since.
	CheckedAt time.Time `json:"checked_at,omitzero"`
	Extra     `json:"-"`
}

// MarshalJSON writes the value with the fields this version does not
// know.
func (v PageValue) MarshalJSON() ([]byte, error) {
	type plain PageValue
	return MarshalExtra(plain(v), v.Extra)
}

// UnmarshalJSON reads the value, keeping the fields this version does not
// know.
func (v *PageValue) UnmarshalJSON(data []byte) error {
	type plain PageValue
	var p plain
	extra, err := UnmarshalExtra(data, &p)
	*v = PageValue(p)
	v.Extra = extra
	return err
}

// Refusal is a shared value a server could not use.
type Refusal struct {
	// Hash identifies the shared value refused: a new shared value has
	// another, and ends the refusal.
	Hash string `json:"hash"`
	// Kept is the value the server uses instead, as JSON; empty is the
	// default.
	Kept   json.RawMessage `json:"kept,omitempty"`
	Reason string          `json:"reason"`
	At     time.Time       `json:"at,omitzero"`
	Extra  `json:"-"`
}

// MarshalJSON writes the refusal with the fields this version does not
// know.
func (r Refusal) MarshalJSON() ([]byte, error) {
	type plain Refusal
	return MarshalExtra(plain(r), r.Extra)
}

// UnmarshalJSON reads the refusal, keeping the fields this version does
// not know.
func (r *Refusal) UnmarshalJSON(data []byte) error {
	type plain Refusal
	var p plain
	extra, err := UnmarshalExtra(data, &p)
	*r = Refusal(p)
	r.Extra = extra
	return err
}

// RunningValue is the value a server runs one of its own settings with.
type RunningValue struct {
	// Value is the value as JSON; a password or key is never written, only
	// Set.
	Value json.RawMessage `json:"value,omitempty"`
	Set   bool            `json:"set,omitempty"`
	// Source is page, file, env or default, and Env the environment
	// variable for env.
	Source string `json:"source"`
	Env    string `json:"env,omitempty"`
}

// MigratedValue is a shared setting whose value on a server's Settings
// page (Value) differed from the shared one (Shared) when the server's
// settings were moved into the shared settings.
type MigratedValue struct {
	Key    string          `json:"key"`
	Value  json.RawMessage `json:"value"`
	Shared json.RawMessage `json:"shared,omitempty"`
	At     time.Time       `json:"at,omitzero"`
}

// SeenHash returns the hash of a setting's value as nodecfg records it:
// "h1:", the id of the cluster key, ":" and the HMAC of the setting's
// name and its value as JSON. The key id lets a hash made under another
// key (before reset-key or a key rotation) be told apart from a changed
// value.
func SeenHash(k *ClusterKey, key string, value any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, k.macKey)
	h.Write([]byte("sgl-seen-v1\x00" + key + "\x00"))
	h.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return "h1:" + k.ID() + ":" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// seenKID returns the id of the cluster key a SeenHash was made with.
func seenKID(hash string) string {
	rest, _ := strings.CutPrefix(hash, "h1:")
	kid, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return kid
}

// Changed reports whether the value of setting key from source, whose
// hash is hash, is to be applied to the shared value: it changed since
// it was recorded, or it was not set at the previous start. At a server's
// first start as a member (first), values are only recorded. A hash
// recorded under another cluster key cannot be compared, so that value is
// only recorded again too: after a new cluster key, an unchanged file
// must not undo the changes made on the pages.
func (n *NodeCfg) Changed(key, source, hash string, first bool) bool {
	if first {
		return false
	}
	old, ok := n.Seen[key][source]
	if ok && seenKID(old) != seenKID(hash) {
		return false
	}
	return !ok || old != hash
}

// Record records the hash of the value of setting key from source.
// A setting removed from a file is not forgotten: removing it changes
// nothing.
func (n *NodeCfg) Record(key, source, hash string) {
	if n.Seen == nil {
		n.Seen = map[string]map[string]string{}
	}
	if n.Seen[key] == nil {
		n.Seen[key] = map[string]string{}
	}
	n.Seen[key][source] = hash
}
