package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"gopkg.in/yaml.v3"
)

// Passwords and keys in signalith.yaml may be written as plain text or
// encrypted (enc:v1:...; see internal/secrets). Load decrypts them, so the
// rest of Signalith sees plain values; the server never writes the file,
// which is often read-only. "signalith secrets encrypt" encrypts plain
// ones in place, and "signalith secrets set" stores a new one encrypted.
// The secrets in the file are:
//
//	opensearch.password
//	assistant.api_key
//	auth.ldap.bind_password
//	ingest.tokens (each one)
//	intel.feeds[<name>].password and .headers.<name> (values that use
//	${ENV_VAR} are left as they are)

// systemdStateDir is the state folder of the systemd unit. Commands run by
// hand do not see the unit's SIGNALITH_STATE_DIR, so on Linux the master
// key is also looked for there.
const systemdStateDir = "/var/lib/signalith"

// StateDir returns the folder where Signalith keeps files it makes for
// itself, such as its master key (in keys/): SIGNALITH_STATE_DIR when set,
// else the folder that holds lookups.dir.
func (c *Config) StateDir() string {
	if d := os.Getenv("SIGNALITH_STATE_DIR"); d != "" {
		return d
	}
	return filepath.Dir(c.LookupsDir())
}

// Keyring returns the master key holder for this config. The key is
// looked for (after systemd credentials and the SIGNALITH_MASTER_KEY_FILE
// and SIGNALITH_MASTER_KEY variables) in keys/ in the state folder, then
// next to this file, where "signalith init" puts it when run before the
// service had a state folder, then on Linux in /var/lib/signalith. A new
// key is made in the state folder.
func (c *Config) Keyring() *secrets.Keyring {
	if c.keys == nil {
		dirs := []string{c.StateDir()}
		if c.path != "" {
			dirs = append(dirs, filepath.Dir(c.path))
		}
		if runtime.GOOS == "linux" {
			dirs = append(dirs, systemdStateDir)
		}
		c.keys = secrets.NewKeyring(dirs...)
	}
	return c.keys
}

// secretRef is one password or key in a Config.
type secretRef struct {
	field string // the name it is encrypted for
	label string // the name shown to people
	// envRefs is true where ${ENV_VAR} is filled in from the environment;
	// such values are not encrypted.
	envRefs bool
	get     func() string
	set     func(string)
}

func feedField(name, part string) string { return "intel.feeds[" + name + "]." + part }

// secretRefs lists the passwords and keys in c.
func (c *Config) secretRefs() []secretRef {
	var out []secretRef
	str := func(field, label string, env bool, p *string) {
		out = append(out, secretRef{field: field, label: label, envRefs: env, get: func() string { return *p }, set: func(v string) { *p = v }})
	}
	str("opensearch.password", "opensearch.password", false, &c.OpenSearch.Password)
	str("assistant.api_key", "assistant.api_key", false, &c.Assistant.APIKey)
	// A bind password from SIGNALITH_LDAP_BIND_PASSWORD replaces the one
	// in the file, which then need not be readable.
	if c.Auth.LDAP != nil && c.ldapBindPassword == "" {
		str("auth.ldap.bind_password", "auth.ldap.bind_password", false, &c.Auth.LDAP.BindPassword)
	}
	for i := range c.Ingest.Tokens {
		str("ingest.tokens", fmt.Sprintf("ingest.tokens[%d]", i), false, &c.Ingest.Tokens[i])
	}
	for i := range c.Intel.Feeds {
		f := &c.Intel.Feeds[i]
		str(feedField(f.Name, "password"), feedField(f.Name, "password"), true, &f.Password)
		names := make([]string, 0, len(f.Headers))
		for h := range f.Headers {
			names = append(names, h)
		}
		sort.Strings(names)
		for _, h := range names {
			m := f.Headers
			out = append(out, secretRef{field: feedField(f.Name, "headers."+h), label: feedField(f.Name, "headers."+h), envRefs: true,
				get: func() string { return m[h] }, set: func(v string) { m[h] = v }})
		}
	}
	return out
}

// isPlain reports whether a stored secret is plain text that should be
// encrypted: set, not encrypted, and not a ${ENV_VAR} reference.
func isPlain(v string, envRefs bool) bool {
	return v != "" && !secrets.IsSealed(v) && !(envRefs && len(intel.EnvRefs(v)) > 0)
}

// openSecrets decrypts the encrypted passwords and keys in c.
func (c *Config) openSecrets() error {
	var problems []string
	for _, r := range c.secretRefs() {
		v := r.get()
		if !secrets.IsSealed(v) {
			continue
		}
		plain, err := c.Keyring().Open(r.field, v)
		if err != nil {
			problems = append(problems, strings.Replace(err.Error(), r.field, r.label, 1)+". "+fixHint(r.field))
			continue
		}
		r.set(plain)
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}

// fixHint says how to enter a secret again.
func fixHint(field string) string {
	switch field {
	case "opensearch.password", "assistant.api_key", "auth.ldap.bind_password":
		return "Enter it again with: signalith secrets set " + field
	case "ingest.tokens":
		return "Remove it from ingest.tokens and add a token with: signalith secrets set ingest.tokens"
	}
	return "Replace it in signalith.yaml with the plain value, then run: signalith secrets encrypt"
}

// PlainSecrets lists the passwords and keys stored as plain text in the
// file this config was loaded from, such as "opensearch.password".
func (c *Config) PlainSecrets() []string { return c.plain }

func plainLabels(refs []secretRef) []string {
	var out []string
	for _, r := range refs {
		if isPlain(r.get(), r.envRefs) {
			out = append(out, r.label)
		}
	}
	return out
}

// secretWarnings are the Warnings about stored secrets.
func (c *Config) secretWarnings() []string {
	var w []string
	if n := len(c.plain); n > 0 {
		what := "passwords or keys in signalith.yaml are"
		if n == 1 {
			what = "password or key in signalith.yaml is"
		}
		w = append(w, fmt.Sprintf("%d %s stored as plain text (%s). Run: signalith secrets encrypt", n, what, strings.Join(c.plain, ", ")))
	}
	if c.path != "" {
		if src, err := c.Keyring().Source(); err == nil && src.Weak() {
			w = append(w, "The master key comes from the SIGNALITH_MASTER_KEY environment variable, which other programs on this computer "+
				"can sometimes read (docker inspect, /proc). Put it in a file readable only by Signalith and set SIGNALITH_MASTER_KEY_FILE instead.")
		}
	}
	return w
}

// secretNode is one password or key in a YAML document of signalith.yaml.
type secretNode struct {
	field, label string
	envRefs      bool
	node         *yaml.Node
}

// mapValue returns the value of key in a YAML mapping, or nil.
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// secretNodes lists the passwords and keys in a signalith.yaml document,
// in the order they appear in it.
func secretNodes(doc *yaml.Node) []secretNode {
	root := doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	var out []secretNode
	add := func(field, label string, env bool, n *yaml.Node) {
		if n != nil && n.Kind == yaml.ScalarNode && n.Tag != "!!null" {
			out = append(out, secretNode{field: field, label: label, envRefs: env, node: n})
		}
	}
	add("opensearch.password", "opensearch.password", false, mapValue(mapValue(root, "opensearch"), "password"))
	add("assistant.api_key", "assistant.api_key", false, mapValue(mapValue(root, "assistant"), "api_key"))
	add("auth.ldap.bind_password", "auth.ldap.bind_password", false, mapValue(mapValue(mapValue(root, "auth"), "ldap"), "bind_password"))
	if toks := mapValue(mapValue(root, "ingest"), "tokens"); toks != nil && toks.Kind == yaml.SequenceNode {
		for i, t := range toks.Content {
			add("ingest.tokens", fmt.Sprintf("ingest.tokens[%d]", i), false, t)
		}
	}
	if feeds := mapValue(mapValue(root, "intel"), "feeds"); feeds != nil && feeds.Kind == yaml.SequenceNode {
		for _, f := range feeds.Content {
			name := ""
			if n := mapValue(f, "name"); n != nil {
				name = n.Value
			}
			add(feedField(name, "password"), feedField(name, "password"), true, mapValue(f, "password"))
			if h := mapValue(f, "headers"); h != nil && h.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(h.Content); i += 2 {
					k := h.Content[i].Value
					add(feedField(name, "headers."+k), feedField(name, "headers."+k), true, h.Content[i+1])
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].node, out[j].node
		return a.Line < b.Line || a.Line == b.Line && a.Column < b.Column
	})
	return out
}

// ResealFile passes every password and key in the signalith.yaml text data
// through fn and returns the text with the values fn changed, and how many
// it changed. Each value is replaced where it stands, so comments and
// layout stay as they are; only if that is not possible (a value written
// over several lines) is the whole document written out again. Values
// that use ${ENV_VAR}, and empty ones, are not passed to fn. Settings from
// environment variables are never involved: only the text is read.
func ResealFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		return data, 0, nil
	}
	nodes := secretNodes(&doc)
	want := make([]string, len(nodes))
	var changed []int
	for i, n := range nodes {
		v := n.node.Value
		want[i] = v
		if v == "" || n.envRefs && len(intel.EnvRefs(v)) > 0 {
			continue
		}
		nv, err := fn(secrets.Stored{Field: n.field, Label: n.label, Value: v})
		if err != nil {
			return nil, 0, err
		}
		if nv != v {
			want[i] = nv
			changed = append(changed, i)
		}
	}
	if len(changed) == 0 {
		return data, 0, nil
	}
	out, ok := data, true
	for _, i := range changed {
		var d yaml.Node
		if yaml.Unmarshal(out, &d) != nil {
			ok = false
			break
		}
		cur := secretNodes(&d)
		if len(cur) != len(nodes) {
			ok = false
			break
		}
		if out, ok = replaceInLine(out, cur[i].node, want[i]); !ok {
			break
		}
	}
	if ok {
		ok = secretsAre(out, want)
	}
	if !ok {
		for _, i := range changed {
			nodes[i].node.Value, nodes[i].node.Tag, nodes[i].node.Style = want[i], "!!str", 0
		}
		var err error
		if out, err = encode(&doc); err != nil {
			return nil, 0, err
		}
		if !secretsAre(out, want) {
			return nil, 0, errors.New("could not rewrite the passwords and keys in place")
		}
	}
	return out, len(changed), nil
}

// secretsAre checks that the passwords and keys in data are want, in
// order.
func secretsAre(data []byte, want []string) bool {
	var d yaml.Node
	if yaml.Unmarshal(data, &d) != nil {
		return false
	}
	got := secretNodes(&d)
	if len(got) != len(want) {
		return false
	}
	for i, n := range got {
		if n.node.Value != want[i] {
			return false
		}
	}
	return true
}

// SettableSecrets are the settings "signalith secrets set" stores.
var SettableSecrets = []string{"opensearch.password", "assistant.api_key", "auth.ldap.bind_password", "ingest.tokens"}

// SetSecret stores value, encrypted with keys, as the setting field of the
// config file at path, changing nothing else in it. For ingest.tokens the
// value is added as another token. Settings from environment variables are
// never copied into the file.
func SetSecret(path, field, value string, keys *secrets.Keyring) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config file %s not found; create one with: signalith init", path)
		}
		return err
	}
	var keysPath []string
	switch field {
	case "opensearch.password", "assistant.api_key", "auth.ldap.bind_password":
		keysPath = strings.Split(field, ".")
	case "ingest.tokens":
		if len(value) < 16 {
			return errors.New("an ingest token must be at least 16 characters")
		}
	default:
		return fmt.Errorf("%s cannot be set this way; the settings are: %s", field, strings.Join(SettableSecrets, ", "))
	}
	if field == "auth.ldap.bind_password" {
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: not valid YAML: %w", path, err)
		}
		root := &doc
		if len(root.Content) == 1 {
			root = root.Content[0]
		}
		if l := mapValue(mapValue(root, "auth"), "ldap"); l == nil || l.Kind != yaml.MappingNode {
			return errors.New("signalith.yaml has no auth.ldap section, so there is no bind password to set here; " +
				"directory sign-in set up on the Users page keeps its own, which you change on that page")
		}
	}
	sealed, err := keys.Seal(field, value)
	if err != nil {
		return err
	}
	var out []byte
	if field == "ingest.tokens" {
		out, err = appendToken(data, sealed)
	} else {
		out, err = setScalar(data, keysPath, sealed)
	}
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return securefile.WriteFile(path, out)
}

// appendToken adds a token at the end of ingest.tokens: as a new line
// after the last token when the list is written one per line, so nothing
// else moves, or else by writing the document out again.
func appendToken(data []byte, token string) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, errors.New("the file is not a YAML mapping of settings")
	}
	before := len(tokenList(data))
	ingest := mapValue(root, "ingest")
	toks := mapValue(ingest, "tokens")
	if toks != nil && toks.Kind == yaml.SequenceNode && toks.Style&yaml.FlowStyle == 0 && len(toks.Content) > 0 {
		last := toks.Content[len(toks.Content)-1]
		lines := bytes.SplitAfter(data, []byte("\n"))
		if last.Kind == yaml.ScalarNode && last.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0 && last.Line >= 1 && last.Line <= len(lines) {
			line := lines[last.Line-1]
			prefix := line[:min(len(line), byteOffset(line, last.Column))]
			if strings.TrimSpace(string(prefix)) == "-" {
				var out bytes.Buffer
				for _, l := range lines[:last.Line] {
					out.Write(l)
				}
				if !bytes.HasSuffix(line, []byte("\n")) {
					out.WriteByte('\n')
				}
				out.Write(prefix)
				out.WriteString(strconv.Quote(token) + "\n")
				for _, l := range lines[last.Line:] {
					out.Write(l)
				}
				if got := tokenList(out.Bytes()); len(got) == before+1 && got[before] == token {
					return out.Bytes(), nil
				}
			}
		}
	}
	// Otherwise change the document and write it out again (comments are
	// kept).
	if ingest == nil || ingest.Kind != yaml.MappingNode {
		if ingest != nil {
			return nil, errors.New("ingest is not a section of settings")
		}
		ingest = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ingest"}, ingest)
	}
	if toks == nil || toks.Kind != yaml.SequenceNode {
		if toks != nil && toks.Tag != "!!null" {
			return nil, errors.New("ingest.tokens is not a list")
		}
		seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if toks != nil {
			*toks = *seq
		} else {
			toks = seq
			ingest.Content = append(ingest.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tokens"}, toks)
		}
	}
	toks.Style &^= yaml.FlowStyle
	toks.Content = append(toks.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: token})
	out, err := encode(&doc)
	if err != nil {
		return nil, err
	}
	if got := tokenList(out); len(got) != before+1 || got[before] != token {
		return nil, errors.New("could not add the token")
	}
	return out, nil
}

// tokenList returns ingest.tokens as written in data.
func tokenList(data []byte) []string {
	var f struct {
		Ingest struct {
			Tokens []string `yaml:"tokens"`
		} `yaml:"ingest"`
	}
	yaml.Unmarshal(data, &f)
	return f.Ingest.Tokens
}
