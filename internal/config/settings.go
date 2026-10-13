package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// The Settings page shows the settings in Registry. Each one names its
// key in signalith.yaml, so a value saved on the page, one in the file and
// one from the environment all mean the same thing. Every setting of
// Config is either in Registry or in Excluded with the reason it is not on
// the page; a test fails when a new one is in neither.

// Setting types, which decide how the page shows a setting and how a
// value from the page is read.
const (
	TypeText     = "text"
	TypeNumber   = "number"
	TypeDuration = "duration" // such as 30m, 12h or 7d
	TypeBool     = "bool"
	TypeChoice   = "choice"
	TypeList     = "list"   // a list of strings
	TypeSecret   = "secret" // never shown; only whether one is set
	TypeURL      = "url"
	TypeAddress  = "address" // host:port to listen on
)

// Section is a group of settings on the page.
type Section struct {
	ID    string
	Title string
	Help  string
}

// Choice is one value a choice setting can take.
type Choice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Setting describes one setting on the Settings page.
type Setting struct {
	Key     string // the key in signalith.yaml, such as "syslog.udp"
	Section string
	Label   string
	Help    string
	Type    string
	Choices []Choice
	// Min and Max bound a number.
	Min, Max *int
	// Placeholder is an example value for an empty field.
	Placeholder string
	// EmptyMeans says what an empty value does, such as "off".
	EmptyMeans string
	// Env is the environment variable that overrides the setting; the
	// page shows such a setting read-only.
	Env string
	// Restart is true when a change applies only after a restart;
	// otherwise it applies as soon as it is saved.
	Restart bool
	// Confirm, when set, is what the page asks before saving a change,
	// naming its consequence. ConfirmWhen limits it to a bool turned "on"
	// or "off".
	Confirm     string
	ConfirmWhen string
	// For a secret: SentWith lists the settings that decide where it is
	// sent, and sentTo returns that address. A saved secret is only sent
	// to the address it was entered for.
	SentWith []string
	sentTo   func(*Config) string
	// WaitsFor lists settings that, while they wait for a restart, make
	// this live setting wait too: the public address is worked out from
	// the listen address.
	WaitsFor []string
	// check checks a value from the page beyond what Validate does.
	check func(any) error
	// problem words what is wrong with the setting in a whole
	// configuration for its field on the page, in place of Validate's
	// wording (which names settings by their keys), or returns "".
	problem func(*Config) string
}

// Live reports whether a change applies as soon as it is saved.
func (s *Setting) Live() bool { return !s.Restart }

// Check checks a value from ParseValue beyond what Validate does, as a
// save from the page does.
func (s *Setting) Check(v any) error {
	if s.check == nil {
		return nil
	}
	return s.check(v)
}

// Noun returns the label for use inside a sentence: "Password" becomes
// "password", while "API key" and "OpenSearch address" keep their
// capitals.
func (s *Setting) Noun() string {
	first, _, _ := strings.Cut(s.Label, " ")
	r := []rune(first)
	for _, c := range r[min(1, len(r)):] {
		if unicode.IsUpper(c) {
			return s.Label
		}
	}
	if len(r) == 0 {
		return s.Label
	}
	return string(unicode.ToLower(r[0])) + s.Label[len(string(r[0])):]
}

// SentTo returns where a secret setting is sent with c, as
// scheme://host:port, or "" when it is not sent anywhere.
func (s *Setting) SentTo(c *Config) string {
	if s.sentTo == nil {
		return ""
	}
	return Origin(s.sentTo(c))
}

func intp(n int) *int { return &n }

// Sections lists the page's sections in order.
var Sections = []Section{
	{ID: "general", Title: "General", Help: "How people and agents reach this server, and how long a sign-in lasts."},
	{ID: "web", Title: "Web server", Help: "Where the web page and the API listen."},
	{ID: "opensearch", Title: "OpenSearch", Help: "Where events, findings and investigations are stored."},
	{ID: "search", Title: "Search", Help: "What a new search starts with, and when a quiet data source is flagged."},
	{ID: "syslog", Title: "Syslog", Help: "Receive syslog from firewalls, switches and servers that cannot run an agent."},
	{ID: "detections", Title: "Detections", Help: "Whether detections run by themselves, and how many findings one run can raise."},
	{ID: "assistant", Title: "AI assistant", Help: "An optional AI model for Ask questions the built-in translator does not fully understand. Only the question and field names are sent, never events."},
	{ID: "intel", Title: "Threat intel", Help: "Where threat intel feeds may be downloaded from."},
}

// Registry lists every setting on the page, in page order.
var Registry = []Setting{
	{Key: "server.public_url", Section: "general", Label: "Public address", Type: TypeURL,
		Help:        "The address agents and links use to reach this server.",
		Placeholder: "https://siem.example.com:8080", EmptyMeans: "worked out from the listen address",
		Env: "SIGNALITH_PUBLIC_URL", WaitsFor: []string{"server.listen", "server.tls_cert", "server.tls_key"}},
	{Key: "auth.session_timeout", Section: "general", Label: "Sign out after", Type: TypeDuration,
		Help:        "Signs people out of the web page after this long without use, unless they ticked Keep me signed in. At least 5m.",
		Placeholder: "12h", EmptyMeans: "12h"},
	{Key: "ingest.max_event_age", Section: "general", Label: "Oldest event time", Type: TypeDuration, Restart: true,
		Help:        "Events from agents and syslog that say they are older than this are filed under the time they arrived, with their own time kept in device_time. Raise it to load old logs.",
		Placeholder: "30d", EmptyMeans: "7d, or the shortest retention period when that is shorter"},

	{Key: "server.listen", Section: "web", Label: "Listen address", Type: TypeAddress, Restart: true,
		Help:        "The address and port the web page and API listen on. 0.0.0.0 accepts other computers; 127.0.0.1 only this one.",
		Placeholder: "0.0.0.0:8080", Env: "SIGNALITH_LISTEN",
		Confirm: "After the restart Signalith answers only at the new address. Agents and bookmarks that use the old one stop working until they are changed."},
	{Key: "server.tls_cert", Section: "web", Label: "Certificate file", Type: TypeText, Restart: true,
		Help:        "Full path of a PEM certificate. With a key file, the web page, the API and syslog over TLS use HTTPS. When Public address is empty, it changes from http:// to https:// too.",
		Placeholder: "/etc/signalith/tls/cert.pem", EmptyMeans: "HTTP, no certificate"},
	{Key: "server.tls_key", Section: "web", Label: "Key file", Type: TypeText, Restart: true,
		Help:        "Full path of the certificate's PEM private key.",
		Placeholder: "/etc/signalith/tls/key.pem"},
	{Key: "server.max_connections", Section: "web", Label: "Most connections", Type: TypeNumber, Restart: true, Min: intp(0), Max: intp(1000000),
		Help:       "The most connections open at once from browsers, agents and the API. One computer may use a tenth of them.",
		EmptyMeans: "10000"},
	{Key: "server.shared_addresses", Section: "web", Label: "Proxies and gateways", Type: TypeList, Restart: true,
		Help:        "IP addresses or ranges of a reverse proxy, load balancer or NAT gateway that many people and agents reach Signalith through. They are not limited like one computer.",
		Placeholder: "10.0.0.5", EmptyMeans: "none", check: checkAddressList, problem: listProblem("server.shared_addresses")},

	{Key: "opensearch.url", Section: "opensearch", Label: "Address", Type: TypeURL, Restart: true,
		Help:        "Where OpenSearch answers.",
		Placeholder: "https://opensearch.example.com:9200", Env: "SIGNALITH_OPENSEARCH_URL", check: noSecretIn("put the username and password in their own fields below"),
		Confirm: "Signalith will store and search events in the OpenSearch at the new address. Events stored in the current one stay there and do not show in searches."},
	{Key: "opensearch.username", Section: "opensearch", Label: "Username", Type: TypeText, Restart: true,
		Help: "Leave empty if OpenSearch does not ask for a password.", Env: "SIGNALITH_OPENSEARCH_USERNAME"},
	{Key: "opensearch.password", Section: "opensearch", Label: "Password", Type: TypeSecret, Restart: true,
		Help: "Only sent to the address it was entered for.", Env: "SIGNALITH_OPENSEARCH_PASSWORD",
		SentWith: []string{"opensearch.url"}, sentTo: func(c *Config) string { return c.OpenSearch.URL }},
	{Key: "opensearch.ca_file", Section: "opensearch", Label: "CA certificate file", Type: TypeText, Restart: true,
		Help:        "Full path of the PEM certificate of the authority that signed OpenSearch's certificate, for an https address with a private authority.",
		Placeholder: "/etc/signalith/opensearch-ca.pem", EmptyMeans: "only authorities this computer trusts"},
	{Key: "opensearch.cert_file", Section: "opensearch", Label: "Client certificate file", Type: TypeText, Restart: true,
		Help:        "For signing in to OpenSearch with a certificate instead of a password: full path of the PEM certificate Signalith presents.",
		Placeholder: "/etc/signalith/opensearch-client.pem", EmptyMeans: "no certificate sign-in"},
	{Key: "opensearch.key_file", Section: "opensearch", Label: "Client key file", Type: TypeText, Restart: true,
		Help:        "Full path of the client certificate's PEM private key.",
		Placeholder: "/etc/signalith/opensearch-client-key.pem"},
	{Key: "opensearch.proxy", Section: "opensearch", Label: "Proxy", Type: TypeText, Restart: true,
		Help:        "A proxy to reach OpenSearch through, such as http://proxy:3128. It sees every event, so use one only when the network needs it.",
		Placeholder: "http://proxy:3128", EmptyMeans: "connect directly", Env: "SIGNALITH_OPENSEARCH_PROXY",
		check: noSecretIn("a proxy that needs a password is set in signalith.yaml or with SIGNALITH_OPENSEARCH_PROXY, where it is not shown")},
	{Key: "opensearch.allow_insecure_http", Section: "opensearch", Label: "Allow password over plain http", Type: TypeBool, Restart: true,
		Help:    "Lets the username and password go to OpenSearch on another computer over http:// instead of https://.",
		Confirm: "The OpenSearch username and password will cross the network unencrypted, where anyone on the way can read them. Use an https:// address instead when you can.", ConfirmWhen: "on"},
	{Key: "opensearch.tls_skip_verify", Section: "opensearch", Label: "Skip certificate check", Type: TypeBool, Restart: true,
		Help:    "Connects even when OpenSearch's certificate is not trusted, for a test system with a self-signed certificate.",
		Confirm: "Signalith will not check who it is connecting to, so someone on the network could read events and the OpenSearch password. Use this only on a test system.", ConfirmWhen: "on"},
	{Key: "opensearch.index_prefix", Section: "opensearch", Label: "Index prefix", Type: TypeText, Restart: true,
		Help:    "The start of every index name, as in signalith-authentication-2026.10.12. Lowercase, no spaces.",
		Confirm: "Signalith will start with empty indices under the new prefix. Events, findings and investigations stored under the current prefix stay in OpenSearch but no longer show in searches or on any page."},
	{Key: "opensearch.replicas", Section: "opensearch", Label: "Replicas", Type: TypeNumber, Restart: true, Min: intp(0),
		Help: "Extra copies of each new index on other OpenSearch nodes: 0 for one node, 1 or more for a cluster. Applies to indices created after the restart."},

	{Key: "search.default_earliest", Section: "search", Label: "Default time range", Type: TypeChoice,
		Help: "The time range the Search page starts with until someone picks another, and of a search sent without one, such as from the API.", check: checkEarliest,
		Choices: []Choice{{"-15m", "Last 15 minutes"}, {"-1h", "Last hour"}, {"-4h", "Last 4 hours"},
			{"-24h", "Last 24 hours"}, {"-7d", "Last 7 days"}, {"-30d", "Last 30 days"}}},
	{Key: "search.max_events", Section: "search", Label: "Events per search", Type: TypeNumber, Min: intp(1), Max: intp(100000),
		Help: "The most events a search fetches to sort, filter or count after searching. More uses more memory."},
	{Key: "dashboards.stale_after", Section: "search", Label: "Quiet data source after", Type: TypeDuration,
		Help:        "The Posture dashboard lists a host and source type as stopped when nothing arrives from it for this long. At least 5m.",
		Placeholder: "2h"},

	{Key: "syslog.udp", Section: "syslog", Label: "UDP address", Type: TypeAddress, Restart: true,
		Help: "Address to receive syslog on over UDP.", Placeholder: "0.0.0.0:514", EmptyMeans: "off",
		Env: "SIGNALITH_SYSLOG_UDP"},
	{Key: "syslog.tcp", Section: "syslog", Label: "TCP address", Type: TypeAddress, Restart: true,
		Help: "Address to receive syslog on over TCP.", Placeholder: "0.0.0.0:514", EmptyMeans: "off",
		Env: "SIGNALITH_SYSLOG_TCP"},
	{Key: "syslog.tls", Section: "syslog", Label: "TLS address", Type: TypeAddress, Restart: true,
		Help:        "Address for syslog over TLS. It uses the web server's certificate and key files.",
		Placeholder: "0.0.0.0:6514", EmptyMeans: "off"},
	{Key: "syslog.allow", Section: "syslog", Label: "Allowed senders", Type: TypeList, Restart: true,
		Help:        "IP addresses or ranges, such as 10.0.0.0/8, that may send syslog. Others are dropped and counted.",
		Placeholder: "10.0.0.0/8", EmptyMeans: "any sender", check: checkAddressList, problem: listProblem("syslog.allow")},
	{Key: "syslog.public_port", Section: "syslog", Label: "Port devices send to", Type: TypeNumber, Restart: true, Min: intp(0), Max: intp(65535),
		Help:       "When Docker or a firewall forwards another port to the one Signalith listens on, the port devices send to. Add data shows it.",
		EmptyMeans: "the listen port"},

	{Key: "detections.scheduler", Section: "detections", Label: "Run detections on schedule", Type: TypeBool, Restart: true,
		Help:    "Runs enabled detections on their schedules and downloads threat intel feeds. Turn it off on extra servers that share one OpenSearch, so each rule runs once.",
		Confirm: "No detections will run and no threat intel feeds will download on this server until this is turned on again.", ConfirmWhen: "off"},
	{Key: "detections.max_findings_per_run", Section: "detections", Label: "Most findings per run", Type: TypeNumber, Min: intp(1), Max: intp(10000),
		Help: "The most findings one detection run can raise, so a noisy rule cannot flood the queue."},

	{Key: "assistant.provider", Section: "assistant", Label: "Provider", Type: TypeChoice,
		Help: "Who runs the model. OpenAI or compatible includes Ollama, LM Studio and vLLM on your own hardware.",
		Choices: []Choice{{"", "Off"}, {assistant.Anthropic, "Anthropic"},
			{assistant.OpenAI, "OpenAI or compatible"}}},
	{Key: "assistant.url", Section: "assistant", Label: "Address", Type: TypeURL,
		Help:        "Only for a model on your own hardware or another compatible service, such as http://localhost:11434/v1 for Ollama.",
		Placeholder: "http://localhost:11434/v1", EmptyMeans: "the provider's own address", check: noSecretIn("put the key in API key below")},
	{Key: "assistant.model", Section: "assistant", Label: "Model", Type: TypeText,
		Help:        "The model's name. Required for OpenAI or compatible, such as llama3.1 with Ollama.",
		Placeholder: "llama3.1", EmptyMeans: "the provider's default model", problem: modelProblem},
	{Key: "assistant.api_key", Section: "assistant", Label: "API key", Type: TypeSecret,
		Help: "Only sent to the provider's address it was entered for. Local models often need none.",
		Env:  "SIGNALITH_ASSISTANT_API_KEY", SentWith: []string{"assistant.provider", "assistant.url"},
		sentTo: func(c *Config) string { return c.AssistantURL() }},

	{Key: "intel.allow_loopback_feeds", Section: "intel", Label: "Allow feeds from this computer", Type: TypeBool, Restart: true,
		Help:    "Lets feeds download from 127.0.0.1 or ::1, for a feed server on this computer.",
		Confirm: "Feeds can then reach services on this computer that are not meant to be reachable from outside. Turn this on only if a feed server runs here.", ConfirmWhen: "on"},
}

// Excluded lists the settings of Config that are not on the Settings
// page, and why.
var Excluded = map[string]string{
	"retention.days":           "Data retention has its own page.",
	"retention.interval":       "Data retention has its own page.",
	"retention.archive_dir":    "Data retention has its own page, and archived days are kept in this folder.",
	"retention.default":        "Data retention has its own page.",
	"retention.policies":       "Data retention has its own page.",
	"retention.guard":          "Data retention has its own page.",
	"auth.admin_user":          "The built-in admin is the break-glass account. It is set only in signalith.yaml, so no change on a page can lock everyone out.",
	"auth.admin_password_hash": "The built-in admin's password is changed on the server with signalith passwd.",
	"auth.users_file":          "The Users page keeps its users there, and a page cannot move a file it depends on. Shown under About this server.",
	"auth.ldap":                "Directory sign-in is set up on the Users page.",
	"ingest.tokens":            "Agent tokens are set in signalith.yaml (ingest.tokens) or with SIGNALITH_INGEST_TOKEN; Add data shows the agent setup that uses them. The page shows how many there are.",
	"detections.dir":           "Pages save detections there, and a page cannot move a folder it saves into. Shown under About this server.",
	"lookups.dir":              "It holds this page's own settings file, users and lists, so it cannot move from a page. Shown under About this server.",
	"dashboards.dir":           "Pages save dashboards there, and a page cannot move a folder it saves into. Shown under About this server.",
	"intel.feeds":              "Feeds are added and changed on the Threat intel page.",
	"intel.feeds_file":         "The Threat intel page keeps its feeds there, and a page cannot move a file it depends on. Shown under About this server.",
}

// Lookup returns the setting with a key.
func Lookup(key string) (*Setting, bool) {
	for i := range Registry {
		if Registry[i].Key == key {
			return &Registry[i], true
		}
	}
	return nil, false
}

// LeafKeys lists every setting of Config by its key, such as
// "server.listen". Lists and nested settings, such as intel.feeds and
// auth.ldap, are one key each.
func LeafKeys() []string {
	var out []string
	var walk func(t reflect.Type, prefix string)
	walk = func(t reflect.Type, prefix string) {
		for i := range t.NumField() {
			f := t.Field(i)
			name := yamlName(f)
			if name == "" {
				continue
			}
			if f.Type.Kind() == reflect.Struct && f.Type != reflect.TypeOf(time.Time{}) {
				walk(f.Type, prefix+name+".")
				continue
			}
			out = append(out, prefix+name)
		}
	}
	walk(reflect.TypeOf(Config{}), "")
	return out
}

// yamlName is a field's key in signalith.yaml, or "" for fields that are
// not in the file.
func yamlName(f reflect.StructField) string {
	if !f.IsExported() {
		return ""
	}
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if name == "-" || name == "" {
		return ""
	}
	return name
}

// field returns the value a key names in c.
func field(c *Config, key string) (reflect.Value, bool) {
	v := reflect.ValueOf(c).Elem()
	for _, part := range strings.Split(key, ".") {
		if v.Kind() != reflect.Struct {
			return reflect.Value{}, false
		}
		found := false
		t := v.Type()
		for i := range t.NumField() {
			if yamlName(t.Field(i)) == part {
				v, found = v.Field(i), true
				break
			}
		}
		if !found {
			return reflect.Value{}, false
		}
	}
	return v, true
}

// Value returns the value of a setting in c: a string, int, bool or
// []string. Lists are never nil.
//
// A public address worked out from the listen address is "", as it was
// set: that is what the page shows, compares and saves.
func (c *Config) Value(key string) any {
	v, ok := field(c, key)
	if !ok {
		return nil
	}
	if key == "server.public_url" && c.publicURLDerived {
		return ""
	}
	if v.Kind() == reflect.Slice && v.Type().Elem().Kind() == reflect.String {
		out := make([]string, v.Len())
		for i := range out {
			out[i] = v.Index(i).String()
		}
		return out
	}
	return v.Interface()
}

// SetValue sets a setting in c to a value of its type, as ParseValue
// returns it.
func (c *Config) SetValue(key string, val any) error {
	v, ok := field(c, key)
	if !ok {
		return fmt.Errorf("unknown setting %s", key)
	}
	nv := reflect.ValueOf(val)
	if !nv.Type().AssignableTo(v.Type()) {
		return fmt.Errorf("%s takes a %s, not a %s", key, v.Type(), nv.Type())
	}
	v.Set(nv)
	if key == "server.public_url" {
		c.publicURLDerived = false
	}
	return nil
}

// CopyValue sets a setting in c to its value in from. The live settings
// saved on the page reach the running server this way.
func (c *Config) CopyValue(key string, from *Config) error {
	src, ok := field(from, key)
	if !ok {
		return fmt.Errorf("unknown setting %s", key)
	}
	dst, _ := field(c, key)
	dst.Set(src)
	if key == "server.public_url" {
		c.publicURLDerived = from.publicURLDerived
	}
	return nil
}

// SameValue reports whether a setting is the same in a and b. An empty
// list and no list are the same.
func SameValue(a, b *Config, key string) bool {
	va, vb := a.Value(key), b.Value(key)
	return reflect.DeepEqual(va, vb)
}

// ParseValue reads a value for a setting from the page, as JSON decoded
// it (a string, float64 or json.Number, bool, or list), and returns it as
// the setting's own type. Text is trimmed.
func ParseValue(s *Setting, raw any) (any, error) {
	v, ok := field(&Config{}, s.Key)
	if !ok {
		return nil, fmt.Errorf("unknown setting %s", s.Key)
	}
	switch v.Kind() {
	case reflect.String:
		str, ok := raw.(string)
		if raw == nil {
			str, ok = "", true
		}
		if !ok {
			return nil, fmt.Errorf("enter text")
		}
		if s.Type == TypeSecret {
			// Secrets are taken as typed: spaces can be part of one. One
			// that looks encrypted would be kept as it is, not encrypted.
			if secrets.IsSealed(str) {
				return nil, errors.New("the value cannot start with enc:v and a number and a colon, which is how encrypted values look")
			}
			return str, nil
		}
		str = strings.TrimSpace(str)
		if err := noControl(str); err != nil {
			return nil, err
		}
		return str, nil
	case reflect.Int:
		var f float64
		switch n := raw.(type) {
		case float64:
			f = n
		case interface{ Float64() (float64, error) }:
			var err error
			if f, err = n.Float64(); err != nil {
				return nil, fmt.Errorf("enter a whole number")
			}
		case string:
			var err error
			if f, err = strconv.ParseFloat(strings.TrimSpace(n), 64); err != nil || strings.TrimSpace(n) == "" {
				return nil, fmt.Errorf("enter a whole number")
			}
		default:
			return nil, fmt.Errorf("enter a whole number")
		}
		if f != float64(int(f)) {
			return nil, fmt.Errorf("enter a whole number")
		}
		n := int(f)
		if s.Min != nil && n < *s.Min || s.Max != nil && n > *s.Max {
			return nil, fmt.Errorf("enter a number from %d to %d", deref(s.Min, 0), deref(s.Max, 1<<31-1))
		}
		return n, nil
	case reflect.Bool:
		b, ok := raw.(bool)
		if !ok {
			return nil, fmt.Errorf("choose on or off")
		}
		return b, nil
	case reflect.Slice:
		var items []string
		switch l := raw.(type) {
		case nil:
		case []any:
			for _, it := range l {
				str, ok := it.(string)
				if !ok {
					return nil, fmt.Errorf("enter a list of text values")
				}
				items = append(items, str)
			}
		case []string:
			items = l
		case string:
			// One value per line or comma, as typed in a text box.
			items = strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' })
		default:
			return nil, fmt.Errorf("enter a list of text values")
		}
		out := []string{}
		for _, it := range items {
			if it = strings.TrimSpace(it); it != "" {
				if err := noControl(it); err != nil {
					return nil, err
				}
				out = append(out, it)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s cannot be changed here", s.Key)
}

// noControl refuses line breaks, tabs and other control characters in a
// one-line value, which could pass for more than one value where it is
// printed.
func noControl(s string) error {
	if strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return fmt.Errorf("remove the line break, tab or other control character")
	}
	return nil
}

// noSecretIn refuses an address with a password or key in it, which
// would be shown on the page and in logs; why says where it goes instead.
func noSecretIn(why string) func(any) error {
	return func(v any) error {
		if hasSecret(v.(string)) {
			return fmt.Errorf("leave passwords and keys out of the address: %s", why)
		}
		return nil
	}
}

// hasSecret reports whether an address holds a user name and password,
// or a query parameter whose name suggests a key or token.
func hasSecret(raw string) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		// Validate refuses it; a password in it must still not be kept.
		return strings.Contains(raw, "@")
	}
	if u.User != nil || u.Host == "" && strings.Contains(raw, "@") {
		return true
	}
	for name := range u.Query() {
		if redact.SecretName(name) {
			return true
		}
	}
	return false
}

// badAddresses lists the entries of a list of IP addresses or ranges that
// are not one.
func badAddresses(list []string) []string {
	var bad []string
	for _, a := range list {
		if _, err := parseAllow(a); err != nil {
			bad = append(bad, "“"+a+"”")
		}
	}
	return bad
}

// addressListProblem words the bad entries of an address list, every one
// of them, or returns "".
func addressListProblem(list []string) string {
	bad := badAddresses(list)
	switch len(bad) {
	case 0:
		return ""
	case 1:
		return bad[0] + " isn't an IP address or a range like 10.0.0.0/8."
	}
	return joinWords(bad) + " aren't IP addresses or ranges like 10.0.0.0/8."
}

func checkAddressList(v any) error {
	if p := addressListProblem(v.([]string)); p != "" {
		return errors.New(p)
	}
	return nil
}

func listProblem(key string) func(*Config) string {
	return func(c *Config) string {
		list, _ := c.Value(key).([]string)
		return addressListProblem(list)
	}
}

// modelProblem asks for a model where the provider needs one named.
func modelProblem(c *Config) string {
	if c.Assistant.Provider == assistant.OpenAI && strings.TrimSpace(c.Assistant.Model) == "" {
		return "Enter the model's name: OpenAI or compatible needs one, such as llama3.1 with Ollama or gpt-4.1 with OpenAI."
	}
	return ""
}

// joinWords joins items as "a, b and c".
func joinWords(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

func deref(p *int, d int) int {
	if p == nil {
		return d
	}
	return *p
}

// AssistantURL returns the address the AI assistant sends questions to:
// assistant.url, or the provider's own; "" when the assistant is off.
func (c *Config) AssistantURL() string {
	if c.Assistant.Provider == "" {
		return ""
	}
	if c.Assistant.URL != "" {
		return c.Assistant.URL
	}
	return assistant.DefaultURL[c.Assistant.Provider]
}

// Origin returns scheme://host:port of an http(s) address, with the
// default port filled in, so two ways of writing the same server compare
// equal. It returns "" for anything else.
func Origin(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch {
	case scheme != "http" && scheme != "https":
		return ""
	case port == "" && scheme == "https":
		port = "443"
	case port == "":
		port = "80"
	}
	return scheme + "://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// keyPattern finds setting keys in a validation problem.
var keyPattern = func() *regexp.Regexp {
	keys := LeafKeys()
	sort.Slice(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	for i, k := range keys {
		keys[i] = regexp.QuoteMeta(k)
	}
	return regexp.MustCompile(`(?:^|[^a-z0-9_.])(` + strings.Join(keys, "|") + `)(?:[^a-z0-9_]|$)`)
}()

// ProblemKeys returns the settings a validation problem is about, in the
// order it names them. Problems name the settings to fix by their keys,
// such as "server.listen", so the page can show each one at its field.
func ProblemKeys(problem string) []string {
	var out []string
	for _, m := range keyPattern.FindAllStringSubmatch(problem, -1) {
		if k := m[1]; !contains(out, k) {
			out = append(out, k)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// quotedValue is a value in quotes at the start of a problem, after its
// key, which the page shows in the field anyway.
var quotedValue = regexp.MustCompile(`^"(?:[^"\\]|\\.)*"\s+`)

// PlainProblem words a validation problem for the field of key on the
// page: without the key it starts with, and with other settings named by
// their labels.
func PlainProblem(key, problem string) string {
	msg := problem
	if rest, ok := strings.CutPrefix(msg, key); ok && !strings.HasPrefix(rest, " and ") && !strings.HasPrefix(rest, " or ") {
		rest = strings.TrimLeft(rest, " :")
		msg = quotedValue.ReplaceAllString(rest, "")
	}
	msg = keyPattern.ReplaceAllStringFunc(msg, func(m string) string {
		sub := keyPattern.FindStringSubmatch(m)
		s, ok := Lookup(sub[1])
		if !ok {
			return m
		}
		return strings.Replace(m, sub[1], "“"+s.Label+"”", 1)
	})
	if msg == "" {
		return problem
	}
	return upperFirst(msg)
}

// upperFirst starts s with a capital letter.
func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}
