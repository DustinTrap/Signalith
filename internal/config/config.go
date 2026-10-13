// Package config loads and validates signalith.yaml. Every setting has a
// working default, so a fresh install needs only the file "signalith init"
// writes, and validation errors say exactly which line to fix.
package config

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Config is the whole configuration file.
type Config struct {
	Server     Server     `yaml:"server"`
	OpenSearch OpenSearch `yaml:"opensearch"`
	Search     Search     `yaml:"search"`
	Retention  Retention  `yaml:"retention"`
	Auth       Auth       `yaml:"auth"`
	Ingest     Ingest     `yaml:"ingest"`
	Syslog     Syslog     `yaml:"syslog"`
	Detections Detections `yaml:"detections"`
	Lookups    Lookups    `yaml:"lookups"`
	Dashboards Dashboards `yaml:"dashboards"`
	Assistant  Assistant  `yaml:"assistant"`
	Intel      Intel      `yaml:"intel"`

	// path is where the file was loaded from.
	path string
	// ldapBindPassword comes from SIGNALITH_LDAP_BIND_PASSWORD. It is kept
	// apart from Auth.LDAP so saving the file never writes it out.
	ldapBindPassword string
	// sections are the top-level keys in that file.
	sections map[string]bool
	// file is the config as that file has it: no settings from the
	// environment, and passwords and keys as written. Save writes it.
	file *Config
	// plain lists the passwords and keys stored as plain text in the file,
	// and addressWarnings those written into addresses that cannot be
	// encrypted there.
	plain, addressWarnings []string
	// unreadable lists the encrypted ones that cannot be decrypted, with
	// what to do; locked has their fields, and feedLocked their labels by
	// feed. See openSecrets.
	unreadable []string
	locked     map[string]bool
	feedLocked map[string][]string
	// pageUnreadable lists the passwords and keys saved on the Settings
	// page that cannot be decrypted, with what to do, and pageLocked their
	// settings, with what the page says about each. See applyPage. A copy
	// of a Config shares them: they are replaced, never changed in place
	// (see copyPageProblem).
	pageUnreadable []pageProblem
	pageLocked     map[string]string
	// keys holds the master key; see Keyring.
	keys *secrets.Keyring
	// layers records where each setting's value came from.
	layers *layers
	// publicURLDerived is true when server.public_url was empty and
	// Validate worked it out from the listen address.
	publicURLDerived bool
}

// PublicURLDerived reports whether server.public_url was worked out from
// the listen address, because it was empty.
func (c *Config) PublicURLDerived() bool { return c.publicURLDerived }

// layers records where the settings of a loaded config came from: the
// environment, the Settings page (see pagefile.go), signalith.yaml or the
// defaults.
type layers struct {
	file     map[string]bool       // keys set in signalith.yaml, such as "server.listen"
	env      map[string]string     // keys set by an environment variable, and its name
	page     map[string]*PageEntry // settings applied from the Settings page
	refused  map[string]*PageEntry // settings from the page a restart set aside
	pageFile string                // the Settings page's file
	// pageFileEnv is true when SIGNALITH_SETTINGS_FILE named it.
	pageFileEnv bool
	// base is the config without the page's settings.
	base     *Config
	mismatch []secretMismatch
	warnings []string
	// problem says why the page's settings are not in use, problemKeys
	// which of them were to blame (when known), and pageFileErr whether
	// it was that their file could not be read.
	problem     string
	problemKeys []string
	pageFileErr bool
}

// Server controls the web UI and API listener.
type Server struct {
	// Listen is host:port. The default binds to localhost only; use
	// 0.0.0.0:8080 to accept agents from other machines.
	Listen string `yaml:"listen"`
	// PublicURL is the address agents and browsers use to reach this
	// server: scheme, host and optional port, no path. It goes into the
	// agent configs Signalith generates. SIGNALITH_PUBLIC_URL overrides it.
	PublicURL string `yaml:"public_url"`
	TLSCert   string `yaml:"tls_cert,omitempty"`
	TLSKey    string `yaml:"tls_key,omitempty"`
	// MaxConnections caps open connections to the UI, API and ingest;
	// 0 means 10000. One client (an IPv4 address, or an IPv6 /64 network)
	// may hold a tenth of them; connections from this machine, such as a
	// local reverse proxy, and from SharedAddresses are not limited that
	// way.
	MaxConnections int `yaml:"max_connections,omitempty"`
	// SharedAddresses lists IP addresses or CIDRs that stand for many
	// clients, such as a reverse proxy, load balancer or NAT gateway on
	// another machine. They are not limited to one client's share of
	// connections, requests and ingest memory, only by the totals.
	SharedAddresses []string `yaml:"shared_addresses,omitempty"`
}

// SharedList returns server.shared_addresses as prefixes; single addresses
// become /32 or /128. Invalid entries are skipped (Validate reports them).
func (s Server) SharedList() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range s.SharedAddresses {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// OpenSearch is the event store connection.
type OpenSearch struct {
	// URL is http(s)://host:port. A user name and password written into it
	// are moved to Username and Password when the file is loaded, so they
	// are never shown or logged with the URL.
	URL      string `yaml:"url"`
	Username string `yaml:"username,omitempty"`
	Password string `yaml:"password,omitempty"`
	// CAFile is a PEM file with the certificate authority that signed
	// OpenSearch's certificate, for an https url with a private CA (the
	// usual case). The system's trusted authorities are trusted too.
	CAFile string `yaml:"ca_file,omitempty"`
	// CertFile and KeyFile are a client certificate and key Signalith
	// presents to OpenSearch, for certificate sign-in.
	CertFile string `yaml:"cert_file,omitempty"`
	KeyFile  string `yaml:"key_file,omitempty"`
	// TLSSkipVerify turns off OpenSearch certificate checks, so anyone on
	// the network path could read and change events. For a lab only; use
	// CAFile instead.
	TLSSkipVerify bool `yaml:"tls_skip_verify,omitempty"`
	// Proxy is a proxy for OpenSearch traffic, such as
	// http://proxy:3128 (SIGNALITH_OPENSEARCH_PROXY overrides it). Empty
	// connects directly: HTTP_PROXY and HTTPS_PROXY are not used for
	// OpenSearch, since a proxy would see every event and the OpenSearch
	// password.
	Proxy string `yaml:"proxy,omitempty"`
	// AllowInsecureHTTP lets the username and password go to OpenSearch
	// over plain http on another machine, where anyone on the network
	// could read them. Off, that is refused; use https instead.
	AllowInsecureHTTP bool   `yaml:"allow_insecure_http,omitempty"`
	IndexPrefix       string `yaml:"index_prefix"`
	Replicas          int    `yaml:"replicas"`
}

// problems checks the connection settings. resolve makes file paths
// relative to the config file.
func (o *OpenSearch) problems(resolve func(string) string) []string {
	var p []string
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return []string{fmt.Sprintf("opensearch.url %q must be http(s)://host:port", redact.URL(o.URL))}
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		// Only the scheme and host are repeated: the rest may hold a key.
		p = append(p, fmt.Sprintf("opensearch.url %s://%s must not have a query string (?...) or fragment (#...); "+
			"put credentials in opensearch.username and password instead", u.Scheme, u.Host))
	}
	if u.Scheme == "http" && (o.Username != "" || o.Password != "") && !isLoopback(u.Hostname()) && !o.AllowInsecureHTTP {
		p = append(p, fmt.Sprintf("opensearch.url is plain http to %s, so the OpenSearch username and password would cross the network unencrypted. "+
			"Use https:// (with opensearch.ca_file set to OpenSearch's CA certificate if it is not publicly trusted), "+
			"or, to accept the risk, set opensearch.allow_insecure_http: true (signalith init: -opensearch-allow-insecure-http)", u.Host))
	}
	if u.Scheme == "http" && (o.CAFile != "" || o.CertFile != "") {
		p = append(p, "opensearch.ca_file, cert_file and key_file only apply to an https:// opensearch.url")
	}
	if o.CAFile != "" {
		if pem, err := os.ReadFile(resolve(o.CAFile)); err != nil {
			p = append(p, fmt.Sprintf("opensearch.ca_file: %v", err))
		} else if !x509.NewCertPool().AppendCertsFromPEM(pem) {
			p = append(p, fmt.Sprintf("opensearch.ca_file %s holds no PEM certificates (it should contain -----BEGIN CERTIFICATE-----)", o.CAFile))
		}
	}
	switch {
	case (o.CertFile == "") != (o.KeyFile == ""):
		p = append(p, "opensearch.cert_file and opensearch.key_file must be set together")
	case o.CertFile != "":
		if _, err := tls.LoadX509KeyPair(resolve(o.CertFile), resolve(o.KeyFile)); err != nil {
			p = append(p, fmt.Sprintf("opensearch.cert_file and key_file: %v", err))
		}
	}
	if o.Proxy != "" {
		if pu, err := url.Parse(o.Proxy); err != nil || !slices.Contains([]string{"http", "https", "socks5"}, pu.Scheme) || pu.Host == "" {
			p = append(p, fmt.Sprintf("opensearch.proxy %q must be http://host:port, https://host:port or socks5://host:port", redact.URL(o.Proxy)))
		}
	}
	return p
}

// moveURLCredentials takes a user name and password out of the URL and
// into Username and Password, unless those are set already.
func (o *OpenSearch) moveURLCredentials() {
	stripped, user, pw, ok := redact.Strip(o.URL)
	if !ok {
		return
	}
	o.URL = stripped
	if o.Username == "" && o.Password == "" {
		o.Username, o.Password = user, pw
	}
}

// isLoopback reports whether host is this machine.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	a, err := netip.ParseAddr(host)
	return err == nil && a.Unmap().IsLoopback()
}

// Search tunes the query engine.
type Search struct {
	DefaultEarliest string `yaml:"default_earliest"`
	MaxEvents       int    `yaml:"max_events"`
}

// Retention controls how long data is kept; see docs/retention.md. Most
// installs set policies on the Data retention page instead. Anything set
// here is shown there as "From signalith.yaml" and cannot be changed in
// the page.
type Retention struct {
	// Days keeps event categories without their own policy searchable for
	// this many days (0 keeps them forever), until a default policy is
	// saved on the page.
	Days int `yaml:"days"`
	// Interval is how often policies are enforced. Default 1h.
	Interval string `yaml:"interval,omitempty"`
	// ArchiveDir holds archived days. A relative path is relative to the
	// folder this config file is in. Default: an "archive" folder next to
	// lookups.dir. SIGNALITH_ARCHIVE_DIR overrides it.
	ArchiveDir string `yaml:"archive_dir,omitempty"`
	// Default is the policy for event categories without their own.
	Default *retention.Policy `yaml:"default,omitempty"`
	// Policies sets a policy per category: a data model (authentication,
	// endpoint, network_traffic, change), other, risk, findings or cases.
	Policies map[string]retention.Policy `yaml:"policies,omitempty"`
	// Guard deletes the oldest days when OpenSearch's disk gets too full.
	Guard *retention.Guard `yaml:"guard,omitempty"`
}

// RetentionInterval returns retention.interval as a duration (1h if unset
// or invalid; Validate reports invalid values).
func (c *Config) RetentionInterval() time.Duration {
	if d, err := detect.ParseDuration(c.Retention.Interval); err == nil && d > 0 {
		return d
	}
	return retention.DefaultInterval
}

// ArchiveDir returns the absolute archive folder.
func (c *Config) ArchiveDir() string {
	if c.Retention.ArchiveDir != "" {
		return c.resolve(c.Retention.ArchiveDir)
	}
	return filepath.Join(filepath.Dir(filepath.Clean(c.LookupsDir())), "archive")
}

// RetentionPolicies returns the retention settings for the retention
// package.
func (c *Config) RetentionPolicies() retention.Config {
	return retention.Config{Days: c.Retention.Days, Default: c.Retention.Default,
		Policies: c.Retention.Policies, Guard: c.Retention.Guard}
}

// Auth protects the UI and API.
type Auth struct {
	// AdminUser and AdminPasswordHash are the built-in admin: a break-glass
	// account that always works, whatever happens to other users.
	AdminUser         string `yaml:"admin_user"`
	AdminPasswordHash string `yaml:"admin_password_hash"`
	// SessionTimeout signs the web UI out after this long without use,
	// unless "keep me signed in" was ticked. Default 12h.
	SessionTimeout string `yaml:"session_timeout,omitempty"`
	// UsersFile holds the users added on the Users page. Default
	// users.json in lookups.dir; directory.json (directory sign-in
	// settings from the Users page) goes in the same folder.
	UsersFile string `yaml:"users_file,omitempty"`
	// LDAP sets up directory sign-in here instead of on the Users page,
	// which then shows it read-only.
	LDAP *users.LDAPSettings `yaml:"ldap,omitempty"`
}

// UsersFile returns the absolute path of the users file.
func (c *Config) UsersFile() string {
	if c.Auth.UsersFile != "" {
		return c.resolve(c.Auth.UsersFile)
	}
	return filepath.Join(c.LookupsDir(), "users.json")
}

// DirectoryFile returns where directory sign-in settings from the Users
// page are kept: directory.json next to the users file.
func (c *Config) DirectoryFile() string {
	return filepath.Join(filepath.Dir(c.UsersFile()), "directory.json")
}

// LDAP returns the directory sign-in settings from auth.ldap, with
// defaults filled in and the bind password from the environment if set
// there, or nil when the file has no auth.ldap.
func (c *Config) LDAP() (*users.LDAPSettings, error) {
	if c.Auth.LDAP == nil {
		return nil, nil
	}
	s := c.Auth.LDAP.Clone()
	if s.Enabled == nil {
		on := true
		s.Enabled = &on
	}
	if c.ldapBindPassword != "" {
		s.BindPassword = c.ldapBindPassword
	}
	if s.CACertFile != "" {
		if strings.TrimSpace(s.CACert) != "" {
			return nil, errors.New("auth.ldap: set ca_cert or ca_cert_file, not both")
		}
		b, err := os.ReadFile(c.resolve(s.CACertFile))
		if err != nil {
			return nil, fmt.Errorf("auth.ldap.ca_cert_file: %w", err)
		}
		s.CACert = string(b)
	}
	s.Normalize()
	return &s, nil
}

// SessionIdle returns auth.session_timeout as a duration.
func (c *Config) SessionIdle() time.Duration {
	if d, err := detect.ParseDuration(c.Auth.SessionTimeout); err == nil && d > 0 {
		return d
	}
	return 12 * time.Hour
}

// Ingest controls agent access.
type Ingest struct {
	// Tokens agents present in the Authorization header. Rotate by adding a
	// new token, updating agents, then removing the old one.
	Tokens []string `yaml:"tokens"`
	// MaxEventAge is how old an event's own time (from an agent or syslog)
	// may be and still be its event time, such as 7d. Older events, and
	// ones more than an hour ahead, are filed under the time they arrived,
	// with their own time kept in device_time. Empty means 7 days, or the
	// shortest retention period when that is shorter. Raise it to load old
	// logs.
	MaxEventAge string `yaml:"max_event_age,omitempty"`
}

// MaxEventAge returns ingest.max_event_age as a duration: the setting, or
// a week (keepDays, the shortest retention period, when that is shorter,
// since older events would land in indices about to be deleted). Each day
// in this window can get its own daily indices, so it bounds how many a
// sender can create.
func (c *Config) MaxEventAge(keepDays int) time.Duration {
	if d, err := detect.ParseDuration(c.Ingest.MaxEventAge); err == nil && d > 0 {
		return d
	}
	week := 7 * 24 * time.Hour
	if d := time.Duration(keepDays) * 24 * time.Hour; d > 0 && d < week {
		return d
	}
	return week
}

// Syslog receives syslog from systems that cannot run an agent: firewalls,
// switches, routers, appliances and servers. Off unless an address is set.
type Syslog struct {
	// UDP and TCP are host:port addresses to listen on, such as
	// 0.0.0.0:514. Empty turns that listener off.
	UDP string `yaml:"udp"`
	TCP string `yaml:"tcp"`
	// TLS is a host:port for syslog over TLS (RFC 5425), such as
	// 0.0.0.0:6514. It uses server.tls_cert and server.tls_key.
	TLS string `yaml:"tls"`
	// Allow lists the sender IP addresses or CIDRs that may send syslog.
	// Empty allows any sender.
	Allow []string `yaml:"allow"`
	// PublicPort is the port devices send UDP and TCP syslog to, when it
	// is not the one Signalith listens on: Docker or a firewall forwards
	// 514 to 5514, say. The Add data page puts it in the setup it shows.
	// Zero means the listen port.
	PublicPort int `yaml:"public_port,omitempty"`
}

// Enabled reports whether any syslog listener is set.
func (s Syslog) Enabled() bool { return s.UDP != "" || s.TCP != "" || s.TLS != "" }

// AllowList returns syslog.allow as prefixes; single addresses become /32
// or /128. Invalid entries are skipped (Validate reports them).
func (s Syslog) AllowList() []netip.Prefix {
	var out []netip.Prefix
	for _, a := range s.Allow {
		if p, err := parseAllow(a); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func parseAllow(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	a = a.Unmap().WithZone("")
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (s *Syslog) problems(server Server) []string {
	var p []string
	for _, l := range []struct{ setting, addr string }{{"syslog.udp", s.UDP}, {"syslog.tcp", s.TCP}, {"syslog.tls", s.TLS}} {
		if l.addr == "" {
			continue
		}
		host, port, err := net.SplitHostPort(l.addr)
		if err != nil {
			p = append(p, fmt.Sprintf("%s %q must be host:port, for example 0.0.0.0:514 (or empty to turn it off)", l.setting, l.addr))
			continue
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			p = append(p, fmt.Sprintf("%s port %q must be 1-65535", l.setting, port))
		}
		if _, err := netip.ParseAddr(host); err != nil && host != "" && host != "localhost" {
			p = append(p, fmt.Sprintf("%s host %q must be an IP address of this server, or 0.0.0.0 for all of them", l.setting, host))
		}
	}
	// TCP listeners cannot share a port with each other or the web server.
	tcp := []struct{ setting, addr string }{{"server.listen", server.Listen}, {"syslog.tcp", s.TCP}, {"syslog.tls", s.TLS}}
	for i := range tcp {
		for j := i + 1; j < len(tcp); j++ {
			if sameListener(tcp[i].addr, tcp[j].addr) {
				p = append(p, fmt.Sprintf("%s and %s both use %s; give them different ports", tcp[i].setting, tcp[j].setting, tcp[j].addr))
			}
		}
	}
	if s.TLS != "" && (server.TLSCert == "" || server.TLSKey == "") {
		p = append(p, "syslog.tls needs server.tls_cert and server.tls_key; syslog over TLS uses the same certificate as the web UI")
	}
	if s.PublicPort < 0 || s.PublicPort > 65535 {
		p = append(p, fmt.Sprintf("syslog.public_port %d must be 1-65535 (or 0 for the port syslog.udp and syslog.tcp listen on)", s.PublicPort))
	}
	for i, a := range s.Allow {
		if _, err := parseAllow(a); err != nil {
			p = append(p, fmt.Sprintf("syslog.allow[%d] %q must be an IP address or a CIDR such as 10.0.0.0/8", i, a))
		}
	}
	return p
}

// sameListener reports whether two listen addresses would take the same
// port: same port, and the same host or either on all interfaces.
func sameListener(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	ha, pa, err1 := net.SplitHostPort(a)
	hb, pb, err2 := net.SplitHostPort(b)
	if err1 != nil || err2 != nil || pa != pb {
		return false
	}
	wildcard := func(h string) bool { return h == "" || h == "0.0.0.0" || h == "::" }
	return ha == hb || wildcard(ha) || wildcard(hb)
}

// Detections controls scheduled detections and findings.
type Detections struct {
	// Dir holds custom and edited detections as YAML files. A relative
	// path is relative to the folder this config file is in.
	Dir string `yaml:"dir"`
	// Scheduler runs enabled detections on their schedules. Turn it off on
	// extra servers that share one OpenSearch so rules run once.
	Scheduler bool `yaml:"scheduler"`
	// MaxFindingsPerRun caps findings one run can raise.
	MaxFindingsPerRun int `yaml:"max_findings_per_run"`
}

// Lookups holds the asset and identity lists.
type Lookups struct {
	// Dir holds assets.csv and identities.csv. A relative path is relative
	// to the folder this config file is in.
	Dir string `yaml:"dir"`
}

// Dashboards controls the posture and custom dashboards.
type Dashboards struct {
	// Dir holds custom dashboards as YAML files, one per dashboard. A
	// relative path is relative to the folder this config file is in.
	Dir string `yaml:"dir"`
	// StaleAfter is how long a host and source type can go quiet before
	// the posture dashboard lists it as a data source that stopped sending.
	StaleAfter string `yaml:"stale_after"`
}

// Assistant is an optional AI model for questions the built-in
// plain-English translator cannot fully understand. Off when Provider is
// empty. Only the question and the field list are sent, never events.
type Assistant struct {
	// Provider is "anthropic" or "openai" (any OpenAI-compatible API,
	// including Ollama and LM Studio on your own hardware).
	Provider string `yaml:"provider,omitempty"`
	// URL overrides the endpoint, for example http://localhost:11434/v1.
	URL    string `yaml:"url,omitempty"`
	Model  string `yaml:"model,omitempty"`
	APIKey string `yaml:"api_key,omitempty"`
}

// Intel configures threat intel feeds. Nothing is downloaded until a
// feed is listed here or added on the Threat intel page.
type Intel struct {
	Feeds []IntelFeed `yaml:"feeds"`
	// FeedsFile keeps the feeds added on the Threat intel page. Default:
	// intel_feeds.yaml in lookups.dir. A relative path is relative to the
	// folder this config file is in.
	FeedsFile string `yaml:"feeds_file,omitempty"`
	// AllowLoopbackFeeds lets feeds download from this machine (127.0.0.1
	// or ::1), for a feed server on the same host. Off by default.
	AllowLoopbackFeeds bool `yaml:"allow_loopback_feeds,omitempty"`
}

// IntelFeed is one feed the server downloads on a schedule. Feeds added on
// the Threat intel page use the same settings and rules.
type IntelFeed = intel.FeedSpec

// ParseFeedDuration parses 30m, 12h, 7d or 2w.
func ParseFeedDuration(s string) (time.Duration, error) { return intel.ParseDuration(s) }

func (in *Intel) problems() []string {
	var p []string
	seen := map[string]bool{}
	for i := range in.Feeds {
		f := &in.Feeds[i]
		f.Defaults()
		at := fmt.Sprintf("intel.feeds[%d]", i)
		if f.Name != "" {
			at = fmt.Sprintf("intel.feeds[%d] (%s)", i, f.Name)
		}
		if seen[f.Name] && f.Name != "" {
			p = append(p, at+": name is used by another feed")
		}
		seen[f.Name] = true
		for _, pr := range f.Problems(true) {
			p = append(p, at+": "+pr.Msg)
		}
	}
	return p
}

// IntelFeedsFile returns the file that keeps the feeds added on the
// Threat intel page.
func (c *Config) IntelFeedsFile() string {
	if c.Intel.FeedsFile != "" {
		return c.resolve(c.Intel.FeedsFile)
	}
	return filepath.Join(c.LookupsDir(), "intel_feeds.yaml")
}

// LookupsDir returns the absolute lookups folder.
func (c *Config) LookupsDir() string { return c.resolve(c.Lookups.Dir) }

func (c *Config) resolve(d string) string {
	if d == "" || filepath.IsAbs(d) || c.path == "" {
		return d
	}
	return filepath.Join(filepath.Dir(c.path), d)
}

// DetectionsDir returns the absolute detections folder.
func (c *Config) DetectionsDir() string { return c.resolve(c.Detections.Dir) }

// DashboardsDir returns the absolute dashboards folder.
func (c *Config) DashboardsDir() string { return c.resolve(c.Dashboards.Dir) }

// StaleAfter returns dashboards.stale_after as a duration (2h if unset or
// invalid; Validate reports invalid values).
func (c *Config) StaleAfter() time.Duration {
	if d, err := detect.ParseDuration(c.Dashboards.StaleAfter); err == nil && d > 0 {
		return d
	}
	return 2 * time.Hour
}

// Default returns a config with every default filled in.
func Default() *Config {
	return &Config{
		Server:     Server{Listen: "127.0.0.1:8080"},
		OpenSearch: OpenSearch{URL: "http://127.0.0.1:9200", IndexPrefix: "signalith"},
		Search:     Search{DefaultEarliest: "-24h", MaxEvents: 10000},
		Retention:  Retention{Days: 90},
		Auth:       Auth{AdminUser: "admin"},
		Detections: Detections{Dir: "detections", Scheduler: true, MaxFindingsPerRun: 100},
		Lookups:    Lookups{Dir: "lookups"},
		Dashboards: Dashboards{Dir: "dashboards", StaleAfter: "2h"},
	}
}

// Path returns the file the config was loaded from.
func (c *Config) Path() string { return c.path }

// HasSection reports whether the file the config was loaded from has the
// top-level section, such as "syslog". Settings for one that is missing
// are added at the end of the file; a second "syslog:" would not load.
func (c *Config) HasSection(name string) bool { return c.sections[name] }

// Load reads a config file, applies the settings changed on the Settings
// page, defaults and environment overrides, decrypts the passwords and keys
// stored encrypted, and validates the result. Settings from the page that
// cannot be used never stop Signalith: it starts with signalith.yaml
// alone, and SettingsProblem says why. A password or key that cannot be
// decrypted is left out and reported by Warnings rather than failing (see
// Unreadable and PageUnreadable).
func Load(path string) (*Config, error) {
	return loadWith(path, nil)
}

// LoadSetAside is Load with the settings keys, changed on the Settings
// page, set aside for reason: they are not used, as after MarkRefused,
// whether or not that could be saved.
func LoadSetAside(path string, keys []string, reason string) (*Config, error) {
	now := time.Now()
	return loadWith(path, func(p *PageSettings) { p.refuse(keys, reason, now) })
}

func loadWith(path string, adjust func(*PageSettings)) (*Config, error) {
	s, err := loadSaved(path, adjust)
	if err != nil {
		return nil, err
	}
	if s.PageErr == nil && s.Problems == nil {
		return s.Config, nil
	}
	if s.PageErr == nil && len(s.Config.PageKeys()) == 0 {
		// Nothing came from the page: the problems are the file's own.
		return nil, fmt.Errorf("%s: %w", path, &ValidationError{Problems: s.Problems})
	}
	c, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	c.layers.pageFileErr = s.PageErr != nil
	if s.PageErr != nil {
		c.layers.problem = fmt.Sprintf("The settings saved on the Settings page were not used, because %v. Signalith started with signalith.yaml alone. Fix the file, or remove it with: signalith settings reset", s.PageErr)
	} else {
		c.layers.problem = "The settings saved on the Settings page were not used, because with them: " + strings.Join(s.Problems, "; ") +
			". Signalith started with signalith.yaml alone. Fix these settings on the Settings page, or remove them with: signalith settings reset"
		for _, p := range s.Problems {
			for _, k := range ProblemKeys(p) {
				if s.Config.Source(k).Kind == FromPage && !slices.Contains(c.layers.problemKeys, k) {
					c.layers.problemKeys = append(c.layers.problemKeys, k)
				}
			}
		}
	}
	return c, nil
}

// LoadWithoutPage is LoadFile for a server that could not start with the
// settings saved on the Settings page; reason says why, and SettingsProblem
// reports it. keys are the settings to blame, when known.
func LoadWithoutPage(path, reason string, keys []string) (*Config, error) {
	c, err := LoadFile(path)
	if err != nil {
		return nil, err
	}
	c.layers.problem = "The settings saved on the Settings page were not used, because " + reason +
		". Signalith started with signalith.yaml alone. Fix these settings on the Settings page, or remove them with: signalith settings reset"
	c.layers.problemKeys = keys
	return c, nil
}

// SettingsProblemKeys lists the settings from the Settings page that kept
// Signalith from starting with them, when SettingsProblem is set and it
// is known which.
func (c *Config) SettingsProblemKeys() []string {
	if c.layers == nil || c.layers.problemKeys == nil {
		return []string{}
	}
	return c.layers.problemKeys
}

// SettingsFileProblem reports whether SettingsProblem is that the
// Settings page's file could not be read.
func (c *Config) SettingsFileProblem() bool {
	return c.layers != nil && c.layers.pageFileErr
}

// LoadFile is Load without the settings changed on the Settings page:
// signalith.yaml, defaults and the environment. Commands that write
// signalith.yaml back load it this way, so the page's settings stay in
// their own file.
func LoadFile(path string) (*Config, error) {
	c, err := build(path, nil)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// LoadUnchecked reads a config file with defaults and environment
// overrides, but neither decrypts nor checks it, and leaves out the
// settings changed on the Settings page: for commands that look at, or
// repair, a file that may not load.
func LoadUnchecked(path string) (*Config, error) {
	return readAndEnv(path)
}

// Saved is the configuration as saved, whether or not it is valid:
// signalith.yaml, the settings changed on the Settings page, and the
// environment. The Settings page shows it.
type Saved struct {
	*Config
	// Page is the Settings page's file as read; nil when it cannot be.
	Page *PageSettings
	// Problems lists what is wrong, as Validate words it; nil when valid.
	Problems []string
	// PageErr is set when the page's file cannot be read or used; Config
	// is then without it.
	PageErr error
}

// LoadSaved reads the configuration as saved, valid or not.
func LoadSaved(path string) (*Saved, error) {
	return loadSaved(path, nil)
}

func loadSaved(path string, adjust func(*PageSettings)) (*Saved, error) {
	c, err := readAndEnv(path)
	if err != nil {
		return nil, err
	}
	s := &Saved{}
	page, perr := ReadPageSettings(c.SettingsFile())
	if perr == nil {
		if adjust != nil {
			page = page.Clone()
			adjust(page)
		}
		s.Page = page
	}
	cfg, err := build(path, page)
	var pe *PageFileError
	if errors.As(err, &pe) {
		perr = pe
		cfg, err = build(path, nil)
	}
	if err != nil {
		return nil, err
	}
	s.Config, s.PageErr = cfg, perr
	s.Problems = problemsOf(cfg)
	return s, nil
}

// problemsOf validates c and returns its problems, or nil.
func problemsOf(c *Config) []string {
	err := c.Validate()
	if err == nil {
		return nil
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		return ve.Problems
	}
	return []string{err.Error()}
}

// build reads signalith.yaml and applies the environment, then the
// settings changed on the page, without validating. A page setting that
// cannot be used is a *PageFileError.
func build(path string, page *PageSettings) (*Config, error) {
	c, err := readAndEnv(path)
	if err != nil {
		return nil, err
	}
	base, err := readAndEnv(path)
	if err != nil {
		return nil, err
	}
	// Both use the same master key.
	base.keys = c.Keyring()
	base.openSecrets()
	// Validating fills in worked-out values, such as the public address.
	_ = base.Validate()
	c.layers.base = base
	if !page.Empty() {
		if err := c.applyPage(page, base); err != nil {
			return nil, &PageFileError{Path: c.layers.pageFile, Err: err}
		}
	}
	// The passwords and keys in signalith.yaml are decrypted once the
	// page's settings are in: one the page replaces is not needed, as one
	// an environment variable replaces is not.
	c.openSecrets()
	return c, nil
}

// readAndEnv reads signalith.yaml with defaults and the environment,
// without decrypting it.
func readAndEnv(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file %s not found; create one with: signalith init", path)
		}
		return nil, err
	}
	c, err := decodeFile(path, data)
	if err != nil {
		return nil, err
	}
	c.path = path
	c.layers = &layers{file: map[string]bool{}, env: map[string]string{}, page: map[string]*PageEntry{}, refused: map[string]*PageEntry{}}
	var top map[string]any
	if yaml.Unmarshal(data, &top) == nil {
		c.sections = make(map[string]bool, len(top))
		for k := range top {
			c.sections[k] = true
		}
		fileKeys(top, "", c.layers.file)
	}
	// Keep the file's own view, before the environment changes anything.
	if c.file, err = decodeFile(path, data); err != nil {
		return nil, err
	}
	c.plain = plainLabels(c.file.secretRefs())
	inURL, warnings := addressPlain(c.file.addressSecrets())
	c.plain, c.addressWarnings = append(c.plain, inURL...), warnings
	if err := c.applyEnv(); err != nil {
		return nil, err
	}
	c.layers.pageFileEnv = strings.TrimSpace(os.Getenv("SIGNALITH_SETTINGS_FILE")) != ""
	c.layers.pageFile = c.SettingsFile()
	return c, nil
}

// decodeFile decodes signalith.yaml over the defaults.
func decodeFile(path string, data []byte) (*Config, error) {
	c := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// fileKeys records every key set in the file, nested ones as "a.b".
func fileKeys(m map[string]any, prefix string, out map[string]bool) {
	for k, v := range m {
		out[prefix+k] = true
		if sub, ok := v.(map[string]any); ok {
			fileKeys(sub, prefix+k+".", out)
		}
	}
}

// fromEnv notes that an environment variable set a setting.
func (c *Config) fromEnv(key, name string) {
	if c.layers != nil {
		c.layers.env[key] = name
	}
}

// applyEnv lets secrets come from the environment instead of the file.
func (c *Config) applyEnv() error {
	if v := os.Getenv("SIGNALITH_OPENSEARCH_URL"); v != "" {
		c.OpenSearch.URL = v
		c.fromEnv("opensearch.url", "SIGNALITH_OPENSEARCH_URL")
	}
	if v := os.Getenv("SIGNALITH_OPENSEARCH_USERNAME"); v != "" {
		c.OpenSearch.Username = v
		c.fromEnv("opensearch.username", "SIGNALITH_OPENSEARCH_USERNAME")
	}
	if v := os.Getenv("SIGNALITH_OPENSEARCH_PASSWORD"); v != "" {
		c.OpenSearch.Password = v
		c.fromEnv("opensearch.password", "SIGNALITH_OPENSEARCH_PASSWORD")
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_OPENSEARCH_PROXY")); v != "" {
		c.OpenSearch.Proxy = v
		c.fromEnv("opensearch.proxy", "SIGNALITH_OPENSEARCH_PROXY")
	}
	if v := os.Getenv("SIGNALITH_LISTEN"); v != "" {
		c.Server.Listen = v
		c.fromEnv("server.listen", "SIGNALITH_LISTEN")
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_PUBLIC_URL")); v != "" {
		if _, err := agents.ParseServerURL(v); err != nil {
			return fmt.Errorf("SIGNALITH_PUBLIC_URL %q: %v", v, err)
		}
		c.Server.PublicURL = v
		c.fromEnv("server.public_url", "SIGNALITH_PUBLIC_URL")
	}
	if v := os.Getenv("SIGNALITH_ADMIN_PASSWORD"); v != "" {
		h, err := envPasswordHash(v)
		if err != nil {
			return err
		}
		c.Auth.AdminPasswordHash = h
		c.fromEnv("auth.admin_password_hash", "SIGNALITH_ADMIN_PASSWORD")
	}
	if v := os.Getenv("SIGNALITH_USERS_FILE"); v != "" {
		c.Auth.UsersFile = v
		c.fromEnv("auth.users_file", "SIGNALITH_USERS_FILE")
	}
	if v := os.Getenv("SIGNALITH_LDAP_BIND_PASSWORD"); v != "" {
		c.ldapBindPassword = v
	}
	if v := os.Getenv("SIGNALITH_DETECTIONS_DIR"); v != "" {
		c.Detections.Dir = v
		c.fromEnv("detections.dir", "SIGNALITH_DETECTIONS_DIR")
	}
	if v := os.Getenv("SIGNALITH_LOOKUPS_DIR"); v != "" {
		c.Lookups.Dir = v
		c.fromEnv("lookups.dir", "SIGNALITH_LOOKUPS_DIR")
	}
	if v := os.Getenv("SIGNALITH_DASHBOARDS_DIR"); v != "" {
		c.Dashboards.Dir = v
		c.fromEnv("dashboards.dir", "SIGNALITH_DASHBOARDS_DIR")
	}
	if v := os.Getenv("SIGNALITH_INTEL_FEEDS_FILE"); v != "" {
		c.Intel.FeedsFile = v
		c.fromEnv("intel.feeds_file", "SIGNALITH_INTEL_FEEDS_FILE")
	}
	if v := os.Getenv("SIGNALITH_ARCHIVE_DIR"); v != "" {
		c.Retention.ArchiveDir = v
		c.fromEnv("retention.archive_dir", "SIGNALITH_ARCHIVE_DIR")
	}
	if v := os.Getenv("SIGNALITH_ASSISTANT_API_KEY"); v != "" {
		c.Assistant.APIKey = v
		c.fromEnv("assistant.api_key", "SIGNALITH_ASSISTANT_API_KEY")
	}
	if v := os.Getenv("SIGNALITH_INGEST_TOKEN"); v != "" {
		c.Ingest.Tokens = append(c.Ingest.Tokens, v)
		c.fromEnv("ingest.tokens", "SIGNALITH_INGEST_TOKEN")
	}
	// "off" turns a syslog listener off, since an empty variable is
	// indistinguishable from an unset one.
	if v := os.Getenv("SIGNALITH_SYSLOG_UDP"); v != "" {
		c.Syslog.UDP = offToEmpty(v)
		c.fromEnv("syslog.udp", "SIGNALITH_SYSLOG_UDP")
	}
	if v := os.Getenv("SIGNALITH_SYSLOG_TCP"); v != "" {
		c.Syslog.TCP = offToEmpty(v)
		c.fromEnv("syslog.tcp", "SIGNALITH_SYSLOG_TCP")
	}
	return nil
}

// envHash remembers the hash of SIGNALITH_ADMIN_PASSWORD, which every
// load of the config needs and which is slow to compute on purpose.
var envHash struct {
	sync.Mutex
	password, hash string
}

func envPasswordHash(pw string) (string, error) {
	envHash.Lock()
	defer envHash.Unlock()
	if envHash.hash != "" && envHash.password == pw {
		return envHash.hash, nil
	}
	h, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	envHash.password, envHash.hash = pw, h
	return h, nil
}

func offToEmpty(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "off") {
		return ""
	}
	return strings.TrimSpace(v)
}

// ValidationError lists every problem found, not just the first.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return "invalid configuration:\n  - " + strings.Join(e.Problems, "\n  - ")
}

// Validate checks the config and fills derived defaults.
func (c *Config) Validate() error {
	var p []string
	if _, port, err := net.SplitHostPort(c.Server.Listen); err != nil {
		p = append(p, fmt.Sprintf("server.listen %q must be host:port, for example 0.0.0.0:8080", c.Server.Listen))
	} else if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		p = append(p, fmt.Sprintf("server.listen port %q must be 1-65535", port))
	}
	if c.Server.MaxConnections < 0 {
		p = append(p, "server.max_connections cannot be negative (0 uses the default, 10000)")
	}
	for i, a := range c.Server.SharedAddresses {
		if _, err := parseAllow(a); err != nil {
			p = append(p, fmt.Sprintf("server.shared_addresses[%d] %q must be an IP address or a CIDR such as 10.0.0.0/24", i, a))
		}
	}
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		p = append(p, "server.tls_cert and server.tls_key must be set together")
	}
	if c.Server.PublicURL == "" || c.publicURLDerived {
		c.Server.PublicURL, c.publicURLDerived = defaultPublicURL(c.Server), true
	} else if _, err := agents.ParseServerURL(c.Server.PublicURL); err != nil {
		p = append(p, fmt.Sprintf("server.public_url %q: %v", c.Server.PublicURL, err))
	}
	c.OpenSearch.moveURLCredentials()
	p = append(p, c.OpenSearch.problems(c.resolve)...)
	if c.OpenSearch.IndexPrefix == "" || strings.ToLower(c.OpenSearch.IndexPrefix) != c.OpenSearch.IndexPrefix || strings.ContainsAny(c.OpenSearch.IndexPrefix, `*?"<>|, /\#`) {
		p = append(p, "opensearch.index_prefix must be lowercase with no spaces or wildcards")
	}
	if c.OpenSearch.Replicas < 0 {
		p = append(p, "opensearch.replicas cannot be negative")
	}
	if c.Search.MaxEvents < 1 || c.Search.MaxEvents > 100000 {
		p = append(p, "search.max_events must be between 1 and 100000")
	}
	if c.Retention.Days < 0 {
		p = append(p, "retention.days cannot be negative (0 keeps data forever)")
	} else if c.Retention.Days > retention.MaxKeepDays {
		p = append(p, fmt.Sprintf("retention.days must be at most %d (0 keeps data forever)", retention.MaxKeepDays))
	}
	if c.Retention.Interval != "" {
		if d, err := detect.ParseDuration(c.Retention.Interval); err != nil || d < 5*time.Minute || d > 24*time.Hour {
			p = append(p, fmt.Sprintf("retention.interval %q must be a duration from 5m to 24h, for example 1h", c.Retention.Interval))
		}
	}
	p = append(p, c.RetentionPolicies().Problems()...)
	if c.Auth.AdminUser == "" {
		p = append(p, "auth.admin_user is required")
	}
	if c.Auth.AdminPasswordHash == "" {
		p = append(p, "auth.admin_password_hash is empty; run signalith passwd, or set SIGNALITH_ADMIN_PASSWORD")
	} else if _, err := bcrypt.Cost([]byte(c.Auth.AdminPasswordHash)); err != nil {
		p = append(p, "auth.admin_password_hash is not a bcrypt hash; generate one with signalith passwd")
	}
	if c.Auth.SessionTimeout != "" {
		if d, err := detect.ParseDuration(c.Auth.SessionTimeout); err != nil || d < 5*time.Minute {
			p = append(p, fmt.Sprintf("auth.session_timeout %q must be a duration of at least 5m, for example 12h or 1d", c.Auth.SessionTimeout))
		}
	}
	if c.Auth.LDAP != nil {
		if s, err := c.LDAP(); err != nil {
			p = append(p, err.Error())
		} else {
			for _, pr := range s.Problems() {
				msg := pr.Message
				if pr.Field == "bind_password" {
					if c.locked["auth.ldap.bind_password"] {
						// Reported by Warnings; directory sign-in fails
						// without trying an empty password.
						continue
					}
					msg = "set auth.ldap.bind_password, or the SIGNALITH_LDAP_BIND_PASSWORD environment variable"
				}
				p = append(p, "auth.ldap."+pr.Field+": "+msg)
			}
		}
	}
	if c.Detections.Dir == "" {
		p = append(p, "detections.dir is required, for example: detections")
	}
	if c.Lookups.Dir == "" {
		p = append(p, "lookups.dir is required, for example: lookups")
	}
	if c.Dashboards.Dir == "" {
		p = append(p, "dashboards.dir is required, for example: dashboards")
	}
	if c.Dashboards.StaleAfter == "" {
		c.Dashboards.StaleAfter = "2h"
	} else if d, err := detect.ParseDuration(c.Dashboards.StaleAfter); err != nil || d < 5*time.Minute {
		p = append(p, fmt.Sprintf("dashboards.stale_after %q must be a duration of at least 5m, for example 2h or 1d", c.Dashboards.StaleAfter))
	}
	switch c.Assistant.Provider {
	case "":
	case "anthropic":
		// A key that cannot be decrypted is reported by Warnings instead.
		if c.Assistant.APIKey == "" && !c.locked["assistant.api_key"] && c.pageLocked["assistant.api_key"] == "" {
			p = append(p, "assistant.api_key is required for anthropic; set it or SIGNALITH_ASSISTANT_API_KEY")
		}
	case "openai":
		if c.Assistant.Model == "" {
			p = append(p, "assistant.model is required for openai, for example gpt-4.1 or, with Ollama, llama3.1")
		}
	default:
		p = append(p, fmt.Sprintf("assistant.provider %q must be anthropic, openai or empty (off)", c.Assistant.Provider))
	}
	if c.Assistant.URL != "" {
		if u, err := url.Parse(c.Assistant.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			p = append(p, fmt.Sprintf("assistant.url %q must be http(s)://host[:port][/path]", redact.URL(c.Assistant.URL)))
		}
	}
	p = append(p, c.Intel.problems()...)
	if c.Detections.MaxFindingsPerRun < 1 || c.Detections.MaxFindingsPerRun > 10000 {
		p = append(p, "detections.max_findings_per_run must be between 1 and 10000")
	}
	for i, t := range c.Ingest.Tokens {
		if len(t) < 16 {
			p = append(p, fmt.Sprintf("ingest.tokens[%d] is shorter than 16 characters", i))
		}
	}
	if c.Ingest.MaxEventAge != "" {
		if d, err := detect.ParseDuration(c.Ingest.MaxEventAge); err != nil || d < time.Hour || d > 3650*24*time.Hour {
			p = append(p, fmt.Sprintf("ingest.max_event_age %q must be a duration from 1h to 3650d, for example 7d or 30d (empty: 7 days)", c.Ingest.MaxEventAge))
		}
	}
	p = append(p, c.Syslog.problems(c.Server)...)
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
}

// Warnings lists settings that work but put data at risk. validate prints
// them, and the server logs them at startup and shows them on the Health
// page.
func (c *Config) Warnings() []string {
	var w []string
	o := c.OpenSearch
	if o.TLSSkipVerify {
		w = append(w, "opensearch.tls_skip_verify is on, so Signalith does not check OpenSearch's certificate: anyone on the network path "+
			"could read and change events and capture the OpenSearch password. Set opensearch.ca_file to OpenSearch's CA certificate and turn tls_skip_verify off.")
	}
	if u, err := url.Parse(o.URL); err == nil && u.Scheme == "http" && o.AllowInsecureHTTP && (o.Username != "" || o.Password != "") && !isLoopback(u.Hostname()) {
		w = append(w, "opensearch.allow_insecure_http is on, so the OpenSearch username and password cross the network to "+u.Host+" unencrypted. Use an https:// opensearch.url.")
	}
	if u, err := url.Parse(c.Assistant.URL); err == nil && c.Assistant.Provider != "" && u.Scheme == "http" && c.Assistant.APIKey != "" && !isLoopback(u.Hostname()) {
		w = append(w, "assistant.url is plain http to "+u.Host+", so the AI model's API key crosses the network unencrypted. Use https://.")
	}
	return append(w, c.secretWarnings()...)
}

// OpenSearchConnection returns the settings Signalith connects to
// OpenSearch with.
func (c *Config) OpenSearchConnection() store.Config {
	ca, cert, key := c.OpenSearchTLSFiles()
	return store.Config{
		URL: c.OpenSearch.URL, Username: c.OpenSearch.Username, Password: secrets.New("opensearch.password", c.OpenSearch.Password),
		CAFile: ca, CertFile: cert, KeyFile: key,
		TLSSkipVerify: c.OpenSearch.TLSSkipVerify, Proxy: c.OpenSearch.Proxy,
	}
}

// OpenSearchProblems lists what is wrong with the OpenSearch connection
// settings, as Validate words it.
func (c *Config) OpenSearchProblems() []string {
	o := c.OpenSearch
	o.moveURLCredentials()
	return o.problems(c.resolve)
}

// OpenSearchTLSFiles returns opensearch.ca_file, cert_file and key_file,
// with relative paths made relative to the folder this config file is in.
func (c *Config) OpenSearchTLSFiles() (ca, cert, key string) {
	return c.resolve(c.OpenSearch.CAFile), c.resolve(c.OpenSearch.CertFile), c.resolve(c.OpenSearch.KeyFile)
}

func defaultPublicURL(s Server) string {
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil {
		return ""
	}
	scheme := "http"
	if s.TLSCert != "" {
		scheme = "https"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
		// The machine's name, if it can go into an agent config as is.
		if h, err := os.Hostname(); err == nil {
			if _, err := agents.ParseServerURL(scheme + "://" + net.JoinHostPort(h, port)); err == nil {
				host = h
			}
		}
	}
	return scheme + "://" + net.JoinHostPort(host, port)
}

// HashPassword returns a bcrypt hash for the admin password. Users'
// passwords follow the same rules.
func HashPassword(pw string) (string, error) { return users.HashPassword(pw) }

// CheckPassword reports whether user and pw are the built-in admin's. The
// username ignores case, like every other username.
func (c *Config) CheckPassword(user, pw string) bool {
	if !strings.EqualFold(strings.TrimSpace(user), c.Auth.AdminUser) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(c.Auth.AdminPasswordHash), []byte(pw)) == nil
}

// RandomToken returns a random hex token.
func RandomToken(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// Save writes the config with a header comment explaining each section,
// with its passwords and keys encrypted. A config from Load is written as
// its file had it: settings from environment variables are never written
// out, and neither are changes made after loading (use SetSecret or
// SetAdminPasswordHash to change one setting in a file). A config with
// settings from the Settings page is refused, so they stay in their own
// file; load it with LoadFile to change signalith.yaml.
func (c *Config) Save(path string) error {
	if len(c.PageKeys()) > 0 {
		return errors.New("this configuration includes settings from the Settings page; load signalith.yaml with LoadFile to save it")
	}
	src := c
	if c.file != nil {
		src = c.file
	}
	if c.path == "" {
		// The master key goes with the file: a keyring made before the
		// config had a file is made again for its folder.
		c.path, c.keys = path, nil
	}
	var doc yaml.Node
	if err := doc.Encode(src); err != nil {
		return err
	}
	for _, n := range secretNodes(&doc) {
		if !isPlain(n.node.Value, n.envRefs) {
			continue
		}
		sealed, err := c.Keyring().Seal(n.field, n.node.Value)
		if err != nil {
			return err
		}
		n.node.Value, n.node.Style = sealed, 0
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	for i := 0; i+1 < len(root.Content); i += 2 {
		if comment, ok := sectionComments[root.Content[i].Value]; ok {
			root.Content[i].HeadComment = comment
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	return securefile.WriteFile(path, []byte(header+string(out)))
}

// sectionComments are written just above a section of the saved file.
var sectionComments = map[string]string{
	"syslog": `Syslog from systems that cannot run an agent (firewalls, switches, routers,
appliances, servers). Point them at this server on UDP or TCP port 514.
An empty address turns that listener off. tls (for example 0.0.0.0:6514)
uses server.tls_cert and server.tls_key. allow limits who may send, as IPs
or CIDRs such as 10.0.0.0/8; empty allows any sender.`,
}

const header = `# Signalith configuration.
# Run "signalith validate" after editing. Secrets can come from environment
# variables instead of this file: SIGNALITH_OPENSEARCH_PASSWORD,
# SIGNALITH_ADMIN_PASSWORD, SIGNALITH_INGEST_TOKEN, SIGNALITH_ASSISTANT_API_KEY,
# SIGNALITH_LDAP_BIND_PASSWORD. Passwords and keys below are encrypted
# (enc:v1:...) with Signalith's master key; a plain value pasted in works
# too, and "signalith secrets encrypt" encrypts it (see docs/encryption.md).
#
# server.listen      address the UI/API binds to (0.0.0.0:8080 for all interfaces)
# server.public_url  URL agents use to reach this server (or SIGNALITH_PUBLIC_URL)
# server.max_connections  open connections allowed at once (default 10000); one
#                    client may hold a tenth of them
# server.shared_addresses  IPs or CIDRs of a proxy, load balancer or NAT that many
#                    clients reach Signalith through; not limited as one client
# auth.admin_user    the built-in admin, a break-glass account; add other users on the Users page
# auth.session_timeout  sign the web UI out after this long idle (default 12h)
# auth.users_file    where Users page accounts are kept (default users.json in lookups.dir)
# auth.ldap          optional LDAP / Active Directory sign-in; usually set up on the Users
#                    page instead (see docs/users.md)
# opensearch.*       where events are stored; for https with a private CA set
#                    ca_file (cert_file and key_file for certificate sign-in)
# search.*           default time range and result limits
# retention.days     days of events to keep (0 = forever) until a default is saved on the
#                    Data retention page; per-category policies, the disk guard and
#                    archiving are set there too (or here: see docs/retention.md)
# ingest.tokens      tokens agents send; see the Add data page for agent setup
# ingest.max_event_age  events older than this (default 7d) are filed under the time
#                    they arrived, with their own time in device_time
# syslog.udp, .tcp   receive syslog from devices without an agent, e.g. 0.0.0.0:514
#                    (empty = off; SIGNALITH_SYSLOG_UDP / _TCP override, "off" turns off)
# syslog.tls         syslog over TLS, e.g. 0.0.0.0:6514; uses server.tls_cert and tls_key
# syslog.allow       sender IPs or CIDRs allowed to send syslog (empty = any sender)
# syslog.public_port port devices send to, if forwarded to another (Docker: 514 -> 5514)
# detections.dir     folder for custom detections (relative to this file)
# lookups.dir        folder for assets.csv and identities.csv (relative to this file)
# dashboards.dir     folder for custom dashboards, one YAML file each (relative to this file)
# dashboards.stale_after  how long a host can go quiet before the posture dashboard flags it
# assistant.*        optional AI model for "Ask in English" (provider: anthropic or openai);
#                    off by default, and only the question and field names are sent
# intel.feeds        threat intel feeds to download (none by default). The easiest way
#                    is the Threat intel page (Add feed), which keeps its feeds in
#                    lookups.dir/intel_feeds.yaml (intel.feeds_file). Or list them here:
#                      - name: feodo-tracker
#                        url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
#                    format: lines, csv (with column:), stix or auto; see docs/threat-intel.md

`
