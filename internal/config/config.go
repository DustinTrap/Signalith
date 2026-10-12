// Package config loads and validates signalith.yaml. Every setting has a
// working default, so a fresh install needs only the file "signalith init"
// writes, and validation errors say exactly which line to fix.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agents"
	"github.com/jrsamsanchez/signalith/internal/detect"
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
}

// OpenSearch is the event store connection.
type OpenSearch struct {
	URL           string `yaml:"url"`
	Username      string `yaml:"username,omitempty"`
	Password      string `yaml:"password,omitempty"`
	TLSSkipVerify bool   `yaml:"tls_skip_verify,omitempty"`
	IndexPrefix   string `yaml:"index_prefix"`
	Replicas      int    `yaml:"replicas"`
}

// Search tunes the query engine.
type Search struct {
	DefaultEarliest string `yaml:"default_earliest"`
	MaxEvents       int    `yaml:"max_events"`
}

// Retention controls how long events are kept.
type Retention struct {
	Days int `yaml:"days"`
}

// Auth protects the UI and API.
type Auth struct {
	AdminUser         string `yaml:"admin_user"`
	AdminPasswordHash string `yaml:"admin_password_hash"`
	// SessionTimeout signs the web UI out after this long without use,
	// unless "keep me signed in" was ticked. Default 12h.
	SessionTimeout string `yaml:"session_timeout,omitempty"`
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

// Intel configures threat intel feeds. Nothing is downloaded unless a
// feed is listed here.
type Intel struct {
	Feeds []IntelFeed `yaml:"feeds"`
}

// IntelFeed is one feed the server downloads on a schedule.
type IntelFeed struct {
	// Name identifies the feed; indicators show it as their source.
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	// Format is lines (one indicator per line, # comments), csv or stix
	// (a STIX 2.1 bundle). Default lines.
	Format string `yaml:"format,omitempty"`
	// Type is the indicator type (ip, cidr, domain, url, md5, sha1, sha256,
	// hash, email) or auto to detect each value. Default auto.
	Type string `yaml:"type,omitempty"`
	// Column picks the CSV column, by header name or number from 1.
	Column string `yaml:"column,omitempty"`
	// Interval is how often to download. Default 1h, at least 5m.
	Interval string `yaml:"interval,omitempty"`
	// MaxAge is how long indicators stay after the feed stops updating
	// (downloads fail). Indicators dropped from the feed are removed at the
	// next download. Default 7d.
	MaxAge string `yaml:"max_age,omitempty"`
	// Weight multiplies the risk a match adds: 1 is normal, 2 doubles it.
	Weight      float64  `yaml:"weight,omitempty"`
	Description string   `yaml:"description,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	// Headers are sent with the download, for feeds that need an API key.
	// Values may use ${ENV_VAR} to keep keys out of this file.
	Headers map[string]string `yaml:"headers,omitempty"`
	// Enabled defaults to true; set false to stop using a feed without
	// deleting its settings. Its indicators are removed.
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IsEnabled reports whether a feed is on.
func (f IntelFeed) IsEnabled() bool { return f.Enabled == nil || *f.Enabled }

// defaults fills empty optional feed settings.
func (f *IntelFeed) defaults() {
	if f.Format == "" {
		f.Format = "lines"
	}
	if f.Type == "" {
		f.Type = "auto"
	}
	if f.Interval == "" {
		f.Interval = "1h"
	}
	if f.MaxAge == "" {
		f.MaxAge = "7d"
	}
	if f.Weight == 0 {
		f.Weight = 1
	}
}

var (
	feedNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{1,63}$`)
	feedDurPattern  = regexp.MustCompile(`^(\d+)\s*(m|h|d|w)$`)
	feedFormats     = []string{"lines", "csv", "stix"}
	feedTypes       = []string{"auto", "hash", "ip", "cidr", "domain", "url", "md5", "sha1", "sha256", "email"}
	envRef          = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)
)

// ParseFeedDuration parses 30m, 12h, 7d or 2w.
func ParseFeedDuration(s string) (time.Duration, error) {
	m := feedDurPattern.FindStringSubmatch(strings.ToLower(strings.TrimSpace(s)))
	if m == nil {
		return 0, fmt.Errorf("%q is not a duration; use a number and a unit, like 30m, 1h, 7d or 2w", s)
	}
	n, _ := strconv.Atoi(m[1])
	unit := map[string]time.Duration{"m": time.Minute, "h": time.Hour, "d": 24 * time.Hour, "w": 7 * 24 * time.Hour}[m[2]]
	return time.Duration(n) * unit, nil
}

func (in *Intel) problems() []string {
	var p []string
	seen := map[string]bool{}
	for i := range in.Feeds {
		f := &in.Feeds[i]
		f.defaults()
		at := fmt.Sprintf("intel.feeds[%d]", i)
		if f.Name != "" {
			at = fmt.Sprintf("intel.feeds[%d] (%s)", i, f.Name)
		}
		switch {
		case !feedNamePattern.MatchString(f.Name):
			p = append(p, at+": name must be 2-64 lowercase letters, digits, -, _ or ., for example feodo-tracker")
		case f.Name == "manual":
			p = append(p, at+`: name "manual" is reserved for indicators added by hand`)
		case seen[f.Name]:
			p = append(p, at+": name is used by another feed")
		}
		seen[f.Name] = true
		if u, err := url.Parse(f.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			p = append(p, fmt.Sprintf("%s: url %q must be an http(s) address", at, f.URL))
		}
		if !slices.Contains(feedFormats, f.Format) {
			p = append(p, fmt.Sprintf("%s: format %q must be one of %s", at, f.Format, strings.Join(feedFormats, ", ")))
		}
		if !slices.Contains(feedTypes, f.Type) {
			p = append(p, fmt.Sprintf("%s: type %q must be one of %s", at, f.Type, strings.Join(feedTypes, ", ")))
		}
		if f.Format == "csv" && strings.TrimSpace(f.Column) == "" {
			p = append(p, at+": csv feeds need a column, by header name or number from 1")
		}
		if f.Format != "csv" && f.Column != "" {
			p = append(p, at+": column only applies to format: csv")
		}
		iv, err := ParseFeedDuration(f.Interval)
		if err != nil {
			p = append(p, at+": interval: "+err.Error())
		} else if iv < 5*time.Minute {
			p = append(p, at+": interval must be at least 5m; feeds update far less often")
		}
		if age, err := ParseFeedDuration(f.MaxAge); err != nil {
			p = append(p, at+": max_age: "+err.Error())
		} else if iv > 0 && age < iv {
			p = append(p, at+": max_age must be at least the interval, or indicators expire between downloads")
		}
		if f.Weight < 0 || f.Weight > 10 {
			p = append(p, at+": weight must be above 0 and at most 10 (1 is normal)")
		}
		for k, v := range f.Headers {
			for _, m := range envRef.FindAllStringSubmatch(v, -1) {
				if os.Getenv(m[1]) == "" {
					p = append(p, fmt.Sprintf("%s: headers.%s uses ${%s}, which is not set in the environment", at, k, m[1]))
				}
			}
		}
	}
	return p
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

// Load reads a config file, applies defaults and environment overrides,
// and validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config file %s not found; create one with: signalith init", path)
		}
		return nil, err
	}
	c := Default()
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil && err.Error() != "EOF" {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.path = path
	if err := c.applyEnv(); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// applyEnv lets secrets come from the environment instead of the file.
func (c *Config) applyEnv() error {
	if v := os.Getenv("SIGNALITH_OPENSEARCH_URL"); v != "" {
		c.OpenSearch.URL = v
	}
	if v := os.Getenv("SIGNALITH_OPENSEARCH_USERNAME"); v != "" {
		c.OpenSearch.Username = v
	}
	if v := os.Getenv("SIGNALITH_OPENSEARCH_PASSWORD"); v != "" {
		c.OpenSearch.Password = v
	}
	if v := os.Getenv("SIGNALITH_LISTEN"); v != "" {
		c.Server.Listen = v
	}
	if v := strings.TrimSpace(os.Getenv("SIGNALITH_PUBLIC_URL")); v != "" {
		if _, err := agents.ParseServerURL(v); err != nil {
			return fmt.Errorf("SIGNALITH_PUBLIC_URL %q: %v", v, err)
		}
		c.Server.PublicURL = v
	}
	if v := os.Getenv("SIGNALITH_ADMIN_PASSWORD"); v != "" {
		h, err := HashPassword(v)
		if err != nil {
			return err
		}
		c.Auth.AdminPasswordHash = h
	}
	if v := os.Getenv("SIGNALITH_DETECTIONS_DIR"); v != "" {
		c.Detections.Dir = v
	}
	if v := os.Getenv("SIGNALITH_LOOKUPS_DIR"); v != "" {
		c.Lookups.Dir = v
	}
	if v := os.Getenv("SIGNALITH_DASHBOARDS_DIR"); v != "" {
		c.Dashboards.Dir = v
	}
	if v := os.Getenv("SIGNALITH_ASSISTANT_API_KEY"); v != "" {
		c.Assistant.APIKey = v
	}
	if v := os.Getenv("SIGNALITH_INGEST_TOKEN"); v != "" {
		c.Ingest.Tokens = append(c.Ingest.Tokens, v)
	}
	// "off" turns a syslog listener off, since an empty variable is
	// indistinguishable from an unset one.
	if v := os.Getenv("SIGNALITH_SYSLOG_UDP"); v != "" {
		c.Syslog.UDP = offToEmpty(v)
	}
	if v := os.Getenv("SIGNALITH_SYSLOG_TCP"); v != "" {
		c.Syslog.TCP = offToEmpty(v)
	}
	return nil
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
	if (c.Server.TLSCert == "") != (c.Server.TLSKey == "") {
		p = append(p, "server.tls_cert and server.tls_key must be set together")
	}
	if c.Server.PublicURL == "" {
		c.Server.PublicURL = defaultPublicURL(c.Server)
	} else if _, err := agents.ParseServerURL(c.Server.PublicURL); err != nil {
		p = append(p, fmt.Sprintf("server.public_url %q: %v", c.Server.PublicURL, err))
	}
	if u, err := url.Parse(c.OpenSearch.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		p = append(p, fmt.Sprintf("opensearch.url %q must be http(s)://host:port", c.OpenSearch.URL))
	}
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
	}
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
		if c.Assistant.APIKey == "" {
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
			p = append(p, fmt.Sprintf("assistant.url %q must be http(s)://host[:port][/path]", c.Assistant.URL))
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
	p = append(p, c.Syslog.problems(c.Server)...)
	if len(p) > 0 {
		return &ValidationError{Problems: p}
	}
	return nil
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

// HashPassword returns a bcrypt hash for the admin password.
func HashPassword(pw string) (string, error) {
	if len(pw) < 8 {
		return "", errors.New("password must be at least 8 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword reports whether pw matches the admin hash.
func (c *Config) CheckPassword(user, pw string) bool {
	if user != c.Auth.AdminUser {
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

// Save writes the config with a header comment explaining each section.
func (c *Config) Save(path string) error {
	var doc yaml.Node
	if err := doc.Encode(c); err != nil {
		return err
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
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}
	content := header + string(out)
	return os.WriteFile(path, []byte(content), 0o600)
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
# SIGNALITH_ADMIN_PASSWORD, SIGNALITH_INGEST_TOKEN, SIGNALITH_ASSISTANT_API_KEY.
#
# server.listen      address the UI/API binds to (0.0.0.0:8080 for all interfaces)
# server.public_url  URL agents use to reach this server (or SIGNALITH_PUBLIC_URL)
# auth.session_timeout  sign the web UI out after this long idle (default 12h)
# opensearch.*       where events are stored
# search.*           default time range and result limits
# retention.days     days of events to keep (0 = forever)
# ingest.tokens      tokens agents send; see the Add data page for agent setup
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
# intel.feeds        threat intel feeds to download (none by default), for example:
#                      - name: feodo-tracker
#                        url: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
#                    format: lines, csv (with column:) or stix; see docs/threat-intel.md

`
