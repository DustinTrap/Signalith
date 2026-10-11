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
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	Detections Detections `yaml:"detections"`

	// path is where the file was loaded from.
	path string
}

// Server controls the web UI and API listener.
type Server struct {
	// Listen is host:port. The default binds to localhost only; use
	// 0.0.0.0:8080 to accept agents from other machines.
	Listen string `yaml:"listen"`
	// PublicURL is the address agents and browsers use to reach this
	// server. It goes into the agent configs Signalith generates.
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
}

// Ingest controls agent access.
type Ingest struct {
	// Tokens agents present in the Authorization header. Rotate by adding a
	// new token, updating agents, then removing the old one.
	Tokens []string `yaml:"tokens"`
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

// DetectionsDir returns the absolute detections folder.
func (c *Config) DetectionsDir() string {
	d := c.Detections.Dir
	if d == "" || filepath.IsAbs(d) || c.path == "" {
		return d
	}
	return filepath.Join(filepath.Dir(c.path), d)
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
	if v := os.Getenv("SIGNALITH_INGEST_TOKEN"); v != "" {
		c.Ingest.Tokens = append(c.Ingest.Tokens, v)
	}
	return nil
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
	} else if u, err := url.Parse(c.Server.PublicURL); err != nil || u.Host == "" {
		p = append(p, fmt.Sprintf("server.public_url %q must be a full URL such as https://siem.example.com:8080", c.Server.PublicURL))
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
	if c.Detections.Dir == "" {
		p = append(p, "detections.dir is required, for example: detections")
	}
	if c.Detections.MaxFindingsPerRun < 1 || c.Detections.MaxFindingsPerRun > 10000 {
		p = append(p, "detections.max_findings_per_run must be between 1 and 10000")
	}
	for i, t := range c.Ingest.Tokens {
		if len(t) < 16 {
			p = append(p, fmt.Sprintf("ingest.tokens[%d] is shorter than 16 characters", i))
		}
	}
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
	if host == "" || host == "0.0.0.0" || host == "::" {
		if h, err := os.Hostname(); err == nil {
			host = h
		} else {
			host = "localhost"
		}
	}
	scheme := "http"
	if s.TLSCert != "" {
		scheme = "https"
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
	out, err := yaml.Marshal(c)
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

const header = `# Signalith configuration.
# Run "signalith validate" after editing. Secrets can come from environment
# variables instead of this file: SIGNALITH_OPENSEARCH_PASSWORD,
# SIGNALITH_ADMIN_PASSWORD, SIGNALITH_INGEST_TOKEN.
#
# server.listen      address the UI/API binds to (0.0.0.0:8080 for all interfaces)
# server.public_url  URL agents use to reach this server
# opensearch.*       where events are stored
# search.*           default time range and result limits
# retention.days     days of events to keep (0 = forever)
# ingest.tokens      tokens agents send; see the Add data page for agent setup
# detections.dir     folder for custom detections (relative to this file)

`
