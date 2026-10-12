package main

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"gopkg.in/yaml.v3"
)

// The Docker quick start cannot be run in unit tests, so these check that
// its files agree with each other and with what bootstrap-docker makes.

var dockerDir = filepath.Join("..", "..", "deploy", "docker")

type composeService struct {
	User        string            `yaml:"user"`
	Restart     string            `yaml:"restart"`
	NetworkMode string            `yaml:"network_mode"`
	Command     []string          `yaml:"command"`
	Environment []string          `yaml:"environment"`
	Volumes     []string          `yaml:"volumes"`
	Ports       []string          `yaml:"ports"`
	ReadOnly    bool              `yaml:"read_only"`
	Tmpfs       []string          `yaml:"tmpfs"`
	CapDrop     []string          `yaml:"cap_drop"`
	CapAdd      []string          `yaml:"cap_add"`
	SecurityOpt []string          `yaml:"security_opt"`
	Ulimits     map[string]any    `yaml:"ulimits"`
	DependsOn   map[string]dep    `yaml:"depends_on"`
	Healthcheck map[string]any    `yaml:"healthcheck"`
	Build       map[string]string `yaml:"build"`
	PullPolicy  string            `yaml:"pull_policy"`
}

type dep struct {
	Condition string `yaml:"condition"`
}

func readCompose(t *testing.T) (map[string]composeService, map[string]any, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dockerDir, "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Services map[string]composeService `yaml:"services"`
		Volumes  map[string]any            `yaml:"volumes"`
	}
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("docker-compose.yml: %v", err)
	}
	return f.Services, f.Volumes, string(raw)
}

func flagValue(args []string, name string) string {
	if i := slices.Index(args, name); i >= 0 && i+1 < len(args) {
		return args[i+1]
	}
	return ""
}

func TestDockerCompose(t *testing.T) {
	svc, vols, raw := readCompose(t)
	for _, name := range []string{"opensearch-data", "opensearch-certs", "signalith-data", "signalith-secrets"} {
		if _, ok := vols[name]; !ok {
			t.Errorf("volume %s is not declared", name)
		}
	}
	for _, s := range []string{"change-me", "change-this", "DISABLE_SECURITY_PLUGIN", "OPENSEARCH_INITIAL_ADMIN_PASSWORD", "memory_lock"} {
		if strings.Contains(raw, s) {
			t.Errorf("docker-compose.yml contains %q", s)
		}
	}

	// setup writes into the two volumes the others read.
	setup := svc["setup"]
	osDir, sigDir := flagValue(setup.Command, "-opensearch-dir"), flagValue(setup.Command, "-signalith-dir")
	if setup.Command[0] != "bootstrap-docker" || osDir == "" || sigDir == "" {
		t.Fatalf("setup command %v", setup.Command)
	}
	if !slices.Contains(setup.Volumes, "opensearch-certs:"+osDir) || !slices.Contains(setup.Volumes, "signalith-secrets:"+sigDir) {
		t.Errorf("setup volumes %v", setup.Volumes)
	}
	if setup.User != "0:0" || setup.Restart != "no" || setup.NetworkMode != "none" || setup.PullPolicy != "build" {
		t.Errorf("setup: user %q restart %q network %q pull %q", setup.User, setup.Restart, setup.NetworkMode, setup.PullPolicy)
	}
	// bootstrap-docker needs to change owners (CHOWN), write in folders
	// it gave away (DAC_OVERRIDE) and set modes on files it gave away
	// (FOWNER), and nothing else.
	if !slices.Equal(setup.CapDrop, []string{"ALL"}) || !slices.Equal(setup.CapAdd, []string{"CHOWN", "DAC_OVERRIDE", "FOWNER"}) {
		t.Errorf("setup capabilities: drop %v add %v", setup.CapDrop, setup.CapAdd)
	}
	if len(setup.Build) == 0 || !maps.Equal(setup.Build, svc["signalith"].Build) {
		t.Errorf("setup builds %v, signalith %v", setup.Build, svc["signalith"].Build)
	}

	// OpenSearch: our settings and security files, the certificates
	// read-only, demo setup off, nothing published.
	o := svc["opensearch"]
	if o.DependsOn["setup"].Condition != "service_completed_successfully" {
		t.Errorf("opensearch depends on %v", o.DependsOn)
	}
	if !slices.Contains(o.Environment, "DISABLE_INSTALL_DEMO_CONFIG=true") || !slices.Contains(o.Environment, "discovery.type=single-node") ||
		!slices.Contains(o.Environment, "DISABLE_PERFORMANCE_ANALYZER_AGENT_CLI=true") {
		t.Errorf("opensearch environment %v", o.Environment)
	}
	if len(o.Ports) != 0 {
		t.Errorf("opensearch publishes %v", o.Ports)
	}
	want := []string{
		"opensearch-data:/usr/share/opensearch/data",
		"opensearch-certs:/usr/share/opensearch/config/certs:ro",
		"./opensearch/opensearch.yml:/usr/share/opensearch/config/opensearch.yml:ro",
	}
	for name := range ospki.SecurityFiles() {
		want = append(want, "./opensearch/security/"+name+":/usr/share/opensearch/config/opensearch-security/"+name+":ro")
	}
	for _, v := range want {
		if !slices.Contains(o.Volumes, v) {
			t.Errorf("opensearch lacks volume %s", v)
		}
	}
	for _, v := range o.Volumes {
		if src, _, _ := strings.Cut(v, ":"); strings.HasPrefix(src, "./") {
			if _, err := os.Stat(filepath.Join(dockerDir, src)); err != nil {
				t.Errorf("opensearch mounts %s: %v", src, err)
			}
		}
	}
	health := strings.Join(anyStrings(o.Healthcheck["test"]), " ")
	for _, f := range []string{ospki.RootCAFile, ospki.AdminCertFile, ospki.AdminKeyFile} {
		if !strings.Contains(health, "/usr/share/opensearch/config/certs/"+f) {
			t.Errorf("health check does not use %s: %s", f, health)
		}
	}
	if !strings.Contains(health, "https://localhost:9200/") {
		t.Errorf("health check: %s", health)
	}

	// Signalith: secrets only as files from setup, and hardened.
	s := svc["signalith"]
	if s.DependsOn["setup"].Condition != "service_completed_successfully" || s.DependsOn["opensearch"].Condition != "service_healthy" {
		t.Errorf("signalith depends on %v", s.DependsOn)
	}
	secretsAt := ""
	for _, v := range s.Volumes {
		if after, ok := strings.CutPrefix(v, "signalith-secrets:"); ok {
			secretsAt = strings.TrimSuffix(after, ":ro")
			if !strings.HasSuffix(v, ":ro") {
				t.Errorf("secrets are writable: %s", v)
			}
		}
	}
	for _, v := range []string{"SIGNALITH_ADMIN_PASSWORD_FILE=" + secretsAt + "/" + initialPasswordFile, "SIGNALITH_INGEST_TOKEN_FILE=" + secretsAt + "/" + ingestTokenFile} {
		if !slices.Contains(s.Environment, v) {
			t.Errorf("signalith environment lacks %s: %v", v, s.Environment)
		}
	}
	for _, e := range s.Environment {
		name, _, _ := strings.Cut(e, "=")
		if (strings.Contains(name, "PASSWORD") || strings.Contains(name, "TOKEN") || strings.Contains(name, "KEY")) && !strings.HasSuffix(name, "_FILE") {
			t.Errorf("a secret in the environment: %s", name)
		}
	}
	for _, v := range []string{"./signalith.yaml:/etc/signalith/signalith.yaml:ro", "signalith-data:/var/lib/signalith"} {
		if !slices.Contains(s.Volumes, v) {
			t.Errorf("signalith lacks volume %s", v)
		}
	}
	if !s.ReadOnly || !slices.Contains(s.Tmpfs, "/tmp") || !slices.Equal(s.CapDrop, []string{"ALL"}) || len(s.CapAdd) != 0 ||
		!slices.Contains(s.SecurityOpt, "no-new-privileges:true") || s.Ulimits["core"] != 0 {
		t.Errorf("signalith hardening: read_only %v tmpfs %v cap_drop %v cap_add %v security_opt %v ulimits %v",
			s.ReadOnly, s.Tmpfs, s.CapDrop, s.CapAdd, s.SecurityOpt, s.Ulimits)
	}
	for _, p := range []string{"8080:8080", "514:5514/udp", "514:5514/tcp", "6514:6514"} {
		if !slices.Contains(s.Ports, p) {
			t.Errorf("signalith does not publish %s", p)
		}
	}
}

// TestDockerConfigLoads loads the Docker quick start's signalith.yaml the
// way the container does, with the files bootstrap-docker makes.
func TestDockerConfigLoads(t *testing.T) {
	svc, _, _ := readCompose(t)
	root := t.TempDir()
	osDir, sigDir, data := filepath.Join(root, "certs"), filepath.Join(root, "secrets"), filepath.Join(root, "data")
	bootstrap(t, osDir, sigDir)
	raw, err := os.ReadFile(filepath.Join(dockerDir, "signalith.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "change-me") || strings.Contains(string(raw), "password:") {
		t.Error("signalith.yaml holds a secret")
	}
	// The container's paths, here in temporary folders.
	secretsAt := "/run/signalith-secrets"
	for _, v := range svc["signalith"].Volumes {
		if after, ok := strings.CutPrefix(v, "signalith-secrets:"); ok {
			secretsAt = strings.TrimSuffix(after, ":ro")
		}
	}
	for _, f := range []string{ospki.ClientCAFile, ospki.ClientCertFile, ospki.ClientKeyFile} {
		if !strings.Contains(string(raw), secretsAt+"/"+f) {
			t.Errorf("signalith.yaml does not use %s/%s", secretsAt, f)
		}
	}
	text := strings.ReplaceAll(string(raw), secretsAt, filepath.ToSlash(sigDir))
	text = strings.ReplaceAll(text, "/var/lib/signalith", filepath.ToSlash(data))
	path := filepath.Join(root, "signalith.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, e := range svc["signalith"].Environment {
		k, v, _ := strings.Cut(e, "=")
		env[k] = strings.Replace(v, secretsAt, sigDir, 1)
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	t.Setenv("SIGNALITH_STATE_DIR", data)
	t.Setenv("SIGNALITH_PUBLIC_URL", "")
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	pw, _ := os.ReadFile(filepath.Join(sigDir, initialPasswordFile))
	token, _ := os.ReadFile(filepath.Join(sigDir, ingestTokenFile))
	if !c.CheckPassword("admin", strings.TrimSpace(string(pw))) || !slices.Equal(c.Ingest.Tokens, []string{strings.TrimSpace(string(token))}) {
		t.Errorf("secrets not taken from the files: tokens %v", c.Ingest.Tokens)
	}
	if c.Server.TLSMode() != config.TLSAuto || !c.Server.PlaintextIngest() || c.Server.PublicURL != "https://localhost:8080" {
		t.Errorf("server: mode %s plaintext %v url %s", c.Server.TLSMode(), c.Server.PlaintextIngest(), c.Server.PublicURL)
	}
	if c.OpenSearch.URL != "https://opensearch:9200" || c.OpenSearch.Username != "" || c.Syslog.TLS != "0.0.0.0:6514" {
		t.Errorf("opensearch %s user %q syslog.tls %q", c.OpenSearch.URL, c.OpenSearch.Username, c.Syslog.TLS)
	}
	if w := c.Warnings(); len(w) != 0 {
		t.Errorf("warnings: %v", w)
	}
}

func anyStrings(v any) []string {
	var out []string
	if list, ok := v.([]any); ok {
		for _, x := range list {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
