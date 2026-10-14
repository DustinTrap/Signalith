package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/clustercfg"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// memSettings is a SettingsStore that keeps the shared layer of one
// server in memory, as clustercfg.Save would in OpenSearch.
type memSettings struct {
	mu       sync.Mutex
	sh       *config.Shared
	writable error
}

func newMemSettings() *memSettings {
	return &memSettings{sh: (&config.Shared{Self: "siem-a", Server: map[string]*config.PageEntry{}}).Clone()}
}

func (m *memSettings) Shared() bool { return true }
func (m *memSettings) Writable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.writable
}
func (m *memSettings) Self() string { return "n_a" }
func (m *memSettings) ETag() string { return `"1"` }

func (m *memSettings) Layer(context.Context, string) (*config.Shared, *shared.NodeCfg, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sh.Clone(), nil, nil
}

func (m *memSettings) Save(_ context.Context, _, _ string, _ *config.Shared, res *config.SharedEditResult, _ map[string]int64) (map[string]int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	revs := map[string]int64{}
	for _, k := range res.Touched {
		if v, ok := res.Shared.Cluster[k]; ok {
			v.Rev = m.sh.Cluster[k].Rev + 1
			m.sh.Cluster[k] = v
			revs[k] = v.Rev
		} else {
			delete(m.sh.Cluster, k)
		}
		if e, ok := res.Shared.Server[k]; ok && e != nil {
			m.sh.Server[k] = e
		} else if res.Scope == config.ScopeServer {
			delete(m.sh.Server, k)
		}
	}
	return revs, nil
}

func (m *memSettings) Check(context.Context, string, string, clustercfg.SettingsCheckArgs) (*clustercfg.SettingsCheckResult, bool, error) {
	return nil, false, nil
}

func (m *memSettings) Restart(context.Context, string, []string, bool) (*shared.Request, error) {
	return nil, errors.New("no other servers")
}

// W28: with the settings shared, saving trusted proxies that leave out
// the one the request came through is still refused, and listing it
// saves the shared value.
func TestSharedTrustedProxiesLockout(t *testing.T) {
	mem := newMemSettings()
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = mem })
	plain := httptest.NewServer(srv.PlainHandler(srv.Handler()))
	defer plain.Close()
	viaProxy := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, plain.URL+path, strings.NewReader(body))
		req.SetBasicAuth("admin", "s3cret-pass")
		req.Host = "siem.lan"
		req.Header.Set("X-Forwarded-Proto", "https")
		resp, err := noRedirect.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	code, view := viaProxy("GET", "/api/settings", "")
	if code != http.StatusOK || view["shared"] != true {
		t.Fatalf("the shared page: %d %v", code, view["shared"])
	}
	if f := field(t, view, "server.trusted_proxies"); f["scope"] != "cluster" {
		t.Errorf("trusted proxies %v", f)
	}
	code, out := viaProxy("PUT", "/api/settings", `{"values":{"server.trusted_proxies":["10.0.0.9"]}}`)
	fields, _ := out["fields"].(map[string]any)
	if msg, _ := fields["server.trusted_proxies"].(string); code != http.StatusBadRequest || !strings.Contains(msg, "through the reverse proxy at 127.0.0.1") {
		t.Fatalf("a list without the proxy: %d %v", code, out)
	}
	if _, ok := mem.sh.Cluster["server.trusted_proxies"]; ok {
		t.Fatal("the refused list was saved")
	}
	code, out = viaProxy("PUT", "/api/settings", `{"values":{"server.trusted_proxies":["127.0.0.1","10.0.0.9"]}}`)
	if code != http.StatusOK || !slices.Contains(toList(out["applied"]), "server.trusted_proxies") {
		t.Fatalf("listing the proxy: %d %v", code, out)
	}
	if v := mem.sh.Cluster["server.trusted_proxies"]; string(v.Value) != `["127.0.0.1","10.0.0.9"]` || v.Rev != 1 {
		t.Errorf("shared value %s rev %d", v.Value, v.Rev)
	}
	_ = ts
}

// W25, the page's part: while the shared settings cannot be changed
// (OpenSearch refuses writes), a change of a shared setting or of this
// server's own is answered 503 and nothing is saved; one of the settings
// this server needs to reach OpenSearch is saved in its settings.yaml.
func TestSharedSettingsWhileDegraded(t *testing.T) {
	mem := newMemSettings()
	mem.writable = &shared.PausedError{Why: "OpenSearch refuses writes"}
	ts, srv, _ := newSettingsServer(t, "", func(s *Server) { s.Settings = mem })
	code, view := do(t, ts, "GET", "/api/settings", "", true)
	if code != http.StatusOK || view["writable"] != false || !strings.Contains(view["paused"].(string), "OpenSearch refuses writes") {
		t.Fatalf("page: %d writable %v paused %v", code, view["writable"], view["paused"])
	}
	for _, body := range []string{`{"values":{"auth.session_timeout":"2h"}}`, `{"values":{"syslog.udp":"127.0.0.1:5514"}}`} {
		if code, out := do(t, ts, "PUT", "/api/settings", body, true); code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	if len(mem.sh.Cluster) != 0 || len(mem.sh.Server) != 0 {
		t.Errorf("saved while paused: %v %v", mem.sh.Cluster, mem.sh.Server)
	}
	code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"opensearch.username":"siem"}}`, true)
	if code != http.StatusOK || !slices.Contains(toList(out["saved"]), "opensearch.username") {
		t.Fatalf("a connection setting: %d %v", code, out)
	}
	page, err := config.ReadPageSettings(srv.Config.SettingsFile())
	if err != nil || page.Settings["opensearch.username"] == nil {
		t.Fatalf("settings.yaml: %v %v", page, err)
	}
}

// toList turns a JSON list into strings.
func toList(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}
