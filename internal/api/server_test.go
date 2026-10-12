package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

type fakeOS struct {
	bulk []store.IndexedDoc
}

func (f *fakeOS) Search(_ context.Context, index string, body map[string]any) (map[string]any, error) {
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(`{"hits":{"total":{"value":2}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"10.0.0.9"},"doc_count":25},{"key":{"k0":"10.0.0.7"},"doc_count":3}]}}}`))
	dec.UseNumber()
	_ = dec.Decode(&out)
	return out, nil
}
func (f *fakeOS) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	f.bulk = append(f.bulk, docs...)
	return nil, nil
}
func (f *fakeOS) Health(context.Context) (string, error) { return "green", nil }
func (f *fakeOS) Mapping(context.Context, string) (map[string]string, error) {
	return map[string]string{"user": "keyword", "custom_score": "long"}, nil
}

func newTestServer(t *testing.T) (*httptest.Server, *fakeOS) {
	t.Helper()
	cfg := config.Default()
	h, _ := config.HashPassword("s3cret-pass")
	cfg.Auth.AdminPasswordHash = h
	cfg.Ingest.Tokens = []string{"tok-0123456789abcdef"}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	fos := &fakeOS{}
	lib, _, err := detect.NewLibrary(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng := &search.Engine{Store: fos}
	fs := findings.NewMemory()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{
		Config:     cfg,
		Engine:     eng,
		Pipeline:   &ingest.Pipeline{Store: fos},
		Backend:    fos,
		Detections: lib,
		Scheduler:  &detect.Scheduler{Library: lib, Engine: eng, Findings: fs, Log: logger},
		Findings:   fs,
		Log:        logger,
		Version:    "test",
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return ts, fos
}

func do(t *testing.T, ts *httptest.Server, method, path, body string, auth bool) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	if auth {
		req.SetBasicAuth("admin", "s3cret-pass")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) > 0 && raw[0] == '{' {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func TestAuthRequired(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "GET", "/api/health", "", false); code != 401 {
		t.Errorf("unauthenticated health = %d", code)
	}
	if code, body := do(t, ts, "GET", "/api/health", "", true); code != 200 || body["opensearch"].(map[string]any)["status"] != "green" {
		t.Errorf("health = %d %v", code, body)
	}
}

func TestSearchAndErrors(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/search", `{"query":"datamodel=Authentication action=failure | stats count by src | where count > 10","earliest":"-24h"}`, true)
	if code != 200 {
		t.Fatalf("search = %d %v", code, body)
	}
	rows := body["rows"].([]any)
	if len(rows) != 1 || rows[0].(map[string]any)["src"] != "10.0.0.9" {
		t.Errorf("rows = %v", rows)
	}
	code, body = do(t, ts, "POST", "/api/search", `{"query":"a=1 | stats avg"}`, true)
	if code != 400 || body["pos"] == nil {
		t.Errorf("parse error = %d %v", code, body)
	}
}

func TestBuildParseExplain(t *testing.T) {
	ts, _ := newTestServer(t)
	spec, _ := json.Marshal(query.Spec{Datamodel: "Authentication", Mode: "stats", AggFunc: "count", By: []string{"user"}, Filters: []query.Filter{{Field: "action", Op: "=", Value: "failure"}}})
	_, body := do(t, ts, "POST", "/api/build", string(spec), true)
	q := body["query"].(string)
	if q != "datamodel=Authentication action=failure\n| stats count by user" {
		t.Errorf("built %q", q)
	}
	b, _ := json.Marshal(map[string]string{"query": q})
	_, body = do(t, ts, "POST", "/api/parse", string(b), true)
	if body["builder_ok"] != true {
		t.Errorf("parse = %v", body)
	}
	_, body = do(t, ts, "POST", "/api/explain", `{"query":"datamodel=Authentication action=failure earliest=-24h | stats dc(user) as users by src | sort -users"}`, true)
	steps := body["steps"].([]any)
	if len(steps) != 3 || !strings.Contains(steps[0].(string), "24 hours ago") || !strings.Contains(steps[1].(string), "distinct user") {
		t.Errorf("steps = %v", steps)
	}
	if body["index"] != "signalith-authentication-*" {
		t.Errorf("index = %v", body["index"])
	}
}

func TestIngestNeedsToken(t *testing.T) {
	ts, fos := newTestServer(t)
	line := `[{"log":"Oct 11 09:15:02 web1 sshd[811]: Failed password for bob from 192.0.2.4 port 1 ssh2"}]`
	if code, _ := do(t, ts, "POST", "/api/ingest", line, false); code != 401 {
		t.Errorf("ingest without token = %d", code)
	}
	req, _ := http.NewRequest("POST", ts.URL+"/api/ingest", strings.NewReader(line))
	req.Header.Set("Authorization", "Bearer tok-0123456789abcdef")
	req.Header.Set("X-Signalith-Tag", "linux.auth")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("ingest = %v %v", resp.StatusCode, err)
	}
	if len(fos.bulk) != 1 || fos.bulk[0].Doc["user"] != "bob" {
		t.Errorf("bulk = %v", fos.bulk)
	}
}

func TestDecodeRecordsFormats(t *testing.T) {
	for _, body := range []string{`[{"a":1},{"a":2}]`, "{\"a\":1}\n{\"a\":2}\n"} {
		recs, err := decodeRecords([]byte(body))
		if err != nil || len(recs) != 2 {
			t.Errorf("%q -> %v %v", body, recs, err)
		}
	}
}

func TestFieldsMergeDiscovered(t *testing.T) {
	ts, _ := newTestServer(t)
	req, _ := http.NewRequest("GET", ts.URL+"/api/fields?datamodel=Authentication", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, _ := http.DefaultClient.Do(req)
	var fields []map[string]any
	json.NewDecoder(resp.Body).Decode(&fields)
	var sawCustom, userIndexed bool
	for _, f := range fields {
		if f["name"] == "custom_score" && f["type"] == "number" {
			sawCustom = true
		}
		if f["name"] == "user" && f["indexed"] == true {
			userIndexed = true
		}
	}
	if !sawCustom || !userIndexed || fields[0]["name"] != "_time" {
		t.Errorf("fields = %v", fields)
	}
}

func TestAgentConfig(t *testing.T) {
	ts, _ := newTestServer(t)
	_, body := do(t, ts, "GET", "/api/agents/config?os=windows&sysmon=true", "", true)
	cfg := body["config"].(string)
	for _, want := range []string{"winevtlog", "Microsoft-Windows-Sysmon/Operational", "Bearer tok-0123456789abcdef", "Port             8080", "Header_Tag"} {
		if !strings.Contains(cfg, want) {
			t.Errorf("windows config missing %q:\n%s", want, cfg)
		}
	}
}
