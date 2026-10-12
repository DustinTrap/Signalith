package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDetectionsCRUD(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "GET", "/api/detections", "", true)
	if code != 200 || len(body["detections"].([]any)) < 15 {
		t.Fatalf("list = %d %v", code, body)
	}

	code, body = do(t, ts, "GET", "/api/detections/auth-brute-force", "", true)
	if code != 200 || body["source"] != "builtin" || body["enabled"] != true {
		t.Fatalf("get = %d %v", code, body)
	}

	// Disabling a built-in saves an override.
	code, body = do(t, ts, "PUT", "/api/detections/auth-brute-force",
		`{"title":"Brute force from $src$","query":"datamodel=Authentication action=failure | stats count by src | where count > 20","severity":"high","enabled":false,"mitre":["T1110"]}`, true)
	if code != 200 || body["source"] != "override" || body["enabled"] != false || body["schedule"] != "5m" {
		t.Fatalf("put = %d %v", code, body)
	}
	code, body = do(t, ts, "DELETE", "/api/detections/auth-brute-force", "", true)
	if code != 200 || body["reverted"] == nil {
		t.Fatalf("revert = %d %v", code, body)
	}

	// Validation returns every problem.
	code, body = do(t, ts, "POST", "/api/detections", `{"id":"x","query":"| bad","severity":"nope"}`, true)
	if code != 400 || len(body["problems"].([]any)) < 3 {
		t.Fatalf("invalid create = %d %v", code, body)
	}
	code, _ = do(t, ts, "POST", "/api/detections", `{"id":"my-rule","title":"Mine","query":"user=bob","mitre":["T1078"]}`, true)
	if code != 201 {
		t.Fatalf("create = %d", code)
	}
	code, _ = do(t, ts, "POST", "/api/detections", `{"id":"my-rule","title":"Mine","query":"user=bob"}`, true)
	if code != 409 {
		t.Errorf("duplicate create = %d", code)
	}
	code, body = do(t, ts, "DELETE", "/api/detections/my-rule", "", true)
	if code != 200 || body["deleted"] != true {
		t.Errorf("delete = %d %v", code, body)
	}
	code, _ = do(t, ts, "GET", "/api/detections/my-rule", "", true)
	if code != 404 {
		t.Errorf("get deleted = %d", code)
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/detections/auth-brute-force/yaml", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	y, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(y), "id: auth-brute-force") || !strings.Contains(resp.Header.Get("Content-Type"), "yaml") {
		t.Errorf("yaml export = %s", y)
	}
}

func TestDetectionTestAndRunRaiseFindings(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/detections/test",
		`{"title":"Failures from $src$","query":"datamodel=Authentication action=failure | stats count by src | where count >= 10","lookback":"1h"}`, true)
	if code != 200 {
		t.Fatalf("test = %d %v", code, body)
	}
	titles := body["titles"].([]any)
	if len(titles) != 1 || titles[0] != "Failures from 10.0.0.9" {
		t.Errorf("titles = %v", titles)
	}
	code, _ = do(t, ts, "POST", "/api/detections/test", `{"query":"user=x earliest=-1h"}`, true)
	if code != 400 {
		t.Errorf("earliest in test query = %d", code)
	}

	code, body = do(t, ts, "POST", "/api/detections/auth-brute-force/run", "", true)
	if code != 200 {
		t.Fatalf("run = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/findings?status=new&since=-1h", "", true)
	if code != 200 {
		t.Fatalf("findings = %d %v", code, body)
	}
	list := body["findings"].([]any)
	if len(list) == 0 {
		t.Fatal("run raised no findings")
	}
	id := list[0].(map[string]any)["id"].(string)

	code, body = do(t, ts, "PATCH", "/api/findings/"+id, `{"status":"in_progress","owner":"sam","comment":"looking"}`, true)
	if code != 200 || body["status"] != "in_progress" || len(body["history"].([]any)) != 2 {
		t.Fatalf("patch = %d %v", code, body)
	}
	if code, _ := do(t, ts, "PATCH", "/api/findings/"+id, `{"status":"done"}`, true); code != 400 {
		t.Errorf("bad status = %d", code)
	}
	code, body = do(t, ts, "GET", "/api/findings/"+id, "", true)
	if code != 200 || body["detection"] == nil || body["finding"].(map[string]any)["comments"] == nil {
		t.Errorf("get = %d %v", code, body)
	}
	code, body = do(t, ts, "POST", "/api/findings/bulk", fmt.Sprintf(`{"ids":[%q,"missing"],"update":{"status":"closed","disposition":"false_positive"}}`, id), true)
	if code != 200 || body["updated"] != float64(1) || body["failed"].(map[string]any)["missing"] == nil {
		t.Errorf("bulk = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/findings/summary", "", true)
	if code != 200 || body["by_status"].(map[string]any)["closed"] != float64(1) {
		t.Errorf("summary = %d %v", code, body)
	}
	if code, _ := do(t, ts, "GET", "/api/findings/nope", "", true); code != 404 {
		t.Errorf("missing finding = %d", code)
	}
}

func TestManualFindingAndCoverage(t *testing.T) {
	ts, _ := newTestServer(t)
	code, body := do(t, ts, "POST", "/api/findings", `{"title":"Odd logon","severity":"low","query":"user=bob","result":{"user":"bob","count":3}}`, true)
	if code != 201 || body["detection_id"] != "manual" || body["entities"].(map[string]any)["user"] != "bob" {
		t.Fatalf("create = %d %v", code, body)
	}
	if code, _ := do(t, ts, "POST", "/api/findings", `{"title":""}`, true); code != 400 {
		t.Errorf("empty title = %d", code)
	}
	code, body = do(t, ts, "GET", "/api/coverage", "", true)
	if code != 200 {
		t.Fatal(code)
	}
	sum := body["summary"].(map[string]any)
	if sum["enabled"].(float64) < 10 || len(body["tactics"].([]any)) < 12 {
		t.Errorf("coverage summary = %v", sum)
	}
}

func TestSigmaEndpoint(t *testing.T) {
	ts, _ := newTestServer(t)
	rule := "title: Whoami\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    Image|endswith: '\\\\whoami.exe'\n  condition: sel\nlevel: low\ntags: [attack.t1033]\n"
	req, _ := http.NewRequest("POST", ts.URL+"/api/detections/sigma", strings.NewReader(rule))
	req.SetBasicAuth("admin", "s3cret-pass")
	req.Header.Set("Content-Type", "application/yaml")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `process_name=whoami.exe`) {
		t.Errorf("sigma = %d %s", resp.StatusCode, b)
	}
	code, body := do(t, ts, "POST", "/api/detections/sigma", "title: x\n", true)
	if code != 400 || !strings.Contains(body["error"].(string), "detection") {
		t.Errorf("bad sigma = %d %v", code, body)
	}
}
