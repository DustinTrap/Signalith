package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestDashboardsAPI(t *testing.T) {
	ts, _ := newTestServer(t)

	code, out := do(t, ts, "GET", "/api/dashboards", "", true)
	list := out["dashboards"].([]any)
	if code != 200 || len(list) != 1 || list[0].(map[string]any)["id"] != "posture" {
		t.Fatalf("empty list = %d %v", code, out)
	}

	// Create without an id: one is made from the title.
	code, out = do(t, ts, "POST", "/api/dashboards", `{"title":"Auth watch","time_range":"7d","panels":[
		{"title":"Failures by source","query":"datamodel=Authentication action=failure | stats count by src"},
		{"title":"Failures","query":"datamodel=Authentication action=failure | stats count","compare":true}]}`, true)
	if code != 201 || out["id"] != "auth-watch" {
		t.Fatalf("create = %d %v", code, out)
	}
	panels := out["panels"].([]any)
	if panels[0].(map[string]any)["viz"] != "bar" || panels[1].(map[string]any)["viz"] != "single" {
		t.Errorf("suggested vizs = %v", panels)
	}
	if code, _ := do(t, ts, "POST", "/api/dashboards", `{"id":"auth-watch","title":"Again"}`, true); code != 409 {
		t.Errorf("duplicate = %d", code)
	}
	code, out = do(t, ts, "POST", "/api/dashboards", `{"title":"","panels":[{"title":"x","query":"a=1 | stats avg","viz":"pie"}]}`, true)
	if code != 400 || len(out["problems"].([]any)) != 3 {
		t.Errorf("invalid = %d %v", code, out)
	}

	code, out = do(t, ts, "GET", "/api/dashboards/auth-watch", "", true)
	if code != 200 || out["title"] != "Auth watch" || out["time_range"] != "7d" {
		t.Errorf("get = %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/dashboards/nope", "", true); code != 404 {
		t.Errorf("missing = %d", code)
	}

	// Add a panel from the Search page, then reorder and save.
	code, out = do(t, ts, "POST", "/api/dashboards/auth-watch/panels", `{"title":"Broken","query":"* | timechart span=soon count"}`, true)
	if code != 200 || len(out["panels"].([]any)) != 3 {
		t.Fatalf("add panel = %d %v", code, out)
	}
	code, out = do(t, ts, "PUT", "/api/dashboards/auth-watch", `{"title":"Auth watch","time_range":"24h","panels":[
		{"title":"Failures","query":"datamodel=Authentication action=failure | stats count","viz":"single","compare":true},
		{"title":"Broken","query":"* | timechart span=soon count","viz":"line"},
		{"title":"Failures by source","query":"datamodel=Authentication action=failure | stats count by src","viz":"bar"}]}`, true)
	if code != 200 || out["panels"].([]any)[0].(map[string]any)["title"] != "Failures" {
		t.Fatalf("put = %d %v", code, out)
	}
	if code, _ := do(t, ts, "PUT", "/api/dashboards/auth-watch", `{"id":"other","title":"x"}`, true); code != 400 {
		t.Errorf("id mismatch = %d", code)
	}

	// Run: the broken panel reports its error and the others still work.
	code, out = do(t, ts, "POST", "/api/dashboards/auth-watch/run", `{"range":"4h"}`, true)
	if code != 200 || out["range"] != "4h" {
		t.Fatalf("run = %d %v", code, out)
	}
	res := out["panels"].([]any)
	single, broken, bar := res[0].(map[string]any), res[1].(map[string]any), res[2].(map[string]any)
	if single["error"] != nil || fmt.Sprint(single["value"]) != "2" || single["previous"] == nil || single["earliest"] != "-4h" {
		t.Errorf("single = %v", single)
	}
	if !strings.Contains(fmt.Sprint(broken["error"]), "span") || broken["result"] != nil {
		t.Errorf("broken = %v", broken)
	}
	if bar["error"] != nil || len(bar["result"].(map[string]any)["rows"].([]any)) != 2 {
		t.Errorf("bar = %v", bar)
	}
	code, out = do(t, ts, "POST", "/api/dashboards/auth-watch/run", "", true)
	if code != 200 || out["range"] != "24h" {
		t.Errorf("default range = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/dashboards/auth-watch/run", `{"range":"soon"}`, true); code != 400 {
		t.Errorf("bad range = %d", code)
	}

	// Preview an unsaved panel.
	code, out = do(t, ts, "POST", "/api/panels/run", `{"range":"24h","panel":{"title":"p","query":"datamodel=Authentication | stats count by src"}}`, true)
	if code != 200 || out["panel"].(map[string]any)["viz"] != "bar" || out["result"].(map[string]any)["error"] != nil {
		t.Errorf("preview = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/panels/run", `{"panel":{}}`, true); code != 400 {
		t.Errorf("empty preview = %d", code)
	}

	// YAML download.
	req, _ := http.NewRequest("GET", ts.URL+"/api/dashboards/auth-watch/yaml", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.HasPrefix(string(b), "id: auth-watch\ntitle: Auth watch\n") || !strings.Contains(resp.Header.Get("Content-Disposition"), "auth-watch.yaml") {
		t.Errorf("yaml = %s", b)
	}

	code, out = do(t, ts, "GET", "/api/dashboards", "", true)
	if code != 200 || len(out["dashboards"].([]any)) != 2 {
		t.Errorf("list = %v", out)
	}
	if code, _ := do(t, ts, "DELETE", "/api/dashboards/posture", "", true); code != 400 {
		t.Errorf("delete posture = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/dashboards/auth-watch", "", true); code != 204 {
		t.Errorf("delete = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/dashboards/auth-watch", "", true); code != 404 {
		t.Errorf("delete again = %d", code)
	}
}

func TestDashboardsOff(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.Dashboards = nil })
	code, out := do(t, ts, "GET", "/api/dashboards", "", true)
	if code != 200 || len(out["dashboards"].([]any)) != 1 || out["error"] == nil {
		t.Errorf("list = %d %v", code, out)
	}
	if code, _ := do(t, ts, "POST", "/api/dashboards", `{"title":"x"}`, true); code != 503 {
		t.Errorf("create = %d", code)
	}
	// Posture still works without custom dashboards.
	if code, _ := do(t, ts, "GET", "/api/posture", "", true); code != 200 {
		t.Errorf("posture = %d", code)
	}
}

func TestPostureAPI(t *testing.T) {
	ts, _ := newTestServer(t)
	do(t, ts, "POST", "/api/findings", `{"title":"Manual","severity":"high","result":{"src":"10.0.0.9"}}`, true)
	code, out := do(t, ts, "GET", "/api/posture?range=7d", "", true)
	if code != 200 || out["range"] != "7d" {
		t.Fatalf("posture = %d %v", code, out)
	}
	ind := map[string]any{}
	for _, i := range out["indicators"].([]any) {
		m := i.(map[string]any)
		ind[m["id"].(string)] = m["value"]
	}
	if fmt.Sprint(ind["open_findings"]) != "1" || fmt.Sprint(ind["new_findings"]) != "1" || len(ind) != 6 {
		t.Errorf("indicators = %v", ind)
	}
	h := out["health"].(map[string]any)
	if h["total"].(float64) < 20 || h["enabled"].(float64) < 10 {
		t.Errorf("health = %v", h)
	}
	if out["queries"].(map[string]any)["events_by_datamodel"] == nil {
		t.Errorf("queries = %v", out["queries"])
	}
	for _, bad := range []string{"soon", "1000d"} {
		if code, _ := do(t, ts, "GET", "/api/posture?range="+bad, "", true); code != 400 {
			t.Errorf("range %s = %d", bad, code)
		}
	}
}
