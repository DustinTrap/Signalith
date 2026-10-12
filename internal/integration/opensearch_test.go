//go:build integration

// Package integration runs Signalith end to end against a real OpenSearch.
// Run with: SIGNALITH_TEST_OPENSEARCH=http://localhost:9200 go test -tags integration ./internal/integration/
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func setup(t *testing.T) (*store.Client, *search.Engine, string) {
	t.Helper()
	url := os.Getenv("SIGNALITH_TEST_OPENSEARCH")
	if url == "" {
		t.Skip("SIGNALITH_TEST_OPENSEARCH not set")
	}
	cl := store.New(store.Config{URL: url})
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if _, err := cl.Health(ctx); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("opensearch not reachable: %v", err)
		}
		time.Sleep(2 * time.Second)
	}
	prefix := "sigtest" + config.RandomToken(3)
	if err := cl.PutIndexTemplate(ctx, prefix, ingest.IndexTemplate(prefix, 0)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		names, _ := cl.ListIndices(ctx, prefix+"-*")
		for _, n := range names {
			_ = cl.DeleteIndex(ctx, n)
		}
		_ = cl.Do(ctx, http.MethodDelete, "/_index_template/"+prefix, nil, nil)
		_ = cl.DeleteIndex(ctx, prefix+"_findings")
	})
	eng := &search.Engine{Store: cl, Opt: search.Options{IndexPrefix: prefix, DefaultEarliest: "-24h"}}
	return cl, eng, prefix
}

func syslogTime(t time.Time) string { return t.Local().Format("Jan _2 15:04:05") }

func load(t *testing.T, cl *store.Client, prefix string) {
	t.Helper()
	ctx := context.Background()
	p := &ingest.Pipeline{Store: cl, Prefix: prefix}
	now := time.Now()

	var linux []map[string]any
	add := func(ago time.Duration, rest string) {
		linux = append(linux, map[string]any{"log": syslogTime(now.Add(-ago)) + " web1 " + rest})
	}
	for i := 0; i < 12; i++ {
		add(time.Duration(i)*time.Minute+5*time.Minute, fmt.Sprintf("sshd[%d]: Failed password for invalid user oracle from 203.0.113.9 port %d ssh2", 100+i, 40100+i))
	}
	for i := 0; i < 3; i++ {
		add(time.Duration(i)*time.Minute+5*time.Minute, fmt.Sprintf("sshd[%d]: Failed password for root from 198.51.100.23 port %d ssh2", 200+i, 30000+i))
	}
	add(2*time.Minute, "sshd[300]: Accepted publickey for deploy from 10.20.0.15 port 50000 ssh2: RSA SHA256:abc")
	add(3*time.Hour, "sshd[301]: Accepted password for alice from 10.20.0.16 port 50001 ssh2")
	add(time.Minute, "sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
	add(time.Minute, "useradd[900]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash")
	add(time.Minute, "cron[5]: (root) CMD (run-parts /etc/cron.hourly)")
	res, err := p.Ingest(ctx, "linux.auth", linux)
	if err != nil || len(res.Errors) > 0 {
		t.Fatalf("linux ingest: %v %+v", err, res)
	}

	ins4625 := make([]string, 21)
	ins4625[5], ins4625[9], ins4625[10], ins4625[19], ins4625[20] = "Administrator", "0xC000006A", "3", "203.0.113.9", "51234"
	ins4688 := make([]string, 15)
	ins4688[1], ins4688[4], ins4688[5], ins4688[8], ins4688[13] = "bob", "0x1a2c", `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, "powershell -enc SQBFAFgA", `C:\Windows\explorer.exe`
	ts := now.Add(-4 * time.Minute).UTC().Format("2006-01-02 15:04:05 -0700")
	win := []map[string]any{
		{"Channel": "Security", "Computer": "DC01", "EventID": json.Number("4625"), "TimeCreated": ts, "StringInserts": toAny(ins4625)},
		{"Channel": "Security", "Computer": "WS1", "EventID": json.Number("4688"), "TimeCreated": ts, "StringInserts": toAny(ins4688)},
	}
	if res, err := p.Ingest(ctx, "win.events", win); err != nil || len(res.Errors) > 0 {
		t.Fatalf("windows ingest: %v %+v", err, res)
	}
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
}

func toAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func run(t *testing.T, eng *search.Engine, q string) *search.Result {
	t.Helper()
	res, err := eng.Run(context.Background(), q)
	if err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return res
}

func TestEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	load(t, cl, prefix)

	t.Run("stats by src", func(t *testing.T) {
		res := run(t, eng, `datamodel=Authentication action=failure | stats count, dc(user) as users by src | sort -count`)
		if len(res.Rows) != 2 {
			t.Fatalf("rows = %v", res.Rows)
		}
		top := res.Rows[0]
		if top["src"] != "203.0.113.9" || top["count"] != int64(13) || top["users"] != int64(2) {
			t.Errorf("top row = %v", top)
		}
	})
	t.Run("case-insensitive match and text search", func(t *testing.T) {
		if res := run(t, eng, `user=ORACLE`); res.Matched != 12 {
			t.Errorf("user=ORACLE matched %d", res.Matched)
		}
		if res := run(t, eng, `"failed password" root`); res.Matched != 3 {
			t.Errorf("text search matched %d", res.Matched)
		}
	})
	t.Run("wildcard, range, IN and NOT", func(t *testing.T) {
		if res := run(t, eng, `datamodel=Endpoint process_name=power* process="*-enc*"`); res.Matched != 1 {
			t.Errorf("wildcard matched %d", res.Matched)
		}
		if res := run(t, eng, `src_port>=40105 src_port<40200`); res.Matched != 7 {
			t.Errorf("range matched %d", res.Matched)
		}
		if res := run(t, eng, `datamodel=Authentication src IN (198.51.100.23, 10.20.0.15) NOT user=root`); res.Matched != 1 {
			t.Errorf("IN/NOT matched %d", res.Matched)
		}
	})
	t.Run("time range", func(t *testing.T) {
		if res := run(t, eng, `datamodel=Authentication action=success earliest=-1h`); res.Matched != 2 {
			// deploy (2m ago) and sudo (1m ago); alice's logon was 3h ago
			t.Errorf("earliest=-1h matched %d", res.Matched)
		}
		if res := run(t, eng, `datamodel=Authentication action=success earliest=-24h`); res.Matched != 3 {
			t.Errorf("earliest=-24h matched %d", res.Matched)
		}
	})
	t.Run("events come back newest first with _raw", func(t *testing.T) {
		res := run(t, eng, `datamodel=Change`)
		if len(res.Rows) != 1 || res.Rows[0]["object"] != "backdoor" || res.Rows[0]["_raw"] == nil {
			t.Errorf("rows = %v", res.Rows)
		}
	})
	t.Run("timechart and top", func(t *testing.T) {
		res := run(t, eng, `datamodel=Authentication earliest=-4h | timechart span=1h count by action`)
		var fail int64
		for _, r := range res.Rows {
			if n, ok := r["failure"].(int64); ok {
				fail += n
			}
		}
		if fail != 16 {
			t.Errorf("failures across buckets = %d, rows %v", fail, res.Rows)
		}
		top := run(t, eng, `datamodel=Authentication | top limit=1 src`)
		if len(top.Rows) != 1 || top.Rows[0]["src"] != "203.0.113.9" {
			t.Errorf("top = %v", top.Rows)
		}
	})
	t.Run("numeric stats and post-processing", func(t *testing.T) {
		res := run(t, eng, `datamodel=Authentication src=203.0.113.9 | stats min(src_port) as lo, max(src_port) as hi, avg(src_port) as mean`)
		r := res.Rows[0]
		if r["lo"] != int64(40100) || r["hi"] != int64(51234) {
			t.Errorf("row = %v", r)
		}
		res = run(t, eng, `datamodel=Authentication | stats count by src, action | stats dc(action) as outcomes by src | where outcomes > 1`)
		if len(res.Rows) != 0 {
			t.Errorf("no src has both outcomes, got %v", res.Rows)
		}
	})
	t.Run("plain-English questions run", func(t *testing.T) {
		ip, err := nlq.Translate("failed logins from 203.0.113.9", nil)
		if err != nil {
			t.Fatal(err)
		}
		cidr, _ := nlq.Translate("failed logins from 203.0.113.0/24", nil)
		a, b := run(t, eng, ip.Query), run(t, eng, cidr.Query)
		if a.Matched == 0 || a.Matched != b.Matched {
			t.Errorf("ip matched %d, cidr matched %d", a.Matched, b.Matched)
		}
		for _, q := range []string{"top 5 users with failed logins", "users with more than 2 failed logins per hour",
			"which sources failed against at least 2 users", "processes containing enc", "how many distinct users logged in"} {
			r, err := nlq.Translate(q, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res := run(t, eng, r.Query); len(res.Rows) == 0 {
				t.Errorf("%q (%s) returned nothing", q, r.Query)
			}
		}
	})

	t.Run("mapping discovers fields", func(t *testing.T) {
		m, err := cl.Mapping(context.Background(), prefix+"-authentication-*")
		if err != nil {
			t.Fatal(err)
		}
		if m["src_port"] != "long" || m["user"] != "keyword" || m["message"] != "text" {
			t.Errorf("mapping = %v", m)
		}
	})
}

func TestDetectionsEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	load(t, cl, prefix)
	ctx := context.Background()
	fs := findings.NewOpenSearch(cl, prefix)
	if err := fs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	if err := fs.EnsureIndex(ctx); err != nil {
		t.Fatalf("second EnsureIndex: %v", err)
	}
	lib, _, err := detect.NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	lists, err := assets.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lists.SetAssets([]byte("host,ip,priority,owner\nweb1,,critical,web team\nWS1,,low,\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := lists.SetIdentities([]byte("identity,priority,watchlist\nalice,medium,true\n")); err != nil {
		t.Fatal(err)
	}
	eng.Assets = lists
	rs := &risk.Store{Client: cl, Prefix: prefix}
	sched := &detect.Scheduler{Library: lib, Engine: eng, Findings: fs, Risk: rs, Assets: lists}
	run := func(id string, want int) []*findings.Finding {
		t.Helper()
		d, err := lib.Get(id)
		if err != nil {
			t.Fatal(err)
		}
		d.Lookback = "1h" // test data spans the last 16 minutes
		res, err := sched.Run(ctx, d)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if len(res.Findings) != want {
			t.Fatalf("%s raised %d findings, want %d (results %d, throttled %d)", id, len(res.Findings), want, res.Results, res.Throttled)
		}
		return res.Findings
	}

	bf := run("auth-brute-force", 1)
	if bf[0].Title != "Brute force against web1 from 203.0.113.9" || bf[0].Result["count"] != int64(12) {
		t.Errorf("brute force finding = %q %v", bf[0].Title, bf[0].Result)
	}
	// The drilldown search returns the events behind the finding.
	dq := bf[0].Query + " earliest=" + bf[0].Earliest
	if res, err := eng.Run(ctx, dq); err != nil || res.Matched != 12 {
		t.Errorf("drilldown %q: %v matched %v", dq, err, res)
	}
	run("auth-brute-force", 0) // throttled
	sh := run("auth-shadow-file-access", 1)
	// web1 is a critical asset, so a high finding there is critical.
	if sh[0].Urgency != "critical" || sh[0].Context["dest"] == nil || sh[0].Context["dest"].Owner != "web team" {
		t.Errorf("shadow finding urgency %q context %v", sh[0].Urgency, sh[0].Context)
	}
	run("change-account-created", 0) // risk only
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-risk-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
	if res, err := sched.Run(ctx, mustGet(t, lib, "change-account-created", "1h")); err != nil || res.Throttled != 1 || res.Risk != 0 {
		t.Errorf("risk-only rerun = %+v %v", res, err)
	}
	ps := run("endpoint-encoded-powershell", 1)
	if ps[0].Entities["dest"] != "WS1" || ps[0].Entities["user"] != "bob" {
		t.Errorf("entities = %v", ps[0].Entities)
	}
	run("endpoint-credential-dumping", 0)

	// A converted Sigma rule finds the same activity.
	sig, err := detect.ConvertSigma([]byte(`title: Encoded PowerShell
logsource: {category: process_creation, product: windows}
detection:
  img:
    Image|endswith: ['\\powershell.exe', '\\pwsh.exe']
  cli:
    CommandLine|contains|windash: ' -enc '
  condition: img and cli
level: high
tags: [attack.t1059.001]
`))
	if err != nil {
		t.Fatal(err)
	}
	if res, err := eng.Run(ctx, sig.Detection.Query+" earliest=-1h"); err != nil || res.Matched != 1 {
		t.Errorf("sigma query %q: %v matched %v", sig.Detection.Query, err, res)
	}

	// Triage and queue queries against the real index.
	f, err := fs.Get(ctx, bf[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	st, owner := findings.StatusInProgress, "analyst1"
	f.Apply(findings.Update{Status: &st, Owner: &owner, Comment: "blocking at the firewall"}, "admin", time.Now())
	if err := fs.Save(ctx, f); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Get(ctx, f.ID)
	if err != nil || got.Status != st || len(got.Comments) != 1 || len(got.History) != 2 {
		t.Fatalf("after save = %+v %v", got, err)
	}
	list, total, err := fs.Search(ctx, findings.Filter{Status: []string{findings.StatusNew}})
	if err != nil || total != 2 || len(list) != 2 {
		t.Errorf("new findings = %d %v", total, err)
	}
	list, _, err = fs.Search(ctx, findings.Filter{Text: "203.0.113.9"})
	if err != nil || len(list) != 1 || list[0].ID != f.ID {
		t.Errorf("entity search = %v %v", list, err)
	}
	list, _, err = fs.Search(ctx, findings.Filter{Text: "powershell"})
	if err != nil || len(list) != 1 {
		t.Errorf("title search = %v %v", list, err)
	}
	sum, err := fs.Summary(ctx)
	if err != nil || sum.Open != 3 || sum.ByStatus[findings.StatusInProgress] != 1 || sum.BySeverity["high"] != 2 || sum.ByUrgency["critical"] != 1 {
		t.Errorf("summary = %+v %v", sum, err)
	}
	if _, err := fs.Get(ctx, "nope"); err != findings.ErrNotFound {
		t.Errorf("missing = %v", err)
	}
	// Event searches never see findings or risk.
	if res := run1(t, eng, `*`); res.Matched != 22 {
		t.Errorf("events matched %d; findings or risk may be leaking into searches", res.Matched)
	}

	// Risk: brute force 30 on the source, shadow access 60 on alice
	// (watchlist, x1.5) and web1 (critical, x2), account created 20 on web1
	// (x2), encoded PowerShell 40 on bob and WS1 (low, x0.5).
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-risk-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}
	rr := run1(t, eng, `datamodel=Risk | stats sum(risk_score) as score by risk_object | sort -score`)
	want := map[string]string{"web1": "160", "alice": "90", "bob": "40", "203.0.113.9": "30", "WS1": "20"}
	scores := map[string]string{}
	for _, r := range rr.Rows {
		scores[fmt.Sprint(r["risk_object"])] = fmt.Sprint(r["score"])
	}
	if fmt.Sprint(scores) != fmt.Sprint(want) {
		t.Errorf("risk by object = %v, want %v", scores, want)
	}
	inc := run("risk-threshold-exceeded", 1)
	if inc[0].Title != "Risk score 160 for system web1" || inc[0].Urgency != "critical" {
		t.Errorf("risk incident = %q urgency %q", inc[0].Title, inc[0].Urgency)
	}
	run("risk-threshold-exceeded", 0) // throttled

	// enrich adds asset context to search results.
	er := run1(t, eng, `datamodel=Authentication | stats count by dest | enrich dest`)
	found := false
	for _, r := range er.Rows {
		if r["dest"] == "web1" {
			found = r["dest_priority"] == "critical" && r["dest_owner"] == "web team"
		}
	}
	if !found {
		t.Errorf("enrich rows = %v", er.Rows)
	}

	// Findings stored before urgency existed get it when the index is
	// upgraded.
	legacy := map[string]any{"id": "legacy", "detection_id": "x", "title": "old", "severity": "low", "status": "new", "created": time.Now().UTC().Format(time.RFC3339)}
	if err := cl.Do(ctx, http.MethodPut, "/"+prefix+"_findings/_doc/legacy?refresh=true", legacy, nil); err != nil {
		t.Fatal(err)
	}
	if err := fs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	list, _, err = fs.Search(ctx, findings.Filter{Urgency: []string{"low"}})
	if err != nil || len(list) != 1 || list[0].ID != "legacy" {
		t.Errorf("legacy urgency = %v %v", list, err)
	}
}

func mustGet(t *testing.T, lib *detect.Library, id, lookback string) *detect.Detection {
	t.Helper()
	d, err := lib.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	d.Lookback = lookback
	return d
}

func run1(t *testing.T, eng *search.Engine, q string) *search.Result { return run(t, eng, q) }

// TestDashboardsEndToEnd runs the posture summary and saved dashboard
// panels against real data.
func TestDashboardsEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	load(t, cl, prefix)
	ctx := context.Background()
	fs := findings.NewOpenSearch(cl, prefix)
	if err := fs.EnsureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	lib, _, err := detect.NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	sched := &detect.Scheduler{Library: lib, Engine: eng, Findings: fs, Risk: &risk.Store{Client: cl, Prefix: prefix}}
	var bf *findings.Finding
	for _, id := range []string{"auth-brute-force", "auth-shadow-file-access"} {
		res, err := sched.Run(ctx, mustGet(t, lib, id, "1h"))
		if err != nil || len(res.Findings) != 1 {
			t.Fatalf("%s: %v %+v", id, err, res)
		}
		if bf == nil {
			bf = res.Findings[0]
		}
	}
	// Triage and resolve one finding so the time-to metrics have data.
	st, owner := findings.StatusResolved, "analyst1"
	bf.Apply(findings.Update{Status: &st, Owner: &owner}, "admin", time.Now())
	if err := fs.Save(ctx, bf); err != nil {
		t.Fatal(err)
	}
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-risk-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}

	p := &dashboards.Posture{Engine: eng, Findings: fs, Detections: lib, Status: sched.Status, SchedulerOn: true, StaleAfter: 3 * time.Minute}
	rep := p.Report(ctx, 24*time.Hour, "24h")
	if rep.Errors != nil {
		t.Fatalf("posture errors: %v", rep.Errors)
	}
	ind := map[string]string{}
	for _, i := range rep.Indicators {
		v, prev := "nil", "nil"
		if i.Value != nil {
			v = fmt.Sprint(*i.Value)
		}
		if i.Previous != nil {
			prev = fmt.Sprint(*i.Previous)
		}
		ind[i.ID] = v + "/" + prev
	}
	for id, want := range map[string]string{"events_ingested": "22/0", "new_findings": "2/0", "closed_findings": "1/0", "open_findings": "1/nil"} {
		if ind[id] != want {
			t.Errorf("%s = %s, want %s (all: %v)", id, ind[id], want, ind)
		}
	}
	if mttr := ind["mean_time_to_resolve"]; !strings.HasSuffix(mttr, "/nil") || strings.HasPrefix(mttr, "nil") {
		t.Errorf("mean time to resolve = %s", mttr)
	}
	sum := func(res *search.Result) (n int64) {
		for _, r := range res.Rows {
			for _, c := range res.Columns[1:] {
				if v, ok := r[c].(int64); ok {
					n += v
				}
			}
		}
		return n
	}
	if n := sum(rep.EventsByDatamodel); n != 22 || !slices.Contains(rep.EventsByDatamodel.Columns, "Authentication") {
		t.Errorf("events by data model = %d %v", n, rep.EventsByDatamodel.Columns)
	}
	if n := sum(rep.EventsBySourcetype); n != 22 {
		t.Errorf("events by source type = %d %v", n, rep.EventsBySourcetype.Columns)
	}
	if n := sum(rep.FindingsOverTime); n != 2 {
		t.Errorf("findings over time = %d", n)
	}
	var sawBF bool
	for _, d := range rep.TopDetections {
		if d.ID == "auth-brute-force" {
			sawBF = d.Findings == 1 && d.RiskEvents == 1
		}
	}
	if !sawBF {
		t.Errorf("top detections = %+v", rep.TopDetections)
	}
	// No asset list here, so scores are unscaled: shadow access adds 60 to
	// alice and web1, brute force 30 to the source.
	scores := map[string]string{}
	for _, r := range rep.TopRiskObjects {
		scores[fmt.Sprint(r["risk_object"])] = fmt.Sprint(r["risk_score"])
	}
	if fmt.Sprint(scores) != fmt.Sprint(map[string]string{"web1": "60", "alice": "60", "203.0.113.9": "30"}) || fmt.Sprint(rep.TopRiskObjects[2]["risk_score"]) != "30" {
		t.Errorf("top risk objects = %v", rep.TopRiskObjects)
	}
	tactics := map[string]bool{}
	for _, x := range rep.Tactics {
		tactics[x.Tactic] = true
	}
	if !tactics["credential-access"] {
		t.Errorf("tactics = %+v", rep.Tactics)
	}
	h := rep.Health
	stale := map[string]bool{}
	for _, s := range h.StaleSources {
		stale[s.Host] = true
	}
	// web1 sent a minute ago; DC01 and WS1 last sent four minutes ago.
	if h.Sources < 3 || stale["web1"] || !stale["DC01"] || !stale["WS1"] {
		t.Errorf("sources %d stale %v", h.Sources, h.StaleSources)
	}
	silent := map[string]bool{}
	for _, s := range h.Silent {
		silent[s.ID] = true
	}
	if silent["auth-brute-force"] || !silent["endpoint-shadow-copy-delete"] {
		t.Errorf("silent = %v", h.Silent)
	}

	// A saved dashboard runs its panels; a failing panel stays on its own.
	store, err := dashboards.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := &dashboards.Dashboard{ID: "auth", Title: "Authentication", Panels: []dashboards.Panel{
		{Title: "Failed logins", Query: "datamodel=Authentication action=failure | stats count", Compare: true},
		{Title: "Top sources", Query: "datamodel=Authentication | top limit=3 src"},
		{Title: "Over time", Query: "datamodel=Authentication earliest=-4h | timechart span=1h count by action"},
		{Title: "Bad span", Query: "datamodel=Authentication | timechart span=soon count"},
	}}
	if err := store.Put(d); err != nil {
		t.Fatal(err)
	}
	saved, err := store.Get("auth")
	if err != nil {
		t.Fatal(err)
	}
	out := (&dashboards.Runner{Engine: eng}).Run(ctx, saved.Panels, saved.TimeRange)
	if out[0].Error != "" || fmt.Sprint(out[0].Value) != "16" || fmt.Sprint(out[0].Previous) != "0" {
		t.Errorf("single = %+v", out[0])
	}
	if out[1].Error != "" || len(out[1].Result.Rows) != 3 || out[1].Result.Rows[0]["src"] != "203.0.113.9" {
		t.Errorf("bar = %+v", out[1])
	}
	// 16 failures and 3 successful logons in the last 4 hours.
	if out[2].Error != "" || out[2].Result.Kind != "timechart" || sum(out[2].Result) != 19 {
		t.Errorf("line = %+v", out[2])
	}
	if out[3].Error == "" || out[3].Result != nil {
		t.Errorf("bad panel = %+v", out[3])
	}
}
