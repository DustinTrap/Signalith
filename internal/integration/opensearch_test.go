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
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
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
