//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// TestIngestLimitsEndToEnd checks the ingest guards against a real
// OpenSearch: the template maps Signalith's fields up front; a flood of
// invented field names, even across a restart that forgets the field
// budget, cannot cost a legitimate event; events dated far ahead or long
// ago do not create indices; and index= cannot leave Signalith's indices.
func TestIngestLimitsEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	ctx := context.Background()
	now := time.Now()
	refresh := func() {
		t.Helper()
		if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	legit := func(user string) map[string]any {
		return map[string]any{"log": syslogTime(now.Add(-time.Minute)) + " web1 sshd[1]: Failed password for " + user + " from 192.0.2.44 port 4000 ssh2"}
	}
	junk := func(run, n int) []map[string]any {
		var recs []map[string]any
		for i := range n {
			r := map[string]any{"date": float64(now.Add(-time.Minute).Unix()), "app_user": fmt.Sprintf("u%d", i)}
			for j := range 100 {
				r[fmt.Sprintf("junk_%d_%d_%d", run, i, j)] = j
			}
			recs = append(recs, r)
		}
		return recs
	}

	// One server run: 30 records with 100 new names each, then a
	// legitimate event.
	p := &ingest.Pipeline{Store: cl, Prefix: prefix}
	res, err := p.Ingest(ctx, "app", junk(1, 30))
	if err != nil || res.Rejected != 0 || res.Indexed != 30 || res.FieldsDropped == 0 {
		t.Fatalf("junk: %+v %v", res, err)
	}
	if res, err := p.Ingest(ctx, "linux.auth", []map[string]any{legit("alice")}); err != nil || res.Indexed != 1 {
		t.Fatalf("legit: %+v %v", res, err)
	}

	// A restart forgets the budget; the next run's junk fills the index's
	// mapping to its limit, so OpenSearch itself refuses the new names.
	// Those events are stored with their known fields, and legitimate
	// events still land.
	p = &ingest.Pipeline{Store: cl, Prefix: prefix}
	res, err = p.Ingest(ctx, "app", junk(2, 30))
	if err != nil || res.Rejected != 0 || res.Indexed != 30 {
		t.Fatalf("junk after restart: %+v %v", res, err)
	}
	// A fresh budget lets 1000 of this run's 3000 names through, so all
	// 3000 being dropped means OpenSearch refused the rest and the events
	// were written again without them.
	p = &ingest.Pipeline{Store: cl, Prefix: prefix}
	res, err = p.Ingest(ctx, "app", junk(3, 30))
	if err != nil || res.Rejected != 0 || res.Indexed != 30 || res.FieldsDropped < 30*100 {
		t.Fatalf("junk over the field limit: %+v %v", res, err)
	}
	if res, err := p.Ingest(ctx, "linux.auth", []map[string]any{legit("bob")}); err != nil || res.Indexed != 1 {
		t.Fatalf("legit after the flood: %+v %v", res, err)
	}
	// A value of the wrong type for a known field is left unindexed, not
	// a reason to refuse the event.
	if res, err := p.Ingest(ctx, "app", []map[string]any{{"date": float64(now.Unix()), "src_port": "ssh", "logon_type": "x", "user": "carol"}}); err != nil || res.Indexed != 1 {
		t.Fatalf("wrong types: %+v %v", res, err)
	}
	refresh()

	r := run(t, eng, `datamodel=Authentication src=192.0.2.44 | stats count by user | sort user`)
	if len(r.Rows) != 2 || r.Rows[0]["user"] != "alice" || r.Rows[1]["user"] != "bob" {
		t.Errorf("legit events: %v", r.Rows)
	}
	if r := run(t, eng, `user=carol | table user, src_port`); len(r.Rows) != 1 || r.Rows[0]["src_port"] != "ssh" {
		t.Errorf("wrong types: %v", r.Rows)
	}
	// Each run's budget runs out after about ten records; the third run's
	// first records are refused by OpenSearch and stored again with only
	// their known fields.
	if r := run(t, eng, `datamodel=Other dropped_fields>0 | stats count`); r.Rows[0]["count"].(int64) < 72 {
		t.Errorf("events with dropped fields: %v", r.Rows)
	}
	if r := run(t, eng, `datamodel=Other app_user=u25 | stats count`); r.Rows[0]["count"] != int64(3) {
		t.Errorf("names already mapped stay: %v", r.Rows)
	}

	m, err := cl.Mapping(ctx, prefix+"-other-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(m) > 2000 {
		t.Errorf("mapping has %d fields", len(m))
	}
	for name, want := range map[string]string{
		"src_port": "long", "user": "keyword", "message": "text", "dropped_fields": "long",
		"device_time": "keyword", "risk_score": "double", "logon_type": "long",
	} {
		if m[name] != want {
			t.Errorf("%s mapped as %q, want %q", name, m[name], want)
		}
	}

	// Event times outside the window do not pick indices. (Known fields
	// only: the junk above spent today's budget for new names.)
	var dated []map[string]any
	for i := range 20 {
		dated = append(dated, map[string]any{"date": float64(now.AddDate(0, 0, 3+i*30).Unix()), "user": "ahead"})
	}
	dated = append(dated, map[string]any{"date": float64(now.AddDate(-5, 0, 0).Unix()), "user": "old"})
	res, err = p.Ingest(ctx, "app", dated)
	if err != nil || res.Indexed != 21 || res.Retimed != 21 {
		t.Fatalf("dated: %+v %v", res, err)
	}
	refresh()
	names, err := cl.ListIndices(ctx, prefix+"-*")
	if err != nil {
		t.Fatal(err)
	}
	today, yesterday := now.UTC().Format("2006.01.02"), now.UTC().Add(-time.Hour).Format("2006.01.02")
	for _, n := range names {
		if !strings.HasSuffix(n, today) && !strings.HasSuffix(n, yesterday) {
			t.Errorf("index %s created", n)
		}
	}
	if r := run(t, eng, `user=ahead device_time=* | stats count`); r.Rows[0]["count"] != int64(20) {
		t.Errorf("retimed events: %v", r.Rows)
	}

	// index= stays inside Signalith's indices, here against real ones.
	if err := cl.Do(ctx, http.MethodPut, "/"+prefix+"_findings/_doc/x?refresh=true", map[string]any{"title": "secret"}, nil); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"index=" + prefix + "_findings", "index=" + prefix + "_*", `index="` + prefix + `-*,` + prefix + `_findings"`, "index=_all",
		"index=.opendistro_security", "index=" + prefix + "*",
	} {
		// Refused by the parser (a *query.Error) or the engine (a
		// *search.QueryError), never sent to OpenSearch.
		_, err := eng.Run(ctx, q)
		var qe *search.QueryError
		var pe *query.Error
		if !errors.As(err, &qe) && !errors.As(err, &pe) {
			t.Errorf("%s: %v", q, err)
		}
	}
	if r := run(t, eng, "index="+prefix+"-other-* app_user=u25 | stats count"); r.Rows[0]["count"] != int64(3) {
		t.Errorf("index= inside the prefix: %v", r.Rows)
	}
}
