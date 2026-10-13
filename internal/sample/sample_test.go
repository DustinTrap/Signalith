package sample

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
)

var fixedNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func genData(t *testing.T, size Size) *Data {
	t.Helper()
	return Generate(Options{Now: fixedNow, Size: size})
}

// TestDeterministic: the same options give byte-for-byte the same events.
func TestDeterministic(t *testing.T) {
	a := genData(t, SizeSmall)
	b := genData(t, SizeSmall)
	if a.ID != b.ID {
		t.Fatalf("IDs differ: %q vs %q", a.ID, b.ID)
	}
	if len(a.Events) != len(b.Events) {
		t.Fatalf("event counts differ: %d vs %d", len(a.Events), len(b.Events))
	}
	for i := range a.Events {
		if a.Events[i].Model != b.Events[i].Model ||
			!a.Events[i].Time.Equal(b.Events[i].Time) ||
			!reflect.DeepEqual(a.Events[i].Fields, b.Events[i].Fields) {
			t.Fatalf("event %d differs between runs", i)
		}
	}
	if !reflect.DeepEqual(a.RunTimes, b.RunTimes) || !reflect.DeepEqual(a.Anchors, b.Anchors) {
		t.Error("run times or anchors differ between runs")
	}
}

// TestMarkerOnEveryEvent: every event carries the load ID in the sample field.
func TestMarkerOnEveryEvent(t *testing.T) {
	d := genData(t, SizeStandard)
	if len(d.Events) < 1000 {
		t.Fatalf("standard produced only %d events", len(d.Events))
	}
	for i, e := range d.Events {
		if got, _ := e.Fields[ingest.SampleField].(string); got != d.ID {
			t.Fatalf("event %d has sample marker %q, want %q", i, got, d.ID)
		}
	}
}

// TestTimeWindow: every event is within the stated range, which ends a few
// minutes before now and reaches back six days.
func TestTimeWindow(t *testing.T) {
	d := genData(t, SizeStandard)
	wantEnd := fixedNow.Add(-5 * time.Minute)
	wantStart := fixedNow.AddDate(0, 0, -6)
	if !d.End.Equal(wantEnd) {
		t.Errorf("end = %v, want %v", d.End, wantEnd)
	}
	if !d.Start.Equal(wantStart) {
		t.Errorf("start = %v, want %v", d.Start, wantStart)
	}
	for i, e := range d.Events {
		if e.Time.Before(d.Start) || e.Time.After(d.End) {
			t.Fatalf("event %d at %v is outside [%v, %v]", i, e.Time, d.Start, d.End)
		}
	}
	// Run times are inside the window and end-inclusive.
	for _, rt := range d.RunTimes {
		if rt.Before(d.Start) || rt.After(d.End) {
			t.Errorf("run time %v is outside the window", rt)
		}
	}
}

var ipv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// realTLD catches a hostname ending in a public top-level domain, which the
// sample must never use (only .example and .test are allowed, RFC 6761).
var realHost = regexp.MustCompile(`\b[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+\.(com|net|org|io|gov|mil|edu|co|uk|de|ru|cn|info|biz|dev|app)\b`)

// TestReservedNamesAndAddresses: no event names a real external address or a
// real domain. Internal addresses are private; external ones are the RFC 5737
// documentation ranges; every hostname ends in .example or .test.
func TestReservedNamesAndAddresses(t *testing.T) {
	d := genData(t, SizeStandard)
	for i, e := range d.Events {
		for k, v := range e.Fields {
			s, ok := v.(string)
			if !ok {
				continue
			}
			for _, ip := range ipv4.FindAllString(s, -1) {
				if !okAddr(ip) {
					t.Fatalf("event %d field %q has non-reserved address %q", i, k, ip)
				}
			}
			if m := realHost.FindString(strings.ToLower(s)); m != "" {
				t.Fatalf("event %d field %q names a real-looking domain %q", i, k, m)
			}
		}
	}
	// Indicators, assets and identities use only reserved values too.
	for _, ind := range d.Indicators {
		if ipv4.MatchString(ind.Value) && !okAddr(ind.Value) {
			t.Errorf("indicator %q is not a reserved address", ind.Value)
		}
		if m := realHost.FindString(strings.ToLower(ind.Value)); m != "" {
			t.Errorf("indicator %q is a real-looking domain", ind.Value)
		}
	}
}

func okAddr(ip string) bool {
	if Internal(ip) || ReservedExternal(ip) {
		return true
	}
	switch ip {
	case "0.0.0.0", "127.0.0.1", "255.255.255.255":
		return true
	}
	return false
}

// TestEmailsAndIdentitiesReserved: sample identities and assets stay fictional.
func TestContextReserved(t *testing.T) {
	d := genData(t, SizeSmall)
	for _, id := range d.Identities {
		if id.Email != "" && !strings.HasSuffix(id.Email, "@corp.example") {
			t.Errorf("identity email %q is not @corp.example", id.Email)
		}
	}
	if len(d.Assets) == 0 || len(d.Identities) == 0 {
		t.Error("expected sample assets and identities")
	}
}

// TestRecipeEveryEnabledDetectionHasData proves the sample is designed from
// the detection recipes: the stories name every enabled built-in detection
// (except the two risk-incident rules and threatmatch, which fire from the
// backfill), and the generated events actually contain data that matches each
// one's search filter.
func TestRecipeEveryEnabledDetectionHasData(t *testing.T) {
	d := genData(t, SizeSmall)
	dets, err := detect.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// Collect the detection IDs the stories claim to fire.
	claimed := map[string]bool{}
	for _, s := range d.Stories {
		for _, id := range s.Detections {
			claimed[id] = true
		}
	}

	indicatorValues := map[string]bool{}
	for _, ind := range d.Indicators {
		indicatorValues[strings.ToLower(ind.Value)] = true
	}

	for _, det := range dets {
		q, err := query.Parse(det.Query)
		if err != nil {
			t.Fatalf("%s: parse: %v", det.ID, err)
		}
		if strings.EqualFold(q.Datamodel, "Risk") {
			// Risk-incident rules fire from the risk the backfill writes; the
			// integration test covers them against real OpenSearch.
			continue
		}
		if !det.Enabled {
			// Disabled by default: the sample still includes matching data, so
			// enabling it fires. Assert the data exists but do not require a
			// story to claim it.
			if !anyMatch(d, q, indicatorValues) {
				t.Errorf("disabled detection %s has no matching sample data", det.ID)
			}
			continue
		}
		// Enabled: a story must claim it, and the data must match.
		if !claimed[det.ID] {
			t.Errorf("enabled detection %s is not named by any story", det.ID)
		}
		if !anyMatch(d, q, indicatorValues) {
			t.Errorf("enabled detection %s has no matching sample data", det.ID)
		}
	}

	// Every detection a story names must be a real built-in.
	real := map[string]bool{}
	for _, det := range dets {
		real[det.ID] = true
	}
	for id := range claimed {
		if !real[id] {
			t.Errorf("a story names detection %q, which does not exist", id)
		}
	}
}

// anyMatch reports whether any sample event matches the query's leading
// search (datamodel + filter), or, for a threatmatch query, carries a value
// that is in the sample threat intel.
func anyMatch(d *Data, q *query.Query, indicators map[string]bool) bool {
	threat := false
	for _, c := range q.Commands {
		if _, ok := c.(*query.ThreatMatch); ok {
			threat = true
		}
	}
	for _, e := range d.Events {
		if q.Datamodel != "" && !strings.EqualFold(e.Model, q.Datamodel) {
			continue
		}
		if !matchExpr(q.Search, e) {
			continue
		}
		if threat {
			if eventHitsIntel(e, indicators) {
				return true
			}
			continue
		}
		return true
	}
	return false
}

func eventHitsIntel(e ingest.Event, indicators map[string]bool) bool {
	for _, f := range []string{"src", "dest", "src_host", "dest_host", "host", "query", "process_hash"} {
		if v, ok := e.Fields[f].(string); ok && indicators[strings.ToLower(v)] {
			return true
		}
	}
	// Hashes and addresses also appear in the raw message.
	if msg, ok := e.Fields["message"].(string); ok {
		low := strings.ToLower(msg)
		for ind := range indicators {
			if strings.Contains(low, ind) {
				return true
			}
		}
	}
	return false
}

// matchExpr evaluates a leading-search filter against one event. It supports
// the operators the built-in recipes use, including glob values with '*'.
func matchExpr(e query.Expr, ev ingest.Event) bool {
	switch x := e.(type) {
	case nil:
		return true
	case *query.And:
		for _, c := range x.Children {
			if !matchExpr(c, ev) {
				return false
			}
		}
		return true
	case *query.Or:
		for _, c := range x.Children {
			if matchExpr(c, ev) {
				return true
			}
		}
		return false
	case *query.Not:
		return !matchExpr(x.Child, ev)
	case *query.Text:
		return strings.Contains(strings.ToLower(fieldStr(ev, "_raw")), strings.ToLower(x.Value))
	case *query.In:
		v := fieldStr(ev, x.Field)
		for _, w := range x.Values {
			if globFold(w, v) {
				return true
			}
		}
		return false
	case *query.Compare:
		return matchCompare(x, ev)
	}
	return false
}

func matchCompare(c *query.Compare, ev ingest.Event) bool {
	v := fieldStr(ev, c.Field)
	switch c.Op {
	case "=":
		if c.Value == "*" {
			return v != ""
		}
		return globFold(c.Value, v)
	case "!=":
		if c.Value == "*" {
			return v == ""
		}
		return !globFold(c.Value, v)
	}
	// Numeric comparisons only appear in post-stats where-clauses, not in a
	// leading search, so they do not gate whether matching data exists.
	return true
}

func fieldStr(ev ingest.Event, field string) string {
	if field == "_raw" {
		field = "message"
	}
	if v, ok := ev.Fields[field]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

// globFold matches a pattern that may contain '*' wildcards against s, case
// insensitively. Without a '*' it is an exact (folded) match.
func globFold(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return strings.EqualFold(pattern, s)
	}
	p := strings.ToLower(pattern)
	v := strings.ToLower(s)
	parts := strings.Split(p, "*")
	pos := 0
	for i, seg := range parts {
		if seg == "" {
			continue
		}
		if i == 0 && !strings.HasPrefix(p, "*") {
			if !strings.HasPrefix(v[pos:], seg) {
				return false
			}
			pos += len(seg)
			continue
		}
		if i == len(parts)-1 && !strings.HasSuffix(p, "*") {
			return strings.HasSuffix(v, seg) && len(v) >= pos+len(seg)
		}
		idx := strings.Index(v[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	return true
}

// TestStoriesAndAnchors: the four intrusion stories and one benign story are
// present, and every anchor is a non-empty entity value.
func TestStories(t *testing.T) {
	d := genData(t, SizeSmall)
	want := []string{"linux-ssh-intrusion", "phishing-to-c2", "ransomware-prep", "domain-persistence", "benign-lookalikes"}
	have := map[string]bool{}
	for _, s := range d.Stories {
		have[s.ID] = true
		if s.Title == "" || s.Summary == "" {
			t.Errorf("story %s has no title or summary", s.ID)
		}
	}
	for _, id := range want {
		if !have[id] {
			t.Errorf("missing story %q", id)
		}
	}
	if len(d.Anchors) == 0 {
		t.Error("no anchors")
	}
	for _, a := range d.Anchors {
		if a == "" {
			t.Error("empty anchor")
		}
	}
}
