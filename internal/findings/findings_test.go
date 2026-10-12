package findings

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func ptr(s string) *string { return &s }

func TestApplyRecordsHistory(t *testing.T) {
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	f := &Finding{ID: "1", Status: StatusNew, Severity: "high"}
	changed := f.Apply(Update{Status: ptr(StatusInProgress), Owner: ptr("sam"), Severity: ptr("high"), Comment: "  looking  "}, "admin", now)
	if !changed || f.Status != StatusInProgress || f.Owner != "sam" || !f.Updated.Equal(now) {
		t.Fatalf("finding = %+v", f)
	}
	if len(f.History) != 2 || f.History[0].Field != "status" || f.History[0].From != "new" || f.History[1].Field != "owner" {
		t.Errorf("history = %+v", f.History)
	}
	if len(f.Comments) != 1 || f.Comments[0].Text != "looking" {
		t.Errorf("comments = %+v", f.Comments)
	}
	if f.Apply(Update{Status: ptr(StatusInProgress)}, "admin", now.Add(time.Minute)) {
		t.Error("no-op update reported a change")
	}
}

func TestUpdateValidate(t *testing.T) {
	if err := (Update{Status: ptr("done")}).Validate(); err == nil || !strings.Contains(err.Error(), "in_progress") {
		t.Errorf("err = %v", err)
	}
	if err := (Update{Disposition: ptr("false_positive"), Severity: ptr("low")}).Validate(); err != nil {
		t.Error(err)
	}
	if err := (Update{Severity: ptr("severe")}).Validate(); err == nil {
		t.Error("accepted bad severity")
	}
}

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	base := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	for i, sev := range []string{"low", "high", "critical"} {
		m.Create(ctx, &Finding{ID: string(rune('a' + i)), DetectionID: "d1", GroupKey: "k" + sev, Severity: sev, Status: StatusNew,
			Title: "Brute force " + sev, Entities: map[string]any{"src": "10.0.0." + string(rune('1'+i))}, Created: base.Add(time.Duration(i) * time.Minute)})
	}
	got, total, _ := m.Search(ctx, Filter{Severity: []string{"high", "critical"}})
	if total != 2 || got[0].ID != "c" {
		t.Errorf("search = %d %v", total, got)
	}
	got, _, _ = m.Search(ctx, Filter{Text: "10.0.0.1"})
	if len(got) != 1 || got[0].ID != "a" {
		t.Errorf("text search = %v", got)
	}
	f, _ := m.Get(ctx, "a")
	f.Status = StatusClosed
	m.Save(ctx, f)
	sum, _ := m.Summary(ctx)
	if sum.Open != 2 || sum.ByStatus[StatusClosed] != 1 || sum.BySeverity["low"] != 0 {
		t.Errorf("summary = %+v", sum)
	}
	if ok, _ := m.Exists(ctx, "d1", "khigh", base); !ok {
		t.Error("exists missed")
	}
	if ok, _ := m.Exists(ctx, "d1", "khigh", base.Add(time.Hour)); ok {
		t.Error("exists ignored since")
	}
	if _, err := m.Get(ctx, "zzz"); err != ErrNotFound {
		t.Errorf("err = %v", err)
	}
}

type recDoer struct {
	method, path string
	body         any
	resp         string
}

func (r *recDoer) Do(_ context.Context, method, path string, body any, out any) error {
	r.method, r.path, r.body = method, path, body
	if out != nil && r.resp != "" {
		return json.Unmarshal([]byte(r.resp), out)
	}
	return nil
}

func TestOpenSearchRequests(t *testing.T) {
	d := &recDoer{}
	s := NewOpenSearch(d, "signalith")
	if s.Index != "signalith_findings" {
		t.Fatal(s.Index)
	}
	f := &Finding{ID: "x1", Entities: map[string]any{"user": "bob", "src": "10.0.0.1"}}
	s.Create(context.Background(), f)
	if d.method != "PUT" || d.path != "/signalith_findings/_doc/x1?refresh=wait_for" {
		t.Errorf("%s %s", d.method, d.path)
	}
	b, _ := json.Marshal(d.body)
	if !strings.Contains(string(b), `"entity_values":["10.0.0.1","bob"]`) {
		t.Errorf("body = %s", b)
	}

	d.resp = `{"hits":{"total":{"value":7},"hits":[{"_source":{"id":"x1","title":"t"}}]}}`
	got, total, err := s.Search(context.Background(), Filter{Status: []string{"new"}, Text: "bob"})
	if err != nil || total != 7 || got[0].ID != "x1" {
		t.Fatalf("search = %v %d %v", got, total, err)
	}
	b, _ = json.Marshal(d.body)
	for _, want := range []string{`"terms":{"status":["new"]}`, `"entity_values":"bob"`, `"size":200`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("search body missing %s: %s", want, b)
		}
	}

	d.resp = `{"aggregations":{"status":{"buckets":[{"key":"new","doc_count":3}]},"open":{"doc_count":3,"severity":{"buckets":[{"key":"high","doc_count":3}]}}}}`
	sum, err := s.Summary(context.Background())
	if err != nil || sum.Open != 3 || sum.BySeverity["high"] != 3 {
		t.Errorf("summary = %+v %v", sum, err)
	}
}
