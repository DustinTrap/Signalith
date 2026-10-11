package query

import (
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Query {
	t.Helper()
	q, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return q
}

func TestParseSpecialTerms(t *testing.T) {
	q := mustParse(t, `datamodel=Authentication action=failure earliest=-24h latest=now`)
	if q.Datamodel != "Authentication" || q.Earliest != "-24h" || q.Latest != "now" {
		t.Fatalf("special terms not extracted: %+v", q)
	}
	c, ok := q.Search.(*Compare)
	if !ok || c.Field != "action" || c.Op != "=" || c.Value != "failure" {
		t.Fatalf("search = %#v", q.Search)
	}
}

func TestSearchPrecedenceFollowsSPL(t *testing.T) {
	// OR binds tighter than the implicit AND.
	q := mustParse(t, `a=1 b=2 OR c=3`)
	and, ok := q.Search.(*And)
	if !ok || len(and.Children) != 2 {
		t.Fatalf("want And of 2, got %s", q.Search)
	}
	if _, ok := and.Children[1].(*Or); !ok {
		t.Fatalf("second child should be Or, got %s", and.Children[1])
	}
}

func TestParseNotInAndText(t *testing.T) {
	q := mustParse(t, `NOT user=root src IN (10.0.0.1, "10.0.0.2") "failed password" ssh*`)
	and := q.Search.(*And)
	if len(and.Children) != 4 {
		t.Fatalf("children = %d: %s", len(and.Children), q.Search)
	}
	if _, ok := and.Children[0].(*Not); !ok {
		t.Errorf("child 0 = %s", and.Children[0])
	}
	in := and.Children[1].(*In)
	if in.Field != "src" || len(in.Values) != 2 || in.Values[1] != "10.0.0.2" {
		t.Errorf("in = %#v", in)
	}
	if tx := and.Children[2].(*Text); tx.Value != "failed password" {
		t.Errorf("text = %#v", tx)
	}
}

func TestParseStatsPipeline(t *testing.T) {
	q := mustParse(t, `datamodel=Authentication action=failure
| stats count, dc(user) as users by src, dest
| where count > 20 AND users >= 2
| sort -count, src
| head 5
| rename src as source
| table source, count`)
	if len(q.Commands) != 6 {
		t.Fatalf("commands = %d", len(q.Commands))
	}
	st := q.Commands[0].(*Stats)
	if len(st.Aggs) != 2 || st.Aggs[1].Column() != "users" || st.Aggs[0].Column() != "count" {
		t.Errorf("aggs = %+v", st.Aggs)
	}
	if strings.Join(st.By, ",") != "src,dest" {
		t.Errorf("by = %v", st.By)
	}
	so := q.Commands[2].(*Sort)
	if !so.Keys[0].Desc || so.Keys[0].Field != "count" || so.Keys[1].Desc {
		t.Errorf("sort = %+v", so.Keys)
	}
	if q.Commands[3].(*Head).N != 5 {
		t.Errorf("head")
	}
}

func TestParseTimechartAndTop(t *testing.T) {
	q := mustParse(t, `* | timechart span=1h count by action`)
	tc := q.Commands[0].(*Timechart)
	if tc.Span != "1h" || tc.By != "action" || tc.Aggs[0].Func != "count" {
		t.Errorf("timechart = %+v", tc)
	}
	q = mustParse(t, `* | top limit=3 user by host`)
	top := q.Commands[0].(*Top)
	if top.Limit != 3 || top.Fields[0] != "user" || top.By[0] != "host" {
		t.Errorf("top = %+v", top)
	}
	q = mustParse(t, `* | top 5 src`)
	if q.Commands[0].(*Top).Limit != 5 {
		t.Errorf("top shorthand limit")
	}
}

func TestParseErrorsArePositioned(t *testing.T) {
	cases := map[string]string{
		`a=1 | bogus`:         "unknown command",
		`a=1 | stats avg`:     "avg needs a field",
		`a=1 | stats foo(x)`:  "unknown function",
		`(a=1`:                "unmatched",
		`a="x`:                "unterminated",
		`a=1 | where`:         "expected",
		`a=1 | sort`:          "sort needs",
		`a=1 | stats count x`: "unknown function",
		`a=1 | head 5 6`:      "unexpected",
	}
	for src, want := range cases {
		_, err := Parse(src)
		if err == nil {
			t.Errorf("Parse(%q): want error containing %q", src, want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", src, err, want)
		}
		if _, ok := err.(*Error); !ok {
			t.Errorf("Parse(%q) error is %T, want *Error", src, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	srcs := []string{
		`datamodel=Authentication action=failure (user=admin OR user=root) earliest=-24h
| stats count, dc(src) as sources by user
| where count > 5 OR sources > 2
| sort -count
| head 10`,
		`NOT host="web 01" src IN (1.2.3.4, 5.6.7.8)
| timechart span=1h count by action`,
		`"failed password"
| top limit=5 src by host
| rename src as source
| table source, count`,
	}
	for _, src := range srcs {
		q1 := mustParse(t, src)
		text := q1.String()
		q2 := mustParse(t, text)
		if q2.String() != text {
			t.Errorf("round trip unstable:\n%s\n---\n%s", text, q2.String())
		}
	}
}

func TestBackslashesInQuotedStrings(t *testing.T) {
	q, err := Parse(`process_path="C:\Windows\System32\cmd.exe" process="say \"hi\" \\ bye"`)
	if err != nil {
		t.Fatal(err)
	}
	and := q.Search.(*And)
	if v := and.Children[0].(*Compare).Value; v != `C:\Windows\System32\cmd.exe` {
		t.Errorf("path = %q", v)
	}
	if v := and.Children[1].(*Compare).Value; v != `say "hi" \ bye` {
		t.Errorf("escapes = %q", v)
	}
	q2, err := Parse(q.String())
	if err != nil || q2.String() != q.String() {
		t.Errorf("round trip: %v %s", err, q2)
	}
}
