package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// funcStore answers searches with a function.
type funcStore func(ctx context.Context, index string, body map[string]any) (map[string]any, error)

func (f funcStore) Search(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	return f(ctx, index, body)
}

// hits returns a search response with n events.
func hits(n int, user func(i int) string) map[string]any {
	var b strings.Builder
	fmt.Fprintf(&b, `{"hits":{"total":{"value":%d},"hits":[`, n)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		u, _ := json.Marshal(user(i))
		fmt.Fprintf(&b, `{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":%s}}`, u)
	}
	b.WriteString(`]}}`)
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(b.String()))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		panic(err)
	}
	return out
}

// TestIndexPatternStaysInsideSignalith reproduces
// outbound-index-any-opensearch-index and authz-index-param-reads-any-index:
// whatever reaches the engine (a parsed query, a dashboard panel, a
// detection, or a query built in code such as the field values lookup)
// can only search "<prefix>-" indices.
func TestIndexPatternStaysInsideSignalith(t *testing.T) {
	e := &Engine{Opt: Options{IndexPrefix: "sig"}}
	for _, c := range []struct{ index, datamodel, want string }{
		{"sig-*", "", "sig-*"},
		{"SIG-Authentication-2026.10.*", "", "sig-authentication-2026.10.*"},
		{"sig-risk-*", "", "sig-risk-*"},
		{"*", "", "sig-*,-sig-risk-*"},
		{"*", "Endpoint", "sig-endpoint-*"},
		{"", "network_traffic", "sig-network_traffic-*"},
	} {
		got, err := e.IndexPattern(&query.Query{Index: c.index, Datamodel: c.datamodel})
		if err != nil || got != c.want {
			t.Errorf("index=%q datamodel=%q: %q %v, want %q", c.index, c.datamodel, got, err, c.want)
		}
	}
	for _, q := range []query.Query{
		{Index: ".opendistro_security"}, {Index: ".kibana*"}, {Index: "_all"}, {Index: "sig_findings"},
		{Index: "sig_cases"}, {Index: "sig_intel"}, {Index: "sig_*"}, {Index: "sig*"}, {Index: "signalith-*"},
		{Index: "sig-*,.security"}, {Index: "sig-*,-sig-risk-*"}, {Index: "remote:sig-*"}, {Index: "<sig-{now/d}>"},
		{Index: "other-app-*"}, {Index: "*,sig-x"}, {Index: "s*-x"}, {Index: "-sig-x"},
		{Datamodel: "../_cat"}, {Datamodel: "Bogus"}, {Datamodel: "authentication,x"}, {Datamodel: "*"},
	} {
		_, err := e.IndexPattern(&q)
		var qe *QueryError
		if !errors.As(err, &qe) {
			t.Errorf("index=%q datamodel=%q: %v, want a *QueryError", q.Index, q.Datamodel, err)
		}
	}

	// A query that names another prefix never reaches OpenSearch, and the
	// error says what to do.
	called := false
	e = &Engine{Store: funcStore(func(context.Context, string, map[string]any) (map[string]any, error) {
		called = true
		return hits(0, nil), nil
	}), Opt: Options{IndexPrefix: "sig"}}
	_, err := e.Run(context.Background(), `index=signalith-* user=bob`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), `must start with "sig-"`) || called {
		t.Errorf("err %v, store called %v", err, called)
	}
}

// TestGlobMatchesLikeTheRegexpItReplaces checks the wildcard matcher
// against the regular expression it replaced, which was compiled for every
// row.
func TestGlobMatchesLikeTheRegexpItReplaces(t *testing.T) {
	alphabet := []string{"a", "b", "A", "é", "É", "\n", "-", "?", "*"}
	rnd := rand.New(rand.NewSource(1))
	word := func(max int, wild bool) string {
		var b strings.Builder
		for range rnd.Intn(max + 1) {
			s := alphabet[rnd.Intn(len(alphabet))]
			if !wild && (s == "*" || s == "?") {
				s = "a"
			}
			b.WriteString(s)
		}
		return b.String()
	}
	for range 20000 {
		pattern, s := word(6, true), word(8, false)
		var re strings.Builder
		re.WriteString(`(?s)^`)
		for _, r := range strings.ToLower(pattern) {
			switch r {
			case '*':
				re.WriteString(".*")
			case '?':
				re.WriteString(".")
			default:
				re.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		re.WriteString("$")
		want := regexp.MustCompile(re.String()).MatchString(strings.ToLower(s))
		if got := compileGlob(pattern, true).match(s); got != want {
			t.Fatalf("pattern %q on %q: %v, want %v", pattern, s, got, want)
		}
	}
}

// TestWherePatternsCompileOnce reproduces dos-6: a where command with a
// long wildcard compiled a regular expression for every row, so one search
// over MaxEvents rows could keep a CPU busy for minutes. Now each pattern
// is compiled once per command, and patterns over maxPatternLen characters
// are refused.
func TestWherePatternsCompileOnce(t *testing.T) {
	long := strings.Repeat("a", 2000)
	pattern := "*" + strings.Repeat("a?", 300) + "*b*"
	fs := funcStore(func(context.Context, string, map[string]any) (map[string]any, error) {
		return hits(10000, func(int) string { return long }), nil
	})
	e := &Engine{Store: fs}
	start := time.Now()
	res, err := e.Run(context.Background(), fmt.Sprintf(`* | sort user | where user=%q OR user=%q | stats count`, pattern, pattern))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("10,000 rows took %v", d)
	}
	if res.Rows[0]["count"] != int64(0) {
		t.Errorf("rows %v", res.Rows)
	}

	m := &matcher{}
	q, _ := query.Parse(fmt.Sprintf(`* | where user=%q`, pattern))
	expr := q.Commands[0].(*query.Where).Expr
	row := Row{"user": "short"}
	m.eval(expr, row)
	if allocs := testing.AllocsPerRun(100, func() { m.eval(expr, row) }); allocs > 3 {
		t.Errorf("matching a row allocates %v times; the pattern should be compiled once", allocs)
	}

	called := false
	e = &Engine{Store: funcStore(func(context.Context, string, map[string]any) (map[string]any, error) {
		called = true
		return hits(0, nil), nil
	})}
	for _, src := range []string{
		fmt.Sprintf(`user=%q`, strings.Repeat("a", maxPatternLen)+"*"),
		fmt.Sprintf(`* | where user IN ("x", %q)`, "*"+strings.Repeat("b", maxPatternLen)),
	} {
		_, err := e.Run(context.Background(), src)
		var qe *QueryError
		if !errors.As(err, &qe) || !strings.Contains(err.Error(), "the limit is 1000") {
			t.Errorf("%.40s: %v", src, err)
		}
	}
	if called {
		t.Error("an over-long pattern reached OpenSearch")
	}
}

// TestCancelStopsInMemoryCommands: a search whose request is cancelled or
// times out stops in the commands that run over rows in memory, rather
// than finishing them for nobody.
func TestCancelStopsInMemoryCommands(t *testing.T) {
	for _, src := range []string{`* | sort user | where user=u1*`, `* | sort user | head 5`, `* | sort user | top user`, `* | stats count by user | where count > 0`} {
		ctx, cancel := context.WithCancel(context.Background())
		fs := funcStore(func(context.Context, string, map[string]any) (map[string]any, error) {
			cancel() // the client goes away while OpenSearch answers
			return hits(5000, func(i int) string { return fmt.Sprint("u", i) }), nil
		})
		_, err := (&Engine{Store: fs}).Run(ctx, src)
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Errorf("%s: %v, want context.Canceled", src, err)
		}
	}
	if got := (&Engine{Opt: Options{MaxEvents: 50_000_000}}).opts().MaxEvents; got != maxEventsLimit {
		t.Errorf("MaxEvents = %d, want it capped at %d", got, maxEventsLimit)
	}
}

// TestSearchesWaitForATurn reproduces the concurrency half of dos-6: any
// number of searches could run at once, each holding up to MaxEvents rows.
// Now at most MaxSearches run; the next waits up to QueueWait and then
// gets ErrBusy, while the detection scheduler's searches are not held up.
func TestSearchesWaitForATurn(t *testing.T) {
	release := make(chan struct{})
	var running atomic.Int32
	fs := funcStore(func(ctx context.Context, _ string, body map[string]any) (map[string]any, error) {
		if fmt.Sprint(body["query"]) != "map[match_all:map[]]" {
			running.Add(1)
			defer running.Add(-1)
			select {
			case <-release:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return hits(1, func(int) string { return "x" }), nil
	})
	e := &Engine{Store: fs, Opt: Options{MaxSearches: 2, QueueWait: 100 * time.Millisecond}}
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.Run(context.Background(), `user=slow`); err != nil {
				t.Error(err)
			}
		}()
	}
	for running.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	start := time.Now()
	_, err := e.Run(context.Background(), `user=next`)
	if !errors.Is(err, ErrBusy) || time.Since(start) < 100*time.Millisecond {
		t.Errorf("third search: %v after %v", err, time.Since(start))
	}
	if !strings.Contains(err.Error(), "busy") {
		t.Errorf("message %q", err)
	}
	// A cancelled request stops waiting at once.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := e.Run(ctx, `user=next`); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled wait: %v", err)
	}
	// The scheduler's searches do not take a turn.
	if _, err := e.Run(Background(context.Background()), `*`); err != nil {
		t.Errorf("background search: %v", err)
	}
	close(release)
	wg.Wait()
	if _, err := e.Run(context.Background(), `*`); err != nil {
		t.Errorf("after the others finished: %v", err)
	}
}
