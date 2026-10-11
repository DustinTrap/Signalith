package search

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// applyCommand runs one pipe command over rows held in memory.
func applyCommand(res *Result, c query.Command) error {
	switch c := c.(type) {
	case *query.Where:
		out := res.Rows[:0:0]
		for _, r := range res.Rows {
			if evalExpr(c.Expr, r) {
				out = append(out, r)
			}
		}
		res.Rows = out
	case *query.Sort:
		sort.SliceStable(res.Rows, func(i, j int) bool {
			for _, k := range c.Keys {
				cmp := compareValues(res.Rows[i][k.Field], res.Rows[j][k.Field])
				if cmp == 0 {
					continue
				}
				if k.Desc {
					return cmp > 0
				}
				return cmp < 0
			}
			return false
		})
	case *query.Head:
		if len(res.Rows) > c.N {
			res.Rows = res.Rows[:c.N]
		}
	case *query.Table:
		var cols []string
		for _, f := range c.Fields {
			if strings.ContainsAny(f, "*?") {
				for _, col := range res.Columns {
					if globMatch(f, col) {
						cols = append(cols, col)
					}
				}
			} else {
				cols = append(cols, f)
			}
		}
		res.Columns = cols
		for i, r := range res.Rows {
			nr := Row{}
			for _, col := range cols {
				if v, ok := r[col]; ok {
					nr[col] = v
				}
			}
			res.Rows[i] = nr
		}
		if res.Kind == "events" {
			res.Kind = "table"
		}
	case *query.Rename:
		for _, p := range c.Pairs {
			for i, col := range res.Columns {
				if col == p[0] {
					res.Columns[i] = p[1]
				}
			}
			for _, r := range res.Rows {
				if v, ok := r[p[0]]; ok {
					delete(r, p[0])
					r[p[1]] = v
				}
			}
		}
	case *query.Stats:
		res.Rows, res.Columns = goStats(res.Rows, c)
		res.Kind = "table"
	case *query.Top:
		var counted []Row
		groups := map[string]Row{}
		keys := append(append([]string{}, c.By...), c.Fields...)
		for _, r := range res.Rows {
			k, ok := groupKey(r, keys)
			if !ok {
				continue
			}
			g, exists := groups[k]
			if !exists {
				g = Row{"count": int64(0)}
				for _, f := range keys {
					g[f] = r[f]
				}
				groups[k] = g
				counted = append(counted, g)
			}
			g["count"] = g["count"].(int64) + 1
		}
		res.Rows, res.Columns = topRows(counted, c)
		res.Kind = "table"
	case *query.Timechart:
		return fmt.Errorf("timechart must come before other commands that change results")
	default:
		return fmt.Errorf("command %q is not supported here", c.Name())
	}
	return nil
}

// topRows turns per-value counts into a top table with percentages,
// limited per by-group.
func topRows(rows []Row, top *query.Top) ([]Row, []string) {
	groupTotals := map[string]int64{}
	byGroup := map[string][]Row{}
	var order []string
	for _, r := range rows {
		k, _ := groupKey(r, top.By)
		if _, ok := byGroup[k]; !ok {
			order = append(order, k)
		}
		byGroup[k] = append(byGroup[k], r)
		n, _ := r["count"].(int64)
		groupTotals[k] += n
	}
	var out []Row
	for _, k := range order {
		g := byGroup[k]
		sort.SliceStable(g, func(i, j int) bool { return g[i]["count"].(int64) > g[j]["count"].(int64) })
		if top.Limit > 0 && len(g) > top.Limit {
			g = g[:top.Limit]
		}
		for _, r := range g {
			if t := groupTotals[k]; t > 0 {
				r["percent"] = math.Round(float64(r["count"].(int64))*10000/float64(t)) / 100
			}
			out = append(out, r)
		}
	}
	cols := append(append(append([]string{}, top.By...), top.Fields...), "count", "percent")
	return out, cols
}

func groupKey(r Row, fields []string) (string, bool) {
	var b strings.Builder
	for _, f := range fields {
		v, ok := r[f]
		if !ok || v == nil {
			return "", false
		}
		b.WriteString(fmt.Sprint(v))
		b.WriteByte(0)
	}
	return b.String(), true
}

type aggState struct {
	count    int64
	sum      float64
	numeric  int64
	min, max float64
	distinct map[string]bool
}

// goStats aggregates rows in memory, for stats after another transform.
func goStats(rows []Row, st *query.Stats) ([]Row, []string) {
	type group struct {
		keys   Row
		states []*aggState
	}
	groups := map[string]*group{}
	var order []string
	for _, r := range rows {
		k, ok := groupKey(r, st.By)
		if !ok {
			continue
		}
		g, exists := groups[k]
		if !exists {
			g = &group{keys: Row{}}
			for _, f := range st.By {
				g.keys[f] = r[f]
			}
			for range st.Aggs {
				g.states = append(g.states, &aggState{min: math.Inf(1), max: math.Inf(-1), distinct: map[string]bool{}})
			}
			groups[k] = g
			order = append(order, k)
		}
		for i, a := range st.Aggs {
			s := g.states[i]
			if a.Field == "" {
				s.count++
				continue
			}
			v, ok := r[a.Field]
			if !ok || v == nil {
				continue
			}
			s.count++
			s.distinct[fmt.Sprint(v)] = true
			if f, ok := asFloat(v); ok {
				s.numeric++
				s.sum += f
				s.min = math.Min(s.min, f)
				s.max = math.Max(s.max, f)
			}
		}
	}
	sort.Strings(order)
	var out []Row
	for _, k := range order {
		g := groups[k]
		row := Row{}
		for f, v := range g.keys {
			row[f] = v
		}
		for i, a := range st.Aggs {
			s := g.states[i]
			var v any
			switch a.Func {
			case "count":
				v = s.count
			case "dc":
				v = int64(len(s.distinct))
			case "sum":
				v = toNumber(s.sum)
			case "avg":
				if s.numeric > 0 {
					v = s.sum / float64(s.numeric)
				}
			case "min":
				if s.numeric > 0 {
					v = toNumber(s.min)
				}
			case "max":
				if s.numeric > 0 {
					v = toNumber(s.max)
				}
			}
			row[a.Column()] = v
		}
		out = append(out, row)
	}
	if len(st.By) == 0 && len(out) == 0 {
		row := Row{}
		for _, a := range st.Aggs {
			if a.Func == "count" || a.Func == "dc" {
				row[a.Column()] = int64(0)
			} else {
				row[a.Column()] = nil
			}
		}
		out = []Row{row}
	}
	return out, append(append([]string{}, st.By...), aggColumns(st.Aggs)...)
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	}
	return 0, false
}

// compareValues orders numbers numerically, everything else as text
// (case-insensitively), and puts missing values last.
func compareValues(a, b any) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return 1
	}
	if b == nil {
		return -1
	}
	fa, oka := asFloat(a)
	fb, okb := asFloat(b)
	if oka && okb {
		switch {
		case fa < fb:
			return -1
		case fa > fb:
			return 1
		}
		return 0
	}
	return strings.Compare(strings.ToLower(fmt.Sprint(a)), strings.ToLower(fmt.Sprint(b)))
}

func evalExpr(e query.Expr, r Row) bool {
	switch e := e.(type) {
	case *query.And:
		for _, c := range e.Children {
			if !evalExpr(c, r) {
				return false
			}
		}
		return true
	case *query.Or:
		for _, c := range e.Children {
			if evalExpr(c, r) {
				return true
			}
		}
		return false
	case *query.Not:
		return !evalExpr(e.Child, r)
	case *query.In:
		for _, v := range e.Values {
			if valueEquals(r[e.Field], v) {
				return true
			}
		}
		return false
	case *query.Compare:
		v, ok := r[e.Field]
		if !ok || v == nil {
			return false
		}
		switch e.Op {
		case "=":
			return valueEquals(v, e.Value)
		case "!=":
			return !valueEquals(v, e.Value)
		}
		cmp := compareValues(v, e.Value)
		switch e.Op {
		case "<":
			return cmp < 0
		case "<=":
			return cmp <= 0
		case ">":
			return cmp > 0
		case ">=":
			return cmp >= 0
		}
	case *query.Text:
		for _, v := range r {
			if strings.Contains(strings.ToLower(fmt.Sprint(v)), strings.ToLower(e.Value)) {
				return true
			}
		}
	}
	return false
}

func valueEquals(v any, want string) bool {
	if v == nil {
		return want == ""
	}
	if want == "*" {
		return true
	}
	if strings.ContainsAny(want, "*?") {
		return globMatch(strings.ToLower(want), strings.ToLower(fmt.Sprint(v)))
	}
	return compareValues(v, want) == 0
}

// globMatch matches * and ? wildcards against the whole string.
func globMatch(pattern, s string) bool {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(s)
}
