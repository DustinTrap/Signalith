// Package search compiles parsed queries into OpenSearch requests, runs them,
// and applies the remaining pipe commands to the results in Go.
package search

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// TimeField is the event timestamp field in every Signalith index.
const TimeField = "@timestamp"

// RawField is the name users see for the original event text. It is stored
// as StoredRawField because OpenSearch reserves leading-underscore names.
const RawField = "_raw"

// StoredRawField is where the original event text lives in OpenSearch.
const StoredRawField = "message"

// compileExpr turns a filter expression into OpenSearch query DSL.
func compileExpr(e query.Expr) (map[string]any, error) {
	switch e := e.(type) {
	case nil:
		return map[string]any{"match_all": map[string]any{}}, nil
	case *query.And:
		var fs []any
		for _, c := range e.Children {
			q, err := compileExpr(c)
			if err != nil {
				return nil, err
			}
			fs = append(fs, q)
		}
		return boolQuery("filter", fs), nil
	case *query.Or:
		var ss []any
		for _, c := range e.Children {
			q, err := compileExpr(c)
			if err != nil {
				return nil, err
			}
			ss = append(ss, q)
		}
		return map[string]any{"bool": map[string]any{"should": ss, "minimum_should_match": 1}}, nil
	case *query.Not:
		q, err := compileExpr(e.Child)
		if err != nil {
			return nil, err
		}
		return boolQuery("must_not", []any{q}), nil
	case *query.Text:
		return textQuery(e.Value), nil
	case *query.In:
		var ss []any
		for _, v := range e.Values {
			ss = append(ss, equalsQuery(e.Field, v))
		}
		return map[string]any{"bool": map[string]any{"should": ss, "minimum_should_match": 1}}, nil
	case *query.Compare:
		return compareQuery(e)
	}
	return nil, fmt.Errorf("unsupported expression %T", e)
}

func boolQuery(clause string, qs []any) map[string]any {
	return map[string]any{"bool": map[string]any{clause: qs}}
}

func compareQuery(c *query.Compare) (map[string]any, error) {
	if c.Field == RawField && (c.Op == "=" || c.Op == "!=") {
		q := textQuery(c.Value)
		if c.Op == "!=" {
			return boolQuery("must_not", []any{q}), nil
		}
		return q, nil
	}
	switch c.Op {
	case "=":
		return equalsQuery(c.Field, c.Value), nil
	case "!=":
		return boolQuery("must_not", []any{equalsQuery(c.Field, c.Value)}), nil
	case "<", "<=", ">", ">=":
		key := map[string]string{"<": "lt", "<=": "lte", ">": "gt", ">=": "gte"}[c.Op]
		var v any = c.Value
		if n, ok := parseNumber(c.Value); ok {
			v = n
		}
		field := c.Field
		if field == "_time" {
			field = TimeField
			v = toDateMath(c.Value)
		}
		return map[string]any{"range": map[string]any{field: map[string]any{key: v}}}, nil
	}
	return nil, fmt.Errorf("unsupported operator %q", c.Op)
}

func equalsQuery(field, value string) map[string]any {
	if field == "_time" {
		field = TimeField
	}
	if field == RawField {
		field = StoredRawField
	}
	if value == "*" {
		return map[string]any{"exists": map[string]any{"field": field}}
	}
	if strings.ContainsAny(value, "*?") {
		return map[string]any{"wildcard": map[string]any{field: map[string]any{"value": value, "case_insensitive": true}}}
	}
	if _, ok := parseNumber(value); ok {
		// Numbers match both numeric and keyword fields exactly.
		return map[string]any{"term": map[string]any{field: map[string]any{"value": value}}}
	}
	return map[string]any{"term": map[string]any{field: map[string]any{"value": value, "case_insensitive": true}}}
}

var queryStringReserved = regexp.MustCompile(`[+\-=&|><!(){}\[\]^"~:\\/]`)

func textQuery(v string) map[string]any {
	if strings.ContainsAny(v, " \t") {
		return map[string]any{"match_phrase": map[string]any{StoredRawField: v}}
	}
	escaped := queryStringReserved.ReplaceAllString(v, `\$0`)
	return map[string]any{"query_string": map[string]any{
		"query":                  escaped,
		"default_field":          StoredRawField,
		"analyze_wildcard":       true,
		"allow_leading_wildcard": true,
	}}
}

func parseNumber(s string) (any, bool) {
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && !strings.ContainsAny(s, "eEnN") {
		return f, true
	}
	return nil, false
}

// ---- time ----

var relTime = regexp.MustCompile(`^([+-]?)(\d*)([a-zA-Z]*)(?:@([a-zA-Z]+))?$`)

var unitMap = map[string]string{
	"s": "s", "sec": "s", "secs": "s", "second": "s", "seconds": "s",
	"m": "m", "min": "m", "mins": "m", "minute": "m", "minutes": "m",
	"h": "h", "hr": "h", "hrs": "h", "hour": "h", "hours": "h",
	"d": "d", "day": "d", "days": "d",
	"w": "w", "week": "w", "weeks": "w",
	"mon": "M", "month": "M", "months": "M",
	"y": "y", "yr": "y", "year": "y", "years": "y",
}

// toDateMath converts SPL-style relative times ("-24h", "-7d@d", "@w",
// "now") to OpenSearch date math. Absolute times pass through unchanged.
func toDateMath(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.EqualFold(v, "now") {
		return "now"
	}
	if strings.HasPrefix(v, "now") {
		return v
	}
	m := relTime.FindStringSubmatch(v)
	if m == nil || (m[1] == "" && m[4] == "") {
		return v // absolute: ISO 8601 or epoch millis
	}
	out := "now"
	if m[3] != "" || m[2] != "" {
		unit, ok := unitMap[strings.ToLower(m[3])]
		if !ok {
			return v
		}
		n := m[2]
		if n == "" {
			n = "1"
		}
		sign := m[1]
		if sign == "" {
			sign = "+"
		}
		out += sign + n + unit
	}
	if m[4] != "" {
		unit, ok := unitMap[strings.ToLower(m[4])]
		if !ok {
			return v
		}
		out += "/" + unit
	}
	return out
}

// relativeDuration estimates how far back a relative time reaches, for
// choosing a timechart span. ok is false for absolute times.
func relativeDuration(v string) (time.Duration, bool) {
	m := relTime.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil || m[1] != "-" {
		return 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		n = 1
	}
	unit := map[string]time.Duration{
		"s": time.Second, "m": time.Minute, "h": time.Hour, "d": 24 * time.Hour,
		"w": 7 * 24 * time.Hour, "M": 30 * 24 * time.Hour, "y": 365 * 24 * time.Hour,
	}[unitMap[strings.ToLower(m[3])]]
	if unit == 0 {
		return 0, false
	}
	return time.Duration(n) * unit, true
}

// autoSpan picks a timechart bucket size for a time range, as SPL does.
func autoSpan(earliest string) string {
	d, ok := relativeDuration(earliest)
	switch {
	case !ok:
		return "1h"
	case d <= 4*time.Hour:
		return "1m"
	case d <= 24*time.Hour:
		return "30m"
	case d <= 7*24*time.Hour:
		return "3h"
	case d <= 31*24*time.Hour:
		return "12h"
	}
	return "1d"
}

// spanInterval converts a span to a date_histogram interval setting.
func spanInterval(span string) (map[string]any, error) {
	m := regexp.MustCompile(`^(\d+)([a-zA-Z]+)$`).FindStringSubmatch(span)
	if m == nil {
		return nil, fmt.Errorf("invalid span %q; use forms like 30m, 1h, 1d", span)
	}
	unit, ok := unitMap[strings.ToLower(m[2])]
	if !ok {
		return nil, fmt.Errorf("invalid span unit in %q", span)
	}
	n, _ := strconv.Atoi(m[1])
	switch unit {
	case "w":
		return map[string]any{"fixed_interval": strconv.Itoa(n*7) + "d"}, nil
	case "M", "y":
		if n != 1 {
			return nil, fmt.Errorf("span %q: months and years support a span of 1 only", span)
		}
		return map[string]any{"calendar_interval": map[string]string{"M": "month", "y": "year"}[unit]}, nil
	}
	return map[string]any{"fixed_interval": strconv.Itoa(n) + unit}, nil
}
