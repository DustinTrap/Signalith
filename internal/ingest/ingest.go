// Package ingest turns raw records from agents (Fluent Bit) into normalized
// events and writes them to OpenSearch. Each source type has a parser that
// maps the record onto a data model; unrecognized events land in "Other"
// and stay searchable by text.
package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Event is a normalized event before it is indexed.
type Event struct {
	Time   time.Time
	Model  string
	Fields map[string]any
}

// Bulker writes documents in bulk.
type Bulker interface {
	Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)
}

// Pipeline parses records and writes them.
type Pipeline struct {
	Store  Bulker
	Prefix string
	Now    func() time.Time

	stats Stats
}

// Stats counts what the pipeline has processed since start, for the health page.
type Stats struct {
	Received atomic.Int64
	Indexed  atomic.Int64
	Failed   atomic.Int64
	LastSeen atomic.Int64 // unix seconds
}

// Snapshot is a JSON-friendly copy of Stats.
type Snapshot struct {
	Received int64     `json:"received"`
	Indexed  int64     `json:"indexed"`
	Failed   int64     `json:"failed"`
	LastSeen time.Time `json:"last_seen,omitzero"`
}

// Stats returns current counters.
func (p *Pipeline) Stats() Snapshot {
	s := Snapshot{
		Received: p.stats.Received.Load(),
		Indexed:  p.stats.Indexed.Load(),
		Failed:   p.stats.Failed.Load(),
	}
	if ls := p.stats.LastSeen.Load(); ls > 0 {
		s.LastSeen = time.Unix(ls, 0).UTC()
	}
	return s
}

func (p *Pipeline) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Result reports one ingest call.
type Result struct {
	Received int                   `json:"received"`
	Indexed  int                   `json:"indexed"`
	Errors   []store.BulkItemError `json:"errors,omitempty"`
}

// Ingest normalizes records sent with a Fluent Bit tag and writes them.
func (p *Pipeline) Ingest(ctx context.Context, tag string, records []map[string]any) (*Result, error) {
	prefix := p.Prefix
	if prefix == "" {
		prefix = "signalith"
	}
	p.stats.Received.Add(int64(len(records)))
	p.stats.LastSeen.Store(p.now().Unix())
	docs := make([]store.IndexedDoc, 0, len(records))
	for _, r := range records {
		ev := Normalize(tag, r, p.now())
		docs = append(docs, store.IndexedDoc{
			Index: datamodel.IndexName(prefix, ev.Model, ev.Time.UTC().Format("2006.01.02")),
			Doc:   ev.Document(),
		})
	}
	errs, err := p.Store.Bulk(ctx, docs)
	if err != nil {
		p.stats.Failed.Add(int64(len(docs)))
		return nil, err
	}
	p.stats.Indexed.Add(int64(len(docs) - len(errs)))
	p.stats.Failed.Add(int64(len(errs)))
	return &Result{Received: len(records), Indexed: len(docs) - len(errs), Errors: errs}, nil
}

// Document returns the OpenSearch document for an event, dropping empty
// values so searches like user=* only match real values.
func (e Event) Document() map[string]any {
	doc := map[string]any{
		"@timestamp": e.Time.UTC().Format(time.RFC3339Nano),
		"datamodel":  e.Model,
	}
	for k, v := range e.Fields {
		if s, ok := v.(string); ok {
			s = strings.TrimSpace(s)
			if s == "" || s == "-" {
				continue
			}
			v = s
		}
		if v == nil {
			continue
		}
		doc[k] = v
	}
	return doc
}

// Normalize maps one record to an event. tag is the Fluent Bit tag, which
// says what kind of source the record came from.
func Normalize(tag string, r map[string]any, now time.Time) Event {
	var ev Event
	switch {
	case isWindowsRecord(tag, r):
		ev = parseWindows(r)
	case strings.HasPrefix(tag, "linux.journal") || has(r, "MESSAGE"):
		ev = parseJournal(r)
	case strings.HasPrefix(tag, "linux.") || strings.HasPrefix(tag, "syslog") || has(r, "log"):
		ev = parseSyslogLine(str(r, "log", "message"), sourcetypeForTag(tag), now)
	default:
		ev = parseGeneric(r)
	}
	if ev.Time.IsZero() {
		ev.Time = recordTime(r, now)
	}
	if ev.Model == "" {
		ev.Model = "Other"
	}
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	if _, ok := ev.Fields["message"]; !ok {
		raw, _ := json.Marshal(r)
		ev.Fields["message"] = string(raw)
	}
	return ev
}

func sourcetypeForTag(tag string) string {
	switch {
	case strings.HasPrefix(tag, "linux.auth"):
		return "linux:auth"
	case strings.HasPrefix(tag, "syslog"):
		return "syslog"
	case strings.HasPrefix(tag, "linux."):
		return "linux:" + strings.TrimPrefix(tag, "linux.")
	}
	return "syslog"
}

func parseGeneric(r map[string]any) Event {
	fields := map[string]any{"sourcetype": "json"}
	for k, v := range r {
		if k == "date" {
			continue
		}
		switch v.(type) {
		case map[string]any, []any:
			b, _ := json.Marshal(v)
			fields[k] = string(b)
		default:
			fields[k] = v
		}
	}
	return Event{Model: "Other", Fields: fields}
}

// recordTime reads Fluent Bit's "date" key (epoch seconds as a float, or an
// ISO string), falling back to now.
func recordTime(r map[string]any, now time.Time) time.Time {
	switch d := r["date"].(type) {
	case float64:
		sec := int64(d)
		return time.Unix(sec, int64((d-float64(sec))*1e9)).UTC()
	case json.Number:
		if f, err := d.Float64(); err == nil {
			sec := int64(f)
			return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC()
		}
	case string:
		if t, ok := parseTime(d); ok {
			return t
		}
	}
	return now.UTC()
}

var timeLayouts = []string{
	time.RFC3339Nano,
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05.000000000 -0700",
	"2006-01-02 15:04:05 MST",
	"2006-01-02T15:04:05.000000000Z",
	"2006-01-02 15:04:05.000",
	"2006-01-02 15:04:05",
}

func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, l := range timeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func has(r map[string]any, k string) bool {
	_, ok := r[k]
	return ok
}

// str returns the first present key as a string.
func str(r map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := r[k]; ok && v != nil {
			switch x := v.(type) {
			case string:
				return x
			case json.Number:
				return x.String()
			case float64:
				return strconv.FormatFloat(x, 'f', -1, 64)
			default:
				return fmt.Sprint(x)
			}
		}
	}
	return ""
}

// atoi returns a number for numeric strings, or nil.
func atoi(s string) any {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		if n, err := strconv.ParseInt(s[2:], 16, 64); err == nil {
			return n
		}
	}
	return nil
}

// baseName returns the file name of a Windows or Unix path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}
