package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Feed formats.
const (
	FormatLines = "lines" // one indicator per line, # comments
	FormatCSV   = "csv"   // one column of a CSV file
	FormatSTIX  = "stix"  // a STIX 2.1 bundle of indicator objects
)

// Formats lists the feed formats.
var Formats = []string{FormatLines, FormatCSV, FormatSTIX}

// ParseOptions say how to read a feed.
type ParseOptions struct {
	Format string
	Type   string // auto, hash or one type
	// Column is the CSV column: a header name or a 1-based number.
	Column string
	Now    time.Time
}

// ParseResult is what a feed contained.
type ParseResult struct {
	Indicators []Indicator
	// Skipped counts values that were not valid indicators of the type.
	Skipped int
	// Example is the first skipped value, to help fix a feed's settings.
	Example string
}

// maxIndicators caps one feed, so a wrong URL cannot fill memory.
const maxIndicators = 2_000_000

func (r *ParseResult) add(o ParseOptions, value, desc string, expires time.Time, tags []string, seen map[string]bool) {
	if len(r.Indicators) >= maxIndicators {
		r.Skipped++
		return
	}
	typ, val, err := Normalize(o.Type, value)
	if err != nil {
		r.Skipped++
		if r.Example == "" {
			r.Example = value
			if len(r.Example) > 120 {
				r.Example = r.Example[:120] + "…"
			}
		}
		return
	}
	if seen[typ+"\x00"+val] {
		return
	}
	seen[typ+"\x00"+val] = true
	r.Indicators = append(r.Indicators, Indicator{Type: typ, Value: val, Description: desc, Expires: expires, Tags: tags})
}

// Parse reads a downloaded feed.
func Parse(data []byte, o ParseOptions) (*ParseResult, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	switch o.Format {
	case "", FormatLines:
		return parseLines(data, o)
	case FormatCSV:
		return parseCSV(data, o)
	case FormatSTIX:
		return parseSTIX(data, o)
	}
	return nil, fmt.Errorf("format %q must be one of %s", o.Format, strings.Join(Formats, ", "))
}

func isComment(line string) bool {
	return line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//")
}

// parseLines takes the first word of each line, so lists like Spamhaus
// DROP ("1.2.3.0/24 ; SBL123") and hosts files ("0.0.0.0 evil.com") work:
// in a hosts file the second word is the indicator.
func parseLines(data []byte, o ParseOptions) (*ParseResult, error) {
	res := &ParseResult{}
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if isComment(line) {
			continue
		}
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ' ' || r == '\t' || r == ';' || r == ',' })
		if len(fields) == 0 {
			continue
		}
		v := fields[0]
		if (v == "0.0.0.0" || v == "127.0.0.1") && len(fields) > 1 {
			v = fields[1]
		}
		res.add(o, v, "", time.Time{}, nil, seen)
	}
	return res, sc.Err()
}

// parseCSV reads one column. A named column is found in the first row,
// or in the last comment line before the data, which is where abuse.ch
// feeds put their header ("# first_seen_utc,dst_ip,...").
func parseCSV(data []byte, o ParseOptions) (*ParseResult, error) {
	col := -1
	if n, err := strconv.Atoi(strings.TrimSpace(o.Column)); err == nil {
		if n < 1 {
			return nil, errors.New("column numbers start at 1")
		}
		col = n - 1
	}
	name := strings.ToLower(strings.TrimSpace(o.Column))
	if col < 0 && name == "" {
		return nil, errors.New("csv feeds need a column: a header name or a number starting at 1")
	}
	var lastComment string
	var body bytes.Buffer
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Text()
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			if body.Len() == 0 {
				lastComment = strings.TrimSpace(strings.TrimLeft(t, "# "))
			}
			continue
		}
		if t == "" {
			continue
		}
		body.WriteString(line)
		body.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	r := csv.NewReader(&body)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	findIn := func(rec []string) int {
		for i, h := range rec {
			if strings.EqualFold(strings.TrimSpace(h), name) {
				return i
			}
		}
		return -1
	}
	res := &ParseResult{}
	seen := map[string]bool{}
	first := true
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if first {
			first = false
			if col < 0 {
				if i := findIn(rec); i >= 0 {
					col = i
					continue // the header row
				}
				if lastComment != "" {
					hr := csv.NewReader(strings.NewReader(lastComment))
					hr.LazyQuotes = true
					if h, err := hr.Read(); err == nil {
						col = findIn(h)
					}
				}
				if col < 0 {
					return nil, fmt.Errorf("no column named %q; the first row is: %s", o.Column, strings.Join(rec, ","))
				}
			}
		}
		if col >= len(rec) {
			res.Skipped++
			continue
		}
		res.add(o, rec[col], "", time.Time{}, nil, seen)
	}
	return res, nil
}

// STIX objects Signalith reads.
type stixObject struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Pattern     string   `json:"pattern"`
	PatternType string   `json:"pattern_type"`
	ValidUntil  string   `json:"valid_until"`
	Revoked     bool     `json:"revoked"`
	Labels      []string `json:"labels"`
	// Indicator types in STIX 2.1, such as malicious-activity.
	IndicatorTypes []string `json:"indicator_types"`
}

// stixComparison matches one "object:path = 'value'" in a pattern.
var stixComparison = regexp.MustCompile(`([a-z0-9-]+):([A-Za-z0-9_.'\-]+)\s*=\s*'((?:[^'\\]|\\.)*)'`)

// stixType maps a STIX object path to an indicator type.
func stixType(object, path string) string {
	path = strings.ToLower(strings.ReplaceAll(path, "'", ""))
	switch object {
	case "ipv4-addr", "ipv6-addr":
		if path == "value" {
			return "ip"
		}
	case "domain-name":
		if path == "value" {
			return TypeDomain
		}
	case "url":
		if path == "value" {
			return TypeURL
		}
	case "email-addr":
		if path == "value" {
			return TypeEmail
		}
	case "email-message":
		if path == "from_ref.value" || path == "sender_ref.value" {
			return TypeEmail
		}
	case "file", "artifact":
		switch path {
		case "hashes.md5":
			return TypeMD5
		case "hashes.sha-1", "hashes.sha1":
			return TypeSHA1
		case "hashes.sha-256", "hashes.sha256":
			return TypeSHA256
		}
	}
	return ""
}

// parseSTIX reads a STIX 2.x bundle, a TAXII 2.1 envelope ({"objects":
// [...]}), a bare array of objects or a single indicator. Every
// comparison in an indicator's pattern becomes an indicator; patterns of
// other languages and revoked or expired indicators are skipped.
func parseSTIX(data []byte, o ParseOptions) (*ParseResult, error) {
	var objs []stixObject
	trimmed := bytes.TrimSpace(data)
	switch {
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &objs); err != nil {
			return nil, fmt.Errorf("not a STIX bundle: %v", err)
		}
	default:
		var env struct {
			Type    string       `json:"type"`
			Objects []stixObject `json:"objects"`
		}
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("not a STIX bundle: %v", err)
		}
		if env.Objects != nil {
			objs = env.Objects
		} else if env.Type == "indicator" {
			var one stixObject
			_ = json.Unmarshal(trimmed, &one)
			objs = []stixObject{one}
		} else {
			return nil, errors.New(`not a STIX bundle: expected {"type": "bundle", "objects": [...]}`)
		}
	}
	res := &ParseResult{}
	seen := map[string]bool{}
	for _, obj := range objs {
		if obj.Type != "indicator" || obj.Revoked || (obj.PatternType != "" && obj.PatternType != "stix") {
			continue
		}
		var exp time.Time
		if obj.ValidUntil != "" {
			if t, err := time.Parse(time.RFC3339, obj.ValidUntil); err == nil {
				if !o.Now.IsZero() && !t.After(o.Now) {
					continue
				}
				exp = t.UTC()
			}
		}
		desc := obj.Name
		if obj.Description != "" {
			if desc != "" {
				desc += ": "
			}
			desc += obj.Description
		}
		if len(desc) > 500 {
			desc = desc[:500] + "…"
		}
		tags := append(append([]string{}, obj.IndicatorTypes...), obj.Labels...)
		for _, m := range stixComparison.FindAllStringSubmatch(obj.Pattern, -1) {
			typ := stixType(m[1], m[2])
			if typ == "" {
				continue
			}
			value := strings.ReplaceAll(strings.ReplaceAll(m[3], `\'`, `'`), `\\`, `\`)
			sub := o
			if sub.Type == "" || sub.Type == "auto" {
				sub.Type = typ
			} else if sub.Type != typ && !(sub.Type == "hash" && Class(typ) == "hash") && Class(sub.Type) != Class(typ) {
				continue // the feed is limited to another type
			}
			res.add(sub, value, desc, exp, tags, seen)
		}
	}
	return res, nil
}
