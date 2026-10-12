package intel

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strconv"
	"strings"
)

// sniffRows is how many data rows Sniff looks at.
const sniffRows = 50

// Sniff guesses how to read a feed from its content: a STIX bundle or
// TAXII envelope is stix; a CSV file with a header row is csv, with the
// column that holds the most indicators of type typ (column, when given,
// is kept if the header has it); anything else is lines.
func Sniff(data []byte, typ, column string) (format, col string) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if looksLikeSTIX(data) {
		return FormatSTIX, ""
	}
	if c, ok := sniffCSV(data, typ, column); ok {
		return FormatCSV, c
	}
	return FormatLines, ""
}

// looksLikeJSON reports whether data starts like a JSON object or array.
func looksLikeJSON(data []byte) bool {
	t := bytes.TrimSpace(data)
	return len(t) > 0 && (t[0] == '{' || t[0] == '[')
}

func looksLikeSTIX(data []byte) bool {
	t := bytes.TrimSpace(data)
	if !looksLikeJSON(t) {
		return false
	}
	type head struct {
		Type    string          `json:"type"`
		Objects json.RawMessage `json:"objects"`
	}
	if t[0] == '[' {
		var arr []head
		if json.Unmarshal(t, &arr) != nil || len(arr) == 0 {
			return false
		}
		return arr[0].Type != ""
	}
	var h head
	if json.Unmarshal(t, &h) != nil {
		return false
	}
	return h.Type == "bundle" || h.Type == "indicator" || len(h.Objects) > 0
}

// sniffCSV finds a header row (the first row, or the last # comment line
// before the data, as abuse.ch writes it) whose rows have the same number
// of fields, and picks the column with the most valid indicators.
func sniffCSV(data []byte, typ, column string) (string, bool) {
	var lastComment string
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() && len(lines) <= sniffRows {
		t := strings.TrimSpace(sc.Text())
		switch {
		case t == "":
		case strings.HasPrefix(t, "#"):
			if len(lines) == 0 {
				lastComment = strings.TrimSpace(strings.TrimLeft(t, "# "))
			}
		case isComment(t):
		default:
			lines = append(lines, t)
		}
	}
	if len(lines) == 0 {
		return "", false
	}
	header, rows := splitCSV(lines[0]), lines[1:]
	if !isHeader(header) {
		header, rows = splitCSV(lastComment), lines
		if !isHeader(header) {
			return "", false
		}
	}
	if len(rows) == 0 {
		return "", false
	}
	var parsed [][]string
	same := 0
	for _, l := range rows {
		rec := splitCSV(l)
		if len(rec) == len(header) {
			same++
		}
		parsed = append(parsed, rec)
	}
	if same*5 < len(rows)*4 {
		return "", false // under 80% of rows match the header
	}
	if column = strings.TrimSpace(column); column != "" {
		if n, err := strconv.Atoi(column); err == nil && n >= 1 && n <= len(header) {
			return column, true
		}
		for _, h := range header {
			if strings.EqualFold(strings.TrimSpace(h), column) {
				return column, true
			}
		}
	}
	best, bestScore := -1, 0
	for i := range header {
		score := 0
		for _, rec := range parsed {
			if i < len(rec) {
				if _, _, err := Normalize(typ, rec[i]); err == nil {
					score++
				}
			}
		}
		// Prefer a column named like an indicator when two score the same,
		// such as url over urlhaus_link.
		if score > bestScore || (score == bestScore && score > 0 && preferredColumn(header[i]) && !preferredColumn(header[best])) {
			best, bestScore = i, score
		}
	}
	if best < 0 {
		return "", false
	}
	name := strings.TrimSpace(header[best])
	dup := 0
	for _, h := range header {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			dup++
		}
	}
	if name == "" || dup > 1 {
		return strconv.Itoa(best + 1), true
	}
	return name, true
}

func splitCSV(line string) []string {
	r := csv.NewReader(strings.NewReader(line))
	r.LazyQuotes = true
	r.TrimLeadingSpace = true
	rec, err := r.Read()
	if err != nil {
		return nil
	}
	return rec
}

// isHeader reports whether a row looks like column names: two or more
// fields, none of them an indicator, and at least one a word.
func isHeader(rec []string) bool {
	if len(rec) < 2 {
		return false
	}
	words := 0
	for _, f := range rec {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if _, _, err := Normalize("auto", f); err == nil {
			return false
		}
		if strings.IndexFunc(f, func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }) >= 0 {
			words++
		}
	}
	return words > 0
}

var preferredNames = []string{"ioc", "ioc_value", "indicator", "value", "url", "domain", "hostname", "host",
	"ip", "ip_address", "ipaddress", "dst_ip", "dstip", "src_ip", "md5", "md5_hash", "sha1", "sha1_hash",
	"sha256", "sha256_hash", "email", "network", "cidr"}

func preferredColumn(h string) bool {
	h = strings.ToLower(strings.TrimSpace(h))
	for _, n := range preferredNames {
		if h == n {
			return true
		}
	}
	return false
}

// SuggestType names the feed type that fits the indicators found: one
// type or class when they all share it, otherwise auto.
func SuggestType(byType map[string]int) string {
	classes := map[string]bool{}
	types := 0
	last := ""
	for t, n := range byType {
		if n > 0 {
			classes[Class(t)] = true
			types++
			last = t
		}
	}
	switch {
	case len(classes) != 1:
		return "auto"
	case types == 1:
		return last
	}
	for c := range classes {
		return c // ip (addresses and networks) or hash (several kinds)
	}
	return "auto"
}
