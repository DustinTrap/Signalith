package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

// Edit is a change made on the Settings page.
type Edit struct {
	// Values are new values by key, as JSON decoded them. An empty secret
	// keeps the saved one.
	Values map[string]any
	// Clear lists secrets to remove.
	Clear []string
	// Reset lists settings to take off the page, so signalith.yaml or the
	// default applies again.
	Reset []string
	// ResetAll takes every setting off the page, even when the page's
	// file cannot be read.
	ResetAll bool
	// Retry lists changes a restart set aside, to use again.
	Retry []string
	By    string
	At    time.Time
}

// EditResult is an edit checked against the whole configuration.
type EditResult struct {
	// Page is the Settings page's file with the edit; write it with
	// WritePageSettings when there are no problems.
	Page *PageSettings
	// Config is the configuration the edit gives.
	Config *Config
	// Before is the configuration as saved before the edit.
	Before *Config
	// Changed lists the settings whose value changes, in page order.
	Changed []string
	// Fields holds the problems by setting, in plain words for the page.
	Fields map[string]string
	// Problems lists problems that are not about a setting on the page,
	// such as a mistake in signalith.yaml.
	Problems []string
}

// OK reports whether the edit can be saved.
func (r *EditResult) OK() bool { return len(r.Fields) == 0 && len(r.Problems) == 0 }

// ErrPageFile is returned by CheckEdit when the page's file cannot be read
// and the edit would keep its settings.
var ErrPageFile = errors.New("the settings file cannot be read")

// CheckEdit applies an edit to the settings saved on the page and checks
// the whole configuration it gives, as Validate does at startup, without
// saving anything.
func CheckEdit(path string, e Edit) (*EditResult, error) {
	saved, err := LoadSaved(path)
	if err != nil {
		return nil, err
	}
	if saved.PageErr != nil && !e.ResetAll {
		return nil, fmt.Errorf("%w: %v. Reset all settings to start the file again, or fix it on the server", ErrPageFile, saved.PageErr)
	}
	before := saved.Config
	page := saved.Page.Clone()
	if e.ResetAll {
		page = &PageSettings{}
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	res := &EditResult{Before: before, Fields: map[string]string{}}
	touched := map[string]bool{}
	typed := map[string]string{}
	locked := func(key string) bool {
		if env := before.layers.env[key]; env != "" {
			res.Fields[key] = LockedReason(env)
			return true
		}
		return false
	}
	for _, key := range sortedKeys(e.Values) {
		s, ok := Lookup(key)
		if !ok {
			res.Fields[key] = notOnPage(key)
			continue
		}
		if locked(key) {
			continue
		}
		v, err := ParseValue(s, e.Values[key])
		if err == nil && s.check != nil {
			err = s.check(v)
		}
		if err != nil {
			res.Fields[key] = sentence(err.Error())
			continue
		}
		touched[key] = true
		if e := page.Settings[key]; e != nil && e.Refused != "" {
			// A change set aside by a restart is replaced by this one.
			page.Remove(key)
		}
		if s.Type == TypeSecret {
			if v.(string) != "" {
				typed[key] = v.(string)
			}
			continue
		}
		if reflect.DeepEqual(before.Value(key), v) {
			continue
		}
		if err := page.Set(key, v, e.By, e.At); err != nil {
			return nil, err
		}
	}
	for _, key := range e.Clear {
		s, ok := Lookup(key)
		switch {
		case !ok:
			res.Fields[key] = notOnPage(key)
		case s.Type != TypeSecret:
			res.Fields[key] = "Only passwords and keys can be cleared; use Reset instead."
		case locked(key):
		default:
			touched[key] = true
			delete(typed, key)
			page.SetSecret(key, "", "", e.By, e.At)
		}
	}
	for _, key := range e.Reset {
		if _, ok := Lookup(key); !ok {
			res.Fields[key] = notOnPage(key)
			continue
		}
		touched[key] = true
		delete(typed, key)
		page.Remove(key)
	}
	for _, key := range e.Retry {
		if _, ok := Lookup(key); !ok {
			res.Fields[key] = notOnPage(key)
			continue
		}
		if en := page.Settings[key]; en != nil && en.Refused != "" {
			touched[key] = true
			en.Refused, en.RefusedAt, en.CheckedAt = "", time.Time{}, time.Time{}
		}
	}
	if e.ResetAll {
		for _, s := range Registry {
			touched[s.Key] = true
		}
	}
	// A secret typed now may be sent to the address the edited settings
	// point at, and only there.
	if len(typed) > 0 {
		c, err := build(path, page)
		if err != nil {
			return nil, err
		}
		for _, key := range sortedKeys(typed) {
			s, _ := Lookup(key)
			page.SetSecret(key, typed[key], s.SentTo(c), e.By, e.At)
		}
	}
	after, err := build(path, page)
	if err != nil {
		return nil, err
	}
	res.Page, res.Config = page, after
	fields, rest := FieldProblems(after, problemsOf(after))
	for _, k := range sortedKeys(fields) {
		res.setField(k, fields[k])
	}
	res.Problems = append(res.Problems, rest...)
	if touched["server.tls_cert"] || touched["server.tls_key"] {
		if c, k := after.Server.TLSCert, after.Server.TLSKey; c != "" && k != "" {
			if _, err := tls.LoadX509KeyPair(c, k); err != nil {
				res.setField("server.tls_cert", "The certificate and key files cannot be used: "+err.Error())
			}
		}
	}
	// A saved secret that would now be sent somewhere else must be
	// entered again.
	for _, m := range after.layers.mismatch {
		s, _ := Lookup(m.Key)
		moved := touched[m.Key]
		for _, k := range s.SentWith {
			moved = moved || touched[k]
		}
		if !moved {
			continue
		}
		what := s.Noun()
		if env := after.layers.env[m.Key]; env != "" {
			msg := fmt.Sprintf("The %s comes from the %s environment variable and is only sent to %s. To use another address, change it where that variable is set.", what, env, orNone(m.Bound))
			for _, k := range s.SentWith {
				if touched[k] {
					res.setField(k, msg)
				}
			}
			continue
		}
		res.setField(m.Key, fmt.Sprintf("Enter the %s again, or reset it: the saved one is only sent to %s.", what, orNone(m.Bound)))
	}
	for _, s := range Registry {
		// A secret typed again counts as a change even when it is the same.
		if !SameValue(before, after, s.Key) || typed[s.Key] != "" {
			res.Changed = append(res.Changed, s.Key)
		}
	}
	return res, nil
}

// FieldProblems sorts the problems of c, as Validate words them, by the
// setting on the page they are about, worded for its field, and returns
// the rest, which are about settings that are not on the page.
func FieldProblems(c *Config, problems []string) (map[string]string, []string) {
	fields := map[string]string{}
	if len(problems) == 0 {
		return fields, nil
	}
	for i := range Registry {
		s := &Registry[i]
		if s.problem == nil {
			continue
		}
		if msg := s.problem(c); msg != "" {
			fields[s.Key] = msg
		}
	}
	var rest []string
	for _, p := range problems {
		placed := false
		for _, k := range ProblemKeys(p) {
			if _, ok := Lookup(k); ok {
				if _, dup := fields[k]; !dup {
					fields[k] = PlainProblem(k, p)
				}
				placed = true
			}
		}
		if !placed {
			rest = append(rest, p)
		}
	}
	return fields, rest
}

// setField records a field's problem; the first one stays.
func (r *EditResult) setField(key, msg string) {
	if _, ok := r.Fields[key]; !ok {
		r.Fields[key] = msg
	}
}

// notOnPage explains why a key cannot be changed on the page.
func notOnPage(key string) string {
	if ex, ok := Excluded[key]; ok {
		return "This setting is not changed on this page. " + ex.Reason
	}
	return "There is no setting called " + key + "."
}

// sentence makes an error message a sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	s = upperFirst(s)
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// sortedKeys returns a map's keys in page order, then any others.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	order := map[string]int{}
	for i, s := range Registry {
		order[s.Key] = i
	}
	sort.Slice(keys, func(i, j int) bool {
		oi, iok := order[keys[i]]
		oj, jok := order[keys[j]]
		if iok != jok {
			return iok
		}
		if iok {
			return oi < oj
		}
		return keys[i] < keys[j]
	})
	return keys
}

// checkEarliest checks a default time range.
func checkEarliest(v any) error {
	if err := search.ValidEarliest(v.(string)); err != nil {
		return err
	}
	return nil
}
