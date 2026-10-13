// Package assets holds the asset and identity lists that give events
// business context, like the Splunk ES asset and identity framework: who
// owns a host, how critical it is, who a username belongs to, and whether
// they are on a watchlist.
//
// Both lists are CSV files an admin can export from a CMDB or HR system.
package assets

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Priorities, lowest first. Priority scales risk and raises urgency.
var Priorities = []string{"low", "medium", "high", "critical"}

// Asset is one host or network range.
type Asset struct {
	Host     []string `json:"host,omitempty"` // host names, short or fully qualified
	IP       []string `json:"ip,omitempty"`
	CIDR     []string `json:"cidr,omitempty"`
	Owner    string   `json:"owner,omitempty"`
	Priority string   `json:"priority,omitempty"`
	Category []string `json:"category,omitempty"`
	BUnit    string   `json:"bunit,omitempty"`
	Location string   `json:"location,omitempty"`
}

// Identity is one person or service account.
type Identity struct {
	Identity  []string `json:"identity"` // usernames and aliases
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Manager   string   `json:"manager,omitempty"`
	Priority  string   `json:"priority,omitempty"`
	Category  []string `json:"category,omitempty"`
	BUnit     string   `json:"bunit,omitempty"`
	Watchlist bool     `json:"watchlist,omitempty"`
}

// Columns are the CSV headers each list accepts. Multi-value cells use |.
var (
	AssetColumns    = []string{"host", "ip", "cidr", "owner", "priority", "category", "bunit", "location"}
	IdentityColumns = []string{"identity", "name", "email", "manager", "priority", "category", "bunit", "watchlist"}
)

// LineError is a problem on one CSV line.
type LineError struct {
	Line int    `json:"line"`
	Msg  string `json:"msg"`
}

// ParseError lists every bad line.
type ParseError struct{ Lines []LineError }

func (e *ParseError) Error() string {
	var parts []string
	for _, l := range e.Lines {
		parts = append(parts, fmt.Sprintf("line %d: %s", l.Line, l.Msg))
	}
	return strings.Join(parts, "; ")
}

func splitMulti(s string) []string {
	var out []string
	for _, p := range strings.Split(s, "|") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// readCSV returns rows as maps keyed by lower-case header, checking that
// every header is known and the required one is present.
func readCSV(data []byte, known []string, required string) ([]map[string]string, []int, error) {
	r := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(data, []byte("\ufeff"))))
	r.FieldsPerRecord = -1
	r.TrimLeadingSpace = true
	header, err := r.Read()
	if errors.Is(err, io.EOF) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	for i, h := range header {
		header[i] = strings.ToLower(strings.TrimSpace(h))
		if !slices.Contains(known, header[i]) {
			return nil, nil, fmt.Errorf("unknown column %q; columns are: %s", h, strings.Join(known, ", "))
		}
	}
	if !slices.Contains(header, required) && !(required == "host" && (slices.Contains(header, "ip") || slices.Contains(header, "cidr"))) {
		return nil, nil, fmt.Errorf("missing column %q", required)
	}
	var rows []map[string]string
	var lines []int
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		line, _ := r.FieldPos(0)
		m := map[string]string{}
		empty := true
		for i, v := range rec {
			if i < len(header) {
				m[header[i]] = strings.TrimSpace(unquoteCell(v))
				if m[header[i]] != "" {
					empty = false
				}
			}
		}
		if !empty {
			rows = append(rows, m)
			lines = append(lines, line)
		}
	}
	return rows, lines, nil
}

func checkPriority(p string) (string, error) {
	p = strings.ToLower(p)
	if p == "" || slices.Contains(Priorities, p) {
		return p, nil
	}
	return "", fmt.Errorf("priority %q must be one of %s", p, strings.Join(Priorities, ", "))
}

// ParseAssets reads an asset CSV.
func ParseAssets(data []byte) ([]Asset, error) {
	rows, lines, err := readCSV(data, AssetColumns, "host")
	if err != nil {
		return nil, err
	}
	var out []Asset
	var bad []LineError
	for i, m := range rows {
		a := Asset{Host: splitMulti(m["host"]), IP: splitMulti(m["ip"]), CIDR: splitMulti(m["cidr"]),
			Owner: m["owner"], Category: splitMulti(m["category"]), BUnit: m["bunit"], Location: m["location"]}
		var msgs []string
		if a.Priority, err = checkPriority(m["priority"]); err != nil {
			msgs = append(msgs, err.Error())
		}
		for _, ip := range a.IP {
			if _, err := netip.ParseAddr(ip); err != nil {
				msgs = append(msgs, fmt.Sprintf("ip %q is not an IP address", ip))
			}
		}
		for _, c := range a.CIDR {
			if _, err := netip.ParsePrefix(c); err != nil {
				msgs = append(msgs, fmt.Sprintf("cidr %q is not a network like 10.0.0.0/8", c))
			}
		}
		if len(a.Host)+len(a.IP)+len(a.CIDR) == 0 {
			msgs = append(msgs, "needs a host, ip or cidr")
		}
		if len(msgs) > 0 {
			bad = append(bad, LineError{Line: lines[i], Msg: strings.Join(msgs, "; ")})
			continue
		}
		out = append(out, a)
	}
	if len(bad) > 0 {
		return nil, &ParseError{Lines: bad}
	}
	return out, nil
}

// ParseIdentities reads an identity CSV.
func ParseIdentities(data []byte) ([]Identity, error) {
	rows, lines, err := readCSV(data, IdentityColumns, "identity")
	if err != nil {
		return nil, err
	}
	var out []Identity
	var bad []LineError
	for i, m := range rows {
		id := Identity{Identity: splitMulti(m["identity"]), Name: m["name"], Email: m["email"], Manager: m["manager"],
			Category: splitMulti(m["category"]), BUnit: m["bunit"]}
		var msgs []string
		if id.Priority, err = checkPriority(m["priority"]); err != nil {
			msgs = append(msgs, err.Error())
		}
		switch strings.ToLower(m["watchlist"]) {
		case "", "false", "no", "0":
		case "true", "yes", "1":
			id.Watchlist = true
		default:
			msgs = append(msgs, fmt.Sprintf("watchlist %q must be true or false", m["watchlist"]))
		}
		if len(id.Identity) == 0 {
			msgs = append(msgs, "identity is empty")
		}
		if len(msgs) > 0 {
			bad = append(bad, LineError{Line: lines[i], Msg: strings.Join(msgs, "; ")})
			continue
		}
		out = append(out, id)
	}
	if len(bad) > 0 {
		return nil, &ParseError{Lines: bad}
	}
	return out, nil
}

// Store holds both lists and answers lookups. It is safe for concurrent use.
type Store struct {
	Dir string // where assets.csv and identities.csv live; "" keeps them in memory

	mu         sync.RWMutex
	assets     []Asset
	identities []Identity
	byHost     map[string]int
	byIP       map[netip.Addr]int
	nets       []netEntry
	byUser     map[string]int
	modTimes   [2]time.Time
}

type netEntry struct {
	prefix netip.Prefix
	idx    int
}

// File names inside Dir.
const (
	AssetsFile     = "assets.csv"
	IdentitiesFile = "identities.csv"
)

// NewStore loads the lists from dir. Missing files mean empty lists.
func NewStore(dir string) (*Store, error) {
	s := &Store{Dir: dir}
	s.index(nil, nil)
	if dir == "" {
		return s, nil
	}
	if _, err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenStore is NewStore for the server, which must run even when a list
// is damaged: it always returns a store, with empty lists in place of
// ones that cannot be read, and the error. Reload picks the files up once
// they are fixed.
func OpenStore(dir string) (*Store, error) {
	s := &Store{Dir: dir}
	s.index(nil, nil)
	if dir == "" {
		return s, nil
	}
	_, err := s.Reload()
	return s, err
}

// Reload rereads the files if they changed. It reports whether it did.
func (s *Store) Reload() (bool, error) {
	if s.Dir == "" {
		return false, nil
	}
	read := func(name string) ([]byte, time.Time, error) {
		p := filepath.Join(s.Dir, name)
		st, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			return nil, time.Time{}, nil
		}
		if err != nil {
			return nil, time.Time{}, err
		}
		data, err := os.ReadFile(p)
		return data, st.ModTime(), err
	}
	ad, at, err := read(AssetsFile)
	if err != nil {
		return false, err
	}
	id, it, err := read(IdentitiesFile)
	if err != nil {
		return false, err
	}
	s.mu.RLock()
	same := at.Equal(s.modTimes[0]) && it.Equal(s.modTimes[1])
	s.mu.RUnlock()
	if same {
		return false, nil
	}
	as, err := ParseAssets(ad)
	if err != nil {
		return false, fmt.Errorf("%s: %w", filepath.Join(s.Dir, AssetsFile), err)
	}
	ids, err := ParseIdentities(id)
	if err != nil {
		return false, fmt.Errorf("%s: %w", filepath.Join(s.Dir, IdentitiesFile), err)
	}
	s.index(as, ids)
	s.mu.Lock()
	s.modTimes = [2]time.Time{at, it}
	s.mu.Unlock()
	return true, nil
}

func normHost(h string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), ".")) }

// normUser strips DOMAIN\ and @domain so corp\bob, bob@corp.com and bob match.
func normUser(u string) string {
	u = strings.ToLower(strings.TrimSpace(u))
	if i := strings.LastIndexByte(u, '\\'); i >= 0 {
		u = u[i+1:]
	}
	if i := strings.IndexByte(u, '@'); i > 0 {
		u = u[:i]
	}
	return u
}

func (s *Store) index(as []Asset, ids []Identity) {
	byHost := map[string]int{}
	byIP := map[netip.Addr]int{}
	var nets []netEntry
	for i, a := range as {
		for _, h := range a.Host {
			h = normHost(h)
			byHost[h] = i
			if short, _, ok := strings.Cut(h, "."); ok {
				if _, taken := byHost[short]; !taken {
					byHost[short] = i
				}
			}
		}
		for _, ip := range a.IP {
			if addr, err := netip.ParseAddr(ip); err == nil {
				byIP[addr.Unmap()] = i
			}
		}
		for _, c := range a.CIDR {
			if p, err := netip.ParsePrefix(c); err == nil {
				nets = append(nets, netEntry{p.Masked(), i})
			}
		}
	}
	// Most specific network first.
	sort.SliceStable(nets, func(i, j int) bool { return nets[i].prefix.Bits() > nets[j].prefix.Bits() })
	byUser := map[string]int{}
	for i, id := range ids {
		for _, u := range id.Identity {
			byUser[normUser(u)] = i
		}
	}
	s.mu.Lock()
	s.assets, s.identities, s.byHost, s.byIP, s.nets, s.byUser = as, ids, byHost, byIP, nets, byUser
	s.mu.Unlock()
}

// Asset finds the asset for a host name or IP address.
func (s *Store) Asset(v string) (*Asset, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if addr, err := netip.ParseAddr(v); err == nil {
		addr = addr.Unmap()
		if i, ok := s.byIP[addr]; ok {
			return &s.assets[i], true
		}
		for _, n := range s.nets {
			if n.prefix.Contains(addr) {
				return &s.assets[n.idx], true
			}
		}
		return nil, false
	}
	h := normHost(v)
	if i, ok := s.byHost[h]; ok {
		return &s.assets[i], true
	}
	if short, _, ok := strings.Cut(h, "."); ok {
		if i, ok := s.byHost[short]; ok {
			return &s.assets[i], true
		}
	}
	return nil, false
}

// Identity finds the identity for a username in any common form.
func (s *Store) Identity(v string) (*Identity, bool) {
	u := normUser(v)
	if u == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if i, ok := s.byUser[u]; ok {
		return &s.identities[i], true
	}
	return nil, false
}

// Assets and Identities return copies of the lists.
func (s *Store) Assets() []Asset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Asset(nil), s.assets...)
}

func (s *Store) Identities() []Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Identity(nil), s.identities...)
}

// SetAssets validates CSV, saves it to Dir and loads it.
func (s *Store) SetAssets(data []byte) (int, error) {
	as, err := ParseAssets(data)
	if err != nil {
		return 0, err
	}
	if err := s.save(AssetsFile, data); err != nil {
		return 0, err
	}
	s.index(as, s.Identities())
	return len(as), nil
}

// SetIdentities validates CSV, saves it to Dir and loads it.
func (s *Store) SetIdentities(data []byte) (int, error) {
	ids, err := ParseIdentities(data)
	if err != nil {
		return 0, err
	}
	if err := s.save(IdentitiesFile, data); err != nil {
		return 0, err
	}
	s.index(s.Assets(), ids)
	return len(ids), nil
}

func (s *Store) save(name string, data []byte) error {
	if s.Dir == "" {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o750); err != nil {
		return err
	}
	p := filepath.Join(s.Dir, name)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	st, err := os.Stat(p)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if name == AssetsFile {
		s.modTimes[0] = st.ModTime()
	} else {
		s.modTimes[1] = st.ModTime()
	}
	s.mu.Unlock()
	return nil
}

// CSV returns a list as CSV, for download. Cells a spreadsheet would run
// as a formula are written with a leading quote (see SafeCell), as the web
// UI's exports do.
func (s *Store) CSV(kind string) []byte {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	write := func(cells ...string) {
		for i, c := range cells {
			cells[i] = SafeCell(c)
		}
		w.Write(cells)
	}
	join := func(xs []string) string { return strings.Join(xs, "|") }
	switch kind {
	case "assets":
		write(AssetColumns...)
		for _, a := range s.Assets() {
			write(join(a.Host), join(a.IP), join(a.CIDR), a.Owner, a.Priority, join(a.Category), a.BUnit, a.Location)
		}
	default:
		write(IdentityColumns...)
		for _, id := range s.Identities() {
			wl := ""
			if id.Watchlist {
				wl = "true"
			}
			write(join(id.Identity), id.Name, id.Email, id.Manager, id.Priority, join(id.Category), id.BUnit, wl)
		}
	}
	w.Flush()
	return buf.Bytes()
}

// SafeCell returns a CSV cell that a spreadsheet will not run as a
// formula: a value starting with =, +, -, @, a tab or a carriage return
// gets a leading single quote, which spreadsheets show as text. Reading a
// list back (unquoteCell) removes it again, so a downloaded list can be
// edited and uploaded unchanged.
func SafeCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// unquoteCell undoes SafeCell.
func unquoteCell(s string) string {
	if len(s) > 1 && s[0] == '\'' && strings.ContainsRune("=+-@\t\r", rune(s[1])) {
		return s[1:]
	}
	return s
}

// UserFields hold usernames; every other entity field is looked up as an asset.
var UserFields = []string{"user", "src_user"}

// Context describes one entity value for display and scoring.
type Context struct {
	Kind      string   `json:"kind"` // asset or identity
	Priority  string   `json:"priority,omitempty"`
	Owner     string   `json:"owner,omitempty"`
	Name      string   `json:"name,omitempty"`
	Email     string   `json:"email,omitempty"`
	Category  []string `json:"category,omitempty"`
	BUnit     string   `json:"bunit,omitempty"`
	Location  string   `json:"location,omitempty"`
	Watchlist bool     `json:"watchlist,omitempty"`
}

// Lookup returns context for a field's value; user fields are identities.
func (s *Store) Lookup(field, value string) (*Context, bool) {
	if slices.Contains(UserFields, field) {
		id, ok := s.Identity(value)
		if !ok {
			return nil, false
		}
		return &Context{Kind: "identity", Priority: id.Priority, Name: id.Name, Email: id.Email, Owner: id.Manager,
			Category: id.Category, BUnit: id.BUnit, Watchlist: id.Watchlist}, true
	}
	a, ok := s.Asset(value)
	if !ok {
		return nil, false
	}
	return &Context{Kind: "asset", Priority: a.Priority, Owner: a.Owner, Category: a.Category, BUnit: a.BUnit, Location: a.Location}, true
}

// Multiplier scales risk by priority: critical doubles it, low halves it.
func Multiplier(priority string) float64 {
	switch priority {
	case "critical":
		return 2
	case "high":
		return 1.5
	case "low":
		return 0.5
	}
	return 1
}
