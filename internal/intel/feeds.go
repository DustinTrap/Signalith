package intel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Feed is one threat intel feed from the config file.
type Feed struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Format      string            `json:"format"`
	Type        string            `json:"type"`
	Column      string            `json:"column,omitempty"`
	Interval    time.Duration     `json:"-"`
	MaxAge      time.Duration     `json:"-"`
	Weight      float64           `json:"weight"`
	Description string            `json:"description,omitempty"`
	Tags        []string          `json:"tags,omitempty"`
	Headers     map[string]string `json:"-"` // may hold API keys; never shown
	Enabled     bool              `json:"enabled"`
}

// FeedStatus is what the UI shows about a feed's downloads.
type FeedStatus struct {
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastSuccess time.Time `json:"last_success,omitzero"`
	NextRun     time.Time `json:"next_run,omitzero"`
	DurationMS  int64     `json:"duration_ms,omitempty"`
	Count       int       `json:"count"`             // indicators from the last download
	Added       int       `json:"added"`             // new in the last download
	Removed     int       `json:"removed"`           // no longer listed, so removed
	Skipped     int       `json:"skipped,omitempty"` // lines that were not valid indicators
	Example     string    `json:"skipped_example,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
	Running     bool      `json:"running,omitempty"`
}

// FeedView is a feed and its status, for the API.
type FeedView struct {
	Feed
	Interval   string     `json:"interval"`
	MaxAge     string     `json:"max_age"`
	HasHeaders bool       `json:"has_headers,omitempty"`
	Indicators int        `json:"indicators"` // stored now
	Status     FeedStatus `json:"status"`
}

// Feeds downloads the configured feeds on their schedules.
type Feeds struct {
	Store *Store
	List  []Feed
	// HTTP downloads feeds; nil uses a client that honors the
	// HTTPS_PROXY, HTTP_PROXY and NO_PROXY environment variables.
	HTTP *http.Client
	// StatusFile keeps feed status across restarts; "" keeps it in memory.
	StatusFile string
	Log        *slog.Logger
	Now        func() time.Time
	// Tick is how often due feeds are checked (default 30s).
	Tick time.Duration

	mu     sync.Mutex
	status map[string]*FeedStatus
	loaded bool
}

// MaxDownload caps a feed download.
const MaxDownload = 256 << 20

// RetryAfterFailure is how soon a failed download is retried, unless the
// feed's interval is shorter.
const RetryAfterFailure = 15 * time.Minute

func (f *Feeds) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

func (f *Feeds) log() *slog.Logger {
	if f.Log != nil {
		return f.Log
	}
	return slog.Default()
}

func (f *Feeds) client() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	// The default transport reads proxy settings from the environment.
	return &http.Client{Timeout: 5 * time.Minute}
}

// Get returns a configured feed by name.
func (f *Feeds) Get(name string) (Feed, bool) {
	for _, fd := range f.List {
		if fd.Name == name {
			return fd, true
		}
	}
	return Feed{}, false
}

func (f *Feeds) loadStatus() {
	if f.loaded {
		return
	}
	f.loaded = true
	if f.status == nil {
		f.status = map[string]*FeedStatus{}
	}
	if f.StatusFile == "" {
		return
	}
	data, err := os.ReadFile(f.StatusFile)
	if err != nil {
		return
	}
	var saved map[string]*FeedStatus
	if json.Unmarshal(data, &saved) == nil {
		for name, st := range saved {
			st.Running = false
			f.status[name] = st
		}
	}
}

// saveStatus writes the status file; the caller holds f.mu.
func (f *Feeds) saveStatus() {
	if f.StatusFile == "" {
		return
	}
	data, err := json.MarshalIndent(f.status, "", "  ")
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(f.StatusFile), 0o750); err != nil {
		f.log().Warn("could not save threat intel feed status", "file", f.StatusFile, "err", err)
		return
	}
	tmp := f.StatusFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err == nil {
		err = os.Rename(tmp, f.StatusFile)
		if err != nil {
			f.log().Warn("could not save threat intel feed status", "file", f.StatusFile, "err", err)
		}
	}
}

func (f *Feeds) stateFor(name string) *FeedStatus {
	f.loadStatus()
	st, ok := f.status[name]
	if !ok {
		st = &FeedStatus{}
		f.status[name] = st
	}
	return st
}

// Status returns every configured feed with its status.
func (f *Feeds) Status() []FeedView {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]FeedView, 0, len(f.List))
	for _, fd := range f.List {
		v := FeedView{Feed: fd, Interval: fmtDuration(fd.Interval), MaxAge: fmtDuration(fd.MaxAge), HasHeaders: len(fd.Headers) > 0, Status: *f.stateFor(fd.Name)}
		if f.Store != nil {
			v.Indicators = f.Store.CountSource(fd.Name)
		}
		out = append(out, v)
	}
	return out
}

func fmtDuration(d time.Duration) string {
	switch {
	case d == 0:
		return ""
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return fmt.Sprintf("%dm", d/time.Minute)
}

// Start downloads due feeds, removes indicators of feeds that are no
// longer configured, and purges expired indicators, until ctx ends.
// Run it on one server only (the one with the detection scheduler).
func (f *Feeds) Start(ctx context.Context) {
	// Feeds replace what they stored before, so the current indicators
	// must be known first.
	for !f.Store.Loaded() {
		err := f.Store.Load(ctx)
		if err == nil {
			break
		}
		f.log().Warn("waiting to read threat intel indicators before downloading feeds", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
		}
	}
	var keep []string
	for _, fd := range f.List {
		if fd.Enabled {
			keep = append(keep, fd.Name)
		}
	}
	if n, err := f.Store.RemoveSources(ctx, keep); err != nil {
		f.log().Warn("could not remove indicators of removed or disabled feeds", "err", err)
	} else if n > 0 {
		f.log().Info("removed indicators of feeds that are no longer configured or are disabled", "indicators", n)
	}
	tick := f.Tick
	if tick <= 0 {
		tick = 30 * time.Second
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	lastPurge := time.Time{}
	for {
		f.RunDue(ctx)
		if f.now().Sub(lastPurge) >= time.Hour {
			lastPurge = f.now()
			if n, err := f.Store.Purge(ctx); err != nil {
				f.log().Warn("could not purge expired indicators", "err", err)
			} else if n > 0 {
				f.log().Info("expired threat intel indicators removed", "indicators", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// RunDue downloads every enabled feed whose next run has passed.
func (f *Feeds) RunDue(ctx context.Context) {
	now := f.now()
	var due []string
	f.mu.Lock()
	for _, fd := range f.List {
		st := f.stateFor(fd.Name)
		if !fd.Enabled || st.Running {
			continue
		}
		if st.NextRun.IsZero() && !st.LastAttempt.IsZero() {
			st.NextRun = st.LastAttempt.Add(fd.Interval)
		}
		if st.NextRun.IsZero() || !now.Before(st.NextRun) {
			due = append(due, fd.Name)
		}
	}
	f.mu.Unlock()
	sort.Strings(due)
	for _, name := range due {
		if ctx.Err() != nil {
			return
		}
		if _, err := f.Refresh(ctx, name); err != nil {
			f.log().Warn("threat intel feed download failed", "feed", name, "err", err)
		}
	}
}

// ErrUnknownFeed is returned for a feed name that is not configured.
var ErrUnknownFeed = errors.New("no feed with that name is configured")

// ErrFeedRunning is returned when a feed is already downloading.
var ErrFeedRunning = errors.New("this feed is already downloading")

// Refresh downloads one feed now and replaces its indicators.
func (f *Feeds) Refresh(ctx context.Context, name string) (FeedStatus, error) {
	fd, ok := f.Get(name)
	if !ok {
		return FeedStatus{}, ErrUnknownFeed
	}
	start := f.now()
	f.mu.Lock()
	st := f.stateFor(name)
	if st.Running {
		f.mu.Unlock()
		return *st, ErrFeedRunning
	}
	st.Running = true
	f.mu.Unlock()

	res, added, removed, err := f.download(ctx, fd, start)

	f.mu.Lock()
	defer f.mu.Unlock()
	st.Running = false
	st.LastAttempt = start
	st.DurationMS = f.now().Sub(start).Milliseconds()
	if err != nil {
		st.LastError = err.Error()
		st.NextRun = start.Add(min(fd.Interval, RetryAfterFailure))
		f.saveStatus()
		return *st, err
	}
	st.LastError = ""
	st.LastSuccess = start
	st.NextRun = start.Add(fd.Interval)
	st.Count, st.Added, st.Removed = len(res.Indicators), added, removed
	st.Skipped, st.Example = res.Skipped, res.Example
	f.saveStatus()
	f.log().Info("threat intel feed downloaded", "feed", name, "indicators", st.Count, "added", added, "removed", removed, "skipped", res.Skipped)
	return *st, nil
}

func (f *Feeds) download(ctx context.Context, fd Feed, now time.Time) (*ParseResult, int, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fd.URL, nil)
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("User-Agent", "Signalith threat intel")
	for k, v := range fd.Headers {
		req.Header.Set(k, ExpandEnv(v))
	}
	resp, err := f.client().Do(req)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		msg := strings.TrimSpace(string(body))
		if msg != "" {
			msg = ": " + msg
		}
		return nil, 0, 0, fmt.Errorf("download failed: %s%s", resp.Status, msg)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxDownload+1))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("download failed: %w", err)
	}
	if len(data) > MaxDownload {
		return nil, 0, 0, fmt.Errorf("the feed is larger than %d MB", MaxDownload>>20)
	}
	res, err := Parse(data, ParseOptions{Format: fd.Format, Type: fd.Type, Column: fd.Column, Now: now})
	if err != nil {
		return nil, 0, 0, err
	}
	if len(res.Indicators) == 0 {
		msg := "the download had no indicators, so the previous ones are kept"
		if res.Skipped > 0 {
			msg = fmt.Sprintf("none of the %d values were valid indicators (first: %q); check the feed's format, type and column", res.Skipped, res.Example)
		}
		return nil, 0, 0, errors.New(msg)
	}
	expires := now.Add(fd.MaxAge)
	for i := range res.Indicators {
		ind := &res.Indicators[i]
		ind.Weight = fd.Weight
		if ind.Description == "" {
			ind.Description = fd.Description
		}
		ind.Tags = mergeTags(fd.Tags, ind.Tags)
		// A feed that stops updating ages out after max_age.
		if ind.Expires.IsZero() || ind.Expires.After(expires) {
			ind.Expires = expires
		}
	}
	added, removed, err := f.Store.ReplaceSource(ctx, fd.Name, res.Indicators)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("could not store indicators: %w", err)
	}
	return res, added, removed, nil
}

func mergeTags(a, b []string) []string {
	var out []string
	for _, t := range append(append([]string{}, a...), b...) {
		dup := false
		for _, o := range out {
			if strings.EqualFold(o, t) {
				dup = true
				break
			}
		}
		if !dup && t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ExpandEnv replaces ${NAME} with the environment variable NAME, so API
// keys for feeds can stay out of the config file. Other $ signs are kept.
func ExpandEnv(v string) string {
	var b strings.Builder
	for {
		i := strings.Index(v, "${")
		if i < 0 {
			b.WriteString(v)
			return b.String()
		}
		j := strings.Index(v[i:], "}")
		if j < 0 {
			b.WriteString(v)
			return b.String()
		}
		b.WriteString(v[:i])
		b.WriteString(os.Getenv(v[i+2 : i+j]))
		v = v[i+j+1:]
	}
}

// EnvRefs returns the variable names ${NAME} references in v.
func EnvRefs(v string) []string {
	var out []string
	for {
		i := strings.Index(v, "${")
		if i < 0 {
			return out
		}
		j := strings.Index(v[i:], "}")
		if j < 0 {
			return out
		}
		out = append(out, v[i+2:i+j])
		v = v[i+j+1:]
	}
}

// Watch keeps the in-memory indicators in step with the backend, for
// changes made by another server, until ctx ends. Every server runs it.
func (s *Store) Watch(ctx context.Context, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if reloaded, err := s.Sync(ctx); err != nil {
			if log != nil {
				log.Warn("could not read threat intel indicators", "err", err)
			}
		} else if reloaded && log != nil {
			log.Info("threat intel indicators loaded", "indicators", s.Summary().Total)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
