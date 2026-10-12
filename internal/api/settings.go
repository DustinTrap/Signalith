package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/store"
	"gopkg.in/yaml.v3"
)

// The Settings page changes the server's settings. Values saved there go
// to their own file (see config.PageSettings), never to signalith.yaml;
// environment variables still win over them. Settings that are simple to
// change while running apply at once; the others wait for a restart,
// which the server does in-process (see Restarter).

func (s *Server) routeSettings(api *router) {
	api.admin("GET /api/settings", s.handleGetSettings)
	api.admin("PUT /api/settings", s.handlePutSettings)
	api.admin("POST /api/settings/test/opensearch", s.handleTestOpenSearch)
	api.admin("POST /api/settings/test/assistant", s.handleTestAssistant)
	api.admin("POST /api/settings/restart", s.handleRestart)
	api.admin("GET /api/settings/export", s.handleExportSettings)
}

// Restarter restarts the server in-process with the saved settings. The
// serve command provides one; without it the page can save settings but
// not restart.
type Restarter interface {
	// Restart begins a restart shortly after it returns, so the answer to
	// the request that asked for it still goes out. It returns
	// ErrRestarting while one is under way.
	Restart(by, client string) error
	// RestartStatus reports whether a restart is under way and how the
	// last one went.
	RestartStatus() RestartStatus
}

// ErrRestarting refuses a restart while one is under way.
var ErrRestarting = errors.New("a restart is already under way; wait for it to finish")

// RestartStatus is the state of restarts.
type RestartStatus struct {
	InProgress bool `json:"in_progress"`
	// Last is how the last restart went; nil before the first.
	Last *RestartResult `json:"last"`
}

// RestartResult is how a restart went.
type RestartResult struct {
	At time.Time `json:"at"`
	By string    `json:"by"`
	OK bool      `json:"ok"`
	// Error says why it failed, and that the previous settings were kept.
	Error string `json:"error,omitempty"`
	// RolledBack is true when the new settings failed after the switch and
	// the previous ones were started again.
	RolledBack bool `json:"rolled_back,omitempty"`
	// Keys are the settings it applied, or tried to.
	Keys   []string `json:"keys"`
	TookMS int64    `json:"took_ms"`
}

// noConfigFile refuses changes on a server started without a file.
var errNoConfigFile = errors.New("this server was started without a configuration file, so its settings cannot be changed here")

// savedSettings returns the configuration as saved: on the page, in
// signalith.yaml and in the environment.
func (s *Server) savedSettings() (*config.Saved, error) {
	if s.Config.Path() == "" {
		return &config.Saved{Config: s.conf()}, nil
	}
	saved, err := config.LoadSaved(s.Config.Path())
	if err != nil {
		return nil, fmt.Errorf("Signalith could not read its configuration file: %v. Fix it on the server; until then settings cannot be changed here", err)
	}
	return saved, nil
}

// settingField is one setting as the page shows it.
type settingField struct {
	Key         string          `json:"key"`
	Label       string          `json:"label"`
	Help        string          `json:"help"`
	Type        string          `json:"type"`
	Choices     []config.Choice `json:"choices,omitempty"`
	Min         *int            `json:"min,omitempty"`
	Max         *int            `json:"max,omitempty"`
	Placeholder string          `json:"placeholder,omitempty"`
	EmptyMeans  string          `json:"empty_means,omitempty"`
	// Value is the saved value; null for a secret, which is never shown.
	Value any `json:"value"`
	// For a secret: Set says whether one is saved, and SentTo the only
	// address it is sent to.
	Set    *bool         `json:"set,omitempty"`
	SentTo string        `json:"sent_to,omitempty"`
	Source config.Source `json:"source"`
	// Env is the environment variable that would override the setting.
	// Locked is true when it does, and the page shows it read-only.
	Env          string `json:"env,omitempty"`
	Locked       bool   `json:"locked"`
	LockedReason string `json:"locked_reason,omitempty"`
	// Apply is live (at once) or restart.
	Apply string `json:"apply"`
	// A dangerous setting asks Confirm before saving; ConfirmWhen limits
	// that to a switch turned on or off.
	Dangerous   bool   `json:"dangerous"`
	Confirm     string `json:"confirm,omitempty"`
	ConfirmWhen string `json:"confirm_when,omitempty"`
	// Pending is true when the saved value waits for a restart.
	Pending bool `json:"pending"`
	// ResetTo is what Reset goes back to, for a value set on the page.
	ResetTo *resetTo `json:"reset_to,omitempty"`
	// Problem must be fixed before saving or restarting; Warning is a
	// value that is not used, and why.
	Problem string `json:"problem,omitempty"`
	Warning string `json:"warning,omitempty"`
}

// resetTo is a setting's value without the page: from signalith.yaml
// (source file) or the default.
type resetTo struct {
	Value  any    `json:"value"`
	Set    *bool  `json:"set,omitempty"`
	Source string `json:"source"`
}

type settingsSection struct {
	ID     string         `json:"id"`
	Title  string         `json:"title"`
	Help   string         `json:"help,omitempty"`
	Fields []settingField `json:"fields"`
}

// pendingSetting is a saved change that waits for a restart. Old and New
// are left out for secrets.
type pendingSetting struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Section string `json:"section"`
	Secret  bool   `json:"secret,omitempty"`
	Old     any    `json:"old,omitempty"`
	New     any    `json:"new,omitempty"`
}

// fieldValue is a setting's value for the page; secrets are never sent.
func fieldValue(c *config.Config, set *config.Setting) (any, *bool) {
	if set.Type == config.TypeSecret {
		v, _ := c.Value(set.Key).(string)
		has := v != ""
		return nil, &has
	}
	return c.Value(set.Key), nil
}

// pendingSettings lists the saved settings that differ from those in use.
func pendingSettings(running, saved *config.Config) []pendingSetting {
	out := []pendingSetting{}
	for i := range config.Registry {
		set := &config.Registry[i]
		if config.SameValue(running, saved, set.Key) {
			continue
		}
		p := pendingSetting{Key: set.Key, Label: set.Label, Section: set.Section}
		if set.Type == config.TypeSecret {
			p.Secret = true
		} else {
			p.Old, p.New = running.Value(set.Key), saved.Value(set.Key)
		}
		out = append(out, p)
	}
	return out
}

// settingsProblems sorts problems by the setting they are about, worded
// for its field, and returns the rest.
func settingsProblems(problems []string) (map[string]string, []string) {
	fields := map[string]string{}
	var rest []string
	for _, p := range problems {
		placed := false
		for _, k := range config.ProblemKeys(p) {
			if _, ok := config.Lookup(k); ok {
				if _, dup := fields[k]; !dup {
					fields[k] = config.PlainProblem(k, p)
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

// publicURLWarning notes a public address whose port is not the one
// Signalith listens on, as after the listen address moved. A proxy or a
// port forward in between makes that right, so it is only a warning.
func publicURLWarning(c *config.Config) string {
	if c.Server.PublicURL == "" || c.Source("server.public_url").Kind == config.FromDefault {
		return ""
	}
	u, err := url.Parse(c.Server.PublicURL)
	_, listen, lerr := net.SplitHostPort(c.Server.Listen)
	if err != nil || lerr != nil || u.Host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if port == "" || port == listen {
		return ""
	}
	return fmt.Sprintf("Agents are told to send to port %s, but Signalith listens on port %s. That is right only when a proxy or a port forward passes port %s on to %s; otherwise change one of them, or empty this to use the listen address.", port, listen, port, listen)
}

// settingsView is GET /api/settings.
func (s *Server) settingsView() (map[string]any, error) {
	saved, err := s.savedSettings()
	if err != nil {
		return nil, err
	}
	running := s.conf()
	problems, general := settingsProblems(saved.Problems)
	warnings, otherWarnings := settingsProblems(saved.SettingsWarnings())
	if w := publicURLWarning(saved.Config); w != "" && warnings["server.public_url"] == "" {
		warnings["server.public_url"] = w
	}
	pending := pendingSettings(running, saved.Config)
	waiting := map[string]bool{}
	for _, p := range pending {
		waiting[p.Key] = true
	}
	sections := make([]settingsSection, 0, len(config.Sections))
	for _, sec := range config.Sections {
		out := settingsSection{ID: sec.ID, Title: sec.Title, Help: sec.Help, Fields: []settingField{}}
		for i := range config.Registry {
			set := &config.Registry[i]
			if set.Section != sec.ID {
				continue
			}
			f := settingField{Key: set.Key, Label: set.Label, Help: set.Help, Type: set.Type, Choices: set.Choices,
				Min: set.Min, Max: set.Max, Placeholder: set.Placeholder, EmptyMeans: set.EmptyMeans,
				Source: saved.Source(set.Key), Env: set.Env, Apply: "live",
				Dangerous: set.Confirm != "", Confirm: set.Confirm, ConfirmWhen: set.ConfirmWhen,
				Pending: waiting[set.Key], Problem: problems[set.Key], Warning: warnings[set.Key]}
			if set.Restart {
				f.Apply = "restart"
			}
			f.Value, f.Set = fieldValue(saved.Config, set)
			if f.Set != nil && *f.Set {
				f.SentTo = set.SentTo(saved.Config)
			}
			if f.Source.Kind == config.FromEnv {
				f.Locked, f.LockedReason = true, config.LockedReason(f.Source.Env)
			}
			if f.Source.Kind == config.FromPage {
				base := saved.Base()
				rt := &resetTo{Source: base.Source(set.Key).Kind}
				rt.Value, rt.Set = fieldValue(base, set)
				f.ResetTo = rt
			}
			out.Fields = append(out.Fields, f)
		}
		sections = append(sections, out)
	}
	file := map[string]any{
		"path": saved.SettingsFile(), "env": "SIGNALITH_SETTINGS_FILE", "from_env": saved.SettingsFileFromEnv(),
		"keys": saved.PageKeys(),
	}
	if saved.PageErr != nil {
		file["error"] = "The settings file cannot be read (" + saved.PageErr.Error() + "). Reset all settings to start it again, or fix it on the server."
	}
	restart := map[string]any{"available": s.Restarter != nil, "in_progress": false, "last": nil, "needed": len(pending) > 0}
	if s.Restarter != nil {
		st := s.Restarter.RestartStatus()
		restart["in_progress"], restart["last"] = st.InProgress, st.Last
	} else {
		restart["unavailable"] = "This server cannot restart itself. Restart Signalith on the server to apply the changes."
	}
	if blocked := restartBlocked(saved); blocked != "" {
		restart["blocked"] = blocked
	}
	if general == nil {
		general = []string{}
	}
	if otherWarnings == nil {
		otherWarnings = []string{}
	}
	return map[string]any{
		"sections":      sections,
		"editable":      s.Config.Path() != "",
		"config_file":   s.Config.Path(),
		"settings_file": file,
		// startup_problem says why the running server is not using the
		// page's settings, when it started without them.
		"startup_problem": running.SettingsProblem(),
		"problems":        general,
		"warnings":        otherWarnings,
		"pending":         pending,
		"restart":         restart,
		"about":           s.aboutServer(running),
		"elsewhere":       s.managedElsewhere(running),
	}, nil
}

// restartBlocked says why the saved settings cannot be applied, or "".
func restartBlocked(saved *config.Saved) string {
	switch {
	case saved.PageErr != nil:
		return "The settings file cannot be read. Reset all settings, or fix the file on the server, before restarting."
	case len(saved.Problems) > 0:
		return "Fix the problems shown on this page before restarting."
	}
	return ""
}

// aboutServer describes the server for the page's read-only part.
func (s *Server) aboutServer(c *config.Config) map[string]any {
	type pathInfo struct {
		Key    string        `json:"key,omitempty"`
		Label  string        `json:"label"`
		Path   string        `json:"path"`
		Source config.Source `json:"source"`
	}
	paths := []pathInfo{
		{Label: "Configuration file", Path: c.Path(), Source: config.Source{Kind: config.FromFile}},
		{Label: "Settings page file", Path: c.SettingsFile(), Source: settingsFileSource(c)},
		{Key: "lookups.dir", Label: "Lookups folder", Path: c.LookupsDir(), Source: c.Source("lookups.dir")},
		{Key: "detections.dir", Label: "Detections folder", Path: c.DetectionsDir(), Source: c.Source("detections.dir")},
		{Key: "dashboards.dir", Label: "Dashboards folder", Path: c.DashboardsDir(), Source: c.Source("dashboards.dir")},
		{Key: "auth.users_file", Label: "Users file", Path: c.UsersFile(), Source: c.Source("auth.users_file")},
		{Key: "intel.feeds_file", Label: "Threat intel feeds file", Path: c.IntelFeedsFile(), Source: c.Source("intel.feeds_file")},
	}
	about := map[string]any{
		"version":       s.Version,
		"platform":      runtime.GOOS + "/" + runtime.GOARCH,
		"paths":         paths,
		"ingest_tokens": len(c.Ingest.Tokens),
		"container":     s.runtimeInfo().Container,
	}
	if !s.Started.IsZero() {
		about["started"] = s.Started.UTC()
		about["uptime_seconds"] = int64(time.Since(s.Started).Seconds())
	}
	return about
}

func settingsFileSource(c *config.Config) config.Source {
	if c.SettingsFileFromEnv() {
		return config.Source{Kind: config.FromEnv, Env: "SIGNALITH_SETTINGS_FILE"}
	}
	return config.Source{Kind: config.FromDefault}
}

// managedElsewhere points to the pages that manage what this one does
// not. Page is the app's page name.
func (s *Server) managedElsewhere(c *config.Config) []map[string]any {
	tokens := len(c.Ingest.Tokens)
	detail := fmt.Sprintf("%d agent tokens are set.", tokens)
	switch tokens {
	case 0:
		detail = "No agent token is set, so agents cannot send data."
	case 1:
		detail = "1 agent token is set."
	}
	return []map[string]any{
		{"what": "Users and directory sign-in", "page": "users"},
		{"what": "Agent setup and tokens", "page": "data", "detail": detail},
		{"what": "Threat intel feeds", "page": "intel"},
		{"what": "Data retention", "page": "retention"},
	}
}

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	view, err := s.settingsView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// settingsRequest is the body of PUT /api/settings.
type settingsRequest struct {
	// Values are new values by key. An empty secret keeps the saved one.
	Values map[string]any `json:"values"`
	// Clear lists secrets to remove.
	Clear []string `json:"clear"`
	// Reset lists settings to take off the page.
	Reset []string `json:"reset"`
	// ResetAll takes every setting off the page.
	ResetAll bool `json:"reset_all"`
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var req settingsRequest
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if s.Config.Path() == "" {
		writeError(w, http.StatusConflict, errNoConfigFile)
		return
	}
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	res, err := config.CheckEdit(s.Config.Path(), config.Edit{Values: req.Values, Clear: req.Clear, Reset: req.Reset,
		ResetAll: req.ResetAll, By: userOf(r)})
	switch {
	case errors.Is(err, config.ErrPageFile):
		writeJSON(w, http.StatusConflict, map[string]any{"error": sentence(err.Error()), "code": "settings_file"})
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !res.OK() {
		msg := "Nothing was saved. Fix the settings marked below."
		if len(res.Problems) > 0 {
			msg = "Nothing was saved, because signalith.yaml has problems: " + strings.Join(res.Problems, "; ") + "."
		}
		problems := res.Problems
		if problems == nil {
			problems = []string{}
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": msg, "fields": res.Fields, "problems": problems})
		return
	}
	file := res.Config.SettingsFile()
	if err := config.WritePageSettings(file, res.Page); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("could not save the settings file %s: %w", file, err))
		return
	}
	applied := s.applyLive(res)
	// Changes that wait for a restart; one back to the value in use, such
	// as a reset of a change not applied yet, needs none.
	var restart []string
	running := s.conf()
	for _, k := range res.Changed {
		if !slices.Contains(applied, k) && !config.SameValue(running, res.Config, k) {
			restart = append(restart, k)
		}
	}
	s.audit(r, "settings saved", "changes", describeChanges(res), "reset", strings.Join(req.Reset, ","),
		"cleared", strings.Join(req.Clear, ","), "reset_all", req.ResetAll, "applied_now", strings.Join(applied, ","),
		"after_restart", strings.Join(restart, ","), "file", file)
	view, err := s.settingsView()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if applied == nil {
		applied = []string{}
	}
	if restart == nil {
		restart = []string{}
	}
	view["saved"], view["applied"], view["after_restart"] = nonNil(res.Changed), applied, restart
	writeJSON(w, http.StatusOK, view)
}

func nonNil(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// describeChanges lists what a save changed for the audit log: the new
// values, but for secrets only that they changed.
func describeChanges(res *config.EditResult) string {
	var parts []string
	for _, k := range res.Changed {
		set, _ := config.Lookup(k)
		v := res.Config.Value(k)
		switch {
		case set.Type == config.TypeSecret:
			if s, _ := v.(string); s == "" {
				parts = append(parts, k+"=(none)")
			} else {
				parts = append(parts, k+"=(changed)")
			}
		case set.Type == config.TypeList:
			parts = append(parts, k+"="+strings.Join(v.([]string), ","))
		default:
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	return strings.Join(parts, " ")
}

// applyLive puts the saved settings that apply at once into use, and
// returns their keys. A setting worked out from one that waits for a
// restart waits too.
func (s *Server) applyLive(res *config.EditResult) []string {
	cur := s.conf()
	next := *cur
	var applied []string
	for _, key := range res.Changed {
		set, _ := config.Lookup(key)
		if !set.Live() {
			continue
		}
		wait := false
		for _, k := range set.WaitsFor {
			wait = wait || !config.SameValue(cur, res.Config, k)
		}
		if wait {
			continue
		}
		if err := next.CopyValue(key, res.Config); err != nil {
			continue
		}
		applied = append(applied, key)
	}
	if len(applied) == 0 {
		return nil
	}
	s.live.Store(&next)
	// Parts of the server that keep their own copy.
	changed := func(prefix string) bool {
		return slices.ContainsFunc(applied, func(k string) bool { return strings.HasPrefix(k, prefix) })
	}
	if changed("auth.session_timeout") {
		s.sessions().SetIdle(next.SessionIdle())
	}
	if changed("search.") && s.Engine != nil {
		s.Engine.SetDefaults(next.Search.DefaultEarliest, next.Search.MaxEvents)
	}
	if changed("detections.max_findings_per_run") && s.Scheduler != nil {
		s.Scheduler.SetMaxFindingsPerRun(next.Detections.MaxFindingsPerRun)
	}
	if changed("assistant.") {
		a := next.Assistant
		s.liveAI.Store(&liveModel{c: assistant.New(a.Provider, a.URL, a.Model, a.APIKey)})
	}
	return applied
}

// settingsTest is the body of the test routes: form values, saved or not,
// by key; settings left out use their saved values.
type settingsTest struct {
	Values map[string]any `json:"values"`
	Clear  []string       `json:"clear"`
}

// testValues returns the saved configuration with the form's values in
// place, and the problems with them by key. A secret left empty is the
// saved one, but only when it would go to the address it was saved for.
func (s *Server) testValues(r *http.Request, keys ...string) (*config.Config, map[string]string, error) {
	var req settingsTest
	if r.ContentLength != 0 {
		if err := readJSON(r, &req); err != nil {
			return nil, nil, err
		}
	}
	saved, err := s.savedSettings()
	if err != nil {
		return nil, nil, err
	}
	test := *saved.Config
	fields := map[string]string{}
	typed := map[string]bool{}
	for _, key := range keys {
		set, _ := config.Lookup(key)
		raw, given := req.Values[key]
		if saved.Source(key).Kind == config.FromEnv {
			continue
		}
		if slices.Contains(req.Clear, key) {
			raw, given, typed[key] = "", true, true
		}
		if !given {
			continue
		}
		v, err := config.ParseValue(set, raw)
		if err != nil {
			fields[key] = sentence(err.Error())
			continue
		}
		if set.Type == config.TypeSecret && v.(string) == "" && !typed[key] {
			continue
		}
		typed[key] = true
		if err := test.SetValue(key, v); err != nil {
			fields[key] = sentence(err.Error())
		}
	}
	for _, key := range keys {
		set, _ := config.Lookup(key)
		if set.Type != config.TypeSecret || typed[key] {
			continue
		}
		v, _ := saved.Value(key).(string)
		if v == "" {
			continue
		}
		bound := set.SentTo(saved.Config)
		if now := set.SentTo(&test); now != bound {
			what := strings.ToLower(set.Label)
			if env := saved.Source(key).Env; env != "" {
				for _, k := range set.SentWith {
					fields[k] = fmt.Sprintf("The %s comes from the %s environment variable and is only sent to %s.", what, env, bound)
				}
				continue
			}
			fields[key] = fmt.Sprintf("Enter the %s again: the saved one is only sent to %s.", what, bound)
		}
	}
	return &test, fields, nil
}

// writeFieldProblems answers 400 with problems by field.
func writeFieldProblems(w http.ResponseWriter, fields map[string]string) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": "Fix the settings marked below, then test again.", "fields": fields, "problems": []string{}})
}

// handleTestOpenSearch tries the OpenSearch connection settings in the
// form, saved or not, and says what it found in plain words.
func (s *Server) handleTestOpenSearch(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, "opensearch.url", "opensearch.username", "opensearch.password", "opensearch.tls_skip_verify")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(fields) == 0 && config.Origin(c.OpenSearch.URL) == "" {
		fields["opensearch.url"] = "Enter an address like https://opensearch.example.com:9200."
	}
	if len(fields) > 0 {
		writeFieldProblems(w, fields)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), store.CheckTimeout+5*time.Second)
	defer cancel()
	rep := store.Check(ctx, store.Config{URL: c.OpenSearch.URL, Username: c.OpenSearch.Username,
		Password: c.OpenSearch.Password, TLSSkipVerify: c.OpenSearch.TLSSkipVerify})
	s.audit(r, "settings tested", "what", "opensearch", "url", c.OpenSearch.URL, "username", c.OpenSearch.Username,
		"ok", rep.OK, "problem", rep.Problem)
	writeJSON(w, http.StatusOK, rep)
}

// assistantQuestion is the fixed question the assistant test asks.
const assistantQuestion = "failed logins in the last 24 hours"

// assistantReport is what the assistant test found.
type assistantReport struct {
	OK       bool   `json:"ok"`
	Provider string `json:"provider"`
	Model    string `json:"model"`
	URL      string `json:"url"`
	Question string `json:"question"`
	// Query is the model's answer, when it gave one.
	Query   string `json:"query,omitempty"`
	Message string `json:"message"`
	TookMS  int64  `json:"took_ms"`
}

// handleTestAssistant asks the model in the form one fixed question and
// says whether it answered.
func (s *Server) handleTestAssistant(w http.ResponseWriter, r *http.Request) {
	c, fields, err := s.testValues(r, "assistant.provider", "assistant.url", "assistant.model", "assistant.api_key")
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	a := c.Assistant
	if len(fields) == 0 {
		switch {
		case a.Provider == "":
			fields["assistant.provider"] = "Choose a provider to test."
		case a.Provider != assistant.Anthropic && a.Provider != assistant.OpenAI:
			fields["assistant.provider"] = "Choose Anthropic or OpenAI or compatible."
		case a.URL != "" && config.Origin(a.URL) == "":
			fields["assistant.url"] = "Enter an address like http://localhost:11434/v1, or leave it empty."
		case a.Provider == assistant.OpenAI && a.Model == "":
			fields["assistant.model"] = "Enter the model's name, such as llama3.1."
		case a.Provider == assistant.Anthropic && a.APIKey == "":
			fields["assistant.api_key"] = "Enter the API key."
		}
	}
	if len(fields) > 0 {
		writeFieldProblems(w, fields)
		return
	}
	client := assistant.New(a.Provider, a.URL, a.Model, a.APIKey)
	client.HTTP.Timeout = 45 * time.Second
	rep := assistantReport{Provider: a.Provider, Model: client.Model, URL: client.URL, Question: assistantQuestion}
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), time.Minute)
	defer cancel()
	q, err := client.Translate(ctx, assistantQuestion, "")
	rep.TookMS = time.Since(start).Milliseconds()
	if err != nil {
		rep.Message = explainAssistant(err)
	} else {
		rep.OK, rep.Query = true, q
		rep.Message = fmt.Sprintf("The model answered in %.1f seconds.", time.Since(start).Seconds())
	}
	s.audit(r, "settings tested", "what", "assistant", "provider", a.Provider, "url", client.URL, "model", client.Model, "ok", rep.OK)
	writeJSON(w, http.StatusOK, rep)
}

// explainAssistant words a failed assistant test.
func explainAssistant(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "returned 401"), strings.Contains(msg, "returned 403"):
		return "The model's service refused the API key. Check the key. (" + msg + ")"
	case strings.Contains(msg, "returned 404"):
		return "The model's service answered \"not found\": check the address and the model's name. (" + msg + ")"
	case strings.Contains(msg, "did not parse"):
		return "The model answered, but not with a query Signalith understands. A larger model may do better."
	}
	return sentence(msg)
}

// sentence makes an error message a sentence.
func sentence(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// handleRestart restarts the server with the saved settings, shortly
// after answering 202.
func (s *Server) handleRestart(w http.ResponseWriter, r *http.Request) {
	if s.Restarter == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"code": "restart_unavailable",
			"error": "This server cannot restart itself. Restart Signalith on the server to apply the changes."})
		return
	}
	saved, err := s.savedSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if blocked := restartBlocked(saved); blocked != "" {
		writeJSON(w, http.StatusConflict, map[string]any{"code": "settings_invalid", "error": blocked})
		return
	}
	running := s.conf()
	pending := pendingSettings(running, saved.Config)
	if err := s.Restarter.Restart(userOf(r), clientIP(r)); err != nil {
		code := "restart_failed"
		if errors.Is(err, ErrRestarting) {
			code = "restarting"
		}
		writeJSON(w, http.StatusConflict, map[string]any{"code": code, "error": sentence(err.Error())})
		return
	}
	keys := []string{}
	for _, p := range pending {
		keys = append(keys, p.Key)
	}
	s.audit(r, "restart requested", "pending", strings.Join(keys, ","))
	resp := map[string]any{"restarting": true, "pending": keys, "listen_changed": false}
	if moved := newAddress(r, running, saved.Config); moved != "" {
		resp["listen_changed"], resp["new_listen"], resp["go_to"] = true, saved.Server.Listen, moved
	}
	writeJSON(w, http.StatusAccepted, resp)
}

// newAddress returns where the browser finds the web page after a
// restart that moves it, or "" when it stays: the host the browser uses
// now (or the new listen address's own host, when it listens on one
// address only), with the new port and scheme.
func newAddress(r *http.Request, running, saved *config.Config) string {
	https := func(c *config.Config) bool { return c.Server.TLSCert != "" && c.Server.TLSKey != "" }
	if running.Server.Listen == saved.Server.Listen && https(running) == https(saved) {
		return ""
	}
	lhost, port, err := net.SplitHostPort(saved.Server.Listen)
	if err != nil {
		return ""
	}
	host := r.Host
	if h, _, err := net.SplitHostPort(r.Host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	switch lhost {
	case "", "0.0.0.0", "::":
	default:
		if !strings.EqualFold(lhost, host) && !(isLoopback(lhost) && isLoopback(host)) {
			host = lhost
		}
	}
	scheme := "http"
	if https(saved) {
		scheme = "https"
	}
	return scheme + "://" + net.JoinHostPort(host, port) + "/"
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// handleExportSettings returns the saved settings as a signalith.yaml
// snippet, for setting up other servers the same way. Secrets are left
// out. ?download=1 sends it as a file.
func (s *Server) handleExportSettings(w http.ResponseWriter, r *http.Request) {
	saved, err := s.savedSettings()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	c := saved.Config
	if len(saved.Problems) > 0 || saved.PageErr != nil {
		c = s.conf()
	}
	text, err := exportSettings(c, s.conf().Server.PublicURL, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	const name = "signalith-settings.yaml"
	if r.URL.Query().Get("download") != "" {
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		_, _ = w.Write([]byte(text))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"yaml": text, "filename": name})
}

// serverOwn are settings that belong to one server, marked in the export.
var serverOwn = map[string]string{
	"server.listen":     "this server's own address",
	"server.public_url": "this server's own address",
	"server.tls_cert":   "a file on this server",
	"server.tls_key":    "a file on this server",
}

// exportSettings writes the page's settings of c as signalith.yaml
// sections, in page order.
func exportSettings(c *config.Config, from string, now time.Time) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "# Settings exported from Signalith at %s on %s.\n", from, now.UTC().Format("2006-01-02"))
	b.WriteString("# Copy what you need into signalith.yaml on another server. Passwords and\n")
	b.WriteString("# keys are left out: set them there, or with environment variables.\n")
	// signalith.yaml groups settings by their first word, which does not
	// always follow the page's sections (server.public_url is under
	// General, server.listen under Web server).
	var tops []string
	byTop := map[string][]*config.Setting{}
	for i := range config.Registry {
		set := &config.Registry[i]
		top, _, _ := strings.Cut(set.Key, ".")
		if byTop[top] == nil {
			tops = append(tops, top)
		}
		byTop[top] = append(byTop[top], set)
	}
	for _, top := range tops {
		fmt.Fprintf(&b, "%s:\n", top)
		if err := exportSection(&b, c, byTop[top]); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

func exportSection(b *strings.Builder, c *config.Config, settings []*config.Setting) error {
	for _, set := range settings {
		_, name, _ := strings.Cut(set.Key, ".")
		if set.Type == config.TypeSecret {
			hint := "set it here"
			if set.Env != "" {
				hint += " or with " + set.Env
			}
			fmt.Fprintf(b, "  # %s: left out; %s\n", name, hint)
			continue
		}
		v := &yaml.Node{}
		if err := v.Encode(c.Value(set.Key)); err != nil {
			return err
		}
		if v.Kind == yaml.SequenceNode {
			v.Style = yaml.FlowStyle
		}
		out, err := yaml.Marshal(v)
		if err != nil {
			return err
		}
		line := fmt.Sprintf("  %s: %s", name, strings.TrimSpace(string(out)))
		if note := serverOwn[set.Key]; note != "" {
			line += "  # " + note
		}
		b.WriteString(line + "\n")
	}
	return nil
}
