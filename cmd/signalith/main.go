// Command signalith is the Signalith SIEM server and admin CLI.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/dashboards"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/nlq"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/syslog"
	"github.com/jrsamsanchez/signalith/web"
)

// version is set at build time with -ldflags "-X main.version=..."
var version = "dev"

const usage = `Signalith: an open-source SIEM.

Usage:
  signalith init      [-c file] [flags]   write a starter config file
  signalith serve     [-c file]           run the server
  signalith validate  [-c file]           check the config file
  signalith passwd    [-c file]           set the admin password
  signalith query     [-c file] [-explain] "<query>"   run a query from the shell
  signalith ask       [-c file] [-ai] "<question>"     turn a question into a query
  signalith service   install|uninstall|start|stop     manage the Windows service
  signalith version

The config file defaults to %s
(override with -c or the SIGNALITH_CONFIG environment variable).
`

func defaultConfigPath() string {
	if p := os.Getenv("SIGNALITH_CONFIG"); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return base + `\Signalith\signalith.yaml`
	}
	return "/etc/signalith/signalith.yaml"
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, defaultConfigPath())
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "serve":
		err = cmdServe(args)
	case "validate":
		err = cmdValidate(args)
	case "passwd":
		err = cmdPasswd(args)
	case "query":
		err = cmdQuery(args)
	case "ask":
		err = cmdAsk(args)
	case "service":
		err = cmdService(args)
	case "version", "-v", "--version":
		fmt.Println("signalith", version)
	case "help", "-h", "--help":
		fmt.Printf(usage, defaultConfigPath())
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n"+usage, cmd, defaultConfigPath())
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func configFlag(fs *flag.FlagSet) *string {
	return fs.String("c", defaultConfigPath(), "config file")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	path := configFlag(fs)
	listen := fs.String("listen", "0.0.0.0:8080", "address to listen on")
	publicURL := fs.String("public-url", "", "URL agents use to reach this server (default: derived from -listen)")
	osURL := fs.String("opensearch", "http://127.0.0.1:9200", "OpenSearch URL")
	osUser := fs.String("opensearch-user", "", "OpenSearch username")
	password := fs.String("admin-password", "", "admin password (default: generate one)")
	syslogUDP := fs.String("syslog-udp", "0.0.0.0:514", "address to receive syslog on over UDP (empty: off)")
	syslogTCP := fs.String("syslog-tcp", "0.0.0.0:514", "address to receive syslog on over TCP (empty: off)")
	force := fs.Bool("force", false, "overwrite an existing config file")
	fs.Parse(args)

	if _, err := os.Stat(*path); err == nil && !*force {
		return fmt.Errorf("%s already exists; use -force to overwrite it", *path)
	}
	c := config.Default()
	c.Server.Listen = *listen
	c.Server.PublicURL = *publicURL
	c.OpenSearch.URL = *osURL
	c.OpenSearch.Username = *osUser
	// New installs receive syslog right away; existing configs without a
	// syslog section keep it off.
	c.Syslog.UDP = *syslogUDP
	c.Syslog.TCP = *syslogTCP
	pw := *password
	generated := pw == ""
	if generated {
		pw = config.RandomToken(9)
	}
	h, err := config.HashPassword(pw)
	if err != nil {
		return err
	}
	c.Auth.AdminPasswordHash = h
	c.Ingest.Tokens = []string{config.RandomToken(24)}
	if err := c.Validate(); err != nil {
		return err
	}
	if err := c.Save(*path); err != nil {
		return err
	}
	fmt.Printf("Wrote %s\n\n", *path)
	fmt.Printf("  Web UI:    %s\n", c.Server.PublicURL)
	fmt.Printf("  User:      %s\n", c.Auth.AdminUser)
	if generated {
		fmt.Printf("  Password:  %s   (shown once; change it with: signalith passwd)\n", pw)
	}
	if s := syslogSummary(c); s != "" {
		fmt.Printf("  Syslog:    %s\n", s)
	}
	fmt.Printf("\nNext: start OpenSearch, then run: signalith serve -c %s\n", *path)
	return nil
}

// syslogMaxAge is how old a syslog message's own timestamp may be and still
// be its event time: a week, or the retention period when that is shorter,
// since older events would only land in indices about to be deleted.
func syslogMaxAge(retentionDays int) time.Duration {
	if d := time.Duration(retentionDays) * 24 * time.Hour; d > 0 && d < syslog.DefaultMaxAge {
		return d
	}
	return syslog.DefaultMaxAge
}

// syslogSummary describes the syslog listeners, or "" when syslog is off.
func syslogSummary(c *config.Config) string {
	var parts []string
	for _, l := range []struct{ name, addr string }{{"UDP", c.Syslog.UDP}, {"TCP", c.Syslog.TCP}, {"TLS", c.Syslog.TLS}} {
		if l.addr != "" {
			parts = append(parts, l.name+" "+l.addr)
		}
	}
	s := strings.Join(parts, ", ")
	// public_port applies to UDP and TCP, whichever are on.
	var fwd []string
	for _, l := range []struct{ name, addr string }{{"UDP", c.Syslog.UDP}, {"TCP", c.Syslog.TCP}} {
		if l.addr != "" {
			fwd = append(fwd, l.name)
		}
	}
	if c.Syslog.PublicPort > 0 && len(fwd) > 0 {
		s += fmt.Sprintf(" (devices send %s to port %d)", strings.Join(fwd, " and "), c.Syslog.PublicPort)
	}
	return s
}

// printSyslogPorts prints the syslog listeners for install scripts, such
// as "udp 514 10.0.0.0/8,192.0.2.10/32" or "tcp 514 any".
func printSyslogPorts(c *config.Config) {
	allow := "any"
	if list := c.Syslog.AllowList(); len(list) > 0 {
		var parts []string
		for _, p := range list {
			parts = append(parts, p.String())
		}
		allow = strings.Join(parts, ",")
	}
	for _, l := range []struct{ proto, addr string }{{"udp", c.Syslog.UDP}, {"tcp", c.Syslog.TCP}, {"tls", c.Syslog.TLS}} {
		if _, port, err := net.SplitHostPort(l.addr); err == nil {
			fmt.Println(l.proto, port, allow)
		}
	}
}

func cmdValidate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	path := configFlag(fs)
	ports := fs.Bool("syslog-ports", false, "only print the syslog listeners, one per line: protocol, port, and the allowed senders (any, or a comma-separated list); for installers")
	fs.Parse(args)
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *ports {
		printSyslogPorts(c)
		return nil
	}
	fmt.Printf("%s is valid.\n", *path)
	lib, problems, err := detect.NewLibrary(c.DetectionsDir())
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Println("Detection error:", p)
		}
		return fmt.Errorf("%d detection file(s) in %s need fixing", len(problems), c.DetectionsDir())
	}
	enabled := 0
	for _, d := range lib.List() {
		if d.Enabled {
			enabled++
		}
	}
	fmt.Printf("%d detections loaded, %d enabled (custom ones in %s).\n", len(lib.List()), enabled, c.DetectionsDir())
	lists, err := assets.NewStore(c.LookupsDir())
	if err != nil {
		return err
	}
	fmt.Printf("%d assets and %d identities loaded from %s.\n", len(lists.Assets()), len(lists.Identities()), c.LookupsDir())
	feeds := newFeeds(c, nil, nil)
	if err := feeds.Load(); err != nil {
		fmt.Println("Warning:", err)
	}
	if list := feeds.Status(); len(list) > 0 {
		on, page := 0, 0
		for _, f := range list {
			if f.Enabled && f.Problem == "" {
				on++
			}
			if f.Source == intel.SourceUI {
				page++
			}
			if f.Problem != "" {
				fmt.Printf("Warning: threat intel feed %s (added on the Threat intel page): %s\n", f.Name, f.Problem)
			}
		}
		fmt.Printf("%d threat intel feeds (%d in signalith.yaml, %d added on the Threat intel page), %d enabled.\n", len(list), len(list)-page, page, on)
	}
	if s := syslogSummary(c); s != "" {
		allow := "any sender"
		if len(c.Syslog.Allow) > 0 {
			allow = strings.Join(c.Syslog.Allow, ", ")
		}
		fmt.Printf("Syslog receiver on %s, accepting %s.\n", s, allow)
		if c.Syslog.UDP != "" && len(c.Syslog.Allow) > 0 {
			fmt.Println("Note: over UDP a sender's address can be forged, so syslog.allow cannot fully protect syslog.udp. Use TCP or TLS for trusted senders, and limit the port with a firewall.")
		}
	} else {
		fmt.Println("Syslog receiver is off (set syslog.udp or syslog.tcp to turn it on).")
	}
	if boards, err := dashboards.NewStore(c.DashboardsDir()); err != nil {
		fmt.Printf("Warning: dashboards folder %s: %v\n", c.DashboardsDir(), err)
	} else if list, problems, err := boards.List(); err == nil {
		for _, p := range problems {
			fmt.Printf("Dashboard error: %s: %s\n", p.File, p.Error)
		}
		if len(problems) > 0 {
			return fmt.Errorf("%d dashboard file(s) in %s need fixing", len(problems), c.DashboardsDir())
		}
		fmt.Printf("%d custom dashboards loaded from %s.\n", len(list), c.DashboardsDir())
	}
	cl := newStore(c)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if status, err := cl.Health(ctx); err != nil {
		fmt.Printf("Warning: OpenSearch is not reachable yet: %v\n", err)
	} else {
		fmt.Printf("OpenSearch at %s is %s.\n", c.OpenSearch.URL, status)
	}
	return nil
}

func cmdPasswd(args []string) error {
	fs := flag.NewFlagSet("passwd", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	c, err := loadForEdit(*path)
	if err != nil {
		return err
	}
	pw := os.Getenv("SIGNALITH_NEW_PASSWORD")
	if pw == "" {
		fmt.Print("New admin password (input is visible): ")
		if _, err := fmt.Scanln(&pw); err != nil {
			return errors.New("no password entered")
		}
	}
	h, err := config.HashPassword(strings.TrimSpace(pw))
	if err != nil {
		return err
	}
	c.Auth.AdminPasswordHash = h
	if err := c.Save(*path); err != nil {
		return err
	}
	fmt.Println("Password updated. Restart the server to apply it.")
	return nil
}

// loadForEdit loads a config without failing on a missing password hash,
// which is exactly what passwd fixes.
func loadForEdit(path string) (*config.Config, error) {
	c, err := config.Load(path)
	if err == nil {
		return c, nil
	}
	var ve *config.ValidationError
	if !errors.As(err, &ve) {
		return nil, err
	}
	os.Setenv("SIGNALITH_ADMIN_PASSWORD", "placeholder-to-load")
	defer os.Unsetenv("SIGNALITH_ADMIN_PASSWORD")
	return config.Load(path)
}

func newStore(c *config.Config) *store.Client {
	return store.New(store.Config{
		URL:           c.OpenSearch.URL,
		Username:      c.OpenSearch.Username,
		Password:      c.OpenSearch.Password,
		TLSSkipVerify: c.OpenSearch.TLSSkipVerify,
	})
}

func newEngine(c *config.Config, s store.Searcher) *search.Engine {
	return &search.Engine{Store: s, Opt: search.Options{
		IndexPrefix:     c.OpenSearch.IndexPrefix,
		DefaultEarliest: c.Search.DefaultEarliest,
		MaxEvents:       c.Search.MaxEvents,
	}}
}

func cmdQuery(args []string) error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	path := configFlag(fs)
	explain := fs.Bool("explain", false, "print the OpenSearch request instead of running it")
	fs.Parse(args)
	src := strings.Join(fs.Args(), " ")
	if src == "" {
		return errors.New(`usage: signalith query "datamodel=Authentication | stats count by action"`)
	}
	q, err := query.Parse(src)
	if err != nil {
		return err
	}
	var c *config.Config
	if *explain {
		c, err = config.Load(*path)
		if err != nil {
			c = config.Default() // explaining needs no server
		}
	} else if c, err = config.Load(*path); err != nil {
		return err
	}
	if q.Earliest == "" {
		q.Earliest = c.Search.DefaultEarliest
	}
	eng := newEngine(c, newStore(c))
	if lists, err := assets.NewStore(c.LookupsDir()); err == nil {
		eng.Assets = lists
	}
	if strings.Contains(src, "intel") || strings.Contains(src, "threatmatch") {
		eng.Intel = intel.NewStore(intel.NewOpenSearch(newStore(c), c.OpenSearch.IndexPrefix))
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err := eng.Intel.Load(ctx)
		cancel()
		if err != nil && !*explain {
			return fmt.Errorf("could not read threat intel indicators: %w", err)
		}
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if *explain {
		for i, s := range api.Explain(q) {
			fmt.Printf("%d. %s\n", i+1, s)
		}
		plan, err := eng.Compile(q)
		if err != nil {
			return err
		}
		fmt.Printf("\nPOST /%s/_search\n", plan.Index)
		return enc.Encode(plan.Body)
	}
	res, err := eng.Execute(context.Background(), q)
	if err != nil {
		return err
	}
	return enc.Encode(res)
}

func newAssistant(c *config.Config) *assistant.Client {
	a := c.Assistant
	return assistant.New(a.Provider, a.URL, a.Model, a.APIKey)
}

// cmdAsk prints the query for a plain-English question, with how each
// part was understood.
func cmdAsk(args []string) error {
	fs := flag.NewFlagSet("ask", flag.ExitOnError)
	path := configFlag(fs)
	useAI := fs.Bool("ai", false, "ask the configured AI model instead of the built-in translator")
	fs.Parse(args)
	question := strings.Join(fs.Args(), " ")
	if question == "" {
		return errors.New(`usage: signalith ask "failed logins from 203.0.113.9 in the last 24 hours"`)
	}
	c, err := config.Load(*path)
	if err != nil {
		if *useAI {
			return err
		}
		c = config.Default() // the built-in translator needs no server
	}
	var hints nlq.Hints
	if lists, err := assets.NewStore(c.LookupsDir()); err == nil {
		hints = api.AssetHints{A: lists}
	}
	res, err := nlq.Translate(question, hints)
	if err != nil {
		return err
	}
	if *useAI {
		ai := newAssistant(c)
		if ai == nil {
			return errors.New("no AI model is configured; set assistant.provider in the config file")
		}
		q, err := ai.Translate(context.Background(), question, res.Query)
		if err != nil {
			return err
		}
		fmt.Println(q)
		return nil
	}
	fmt.Println(res.Query)
	fmt.Println()
	for _, s := range res.Steps {
		if s.Phrase != "" {
			fmt.Printf("  %-28s %s\n", "\""+s.Phrase+"\"", s.Meaning)
		} else {
			fmt.Printf("  %-28s %s\n", "", s.Meaning)
		}
	}
	if len(res.Unknown) > 0 {
		fmt.Printf("\nNot understood: %s\n", strings.Join(res.Unknown, ", "))
	}
	return nil
}

// cmdServe runs until interrupted (or until the Windows service stops).
func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	path := configFlag(fs)
	fs.Parse(args)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, *path, slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

func serve(ctx context.Context, path string, log *slog.Logger) error {
	c, err := config.Load(path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cl := newStore(c)
	pipeline := &ingest.Pipeline{Store: cl, Prefix: c.OpenSearch.IndexPrefix}
	// Closed once the index template is in place, so syslog does not
	// create the day's first indices with the wrong field types.
	templateReady := make(chan struct{})
	var receiver *syslog.Receiver
	if c.Syslog.Enabled() {
		receiver = syslog.New(syslog.Config{
			UDP: c.Syslog.UDP, TCP: c.Syslog.TCP, TLS: c.Syslog.TLS,
			CertFile: c.Server.TLSCert, KeyFile: c.Server.TLSKey,
			Allow: c.Syslog.AllowList(), Ready: templateReady,
			MaxAge: syslogMaxAge(c.Retention.Days), PublicPort: c.Syslog.PublicPort,
		}, pipeline, log)
		if err := receiver.Start(ctx); err != nil {
			return err
		}
		// On the way out: stop receiving and write out what is queued.
		defer func() {
			cancel()
			receiver.Wait()
			s := receiver.Stats()
			log.Info("syslog receiver stopped", "received", s.Received, "dropped", s.Dropped, "write_failed", s.WriteFailed, "rejected", s.Rejected)
		}()
		var addrs []any
		for _, l := range receiver.Stats().Listeners {
			addrs = append(addrs, l.Protocol, l.Address)
		}
		allow := "any sender"
		if len(c.Syslog.Allow) > 0 {
			allow = strings.Join(c.Syslog.Allow, ", ")
		}
		log.Info("syslog receiver listening", append(addrs, "allow", allow)...)
	}
	eng := newEngine(c, cl)
	lists, err := assets.NewStore(c.LookupsDir())
	if err != nil {
		return err
	}
	log.Info("asset and identity lists loaded", "assets", len(lists.Assets()), "identities", len(lists.Identities()), "dir", c.LookupsDir())
	eng.Assets = lists
	go reloadLookups(ctx, lists, log)
	ibackend := intel.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	indicators := intel.NewStore(ibackend)
	eng.Intel = indicators
	feeds := newFeeds(c, indicators, log)
	if err := feeds.Load(); err != nil {
		log.Error("threat intel feeds added on the Threat intel page cannot be used until the file is fixed", "err", err)
	}
	lib, problems, err := detect.NewLibrary(c.DetectionsDir())
	if err != nil {
		return err
	}
	for _, p := range problems {
		// One bad file should not stop the SIEM; it is skipped and reported.
		log.Error("detection skipped", "err", p)
	}
	boards, err := dashboards.NewStore(c.DashboardsDir())
	if err != nil {
		return fmt.Errorf("dashboards.dir: %w", err)
	}
	if _, problems, err := boards.List(); err == nil {
		for _, p := range problems {
			log.Error("dashboard file has errors; fix it to show the dashboard", "file", p.File, "err", p.Error)
		}
	}
	fstore := findings.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	cstore := cases.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	sched := &detect.Scheduler{
		Library: lib, Engine: eng, Findings: fstore, Log: log,
		Risk: &risk.Store{Client: cl, Prefix: c.OpenSearch.IndexPrefix}, Assets: lists,
		MaxFindingsPerRun: c.Detections.MaxFindingsPerRun,
	}
	srv := &api.Server{
		Config:     c,
		Engine:     eng,
		Pipeline:   pipeline,
		Syslog:     receiver,
		Backend:    cl,
		Detections: lib,
		Scheduler:  sched,
		Findings:   fstore,
		Assets:     lists,
		Intel:      indicators,
		Feeds:      feeds,
		Dashboards: boards,
		Cases:      cstore,
		Assistant:  newAssistant(c),
		UI:         web.FS(),
		Log:        log,
		Version:    version,
	}
	go func() {
		if !ensureTemplate(ctx, cl, c, log) {
			return
		}
		close(templateReady)
		if err := ibackend.EnsureIndex(ctx); err != nil {
			log.Error("could not create the threat intel index; threat intel will not work", "index", ibackend.Index, "err", err)
		} else {
			go indicators.Watch(ctx, time.Minute, log)
			if c.Detections.Scheduler {
				// Feeds can be added on the page at any time, so the
				// downloader runs even with none yet.
				log.Info("threat intel feeds will download on their schedules", "feeds", feeds.Len(), "file", c.IntelFeedsFile())
				go feeds.Start(ctx)
			}
		}
		if err := cstore.EnsureIndex(ctx); err != nil {
			log.Error("could not create the cases index; investigations will not work", "index", cstore.Index, "err", err)
		}
		if err := fstore.EnsureIndex(ctx); err != nil {
			log.Error("could not create the findings index; detections will not run", "index", fstore.Index, "err", err)
			return
		}
		if c.Detections.Scheduler {
			log.Info("detection scheduler started", "detections", len(lib.List()))
			sched.Start(ctx)
		} else {
			log.Info("detection scheduler is off (detections.scheduler: false)")
		}
	}()
	go retention.Run(ctx, cl, c.OpenSearch.IndexPrefix, c.Retention.Days, 6*time.Hour, log)

	hs := &http.Server{
		Addr:              c.Server.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("signalith listening", "addr", c.Server.Listen, "ui", c.Server.PublicURL, "version", version)
		if c.Server.TLSCert != "" {
			errc <- hs.ListenAndServeTLS(c.Server.TLSCert, c.Server.TLSKey)
		} else {
			errc <- hs.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(shutdownCtx)
	}
}

// intelFeeds converts the feeds in signalith.yaml; the config is already
// validated, so durations parse.
func intelFeeds(c *config.Config) []intel.Feed {
	var out []intel.Feed
	for _, f := range c.Intel.Feeds {
		out = append(out, f.Feed(intel.SourceConfig))
	}
	return out
}

// newFeeds returns the feed downloader: the feeds in signalith.yaml and
// those added on the Threat intel page.
func newFeeds(c *config.Config, indicators *intel.Store, log *slog.Logger) *intel.Feeds {
	f := &intel.Feeds{Store: indicators, List: intelFeeds(c), Log: log,
		File:          c.IntelFeedsFile(),
		StatusFile:    filepath.Join(c.LookupsDir(), "intel_feeds.json"),
		AllowLoopback: c.Intel.AllowLoopbackFeeds}
	// Feed downloads never reach Signalith's own OpenSearch, which may
	// accept requests without a password on the local network.
	if p := intel.ProtectedAddr(c.OpenSearch.URL); p != "" {
		f.Protected = []string{p}
	}
	return f
}

// reloadLookups picks up edits to the CSV files made outside the UI.
func reloadLookups(ctx context.Context, lists *assets.Store, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if changed, err := lists.Reload(); err != nil {
			log.Error("asset or identity list has errors; keeping the previous version", "err", err)
		} else if changed {
			log.Info("asset and identity lists reloaded", "assets", len(lists.Assets()), "identities", len(lists.Identities()))
		}
	}
}

// ensureTemplate installs the index template, retrying until OpenSearch is up.
// It reports false if ctx ended first.
func ensureTemplate(ctx context.Context, cl *store.Client, c *config.Config, log *slog.Logger) bool {
	tmpl := ingest.IndexTemplate(c.OpenSearch.IndexPrefix, c.OpenSearch.Replicas)
	for {
		err := cl.PutIndexTemplate(ctx, c.OpenSearch.IndexPrefix, tmpl)
		if err == nil {
			log.Info("opensearch index template ready", "url", c.OpenSearch.URL)
			return true
		}
		log.Warn("waiting for opensearch", "url", c.OpenSearch.URL, "err", err)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(15 * time.Second):
		}
	}
}
