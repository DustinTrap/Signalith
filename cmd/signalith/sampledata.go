package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/risk"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const sampleUsage = `usage:
  signalith sample-data load   [-c file] [-size standard|small]   load a week of made-up activity with attacks to try
  signalith sample-data remove [-c file]                          remove every bit of it
  signalith sample-data status [-c file]                          show whether sample data is loaded

Everything is fictional and kept apart from your own data. Remove takes out
all of it and nothing else. Servers that share one OpenSearch share one set
of sample data: load or remove it from any of them. In Docker:
  docker compose -f deploy/docker/docker-compose.yml exec signalith signalith sample-data load
`

func cmdSampleData(args []string) error {
	if len(args) == 0 {
		return errors.New(sampleUsage)
	}
	sub := args[0]
	fs := flag.NewFlagSet("sample-data "+sub, flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, sampleUsage) }
	path := configFlag(fs)
	size := fs.String("size", string(sample.SizeStandard), "how much background activity: standard or small")
	fs.Parse(args[1:])

	useServiceEnv(*path, os.Stdout)
	log := newLogger(os.Stderr)
	c, err := loadConfig(*path, log)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// status only reads the load's record in OpenSearch; it changes nothing.
	if sub == "status" {
		cl, err := sampleClient(ctx, c)
		if err != nil {
			return err
		}
		return sampleStatusCmd(ctx, &sample.Loader{Prefix: c.OpenSearch.IndexPrefix, OS: cl, Docs: cl})
	}
	loader, err := buildSampleLoader(ctx, c, log)
	if err != nil {
		return err
	}

	switch sub {
	case "load":
		sz := sample.Size(*size)
		if !sz.Valid() {
			return fmt.Errorf("-size must be \"standard\" or \"small\"")
		}
		return sampleLoadCmd(ctx, loader, sz)
	case "remove":
		return sampleRemoveCmd(ctx, loader)
	default:
		return fmt.Errorf("unknown sample-data command %q\n\n%s", sub, sampleUsage)
	}
}

// sampleClient connects to OpenSearch, where the sample data and the
// record of its load are kept.
func sampleClient(ctx context.Context, c *config.Config) (*store.Client, error) {
	cl := newStore(c)
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, herr := cl.Health(hctx)
	cancel()
	if herr != nil {
		return nil, fmt.Errorf("OpenSearch is not reachable, so sample data cannot be loaded, removed or looked up: %w", herr)
	}
	return cl, nil
}

// buildSampleLoader wires the loader to OpenSearch and the stores, and makes
// sure the indices and the index template are in place first, so the sample
// events get the right field types and the detections can write findings.
// The loader itself makes sure the findings and cases indices hold the
// sample's marker field.
func buildSampleLoader(ctx context.Context, c *config.Config, log *slog.Logger) (*sample.Loader, error) {
	cl, err := sampleClient(ctx, c)
	if err != nil {
		return nil, err
	}
	tctx, tcancel := context.WithTimeout(ctx, 30*time.Second)
	terr := cl.PutIndexTemplate(tctx, c.OpenSearch.IndexPrefix, ingest.IndexTemplate(c.OpenSearch.IndexPrefix, c.OpenSearch.Replicas))
	tcancel()
	if terr != nil {
		return nil, fmt.Errorf("could not install the index template: %w", terr)
	}

	// The sample keeps its asset and identity entries in files of its own,
	// so a damaged list of the user's is no reason to stop; it is left as
	// it is.
	lists, err := assets.OpenStore(c.LookupsDir())
	if err != nil {
		log.Warn("an asset or identity list could not be read; the sample data does not change it", "err", err)
	}
	lib, _, err := detect.NewLibrary(c.DetectionsDir())
	if err != nil {
		return nil, fmt.Errorf("detections: %w", err)
	}
	fstore := findings.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	cstore := cases.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	ibackend := intel.NewOpenSearch(cl, c.OpenSearch.IndexPrefix)
	indicators := intel.NewStore(ibackend)

	ectx, ecancel := context.WithTimeout(ctx, time.Minute)
	defer ecancel()
	if err := ibackend.EnsureIndex(ectx); err != nil {
		return nil, fmt.Errorf("could not prepare the threat intel index: %w", err)
	}
	// The intel store removes sample indicators from its in-memory set, so
	// load the current indicators first.
	if err := indicators.Load(ectx); err != nil {
		return nil, fmt.Errorf("could not read threat intel: %w", err)
	}

	eng := newEngine(c, cl)
	eng.Assets = lists
	eng.Intel = indicators
	host, _ := os.Hostname()

	return &sample.Loader{
		Prefix:   c.OpenSearch.IndexPrefix,
		Bulk:     cl,
		OS:       cl,
		Intel:    indicators,
		Assets:   lists,
		Library:  lib,
		Engine:   eng,
		Findings: fstore,
		Cases:    cstore,
		Risk:     &risk.Store{Client: cl, Prefix: c.OpenSearch.IndexPrefix},
		Docs:     cl,
		Server:   host,
		Command:  true,
		Log:      log,
	}, nil
}

// progressPrinter prints the plain-English step of a load or remove: a
// line when the step changes, and otherwise at most one every few seconds
// and only after the share done has moved on, so a long run stays short.
func progressPrinter(out io.Writer) sample.ProgressFn {
	var phase string
	var pct int
	var at time.Time
	return func(p sample.Progress) {
		switch {
		case p.Phase == "Done":
			return // the caller prints the summary
		case p.Phase != phase:
		case p.Percent >= pct+10 && time.Since(at) >= 3*time.Second:
		default:
			return
		}
		phase, pct, at = p.Phase, p.Percent, time.Now()
		fmt.Fprintf(out, "  %s (%d%%)\n", p.Phase, p.Percent)
	}
}

func sampleLoadCmd(ctx context.Context, loader *sample.Loader, size sample.Size) error {
	fmt.Printf("Loading the %s sample data. This writes a week of made-up activity and runs the detections over it.\n", size)
	st, err := loader.Load(ctx, size, progressPrinter(os.Stdout))
	switch {
	case errors.Is(err, sample.ErrAlreadyLoaded):
		return errors.New("sample data is already loaded; run \"signalith sample-data remove\" first")
	case errors.Is(err, sample.ErrPartial):
		return errors.New("the last load did not finish; run \"signalith sample-data remove\" to take out what it loaded, then load again")
	case errors.Is(err, sample.ErrBusy):
		return errors.New("a sample-data load or removal is already running (here, in the web page, or on another server that shares this OpenSearch); wait for it to finish")
	case errors.Is(err, context.Canceled):
		return errors.New("the load was stopped before it finished; run \"signalith sample-data remove\" to take out what it loaded")
	case err != nil:
		if cur, _ := loader.Status(context.WithoutCancel(ctx)); cur != nil && cur.Partial {
			return fmt.Errorf("%w\n\nThe load did not finish. Run \"signalith sample-data remove\" to take out what it loaded", err)
		}
		return err
	}
	fmt.Printf("\nDone. Loaded %d events, %d findings and %d risk events across %d stories.\n",
		st.Events, st.Findings, st.RiskEvents, len(st.Stories))
	if st.Skipped > 0 {
		fmt.Printf("%d events were not written; their days are read-only after retention compacted them.\n", st.Skipped)
	}
	fmt.Println("Open Signalith to try it. When you are finished, run \"signalith sample-data remove\".")
	return nil
}

func sampleRemoveCmd(ctx context.Context, loader *sample.Loader) error {
	cur, err := loader.Status(ctx)
	if err != nil {
		return err
	}
	if cur == nil {
		fmt.Println("There is no sample data to remove.")
		return nil
	}
	if cur.Partial {
		fmt.Println("Removing what the unfinished load wrote.")
	} else {
		fmt.Println("Removing the sample data.")
	}
	st, err := loader.Remove(ctx, progressPrinter(os.Stdout))
	if errors.Is(err, sample.ErrBusy) {
		return errors.New("a sample-data load or removal is already running (here, in the web page, or on another server that shares this OpenSearch); wait for it to finish")
	}
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("There is no sample data to remove.")
		return nil
	}
	fmt.Println("\nDone. All of the sample data is gone; nothing else was changed.")
	return nil
}

func sampleStatusCmd(ctx context.Context, loader *sample.Loader) error {
	st, a, err := loader.Current(ctx)
	if err != nil {
		return err
	}
	if a != nil {
		verb := "loading"
		if a.Op == "remove" {
			verb = "removing"
		}
		where := ""
		switch {
		case a.Command && a.Server != "":
			where = " with the signalith sample-data command on " + a.Server
		case a.Server != "":
			where = " on the server " + a.Server
		}
		fmt.Printf("Sample data is %s%s: %s (%d%%).\n", verb, where, a.Phase, a.Percent)
		return nil
	}
	if st == nil {
		fmt.Println("No sample data is loaded.")
		return nil
	}
	if st.Partial {
		fmt.Printf("A load started %s did not finish.\n", st.Started.Local().Format(time.RFC1123))
		fmt.Println("Run \"signalith sample-data remove\" to take out what it loaded.")
		return nil
	}
	fmt.Printf("Sample data is loaded (%s set, loaded %s).\n", st.Size, st.LoadedAt.Local().Format(time.RFC1123))
	fmt.Printf("  events:                   %d\n", st.Events)
	fmt.Printf("  findings:                 %d\n", st.Findings)
	fmt.Printf("  risk events:              %d\n", st.RiskEvents)
	fmt.Printf("  threat intel indicators:  %d\n", st.Indicators)
	fmt.Printf("  assets:                   %d\n", st.Assets)
	fmt.Printf("  identities:               %d\n", st.Identities)
	if len(st.Stories) > 0 {
		fmt.Println("  stories:")
		for _, s := range st.Stories {
			fmt.Printf("    - %s\n", s.Title)
		}
	}
	fmt.Println("Run \"signalith sample-data remove\" to take it all out.")
	return nil
}
