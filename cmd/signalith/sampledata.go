package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
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
)

const sampleUsage = `usage:
  signalith sample-data load   [-c file] [-size standard|small]   load a week of made-up activity with attacks to try
  signalith sample-data remove [-c file]                          remove every bit of it
  signalith sample-data status [-c file]                          show whether sample data is loaded

Everything is fictional and safe to load on any network. Remove puts the
server back exactly as it was. In Docker:
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

	// status only reads the small bookkeeping file; it needs no OpenSearch.
	if sub == "status" {
		return sampleStatusCmd(&sample.Loader{StateDir: c.StateDir()})
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
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

// buildSampleLoader wires the loader to OpenSearch and the stores, and makes
// sure the indices and the index template are in place first, so the sample
// events get the right field types and the detections can write findings.
func buildSampleLoader(ctx context.Context, c *config.Config, log *slog.Logger) (*sample.Loader, error) {
	cl := newStore(c)

	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	_, herr := cl.Health(hctx)
	cancel()
	if herr != nil {
		return nil, fmt.Errorf("OpenSearch is not reachable, so no sample data can be loaded or removed: %w", herr)
	}
	tctx, tcancel := context.WithTimeout(ctx, 30*time.Second)
	terr := cl.PutIndexTemplate(tctx, c.OpenSearch.IndexPrefix, ingest.IndexTemplate(c.OpenSearch.IndexPrefix, c.OpenSearch.Replicas))
	tcancel()
	if terr != nil {
		return nil, fmt.Errorf("could not install the index template: %w", terr)
	}

	lists, err := assets.OpenStore(c.LookupsDir())
	if err != nil {
		return nil, fmt.Errorf("asset and identity lists: %w", err)
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
	for _, step := range []struct {
		what string
		fn   func(context.Context) error
	}{
		{"findings", fstore.EnsureIndex},
		{"cases", cstore.EnsureIndex},
		{"threat intel", ibackend.EnsureIndex},
	} {
		if err := step.fn(ectx); err != nil {
			return nil, fmt.Errorf("could not prepare the %s index: %w", step.what, err)
		}
	}
	// The intel store removes sample indicators from its in-memory set, so
	// load the current indicators first.
	if err := indicators.Load(ectx); err != nil {
		return nil, fmt.Errorf("could not read threat intel: %w", err)
	}

	eng := newEngine(c, cl)
	eng.Assets = lists
	eng.Intel = indicators

	return &sample.Loader{
		Prefix:   c.OpenSearch.IndexPrefix,
		Pipeline: &ingest.Pipeline{Store: cl, Prefix: c.OpenSearch.IndexPrefix, MaxEventAge: c.MaxEventAge(0), Log: log},
		OS:       cl,
		Intel:    indicators,
		Assets:   lists,
		Library:  lib,
		Engine:   eng,
		Findings: fstore,
		Cases:    cstore,
		Risk:     &risk.Store{Client: cl, Prefix: c.OpenSearch.IndexPrefix},
		StateDir: c.StateDir(),
		Log:      log,
	}, nil
}

// progressPrinter prints the plain-English step of a load or remove, at most
// one line every second so a long run does not scroll past.
func progressPrinter() sample.ProgressFn {
	var last string
	var lastAt time.Time
	return func(p sample.Progress) {
		line := p.Phase
		if p.Total > 0 {
			line = fmt.Sprintf("%s (%d of %d)", p.Phase, p.Done, p.Total)
		}
		if line == last && time.Since(lastAt) < time.Second {
			return
		}
		last, lastAt = line, time.Now()
		fmt.Println("  " + line)
	}
}

func sampleLoadCmd(ctx context.Context, loader *sample.Loader, size sample.Size) error {
	if loader.Loaded() {
		return errors.New("sample data is already loaded; run \"signalith sample-data remove\" first")
	}
	fmt.Printf("Loading the %s sample data. This writes a week of made-up activity and runs the detections over it.\n", size)
	st, err := loader.Load(ctx, size, progressPrinter())
	if err != nil {
		return err
	}
	fmt.Printf("\nDone. Loaded %d events, %d findings and %d risk events across %d stories.\n",
		st.Events, st.Findings, st.RiskEvents, len(st.Stories))
	fmt.Println("Open Signalith to try it. When you are finished, run \"signalith sample-data remove\".")
	return nil
}

func sampleRemoveCmd(ctx context.Context, loader *sample.Loader) error {
	if !loader.Loaded() {
		fmt.Println("There is no sample data to remove.")
		return nil
	}
	fmt.Println("Removing the sample data.")
	st, err := loader.Remove(ctx, progressPrinter())
	if err != nil {
		return err
	}
	fmt.Printf("\nDone. Removed the sample set loaded %s. The server is back as it was.\n", st.LoadedAt.Format(time.RFC1123))
	return nil
}

func sampleStatusCmd(loader *sample.Loader) error {
	st, err := loader.Status()
	if err != nil {
		return err
	}
	if st == nil {
		fmt.Println("No sample data is loaded.")
		return nil
	}
	fmt.Printf("Sample data is loaded (%s set, loaded %s).\n", st.Size, st.LoadedAt.Format(time.RFC1123))
	fmt.Printf("  events:      %d\n", st.Events)
	fmt.Printf("  findings:    %d\n", st.Findings)
	fmt.Printf("  risk events: %d\n", st.RiskEvents)
	fmt.Printf("  indicators:  %d\n", st.Indicators)
	fmt.Printf("  assets:      %d\n", st.Assets)
	fmt.Printf("  identities:  %d\n", st.Identities)
	if len(st.Stories) > 0 {
		titles := make([]string, 0, len(st.Stories))
		for _, s := range st.Stories {
			titles = append(titles, s.Title)
		}
		sort.Strings(titles)
		fmt.Println("  stories:")
		for _, t := range titles {
			fmt.Printf("    - %s\n", t)
		}
	}
	fmt.Println("Run \"signalith sample-data remove\" to take it all out.")
	return nil
}
