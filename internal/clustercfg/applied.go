package clustercfg

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A shared setting set in a server's signalith.yaml is applied to the
// shared value when it changes, not at every start, so an unchanged file
// never undoes a change made on a page (design 4.6). This step's settings
// are retention.days, .default, .policies.<category> and .guard, and each
// feed of intel.feeds; no environment variable sets them, so
// signalith.yaml is their only source.

// fileValue is one shared setting as this server's signalith.yaml sets
// it.
type fileValue struct {
	key   string
	value any
	// feed is the feed's settings, for intel.feeds[<name>].
	feed *intel.FeedSpec
}

// fileValues lists the shared settings signalith.yaml sets. Only keys
// actually set count: removing one from the file changes nothing.
func fileValues(c *config.Config) []fileValue {
	inFile := func(key string) bool { return c.Source(key).Kind == config.FromFile }
	var out []fileValue
	if inFile("retention.days") {
		out = append(out, fileValue{key: "retention.days", value: c.Retention.Days})
	}
	if c.Retention.Default != nil && inFile("retention.default") {
		out = append(out, fileValue{key: "retention.default", value: *c.Retention.Default})
	}
	for _, id := range slices.Sorted(maps.Keys(c.Retention.Policies)) {
		if key := "retention.policies." + id; inFile(key) {
			out = append(out, fileValue{key: key, value: c.Retention.Policies[id]})
		}
	}
	if c.Retention.Guard != nil && inFile("retention.guard") {
		out = append(out, fileValue{key: "retention.guard", value: c.Retention.Guard.Normalized()})
	}
	if inFile("intel.feeds") {
		for _, s := range yamlFeeds(c) {
			s := s
			out = append(out, fileValue{key: "intel.feeds[" + s.Name + "]", value: s, feed: &s})
		}
	}
	return out
}

// Applied is the result of the step: what was applied, and the settings
// whose file value differs from the shared one without having changed.
type Applied struct {
	Applied []string
	Drift   []string
}

// Apply applies the values of this server's signalith.yaml that changed
// since its previous start to the shared settings, records what it saw,
// and audits each change ("retention.days applied from signalith.yaml on
// siem-b"). At a server's first start as a member it only records them.
func Apply(ctx context.Context, rt *shared.Runtime, d *Docs, c *config.Config, node string, log *slog.Logger) (Applied, error) {
	var res Applied
	keys := d.Hub().Keys()
	k := keys.Active()
	if k == nil {
		return res, fmt.Errorf("this server has no cluster key")
	}
	ncDoc := rt.NodeCfg()
	nc, _ := ncDoc.Get()
	first := nc.Applied == ""
	now := time.Now()
	type seen struct{ key, hash string }
	var record []seen
	var apply []fileValue
	for _, fv := range fileValues(c) {
		h, err := shared.SeenHash(k, fv.key, fv.value)
		if err != nil {
			return res, err
		}
		record = append(record, seen{fv.key, h})
		if nc.Changed(fv.key, shared.SourceYAML, h, first) {
			apply = append(apply, fv)
		}
	}
	var feeds []fileValue
	var ret []fileValue
	for _, fv := range apply {
		if fv.feed != nil {
			feeds = append(feeds, fv)
		} else {
			ret = append(ret, fv)
		}
	}
	from := *stamp(FromYAML, node, now)
	if len(ret) > 0 {
		_, err := d.Retention().Mutate(ctx, "signalith", func(b *RetentionBody) error {
			if b.From == nil {
				b.From = map[string]From{}
			}
			for _, fv := range ret {
				switch v := fv.value.(type) {
				case int:
					b.Days = &v
					b.From["days"] = from
				case retention.Policy:
					if fv.key == "retention.default" {
						b.Default = &v
						b.From["default"] = from
						continue
					}
					id := strings.TrimPrefix(fv.key, "retention.policies.")
					if b.Policies == nil {
						b.Policies = map[string]retention.Policy{}
					}
					b.Policies[id] = v
					b.From["policies."+id] = from
				case retention.Guard:
					b.Guard = &v
					b.From["guard"] = from
				}
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	if len(feeds) > 0 {
		_, err := d.Feeds().Mutate(ctx, "signalith", func(b *FeedsBody) error {
			for _, fv := range feeds {
				e, err := entryOf(*fv.feed, k, &from)
				if err != nil {
					return err
				}
				i := slices.IndexFunc(b.Feeds, func(x FeedEntry) bool { return x.Name == fv.feed.Name })
				if i < 0 {
					b.Feeds = append(b.Feeds, e)
					continue
				}
				e.Extra = b.Feeds[i].Extra
				b.Feeds[i] = e
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	for _, fv := range apply {
		res.Applied = append(res.Applied, fv.key)
		log.Info(fv.key+" applied from signalith.yaml on "+node, "audit", true, "setting", fv.key, "server", node)
	}
	if first || len(record) > 0 {
		_, err := ncDoc.Mutate(ctx, "signalith", func(n *shared.NodeCfg) error {
			for _, s := range record {
				n.Record(s.key, shared.SourceYAML, s.hash)
			}
			if n.Applied == "" {
				n.Applied = now.UTC().Format(time.RFC3339Nano)
			}
			return nil
		})
		if err != nil {
			return res, err
		}
	}
	res.Drift = Drift(d, c)
	return res, nil
}

// Drift lists the shared settings whose value in this server's
// signalith.yaml differs from the shared one, for the Servers page
// ("siem-b's signalith.yaml says retention.days: 90; the shared value is
// 365"): information, not a problem.
func Drift(d *Docs, c *config.Config) []string {
	var out []string
	rb, rok := d.Retention().Get()
	fb, fok := d.Feeds().Get()
	var shared intel.FeedSet
	if fok {
		shared = decodeFeeds(fb, opener(d.Hub().Keys()))
	}
	for _, fv := range fileValues(c) {
		var have any
		known := rok
		switch {
		case fv.feed != nil:
			known = fok
			i := slices.IndexFunc(shared.UI, func(s intel.FeedSpec) bool { return s.Name == fv.feed.Name })
			if known && (i < 0 || !sameSpec(shared.UI[i], *fv.feed)) {
				out = append(out, fv.key)
			}
			continue
		case fv.key == "retention.days":
			if rb.Days != nil {
				have = *rb.Days
			}
		case fv.key == "retention.default":
			if rb.Default != nil {
				have = *rb.Default
			}
		case fv.key == "retention.guard":
			if rb.Guard != nil {
				have = rb.Guard.Normalized()
			}
		default:
			if p, ok := rb.Policies[strings.TrimPrefix(fv.key, "retention.policies.")]; ok {
				have = p
			}
		}
		if known && !sameJSON(have, fv.value) {
			out = append(out, fv.key)
		}
	}
	return out
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return reflect.DeepEqual(x, y)
}
