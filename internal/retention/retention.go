// Package retention deletes daily indices older than the configured age.
package retention

import (
	"context"
	"log/slog"
	"regexp"
	"time"
)

// Indexer lists and deletes indices.
type Indexer interface {
	ListIndices(ctx context.Context, pattern string) ([]string, error)
	DeleteIndex(ctx context.Context, name string) error
}

var dateSuffix = regexp.MustCompile(`-(\d{4}\.\d{2}\.\d{2})$`)

// Expired returns the indices whose date suffix is more than days old.
func Expired(indices []string, days int, now time.Time) []string {
	if days <= 0 {
		return nil
	}
	cutoff := now.UTC().AddDate(0, 0, -days).Truncate(24 * time.Hour)
	var out []string
	for _, name := range indices {
		m := dateSuffix.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		day, err := time.Parse("2006.01.02", m[1])
		if err != nil {
			continue
		}
		if day.Before(cutoff) {
			out = append(out, name)
		}
	}
	return out
}

// Run enforces retention now and then every interval until ctx ends.
func Run(ctx context.Context, ix Indexer, prefix string, days int, interval time.Duration, log *slog.Logger) {
	if days <= 0 {
		return
	}
	for {
		names, err := ix.ListIndices(ctx, prefix+"-*")
		if err != nil {
			log.Warn("retention: listing indices failed", "err", err)
		} else {
			for _, name := range Expired(names, days, time.Now()) {
				if err := ix.DeleteIndex(ctx, name); err != nil {
					log.Warn("retention: delete failed", "index", name, "err", err)
				} else {
					log.Info("retention: deleted expired index", "index", name, "days", days)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
