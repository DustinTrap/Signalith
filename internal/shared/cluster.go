package shared

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// The cluster document, <prefix>_config/cluster, says that the servers
// sharing this OpenSearch are one cluster: its id and name, which server
// founded it and when, the level of the stored formats every server must
// read, how far the import of the founder's files has come, and the
// migrations run once for the whole cluster. It is created with _create,
// so of two servers that found at the same moment one wins.

// Document ids and kinds of the cluster and the keyring.
const (
	ClusterDocID = "cluster"
	KeyringDocID = "keyring"
)

// The levels of the stored formats this version reads and writes. A
// cluster whose level is outside them was made by a version too new, or
// too old to upgrade from directly, and this server refuses to start.
const (
	LevelMin = 1
	LevelMax = 1
)

// Import states.
const (
	ImportImporting = "importing"
	ImportReady     = "ready"
)

// ImportState is how far the import of the founder's files has come.
// Done holds, per source, the hash of what was imported (or "none"), so
// an import cut short goes on from where it stopped.
type ImportState struct {
	State string            `json:"state"`
	By    string            `json:"by"`
	At    string            `json:"at"`
	Done  map[string]string `json:"done"`
	Extra `json:"-"`
}

// MarshalJSON writes the state with the fields this version does not
// know.
func (s ImportState) MarshalJSON() ([]byte, error) {
	type plain ImportState
	return MarshalExtra(plain(s), s.Extra)
}

// UnmarshalJSON reads the state, keeping the fields this version does
// not know.
func (s *ImportState) UnmarshalJSON(data []byte) error {
	type plain ImportState
	var p plain
	extra, err := UnmarshalExtra(data, &p)
	*s = ImportState(p)
	s.Extra = extra
	return err
}

// ClusterBody is the body of the cluster document.
type ClusterBody struct {
	ClusterID string `json:"cluster_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	// CreatedBy is the founder's name, and CreatedByID its node id.
	CreatedBy   string      `json:"created_by"`
	CreatedByID string      `json:"created_by_id"`
	IndexPrefix string      `json:"index_prefix"`
	Level       int         `json:"level"`
	Import      ImportState `json:"import"`
	// Merged lists the servers whose files were merged in when they
	// joined (signalith join --merge).
	Merged map[string]json.RawMessage `json:"merged,omitempty"`
	// Migrations holds, per migration run once for the cluster, when it
	// ran.
	Migrations map[string]string `json:"migrations,omitempty"`
	Extra      `json:"-"`
}

// ErrClusterExists is a founding that found a cluster already there.
var ErrClusterExists = errors.New("the servers sharing this OpenSearch are a cluster already")

// LevelError is a cluster whose stored formats this version cannot use.
type LevelError struct{ Level int }

func (e *LevelError) Error() string {
	if e.Level > LevelMax {
		return fmt.Sprintf("the shared settings in OpenSearch are at level %d, which a newer version of Signalith wrote; this version reads up to level %d. "+
			"Install the version the other servers run, or a newer one", e.Level, LevelMax)
	}
	return fmt.Sprintf("the shared settings in OpenSearch are at level %d, which this version of Signalith no longer reads (it needs level %d or above). "+
		"Upgrade through the version named in the release notes first", e.Level, LevelMin)
}

// CheckLevel returns a *LevelError when level is outside what this
// version reads.
func CheckLevel(level int) error {
	if level < LevelMin || level > LevelMax {
		return &LevelError{Level: level}
	}
	return nil
}

func newClusterID() string {
	b := make([]byte, 10)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "c_" + hex.EncodeToString(b)
}

// Importer moves one source of the founder's files into the shared
// configuration, such as its feed list. Each is idempotent: it may run
// again after a crash, and what is already there counts as done.
type Importer struct {
	// Name is the source's name in cluster.import.done.
	Name string
	// Source returns a hash of what there is to import, "" for nothing.
	// An importer whose hash is recorded as done is not run again.
	Source func() (string, error)
	// Run imports it, by the user by.
	Run func(ctx context.Context, by string) error
}

// importNone is recorded for a source that had nothing to import.
const importNone = "none"

// imports runs the importers not done yet, each after a check that this
// server may still change the shared settings (check: it still holds the
// job lease), and records each in the cluster document.
func (rt *Runtime) imports(ctx context.Context, by string, check func(context.Context) error) error {
	h, cdoc := rt.Hub(), rt.Cluster()
	for _, im := range rt.opts.Importers {
		body, ok := cdoc.Get()
		if !ok {
			return errors.New("the cluster document cannot be read")
		}
		hash := importNone
		if im.Source != nil {
			h, err := im.Source()
			if err != nil {
				return fmt.Errorf("could not read what to import for %s: %w", im.Name, err)
			}
			if h != "" {
				hash = h
			}
		}
		if body.Import.Done[im.Name] == hash {
			continue
		}
		if check != nil {
			if err := check(ctx); err != nil {
				return err
			}
		}
		if hash != importNone && im.Run != nil {
			if err := im.Run(ctx, by); err != nil {
				return fmt.Errorf("could not import %s: %w", im.Name, err)
			}
		}
		if _, err := cdoc.Mutate(ctx, by, func(b *ClusterBody) error {
			if b.Import.Done == nil {
				b.Import.Done = map[string]string{}
			}
			b.Import.Done[im.Name] = hash
			return nil
		}); err != nil {
			return err
		}
		rt.log.Info("imported into the shared settings", "source", im.Name)
	}
	_, err := cdoc.Mutate(ctx, by, func(b *ClusterBody) error {
		b.Import.State, b.Import.At = ImportReady, h.now()
		return nil
	})
	return err
}
