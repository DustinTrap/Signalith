package cluster

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// RuntimeIndex is the index that holds heartbeats, the job lease and
// other coordination documents. The underscore keeps it out of the event
// indices (<prefix>-*).
func RuntimeIndex(prefix string) string { return prefix + "_runtime" }

// ensureRuntime creates the runtime index if it is missing. Any server
// may, at any time; one that finds it already made carries on.
func ensureRuntime(ctx context.Context, c *store.Client, prefix string) error {
	kw := map[string]any{"type": "keyword"}
	long := map[string]any{"type": "long"}
	date := map[string]any{"type": "date"}
	body := map[string]any{
		"settings": map[string]any{"number_of_shards": 1, "auto_expand_replicas": "0-1", "refresh_interval": "1s"},
		"mappings": map[string]any{
			"dynamic": "false",
			"properties": map[string]any{
				"kind": kw, "node": kw, "node_id": kw, "state": kw, "target": kw, "detection_id": kw,
				"group_key": kw, "user": kw, "agent": kw,
				"epoch": long, "lease_epoch": long,
				"until": date, "at": date, "last_seen": date, "expires_at": date, "heartbeat_at": date,
				"body": map[string]any{"type": "object", "enabled": false},
			},
		},
	}
	err := c.Do(ctx, http.MethodPut, "/"+url.PathEscape(RuntimeIndex(prefix)), body, nil)
	var oe *store.Error
	if errors.As(err, &oe) && oe.Status == http.StatusBadRequest && strings.Contains(oe.Body, "resource_already_exists_exception") {
		return nil
	}
	return err
}

// Document ids in the runtime index.
const leaseID = "lease:jobs"

func nodeDocID(nodeID string) string { return "node:" + nodeID }

// Server states in heartbeats.
const (
	StateStarting = "starting"
	StateReady    = "ready"
	StateStopping = "stopping"
	StateStopped  = "stopped"
	// StateConflict is a server that found another process using its
	// identity: it runs no jobs until that is fixed.
	StateConflict = "conflict"
	// StateOffline is never written: it is a heartbeat that stopped
	// changing.
	StateOffline = "offline"
)

// Heartbeat is a server's document in the runtime index, node:<node_id>,
// rewritten every 10 seconds.
type Heartbeat struct {
	Kind        string    `json:"kind"`
	NodeID      string    `json:"node_id"`
	Name        string    `json:"name"`
	BootID      string    `json:"boot_id"`
	State       string    `json:"state"`
	Version     string    `json:"version"`
	OS          string    `json:"os"`
	Arch        string    `json:"arch"`
	Deployment  string    `json:"deployment,omitempty"`
	StartedAt   time.Time `json:"started_at"`
	HeartbeatAt time.Time `json:"heartbeat_at"`
	// ClockOffsetMS is OpenSearch's clock minus this server's, nil when
	// it could not be measured.
	ClockOffsetMS *int64 `json:"clock_offset_ms"`
	NodeURL       string `json:"node_url,omitempty"`
	Listen        string `json:"listen,omitempty"`
	Syslog        Syslog `json:"syslog"`
	// LeaderEligible is true when this server may run the background
	// jobs, and NotEligible says why not otherwise.
	LeaderEligible bool   `json:"leader_eligible"`
	NotEligible    string `json:"not_eligible,omitempty"`
	Leader         bool   `json:"leader"`
	LeaseEpoch     int64  `json:"lease_epoch"`
	// Frozen is true while it holds the jobs in delete-only emergency
	// mode, because OpenSearch refuses writes.
	Frozen           bool         `json:"frozen,omitempty"`
	FilesFingerprint Fingerprints `json:"files_fingerprint"`
	OpenSearch       OSInfo       `json:"opensearch"`
	MachineMoved     bool         `json:"machine_moved"`
	Problems         []string     `json:"problems"`
}

// Syslog is where a server listens for syslog.
type Syslog struct {
	UDP string `json:"udp"`
	TCP string `json:"tcp"`
	TLS string `json:"tls"`
}

// OSInfo is how a server reaches OpenSearch.
type OSInfo struct {
	OK        bool   `json:"ok"`
	Endpoint  string `json:"endpoint,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
}

// LeaseDoc is lease:jobs, which names the server that runs the
// background jobs.
type LeaseDoc struct {
	Kind          string    `json:"kind"`
	Job           string    `json:"job"`
	Holder        string    `json:"holder"`
	HolderName    string    `json:"holder_name"`
	HolderVersion string    `json:"holder_version"`
	HolderBoot    string    `json:"holder_boot"`
	Epoch         int64     `json:"epoch"`
	AcquiredAt    time.Time `json:"acquired_at"`
	RenewedAt     time.Time `json:"renewed_at"`
	TTLMS         int64     `json:"ttl_ms"`
	// Prefer names the server a release hands the jobs to.
	Prefer        string `json:"prefer"`
	ReleasedBy    string `json:"released_by"`
	ReleaseReason string `json:"release_reason"`
	// Fingerprint covers the holder's own files that the jobs use, and
	// Fingerprints its parts, so a server whose files differ does not take
	// over without anyone noticing.
	Fingerprint  string       `json:"fingerprint"`
	Fingerprints Fingerprints `json:"fingerprints"`
}

// Fingerprints are hashes of the files each server keeps for itself
// that the background jobs use. Until they are shared through OpenSearch,
// a server whose files differ from the job holder's does not take over the
// jobs by itself.
type Fingerprints struct {
	Retention  string `json:"retention,omitempty"`
	Feeds      string `json:"feeds,omitempty"`
	Detections string `json:"detections,omitempty"`
	// Archives covers the archive folder's list of archives, only while
	// some retention policy archives.
	Archives string `json:"archives,omitempty"`
}

// Combined is one hash over all the parts.
func (f Fingerprints) Combined() string {
	h := sha256.New()
	for _, p := range []string{f.Retention, f.Feeds, f.Detections, f.Archives} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// Differ lists the parts that differ between f and o, in words: "retention
// policies", "threat intel feeds", "detections folder", "archives".
func (f Fingerprints) Differ(o Fingerprints) []string {
	var out []string
	if f.Retention != o.Retention {
		out = append(out, "retention policies")
	}
	if f.Feeds != o.Feeds {
		out = append(out, "threat intel feeds")
	}
	if f.Detections != o.Detections {
		out = append(out, "detections folder")
	}
	if f.Archives != o.Archives {
		out = append(out, "archives")
	}
	return out
}

// Hash returns "sha256:<hex>" of the parts, each ended by a zero byte.
func Hash(parts ...[]byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
