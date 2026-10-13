package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/redact"
)

// Cluster is this server among the servers that share its OpenSearch.
type Cluster interface {
	// RunsJobs reports whether this server runs the background jobs
	// (detections, threat intel downloads, retention) now.
	RunsJobs() bool
	// JobHolder names another server that runs them, or "".
	JobHolder() string
	// Status is every server as this one last saw them.
	Status() cluster.Status
	// Banners are the red problems everyone should see on every page,
	// briefly and without addresses.
	Banners() []string
}

var errNoCluster = errors.New("the list of servers is not available on this server")

func (s *Server) routeCluster(api *router) {
	// The list of servers says where they run and what is wrong with them,
	// so it is for admins. Everyone else learns of a problem that matters
	// to them from the banner on every page (cluster_banners in
	// api/health).
	api.admin("GET /api/cluster", s.handleCluster)
}

// clusterServer is one server in GET /api/cluster.
type clusterServer struct {
	Name         string     `json:"name"`
	Self         bool       `json:"self"`
	State        string     `json:"state"`
	OfflineSince *time.Time `json:"offline_since,omitempty"`
	// SeenSecondsAgo, for an offline or stopped server, and UptimeSeconds
	// are ages worked out by this server's own clocks, so the page needs
	// neither the other server's clock nor the browser's to be right.
	SeenSecondsAgo *int64    `json:"seen_seconds_ago,omitempty"`
	UptimeSeconds  int64     `json:"uptime_seconds"`
	Version        string    `json:"version"`
	Jobs           string    `json:"jobs"`
	StartedAt      time.Time `json:"started_at"`

	NodeID         string                `json:"node_id"`
	HeartbeatAt    time.Time             `json:"heartbeat_at"`
	NodeURL        string                `json:"node_url,omitempty"`
	Listen         string                `json:"listen,omitempty"`
	Syslog         *cluster.Syslog       `json:"syslog,omitempty"`
	OS             string                `json:"os,omitempty"`
	Arch           string                `json:"arch,omitempty"`
	Deployment     string                `json:"deployment,omitempty"`
	ClockOffsetMS  *int64                `json:"clock_offset_ms,omitempty"`
	NotEligible    string                `json:"not_eligible,omitempty"`
	CannotTakeOver string                `json:"cannot_take_over,omitempty"`
	Fingerprints   *cluster.Fingerprints `json:"files_fingerprint,omitempty"`
	OpenSearch     *cluster.OSInfo       `json:"opensearch,omitempty"`
	MachineMoved   bool                  `json:"machine_moved,omitempty"`
	Problems       []string              `json:"problems,omitempty"`
}

// clusterLease is who runs the background jobs.
type clusterLease struct {
	HolderName string     `json:"holder_name"`
	Frozen     bool       `json:"frozen"`
	Holder     string     `json:"holder,omitempty"`
	Epoch      int64      `json:"epoch,omitempty"`
	AcquiredAt *time.Time `json:"acquired_at,omitempty"`
	RenewedAt  *time.Time `json:"renewed_at,omitempty"`
	Mine       bool       `json:"mine"`
	ReleasedBy string     `json:"released_by,omitempty"`
}

// handleCluster lists the servers that share this OpenSearch and which
// one runs the background jobs.
func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	if s.Cluster == nil {
		writeError(w, http.StatusServiceUnavailable, errNoCluster)
		return
	}
	st := s.Cluster.Status()
	servers := make([]clusterServer, 0, len(st.Servers))
	for _, sv := range st.Servers {
		out := clusterServer{Name: sv.Name, Self: sv.Self, State: sv.State, OfflineSince: sv.OfflineSince,
			UptimeSeconds: int64(sv.Uptime / time.Second), Version: sv.Version, Jobs: sv.Jobs, StartedAt: sv.StartedAt,
			NodeID: sv.NodeID, HeartbeatAt: sv.HeartbeatAt, CannotTakeOver: sv.CannotTakeOver}
		if sv.SeenAgo != nil {
			ago := int64(*sv.SeenAgo / time.Second)
			out.SeenSecondsAgo = &ago
		}
		if d := sv.Detail; d != nil {
			syslog, fp, osInfo := d.Syslog, d.FilesFingerprint, d.OpenSearch
			osInfo.Endpoint = redact.URL(osInfo.Endpoint)
			out.NodeURL, out.Listen, out.Syslog, out.OS, out.Arch, out.Deployment = d.NodeURL, d.Listen, &syslog, d.OS, d.Arch, d.Deployment
			out.ClockOffsetMS, out.NotEligible, out.Fingerprints, out.OpenSearch = d.ClockOffsetMS, d.NotEligible, &fp, &osInfo
			out.MachineMoved, out.Problems = d.MachineMoved, d.Problems
		}
		servers = append(servers, out)
	}
	lease := clusterLease{HolderName: st.Jobs.HolderName, Frozen: st.Jobs.Frozen, Holder: st.Jobs.Holder, Epoch: st.Jobs.Epoch,
		AcquiredAt: st.Jobs.AcquiredAt, RenewedAt: st.Jobs.RenewedAt, Mine: st.Jobs.Mine, ReleasedBy: st.Jobs.ReleasedBy}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	health, err := s.Backend.Health(ctx)
	if err != nil {
		health = "unreachable"
	}
	writeJSON(w, http.StatusOK, map[string]any{"self": st.Self, "servers": servers, "lease": lease, "warnings": st.Warnings,
		"writes_refused": st.WritesRefused, "opensearch": map[string]any{"status": health, "url": redact.URL(s.conf().OpenSearch.URL)}})
}
