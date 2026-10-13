package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/users"
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
}

var errNoCluster = errors.New("the list of servers is not available on this server")

func (s *Server) routeCluster(api *router) {
	// Everyone signed in sees which servers there are and whether they
	// work; where they run and what is wrong with them is for admins.
	api.viewer("GET /api/cluster", s.handleCluster)
}

// clusterServer is one server in GET /api/cluster. Fields after Jobs are
// for admins only.
type clusterServer struct {
	Name         string     `json:"name"`
	Self         bool       `json:"self"`
	State        string     `json:"state"`
	OfflineSince *time.Time `json:"offline_since,omitempty"`
	Version      string     `json:"version"`
	Jobs         string     `json:"jobs"`
	StartedAt    time.Time  `json:"started_at"`

	NodeID         string                `json:"node_id,omitempty"`
	HeartbeatAt    *time.Time            `json:"heartbeat_at,omitempty"`
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

// clusterLease is who runs the background jobs. Fields after Frozen are
// for admins only.
type clusterLease struct {
	HolderName string `json:"holder_name"`
	Frozen     bool   `json:"frozen"`

	Holder     string     `json:"holder,omitempty"`
	Epoch      int64      `json:"epoch,omitempty"`
	AcquiredAt *time.Time `json:"acquired_at,omitempty"`
	RenewedAt  *time.Time `json:"renewed_at,omitempty"`
	Mine       *bool      `json:"mine,omitempty"`
	ReleasedBy string     `json:"released_by,omitempty"`
}

// handleCluster lists the servers that share this OpenSearch and which
// one runs the background jobs.
func (s *Server) handleCluster(w http.ResponseWriter, r *http.Request) {
	if s.Cluster == nil {
		writeError(w, http.StatusServiceUnavailable, errNoCluster)
		return
	}
	admin := false
	if p := principalOf(r); p != nil && p.Role.AtLeast(users.Admin) {
		admin = true
	}
	st := s.Cluster.Status()
	servers := make([]clusterServer, 0, len(st.Servers))
	for _, sv := range st.Servers {
		out := clusterServer{Name: sv.Name, Self: sv.Self, State: sv.State, OfflineSince: sv.OfflineSince,
			Version: sv.Version, Jobs: sv.Jobs, StartedAt: sv.StartedAt}
		if admin {
			hbAt := sv.HeartbeatAt
			out.NodeID, out.HeartbeatAt, out.CannotTakeOver = sv.NodeID, &hbAt, sv.CannotTakeOver
			if d := sv.Detail; d != nil {
				syslog, fp, osInfo := d.Syslog, d.FilesFingerprint, d.OpenSearch
				osInfo.Endpoint = redact.URL(osInfo.Endpoint)
				out.NodeURL, out.Listen, out.Syslog, out.OS, out.Arch, out.Deployment = d.NodeURL, d.Listen, &syslog, d.OS, d.Arch, d.Deployment
				out.ClockOffsetMS, out.NotEligible, out.Fingerprints, out.OpenSearch = d.ClockOffsetMS, d.NotEligible, &fp, &osInfo
				out.MachineMoved, out.Problems = d.MachineMoved, d.Problems
			}
		}
		servers = append(servers, out)
	}
	lease := clusterLease{HolderName: st.Jobs.HolderName, Frozen: st.Jobs.Frozen}
	if admin {
		mine := st.Jobs.Mine
		lease.Holder, lease.Epoch, lease.AcquiredAt, lease.RenewedAt = st.Jobs.Holder, st.Jobs.Epoch, st.Jobs.AcquiredAt, st.Jobs.RenewedAt
		lease.Mine, lease.ReleasedBy = &mine, st.Jobs.ReleasedBy
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	health, err := s.Backend.Health(ctx)
	if err != nil {
		health = "unreachable"
	}
	out := map[string]any{"servers": servers, "lease": lease, "opensearch": map[string]any{"status": health}}
	if admin {
		out["self"] = st.Self
		out["writes_refused"] = st.WritesRefused
		out["warnings"] = st.Warnings
		out["opensearch"] = map[string]any{"status": health, "url": redact.URL(s.conf().OpenSearch.URL)}
	}
	writeJSON(w, http.StatusOK, out)
}
