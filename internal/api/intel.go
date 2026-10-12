package api

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
)

func (s *Server) routeIntel(api *http.ServeMux) {
	api.HandleFunc("GET /api/intel", s.handleIntelOverview)
	api.HandleFunc("POST /api/intel/feeds/{name}/refresh", s.handleIntelRefresh)
	api.HandleFunc("GET /api/intel/indicators", s.handleIntelList)
	api.HandleFunc("POST /api/intel/indicators", s.handleIntelAdd)
	api.HandleFunc("DELETE /api/intel/indicators/{id}", s.handleIntelDelete)
	api.HandleFunc("POST /api/intel/upload", s.handleIntelUpload)
	api.HandleFunc("GET /api/intel/lookup", s.handleIntelLookup)
}

var errIntelOff = errors.New("threat intel is not available on this server")

func (s *Server) intelOK(w http.ResponseWriter) bool {
	if s.Intel == nil {
		writeError(w, http.StatusServiceUnavailable, errIntelOff)
		return false
	}
	return true
}

// handleIntelOverview returns indicator counts and every feed's status.
func (s *Server) handleIntelOverview(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	feeds := []intel.FeedView{}
	if s.Feeds != nil {
		feeds = s.Feeds.Status()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":   s.Intel.Summary(),
		"feeds":     feeds,
		"loaded":    s.Intel.Loaded(),
		"downloads": s.Config != nil && s.Config.Detections.Scheduler,
		"types":     intel.Types,
	})
}

func (s *Server) handleIntelRefresh(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	if s.Feeds == nil {
		writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
		return
	}
	name := r.PathValue("name")
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	st, err := s.Feeds.Refresh(ctx, name)
	switch {
	case errors.Is(err, intel.ErrUnknownFeed):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, intel.ErrFeedRunning):
		writeError(w, http.StatusConflict, err)
	case err != nil:
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "status": st})
	default:
		s.Log.Info("threat intel feed refreshed by hand", "feed", name, "by", userOf(r))
		writeJSON(w, http.StatusOK, map[string]any{"status": st})
	}
}

func (s *Server) handleIntelList(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	v := r.URL.Query()
	limit, _ := strconv.Atoi(v.Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	offset, _ := strconv.Atoi(v.Get("offset"))
	list, total := s.Intel.List(intel.Filter{Text: v.Get("q"), Type: v.Get("type"), Source: v.Get("source"), Limit: limit, Offset: max(offset, 0)})
	if list == nil {
		list = []intel.Indicator{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"indicators": list, "total": total})
}

// handleIntelAdd adds one manual indicator.
func (s *Server) handleIntelAdd(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	var in intel.Input
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ind, err := in.Build(time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	inds := []intel.Indicator{ind}
	if err := s.Intel.Add(r.Context(), inds); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.Log.Info("threat intel indicator added", "type", ind.Type, "value", ind.Value, "by", userOf(r))
	got, _ := s.Intel.Get(inds[0].ID)
	writeJSON(w, http.StatusOK, got)
}

// handleIntelDelete removes a manual indicator. Feed indicators come back
// with the next download, so they are removed by disabling the feed.
func (s *Server) handleIntelDelete(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	id := r.PathValue("id")
	ind, ok := s.Intel.Get(id)
	if !ok {
		writeError(w, http.StatusNotFound, errors.New("no indicator with that id"))
		return
	}
	if ind.Source != intel.ManualSource {
		writeError(w, http.StatusConflict, errors.New("this indicator comes from the feed "+ind.Source+" and would return with its next download; disable the feed instead"))
		return
	}
	if err := s.Intel.Delete(r.Context(), []string{id}); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.Log.Info("threat intel indicator deleted", "type", ind.Type, "value", ind.Value, "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// handleIntelUpload adds manual indicators from CSV or a plain list.
// Every bad line is reported and nothing is saved unless all are valid.
func (s *Server) handleIntelUpload(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	inds, err := intel.ParseUpload(data, time.Now())
	var pe *intel.ParseError
	if errors.As(err, &pe) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "the file has problems; nothing was saved", "lines": pe.Lines})
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(inds) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("the file has no indicators"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.Intel.Add(ctx, inds); err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	s.Log.Info("threat intel indicators uploaded", "indicators", len(inds), "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"count": len(inds)})
}

// handleIntelLookup checks one value against every indicator, the way
// the intel search command does.
func (s *Server) handleIntelLookup(w http.ResponseWriter, r *http.Request) {
	if !s.intelOK(w) {
		return
	}
	m := s.Intel.Lookup(r.URL.Query().Get("value"))
	if m == nil {
		m = []intel.Indicator{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"matches": m})
}
