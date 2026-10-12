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
	api.HandleFunc("GET /api/intel/feeds", s.handleIntelFeeds)
	api.HandleFunc("POST /api/intel/feeds", s.handleIntelFeedAdd)
	api.HandleFunc("POST /api/intel/feeds/test", s.handleIntelFeedTest)
	api.HandleFunc("PUT /api/intel/feeds/{name}", s.handleIntelFeedUpdate)
	api.HandleFunc("DELETE /api/intel/feeds/{name}", s.handleIntelFeedDelete)
	api.HandleFunc("POST /api/intel/feeds/{name}/refresh", s.handleIntelRefresh)
	api.HandleFunc("GET /api/intel/catalog", s.handleIntelCatalog)
	api.HandleFunc("POST /api/intel/catalog", s.handleIntelCatalogAdd)
	api.HandleFunc("POST /api/intel/taxii/collections", s.handleIntelTAXIICollections)
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
	out := map[string]any{
		"summary":   s.Intel.Summary(),
		"loaded":    s.Intel.Loaded(),
		"downloads": s.Config != nil && s.Config.Detections.Scheduler,
		"types":     intel.Types,
		// manage says whether feeds can be added and changed on the page.
		"manage": s.Feeds != nil,
	}
	if s.Feeds != nil {
		feeds = s.Feeds.Status()
		// A broken feeds file blocks changes on the page until it is fixed.
		if err := s.Feeds.Load(); err != nil {
			out["file_error"] = err.Error()
		}
	}
	out["feeds"] = feeds
	writeJSON(w, http.StatusOK, out)
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
	case errors.Is(err, intel.ErrFeedRunning), errors.Is(err, intel.ErrFeedChanged):
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
	// A feed's indicators return with its next download. Those of a
	// deleted feed whose indicators were kept can go one by one.
	if ind.Source != intel.ManualSource && s.Feeds != nil {
		if _, ok := s.Feeds.Get(ind.Source); ok {
			writeError(w, http.StatusConflict, errors.New("this indicator comes from the feed "+ind.Source+" and would return with its next download; disable the feed instead"))
			return
		}
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

// ---- feeds managed on the page ----

var errFeedsOff = errors.New("threat intel feeds are not available on this server")

func (s *Server) feedsOK(w http.ResponseWriter) bool {
	if !s.intelOK(w) {
		return false
	}
	if s.Feeds == nil {
		writeError(w, http.StatusServiceUnavailable, errFeedsOff)
		return false
	}
	return true
}

// writeFeedError answers a failed feed change in plain words.
func writeFeedError(w http.ResponseWriter, err error) {
	var ie *intel.InputError
	var fe *intel.FileError
	switch {
	case errors.As(err, &ie):
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": ie.Error(), "problems": ie.Messages(), "fields": ie.Fields()})
	case errors.Is(err, intel.ErrUnknownFeed):
		writeError(w, http.StatusNotFound, err)
	case errors.Is(err, intel.ErrReadOnly):
		writeError(w, http.StatusConflict, err)
	case errors.As(err, &fe):
		writeError(w, http.StatusServiceUnavailable, err)
	default:
		writeError(w, http.StatusInternalServerError, err)
	}
}

// handleIntelFeeds lists every feed with its settings and status. Secret
// values are never included, only whether each is set.
func (s *Server) handleIntelFeeds(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	out := map[string]any{
		"feeds":      s.Feeds.Status(),
		"downloads":  s.Config != nil && s.Config.Detections.Scheduler,
		"feeds_file": s.Feeds.File,
		"formats":    append(append([]string{}, intel.Formats...), intel.FormatAuto),
		"types":      intel.FeedTypes,
	}
	if err := s.Feeds.Load(); err != nil {
		out["file_error"] = err.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleIntelFeedAdd(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	var in intel.FeedInput
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	v, err := s.Feeds.AddFeed(in)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	s.Log.Info("threat intel feed added", "feed", v.Name, "url", intel.RedactURL(v.URL), "by", userOf(r))
	writeJSON(w, http.StatusOK, v)
}

// handleIntelFeedUpdate changes a feed added on the page. Settings the
// request leaves out stay as they are, and so do secrets sent empty.
func (s *Server) handleIntelFeedUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	name := r.PathValue("name")
	in, ok := s.Feeds.InputFor(name)
	if !ok {
		writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
		return
	}
	if err := readJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	v, err := s.Feeds.UpdateFeed(r.Context(), name, in)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	s.Log.Info("threat intel feed changed", "feed", name, "url", intel.RedactURL(v.URL), "enabled", v.Enabled, "by", userOf(r))
	writeJSON(w, http.StatusOK, v)
}

// handleIntelFeedDelete deletes a feed added on the page. Its indicators
// are removed too, unless ?indicators=keep, which lets them age out.
func (s *Server) handleIntelFeedDelete(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	name := r.PathValue("name")
	mode := r.URL.Query().Get("indicators")
	if mode != "" && mode != "remove" && mode != "keep" {
		writeError(w, http.StatusBadRequest, errors.New("indicators must be remove or keep"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	n, err := s.Feeds.RemoveFeed(ctx, name, mode != "keep")
	if err != nil {
		writeFeedError(w, err)
		return
	}
	s.Log.Info("threat intel feed deleted", "feed", name, "indicators_removed", n, "by", userOf(r))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": name, "indicators_removed": n, "indicators_kept": mode == "keep"})
}

// feedTestRequest is a feed to test or a server to list collections of.
// Feed names a saved feed whose stored secrets fill those left empty.
type feedTestRequest struct {
	intel.FeedInput
	Feed string `json:"feed"`
}

// readFeedTest reads a test request; with feed, it starts from that
// feed's settings like a change does.
func (s *Server) readFeedTest(w http.ResponseWriter, r *http.Request) (feedTestRequest, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return feedTestRequest{}, false
	}
	var head struct {
		Feed string `json:"feed"`
	}
	if err := decodeJSON(body, &head); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return feedTestRequest{}, false
	}
	var req feedTestRequest
	if head.Feed != "" {
		in, ok := s.Feeds.InputFor(head.Feed)
		if !ok {
			writeError(w, http.StatusNotFound, intel.ErrUnknownFeed)
			return feedTestRequest{}, false
		}
		req.FeedInput = in
	}
	if err := decodeJSON(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return feedTestRequest{}, false
	}
	return req, true
}

// handleIntelFeedTest downloads a feed without saving it, and reports
// what it found: the format and type (detected for auto), the number of
// indicators by type and a few samples, or why it failed.
func (s *Server) handleIntelFeedTest(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	req, ok := s.readFeedTest(w, r)
	if !ok {
		return
	}
	res, err := s.Feeds.TestFeed(r.Context(), req.FeedInput, req.Feed)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	s.Log.Info("threat intel feed tested", "url", intel.RedactURL(req.URL), "ok", res.OK, "indicators", res.Total, "by", userOf(r))
	writeJSON(w, http.StatusOK, res)
}

// handleIntelTAXIICollections lists a TAXII 2.1 server's collections, so
// the page can offer a choice.
func (s *Server) handleIntelTAXIICollections(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	req, ok := s.readFeedTest(w, r)
	if !ok {
		return
	}
	srv, err := s.Feeds.TAXIICollections(r.Context(), req.FeedInput, req.Feed)
	var ie *intel.InputError
	switch {
	case errors.As(err, &ie), errors.Is(err, intel.ErrUnknownFeed):
		writeFeedError(w, err)
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "collections": []any{}})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "title": srv.Title, "collections": srv.Collections})
	}
}

// handleIntelCatalog lists the built-in catalog of free feeds, marking
// those already added.
func (s *Server) handleIntelCatalog(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": s.Feeds.Catalog()})
}

// handleIntelCatalogAdd adds catalog feeds by ID, such as the recommended
// set, with their suggested settings.
func (s *Server) handleIntelCatalogAdd(w http.ResponseWriter, r *http.Request) {
	if !s.feedsOK(w) {
		return
	}
	var req struct {
		IDs []string `json:"ids"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(req.IDs) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("ids lists the catalog feeds to add"))
		return
	}
	added, skipped, err := s.Feeds.AddCatalog(req.IDs)
	if err != nil {
		writeFeedError(w, err)
		return
	}
	for _, v := range added {
		s.Log.Info("threat intel feed added from the catalog", "feed", v.Name, "by", userOf(r))
	}
	writeJSON(w, http.StatusOK, map[string]any{"added": added, "skipped": skipped})
}
