package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A failed sample-data job is reported in plain English with what to do,
// and the technical text only as the detail.
func TestSampleErrorText(t *testing.T) {
	refused := &url.Error{Op: "Post", URL: "http://127.0.0.1:18944/signalith-risk-%2A/_refresh", Err: errors.New("dial tcp: connection refused")}
	for _, tc := range []struct {
		op      string
		err     error
		partial bool
		want    string
	}{
		{"load", fmt.Errorf("writing sample events: %w", refused), true, "Signalith lost its connection to OpenSearch and could not load the sample data. Check the Health page. Remove what was loaded, then load it again."},
		{"remove", &store.Error{Status: 403, Body: `{"error":{"type":"cluster_block_exception"}}`}, true, "OpenSearch is refusing changes"},
		{"load", &store.Error{Status: 429, Body: "busy"}, false, "OpenSearch was too busy to load the sample data. Check the Health page. Try again."},
		{"load", context.Canceled, true, "Signalith stopped before it could load the sample data."},
		{"load", sample.ErrBusy, false, "Another sample-data load or removal is running."},
		{"load", sample.ErrTakenOver, true, "another server took the job over. Remove what was loaded, then load it again."},
		{"load", errors.New("boom"), false, "Something went wrong and Signalith could not load the sample data. Try again."},
	} {
		msg, detail := sampleErrorText(tc.op, tc.err, tc.partial)
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%v: message %q, want %q", tc.err, msg, tc.want)
		}
		if strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "%2A") || strings.Contains(msg, "dial tcp") {
			t.Errorf("%v: message has technical text: %q", tc.err, msg)
		}
		if !errors.Is(tc.err, sample.ErrBusy) && detail != tc.err.Error() {
			t.Errorf("%v: detail %q", tc.err, detail)
		}
	}
}

// A load that stopped part way shows as partial, and a new load is refused
// until it is removed; a job in another process, such as another server
// that shares the OpenSearch, shows as running, with where it runs. The
// record is in OpenSearch's runtime index, so every server sees it.
func TestSampleStatusPartialAndElsewhere(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader })

	code, out := do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["loaded"] != false || out["partial"] == true || out["running"] != false {
		t.Fatalf("status with nothing loaded: %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/remove", "", true)
	if code != http.StatusConflict || out["code"] != "not_loaded" {
		t.Errorf("remove with nothing loaded: %d %v", code, out)
	}

	record := func(job *sample.Activity) {
		t.Helper()
		body := map[string]any{"state": sample.State{ID: "sample-20261013-120000", Partial: true, Started: time.Now()}}
		if job != nil {
			body["job"] = job
		}
		doc := map[string]any{"kind": "sample_data", "body": body}
		b, _ := json.Marshal(doc)
		var src map[string]any
		_ = json.Unmarshal(b, &src)
		fake.Put("signalith_runtime", "sample:data", src)
	}
	record(nil)
	code, out = do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["partial"] != true || out["loaded"] != false || out["running"] != false {
		t.Fatalf("status %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/load", `{"size":"small"}`, true)
	if code != http.StatusConflict || out["code"] != "partial" {
		t.Errorf("load over a partial set: %d %v", code, out)
	}

	record(&sample.Activity{Op: "remove", Phase: "Deleting events and risk", Percent: 40, Server: "siem-b", PID: 1, Started: time.Now(), Beat: time.Now()})
	code, out = do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["running"] != true || out["op"] != "remove" || out["percent"] != float64(40) || out["partial"] == true ||
		out["where"] != "Started on the server siem-b." {
		t.Errorf("status with a job elsewhere: %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/remove", "", true)
	if code != http.StatusConflict || out["code"] != "busy" {
		t.Errorf("remove while a job runs elsewhere: %d %v", code, out)
	}

	record(&sample.Activity{Op: "load", Phase: "Writing events", Percent: 9, Server: "build-host", Command: true, Beat: time.Now()})
	if _, out = do(t, ts, "GET", "/api/sample", "", true); out["where"] != "Started with the signalith sample-data command on build-host." {
		t.Errorf("status with the command line loading: %v", out)
	}
}

// A failed job's error shows on the server that ran it only until another
// server loads or removes: then the shared record has moved on and the old
// error no longer applies.
func TestSampleErrorFadesWhenAnotherServerActs(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-a"}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader; srv = s })

	put := func(id string, partial bool) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"kind": "sample_data", "body": map[string]any{
			"state": sample.State{ID: id, Partial: partial, Started: time.Now()}}})
		var src map[string]any
		_ = json.Unmarshal(b, &src)
		fake.Put("signalith_runtime", "sample:data", src)
	}
	failed := func(left string, known bool) {
		srv.sampleJob.mu.Lock()
		srv.sampleJob.op, srv.sampleJob.err = "load", errors.New("boom")
		srv.sampleJob.left, srv.sampleJob.leftKnown = left, known
		srv.sampleJob.mu.Unlock()
	}
	errorShown := func() bool {
		t.Helper()
		code, out := do(t, ts, "GET", "/api/sample", "", true)
		if code != 200 {
			t.Fatalf("status %d %v", code, out)
		}
		return out["error"] != nil
	}

	// This server's load stopped part way and left its record.
	put("sample-a", true)
	failed("sample-a", true)
	if !errorShown() {
		t.Error("error missing while the record is the one the failed load left")
	}
	// Another server removed it and loaded a set of its own.
	put("sample-b", false)
	if errorShown() {
		t.Error("old error shown after another server loaded")
	}
	// Another server removed what this server's failed load left.
	fake.Delete("signalith_runtime", "sample:data")
	if errorShown() {
		t.Error("old error shown after another server removed the record")
	}
	// A failed load that wrote nothing: the error stays while nothing is loaded.
	failed("", true)
	if !errorShown() {
		t.Error("error missing for a load that wrote nothing")
	}
	// When the record could not be read after the failure, the error stays.
	put("sample-b", false)
	failed("", false)
	if !errorShown() {
		t.Error("error missing when the record could not be read after the failure")
	}
}
