package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
// until it is removed; a job in another process shows as running.
func TestSampleStatusPartialAndElsewhere(t *testing.T) {
	stateDir := t.TempDir()
	loader := &sample.Loader{Prefix: "signalith", StateDir: stateDir}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader })

	state, _ := json.Marshal(sample.State{ID: "sample-20261013-120000", Partial: true, Started: time.Now()})
	if err := os.WriteFile(filepath.Join(stateDir, "sample.json"), state, 0o640); err != nil {
		t.Fatal(err)
	}
	code, out := do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["partial"] != true || out["loaded"] != false || out["running"] != false {
		t.Fatalf("status %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/load", `{"size":"small"}`, true)
	if code != http.StatusConflict || out["code"] != "partial" {
		t.Errorf("load over a partial set: %d %v", code, out)
	}

	act, _ := json.Marshal(sample.Activity{Op: "remove", Phase: "Deleting events and risk", Percent: 40, PID: 1, Started: time.Now(), Beat: time.Now()})
	if err := os.WriteFile(filepath.Join(stateDir, "sample.lock"), act, 0o640); err != nil {
		t.Fatal(err)
	}
	code, out = do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["running"] != true || out["op"] != "remove" || out["percent"] != float64(40) || out["partial"] == true {
		t.Errorf("status with a job elsewhere: %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/remove", "", true)
	if code != http.StatusConflict || out["code"] != "busy" {
		t.Errorf("remove while a job runs elsewhere: %d %v", code, out)
	}
}
