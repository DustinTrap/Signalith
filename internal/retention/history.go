package retention

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// MaxActions is how many recent actions the history keeps: a few weeks of
// daily runs, since one run can touch dozens of days.
const MaxActions = 200

// Run triggers.
const (
	TriggerSchedule = "schedule"
	TriggerManual   = "manual"
	TriggerGuard    = "disk_guard"
	TriggerChange   = "policy_change"
)

// Run reports one enforcement run.
type Run struct {
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Trigger  string    `json:"trigger"`
	By       string    `json:"by,omitempty"`
	// Indices compacted, archived (then deleted) and deleted outright.
	Compacted      int   `json:"compacted"`
	Archived       int   `json:"archived"`
	Deleted        int   `json:"deleted"`
	DeletedRecords int64 `json:"deleted_records"`
	// FreedBytes is what deletions and compaction freed in OpenSearch.
	FreedBytes int64        `json:"freed_bytes"`
	Errors     []string     `json:"errors"`
	Guard      *GuardStatus `json:"guard,omitempty"`
}

// Action records one thing retention did, or failed to do.
type Action struct {
	Time     time.Time `json:"time"`
	Action   string    `json:"action"` // compact, archive, delete, delete_records, restore
	Category string    `json:"category"`
	Index    string    `json:"index,omitempty"`
	Day      string    `json:"day,omitempty"`
	// Bytes is the index size before the action and Freed what it freed.
	Bytes int64 `json:"bytes,omitempty"`
	Freed int64 `json:"freed,omitempty"`
	// Docs counts events archived or restored, or records deleted.
	Docs   int64  `json:"docs,omitempty"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason"`
	File   string `json:"file,omitempty"`
	By     string `json:"by,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Actions that are not index decisions.
const (
	ActionDeleteRecords = "delete_records"
	ActionRestore       = "restore"
)

// history is the last run and recent actions, kept in a JSON file.
type history struct {
	path string
	mu   sync.Mutex
	data historyData
}

type historyData struct {
	LastRun *Run     `json:"last_run,omitempty"`
	Actions []Action `json:"actions"`
}

func loadHistory(path string) *history {
	h := &history{path: path}
	if path == "" {
		return h
	}
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &h.data)
	}
	return h
}

// add records actions, newest first, and saves the file.
func (h *history) add(run *Run, acts ...Action) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if run != nil {
		r := *run
		h.data.LastRun = &r
	}
	for _, a := range acts {
		h.data.Actions = append([]Action{a}, h.data.Actions...)
	}
	if len(h.data.Actions) > MaxActions {
		h.data.Actions = h.data.Actions[:MaxActions]
	}
	if h.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(h.data, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(h.path, b)
}

func (h *history) get() (*Run, []Action) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var run *Run
	if h.data.LastRun != nil {
		r := *h.data.LastRun
		run = &r
	}
	acts := make([]Action, len(h.data.Actions))
	copy(acts, h.data.Actions)
	return run, acts
}
