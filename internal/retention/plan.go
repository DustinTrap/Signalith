package retention

import (
	"fmt"
	"slices"
	"sort"
	"time"
)

// Actions the planner picks for an index.
const (
	ActionKeep    = "keep"
	ActionCompact = "compact"
	// ActionArchive archives the index, then deletes it.
	ActionArchive = "archive"
	ActionDelete  = "delete"
	// ActionSkip marks an index that is not a Signalith daily index; it is
	// never touched.
	ActionSkip = "skip"
)

// Rules that lead to an action.
const (
	RuleKeepDays = "keep_days"
	RuleSizeCap  = "size_cap"
	RuleGuard    = "guard"
	RuleCompact  = "compact_after_days"
	RuleRecords  = "closed_records"
)

// Decision is what the planner chose for one index, and why.
type Decision struct {
	Index    string `json:"index"`
	Category string `json:"category,omitempty"`
	Day      string `json:"day,omitempty"` // YYYY-MM-DD
	Action   string `json:"action"`
	Rule     string `json:"rule,omitempty"`
	Reason   string `json:"reason"`
	// Source is where the policy behind the decision comes from: default,
	// days, ui or config (for the guard: builtin, ui or config).
	Source string `json:"source,omitempty"`
	Bytes  int64  `json:"bytes"`
	Docs   int64  `json:"docs"`

	age       int
	restored  bool
	compacted bool
	// writesBlocked means writes to the index are already blocked, by an
	// earlier compaction or by OpenSearch's flood-stage block.
	writesBlocked bool
	// diskBlocked means OpenSearch's flood-stage block is on the index:
	// it can still be read and deleted, but not changed or merged.
	diskBlocked bool
}

// Changes reports whether the decision does something to the index.
func (d Decision) Changes() bool {
	return d.Action == ActionCompact || d.Action == ActionArchive || d.Action == ActionDelete
}

// Removes reports whether the decision deletes the index.
func (d Decision) Removes() bool { return d.Action == ActionArchive || d.Action == ActionDelete }

// RecordStep deletes resolved and closed findings or cases.
type RecordStep struct {
	Category string    `json:"category"`
	Index    string    `json:"index"`
	Count    int64     `json:"count"`
	KeepDays int       `json:"keep_days"`
	Before   time.Time `json:"before"`
	Reason   string    `json:"reason"`
	Source   string    `json:"source"`
	// keepCases lists open cases whose findings are kept.
	keepCases []string
}

// Guard states.
const (
	GuardOff     = "off"
	GuardOK      = "ok"
	GuardOver    = "over"    // above the limit; the plan deletes the oldest days
	GuardShort   = "short"   // above the limit and min_days stops the guard getting under it
	GuardUnknown = "unknown" // disk use could not be read
)

// GuardStatus says what the disk guard sees and plans.
type GuardStatus struct {
	State     string  `json:"state"`
	Percent   float64 `json:"percent"`
	Threshold int     `json:"max_disk_percent"`
	MinDays   int     `json:"min_days"`
	// NeedBytes is how much must go to get under the limit after the
	// policies' own deletions; PlannedBytes is what the guard deletes.
	NeedBytes    int64  `json:"need_bytes,omitempty"`
	PlannedBytes int64  `json:"planned_bytes,omitempty"`
	PlannedDays  int    `json:"planned_days,omitempty"`
	Message      string `json:"message"`
}

// Plan is everything a run would do.
type Plan struct {
	Time  time.Time `json:"time"`
	Today string    `json:"today"`
	// Decisions has one entry per index under the prefix, oldest day first.
	Decisions []Decision   `json:"-"`
	Records   []RecordStep `json:"records"`
	Guard     GuardStatus  `json:"guard"`
	Notes     []string     `json:"notes"`
}

// Steps returns the decisions that change something: deletions first,
// oldest day first, then compactions.
func (p *Plan) Steps() []Decision {
	var del, comp []Decision
	for _, d := range p.Decisions {
		switch {
		case d.Removes():
			del = append(del, d)
		case d.Action == ActionCompact:
			comp = append(comp, d)
		}
	}
	return append(del, comp...)
}

// Summary counts what a plan, or part of it, does.
type Summary struct {
	DeleteDays    int      `json:"delete_days"` // archived days included
	DeleteBytes   int64    `json:"delete_bytes"`
	ArchiveDays   int      `json:"archive_days"`
	CompactDays   int      `json:"compact_days"`
	CompactBytes  int64    `json:"compact_bytes"`
	DeleteRecords int64    `json:"delete_records"`
	Categories    []string `json:"categories"`
}

// DeletesData reports whether the summary deletes anything.
func (s Summary) DeletesData() bool { return s.DeleteDays > 0 || s.DeleteRecords > 0 }

// Summarize counts steps and record steps.
func Summarize(steps []Decision, records []RecordStep) Summary {
	s := Summary{Categories: []string{}}
	touch := func(c string) {
		if !slices.Contains(s.Categories, c) {
			s.Categories = append(s.Categories, c)
		}
	}
	for _, d := range steps {
		switch {
		case d.Removes():
			s.DeleteDays++
			s.DeleteBytes += d.Bytes
			if d.Action == ActionArchive {
				s.ArchiveDays++
			}
		case d.Action == ActionCompact:
			s.CompactDays++
			s.CompactBytes += d.Bytes
		default:
			continue
		}
		touch(d.Category)
	}
	for _, r := range records {
		if r.Count > 0 {
			s.DeleteRecords += r.Count
			touch(r.Category)
		}
	}
	return s
}

// Snapshot is the state the planner works from.
type Snapshot struct {
	Now    time.Time
	Prefix string
	// Indices lists the indices under <prefix>-*.
	Indices []IndexInfo
	// Disk is nil when disk use could not be read.
	Disk *Disk
	// Archived maps an index name to how many of its documents the
	// archive holds.
	Archived map[string]int64
}

func startOfDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// PlanIndices decides what happens to every daily index. It is a pure
// function of the snapshot and settings, so previews and runs agree.
//
// The rules, in order:
//   - Names that are not <prefix>-<category>-YYYY.MM.DD are skipped.
//   - Today's and future-dated indices are always kept, as are restored
//     indices until their keep-until day.
//   - keep_days: days more than keep_days before today are deleted.
//   - max_size_gb: while a category is over its cap, its oldest days are
//     deleted.
//   - Disk guard: while the disk is over the limit, the oldest days of any
//     category are deleted, sparing the last min_days days.
//   - compact_after_days: kept days older than that are compacted once.
//
// A deleted day is archived first when its category's policy says so and
// the archive does not already hold all of its documents.
func PlanIndices(snap Snapshot, s Settings) *Plan {
	today := startOfDay(snap.Now)
	plan := &Plan{Time: snap.Now.UTC(), Today: today.Format(time.DateOnly), Notes: []string{}, Records: []RecordStep{}}
	todayKey := today.Format(time.DateOnly)

	order := map[string]int{}
	for i, c := range Categories() {
		order[c.ID] = i
	}
	type entry struct {
		Decision
		dayT time.Time
	}
	var ents []*entry
	for _, ix := range snap.Indices {
		cat, day, ok := ParseIndex(snap.Prefix, ix.Name)
		e := &entry{Decision: Decision{Index: ix.Name, Bytes: ix.Bytes, Docs: ix.Docs}, dayT: day}
		if !ok {
			e.Action, e.Reason = ActionSkip, "Not a Signalith daily index; left alone"
			ents = append(ents, e)
			continue
		}
		pol, src := s.For(cat)
		e.Category, e.Day, e.Source = cat, day.Format(time.DateOnly), src
		e.age = int(today.Sub(day).Hours() / 24)
		e.compacted = ix.Compacted()
		e.writesBlocked, e.diskBlocked = ix.WriteBlocked || ix.DiskBlocked, ix.DiskBlocked
		e.Action = ActionKeep
		switch {
		case day.After(today):
			e.Reason = "Dated in the future; kept"
		case e.age == 0:
			e.Reason = "Today's data"
		case ix.RestoredUntil != "" && ix.RestoredUntil >= todayKey:
			e.restored = true
			e.Reason = "Restored from the archive; kept until " + ix.RestoredUntil
		case pol.KeepDays > 0 && e.age > pol.KeepDays:
			e.Action, e.Rule = ActionDelete, RuleKeepDays
			e.Reason = fmt.Sprintf("Older than %s", days(pol.KeepDays))
		case pol.KeepDays > 0:
			e.Reason = fmt.Sprintf("Within %s", days(pol.KeepDays))
		default:
			e.Reason = "Kept forever"
		}
		ents = append(ents, e)
	}
	sort.SliceStable(ents, func(i, j int) bool {
		a, b := ents[i], ents[j]
		if (a.Category == "") != (b.Category == "") {
			return a.Category != ""
		}
		if !a.dayT.Equal(b.dayT) {
			return a.dayT.Before(b.dayT)
		}
		if order[a.Category] != order[b.Category] {
			return order[a.Category] < order[b.Category]
		}
		return a.Index < b.Index
	})
	// deletable reports whether a kept index may be deleted by the size
	// cap or the guard.
	deletable := func(e *entry) bool {
		return e.Category != "" && e.Action == ActionKeep && e.age >= 1 && !e.dayT.After(today) && !e.restored
	}

	// Size caps, oldest days first.
	for _, c := range Categories() {
		pol, _ := s.For(c.ID)
		capBytes := pol.CapBytes()
		if c.Kind != KindEvents || capBytes <= 0 {
			continue
		}
		var size int64
		for _, e := range ents {
			if e.Category == c.ID && !e.Removes() {
				size += e.Bytes
			}
		}
		if size <= capBytes {
			continue
		}
		for _, e := range ents {
			if size <= capBytes {
				break
			}
			if e.Category == c.ID && deletable(e) {
				e.Action, e.Rule = ActionDelete, RuleSizeCap
				e.Reason = fmt.Sprintf("%s is over its %s size cap", c.Name, gbString(pol.MaxSizeGB))
				size -= e.Bytes
			}
		}
		if size > capBytes {
			plan.Notes = append(plan.Notes, fmt.Sprintf("%s is over its %s size cap, but only today's or restored data is left to delete.",
				c.Name, gbString(pol.MaxSizeGB)))
		}
	}

	// Disk guard, oldest days of any category first.
	g := s.Guard
	plan.Guard = GuardStatus{Threshold: g.MaxDiskPercent, MinDays: g.MinDays}
	switch {
	case !g.IsEnabled():
		plan.Guard.State, plan.Guard.Message = GuardOff, "The disk guard is off."
		if snap.Disk != nil {
			plan.Guard.Percent = roundPercent(snap.Disk.Percent())
		}
	case snap.Disk == nil || snap.Disk.Total <= 0:
		plan.Guard.State, plan.Guard.Message = GuardUnknown, "Disk use could not be read from OpenSearch."
	default:
		d := snap.Disk
		plan.Guard.Percent = roundPercent(d.Percent())
		if d.Percent() <= float64(g.MaxDiskPercent) {
			plan.Guard.State = GuardOK
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used; the guard acts above %d%%.", d.Percent(), g.MaxDiskPercent)
			break
		}
		limit := d.Total * int64(g.MaxDiskPercent) / 100
		need := d.Used() - limit
		for _, e := range ents {
			if e.Removes() {
				need -= e.Bytes
			}
		}
		plan.Guard.State = GuardOver
		if need > 0 {
			plan.Guard.NeedBytes = need
			var cands []*entry
			for _, e := range ents {
				if deletable(e) && e.age > g.MinDays {
					cands = append(cands, e)
				}
			}
			// Oldest day first; on the same day, the biggest first.
			sort.SliceStable(cands, func(i, j int) bool {
				if !cands[i].dayT.Equal(cands[j].dayT) {
					return cands[i].dayT.Before(cands[j].dayT)
				}
				return cands[i].Bytes > cands[j].Bytes
			})
			for _, e := range cands {
				if need <= 0 {
					break
				}
				e.Action, e.Rule, e.Source = ActionDelete, RuleGuard, s.GuardSource
				e.Reason = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard", d.Percent(), g.MaxDiskPercent)
				need -= e.Bytes
				plan.Guard.PlannedBytes += e.Bytes
				plan.Guard.PlannedDays++
			}
		}
		switch {
		case need > 0:
			plan.Guard.State = GuardShort
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard. Only the last %s are left, which the guard never deletes; add disk space or lower what is kept.",
				d.Percent(), g.MaxDiskPercent, days(g.MinDays))
			plan.Notes = append(plan.Notes, plan.Guard.Message)
		case plan.Guard.PlannedDays > 0:
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard; the oldest %s are deleted to get under it.",
				d.Percent(), g.MaxDiskPercent, days(plan.Guard.PlannedDays))
		default:
			plan.Guard.Message = fmt.Sprintf("Disk %.0f%% used, above the %d%% disk guard; the policies' own deletions get it under.",
				d.Percent(), g.MaxDiskPercent)
		}
	}

	// Archive before deleting, and compaction of what is kept.
	for _, e := range ents {
		if e.Category == "" {
			continue
		}
		pol, _ := s.For(e.Category)
		switch {
		case e.Removes():
			if pol.Archive && e.Docs > 0 {
				if snap.Archived[e.Index] >= e.Docs {
					e.Reason += " (already archived)"
				} else {
					e.Action = ActionArchive
				}
			}
		case e.Action == ActionKeep && !e.restored && !e.compacted && !e.diskBlocked && pol.CompactAfterDays > 0 &&
			e.age > pol.CompactAfterDays && !e.dayT.After(today):
			e.Action, e.Rule = ActionCompact, RuleCompact
			e.Reason = fmt.Sprintf("Older than %s", days(pol.CompactAfterDays))
		}
	}
	plan.Decisions = make([]Decision, len(ents))
	for i, e := range ents {
		plan.Decisions[i] = e.Decision
	}
	return plan
}

func days(n int) string {
	if n == 1 {
		return "1 day"
	}
	return fmt.Sprintf("%d days", n)
}

func gbString(gb float64) string {
	if gb == float64(int64(gb)) {
		return fmt.Sprintf("%d GB", int64(gb))
	}
	return fmt.Sprintf("%g GB", gb)
}
