package detect

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
)

// Risk makes a detection add risk to the users and systems in its results,
// as in Splunk ES risk-based alerting. Risk adds up per object, and risk
// incident detections raise a finding when an object's total crosses a
// threshold, so many weak signals about one user can become one alert.
type Risk struct {
	Score   int          `yaml:"score" json:"score"`
	Objects []RiskObject `yaml:"objects" json:"objects"`
	// Only records risk without raising a finding per result. Use it for
	// noisy signals that matter only in combination.
	Only bool `yaml:"only,omitempty" json:"only,omitempty"`
}

// RiskObject names a result field that holds a user or system.
type RiskObject struct {
	Field string `yaml:"field" json:"field"`
	Type  string `yaml:"type" json:"type"` // user, system or other
}

// RiskObjectTypes are the valid risk object types.
var RiskObjectTypes = []string{"user", "system", "other"}

func (r *Risk) problems() []string {
	var p []string
	if r.Score < 1 || r.Score > 1000 {
		p = append(p, "risk.score must be between 1 and 1000")
	}
	if len(r.Objects) == 0 {
		p = append(p, "risk.objects needs at least one field, for example {field: user, type: user}")
	}
	for i, o := range r.Objects {
		if strings.TrimSpace(o.Field) == "" {
			p = append(p, fmt.Sprintf("risk.objects[%d].field is required", i))
		}
		if !slices.Contains(RiskObjectTypes, o.Type) {
			p = append(p, fmt.Sprintf("risk.objects[%d].type must be one of %s", i, strings.Join(RiskObjectTypes, ", ")))
		}
	}
	return p
}

// RiskEvent is one unit of risk attributed to one object.
type RiskEvent struct {
	Time        time.Time
	Object      string
	ObjectType  string
	Score       float64 // after the priority multiplier
	BaseScore   int
	Priority    string
	Message     string
	DetectionID string
	MITRE       []string
	Tactics     []string
	GroupKey    string
	Fields      map[string]any // the row's entity fields
}

// Doc renders a risk event as a stored document in the Risk data model.
func (e RiskEvent) Doc() map[string]any {
	d := map[string]any{
		"@timestamp":       e.Time.UTC().Format(time.RFC3339Nano),
		"datamodel":        "Risk",
		"sourcetype":       "signalith:risk",
		"risk_object":      e.Object,
		"risk_object_type": e.ObjectType,
		"risk_score":       e.Score,
		"risk_base_score":  e.BaseScore,
		"risk_message":     e.Message,
		"detection_id":     e.DetectionID,
		"group_key":        e.GroupKey,
		"message":          fmt.Sprintf("%s: +%g risk to %s %s", e.Message, e.Score, e.ObjectType, e.Object),
	}
	if e.Priority != "" {
		d["risk_priority"] = e.Priority
	}
	if len(e.MITRE) > 0 {
		d["mitre"] = e.MITRE
	}
	if len(e.Tactics) > 0 {
		d["mitre_tactic"] = e.Tactics
	}
	for k, v := range e.Fields {
		if _, taken := d[k]; !taken {
			d[k] = v
		}
	}
	return d
}

// RiskStore persists risk events.
type RiskStore interface {
	Write(ctx context.Context, events []RiskEvent) error
	// Exists reports whether this detection recorded risk with this group
	// key at or after since; throttling for risk-only detections.
	Exists(ctx context.Context, detectionID, groupKey string, since time.Time) (bool, error)
}

// Tactics returns the ATT&CK tactic names of techniques, deduplicated.
func Tactics(techniques []string) []string {
	c := ATTACK()
	var out []string
	for _, id := range techniques {
		if t, ok := c.Technique(id); ok {
			for _, tac := range t.Tactics {
				if !slices.Contains(out, tac) {
					out = append(out, tac)
				}
			}
		}
	}
	return out
}

// lookupAs returns the context of a value, looking it up as an identity or
// an asset depending on the object type.
func lookupAs(a *assets.Store, objType, value string) (*assets.Context, bool) {
	if a == nil {
		return nil, false
	}
	if objType == "user" {
		return a.Lookup("user", value)
	}
	return a.Lookup("dest", value)
}

// RiskEvents builds the risk events for one result row.
func RiskEvents(d *Detection, row map[string]any, key string, a *assets.Store, now time.Time) []RiskEvent {
	if d.Risk == nil {
		return nil
	}
	ents := entities(row)
	title := RenderTitle(d.Title, row)
	tactics := Tactics(d.MITRE)
	var out []RiskEvent
	seen := map[string]bool{}
	for _, o := range d.Risk.Objects {
		v, ok := row[o.Field]
		if !ok || v == nil {
			continue
		}
		val := strings.TrimSpace(fmt.Sprint(v))
		if val == "" || val == "-" || seen[o.Type+"\x00"+strings.ToLower(val)] {
			continue
		}
		seen[o.Type+"\x00"+strings.ToLower(val)] = true
		ev := RiskEvent{
			Time: now, Object: val, ObjectType: o.Type, BaseScore: d.Risk.Score, Score: float64(d.Risk.Score),
			Message: title, DetectionID: d.ID, MITRE: d.MITRE, Tactics: tactics, GroupKey: key, Fields: ents,
		}
		if c, ok := lookupAs(a, o.Type, val); ok {
			ev.Priority = c.Priority
			mult := assets.Multiplier(c.Priority)
			if c.Watchlist && mult < 1.5 {
				mult = 1.5
			}
			ev.Score = math.Round(float64(d.Risk.Score)*mult*10) / 10
		}
		out = append(out, ev)
	}
	return out
}

// Urgency combines a finding's severity with the priority of the assets
// and identities involved, like the ES urgency matrix: a critical asset or
// watchlisted user raises it one level; when every known entity is low
// priority it drops one level.
func Urgency(severity string, ctx map[string]*assets.Context) string {
	sevs := []string{"informational", "low", "medium", "high", "critical"}
	i := slices.Index(sevs, severity)
	if i < 0 {
		return severity
	}
	raise, allLow := false, len(ctx) > 0
	for _, c := range ctx {
		if c.Priority == "critical" || c.Watchlist {
			raise = true
		}
		if c.Priority != "low" {
			allLow = false
		}
	}
	switch {
	case raise:
		i = min(i+1, len(sevs)-1)
	case allLow:
		i = max(i-1, 0)
	}
	return sevs[i]
}

// EntityContext looks up every entity of a finding.
func EntityContext(a *assets.Store, ents map[string]any) map[string]*assets.Context {
	if a == nil {
		return nil
	}
	out := map[string]*assets.Context{}
	objType, _ := ents["risk_object_type"].(string)
	for f, v := range ents {
		var c *assets.Context
		var ok bool
		switch f {
		case "risk_object_type":
			continue
		case "risk_object":
			c, ok = lookupAs(a, objType, fmt.Sprint(v))
		default:
			c, ok = a.Lookup(f, fmt.Sprint(v))
		}
		if ok {
			out[f] = c
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
