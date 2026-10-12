// Package datamodel defines Signalith's common field model. Field names
// follow Splunk's CIM so ES analysts recognize them, and every parser maps
// its source onto one of these models.
package datamodel

import (
	"sort"
	"strings"
)

// Field describes one normalized field.
type Field struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // string, number, ip, time, text
	Description string   `json:"description"`
	Examples    []string `json:"examples,omitempty"`
}

// Model is a data model: a family of events with the same fields.
type Model struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Fields      []Field `json:"fields"`
}

// Common fields exist on every event regardless of model.
var Common = []Field{
	{Name: "_time", Type: "time", Description: "When the event happened"},
	{Name: "host", Type: "string", Description: "Host that reported the event"},
	{Name: "sourcetype", Type: "string", Description: "Source format, for example WinEventLog:Security or linux:auth"},
	{Name: "datamodel", Type: "string", Description: "Data model the event was mapped to"},
	{Name: "vendor_product", Type: "string", Description: "Product that produced the event"},
	{Name: "signature_id", Type: "string", Description: "Vendor event code, such as a Windows event ID"},
	{Name: "signature", Type: "string", Description: "Human-readable event name"},
	{Name: "_raw", Type: "text", Description: "The original event text"},
}

// Models lists every built-in data model.
var Models = []Model{
	{
		Name:        "Authentication",
		Description: "Logons, logoffs and privilege elevation (Windows logons, SSH, sudo, su)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "Outcome", Examples: []string{"success", "failure"}},
			{Name: "app", Type: "string", Description: "Application that authenticated the user", Examples: []string{"win:local", "sshd", "sudo"}},
			{Name: "user", Type: "string", Description: "Account being authenticated"},
			{Name: "src_user", Type: "string", Description: "Account that requested the authentication, for sudo and su"},
			{Name: "user_domain", Type: "string", Description: "Domain of the user"},
			{Name: "src", Type: "ip", Description: "Where the attempt came from"},
			{Name: "src_port", Type: "number", Description: "Source port"},
			{Name: "dest", Type: "string", Description: "System the user authenticated to"},
			{Name: "authentication_method", Type: "string", Description: "Method used", Examples: []string{"password", "publickey"}},
			{Name: "logon_type", Type: "number", Description: "Windows logon type (2 interactive, 3 network, 10 remote desktop)"},
			{Name: "reason", Type: "string", Description: "Why a failure happened"},
			{Name: "process", Type: "string", Description: "Command run through sudo"},
		},
	},
	{
		Name:        "Endpoint",
		Description: "Process launches on hosts (Windows 4688, Sysmon)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What happened", Examples: []string{"allowed"}},
			{Name: "user", Type: "string", Description: "Account that started the process"},
			{Name: "dest", Type: "string", Description: "Host where the process ran"},
			{Name: "process", Type: "string", Description: "Full command line"},
			{Name: "process_name", Type: "string", Description: "Executable file name", Examples: []string{"powershell.exe"}},
			{Name: "process_path", Type: "string", Description: "Executable path"},
			{Name: "process_id", Type: "number", Description: "Process ID"},
			{Name: "parent_process", Type: "string", Description: "Parent command line"},
			{Name: "parent_process_name", Type: "string", Description: "Parent executable file name"},
			{Name: "parent_process_path", Type: "string", Description: "Parent executable path"},
			{Name: "process_hash", Type: "string", Description: "Hashes of the executable"},
		},
	},
	{
		Name:        "Network_Traffic",
		Description: "Network connections (Sysmon event 3, firewalls)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "Outcome", Examples: []string{"allowed", "blocked"}},
			{Name: "src", Type: "ip", Description: "Source address"},
			{Name: "src_port", Type: "number", Description: "Source port"},
			{Name: "dest", Type: "ip", Description: "Destination address"},
			{Name: "dest_host", Type: "string", Description: "Destination host name"},
			{Name: "dest_port", Type: "number", Description: "Destination port"},
			{Name: "transport", Type: "string", Description: "Protocol", Examples: []string{"tcp", "udp"}},
			{Name: "user", Type: "string", Description: "Account that owns the connection"},
			{Name: "process_name", Type: "string", Description: "Process that made the connection"},
			{Name: "bytes", Type: "number", Description: "Total bytes"},
		},
	},
	{
		Name:        "Change",
		Description: "Account and configuration changes (user created, deleted, added to a group)",
		Fields: []Field{
			{Name: "action", Type: "string", Description: "What changed", Examples: []string{"created", "deleted", "modified"}},
			{Name: "object", Type: "string", Description: "What was changed, such as the account name"},
			{Name: "object_category", Type: "string", Description: "Kind of object", Examples: []string{"user", "group"}},
			{Name: "user", Type: "string", Description: "Account that made the change"},
			{Name: "dest", Type: "string", Description: "System where the change happened"},
		},
	},
	{
		Name:        "Risk",
		Description: "Risk that detections attributed to users and systems; not included in searches unless you ask for datamodel=Risk",
		Fields: []Field{
			{Name: "risk_object", Type: "string", Description: "User or system the risk is attributed to"},
			{Name: "risk_object_type", Type: "string", Description: "Kind of risk object", Examples: []string{"user", "system", "other"}},
			{Name: "risk_score", Type: "number", Description: "Score after the asset or identity priority multiplier"},
			{Name: "risk_base_score", Type: "number", Description: "Score the detection assigned before the multiplier"},
			{Name: "risk_priority", Type: "string", Description: "Priority of the risk object from the asset or identity list"},
			{Name: "risk_message", Type: "string", Description: "What happened, from the detection title"},
			{Name: "detection_id", Type: "string", Description: "Detection that added the risk"},
			{Name: "mitre", Type: "string", Description: "ATT&CK techniques of the detection"},
			{Name: "mitre_tactic", Type: "string", Description: "ATT&CK tactics of those techniques"},
		},
	},
	{
		Name:        "Other",
		Description: "Events no parser recognized yet; still searchable by text",
		Fields: []Field{
			{Name: "app", Type: "string", Description: "Program that logged the event"},
		},
	},
}

// Get returns a model by case-insensitive name.
func Get(name string) (Model, bool) {
	for _, m := range Models {
		if strings.EqualFold(m.Name, name) {
			return m, true
		}
	}
	return Model{}, false
}

// FieldsFor returns the common fields plus a model's own, sorted by name
// with _time first. An empty model name returns the union of all models.
func FieldsFor(model string) []Field {
	seen := map[string]bool{}
	var out []Field
	add := func(fs []Field) {
		for _, f := range fs {
			if !seen[f.Name] {
				seen[f.Name] = true
				out = append(out, f)
			}
		}
	}
	add(Common)
	if m, ok := Get(model); ok {
		add(m.Fields)
	} else {
		for _, m := range Models {
			add(m.Fields)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name == "_time" {
			return true
		}
		if out[j].Name == "_time" {
			return false
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// RiskModel is the data model risk events are stored under. The default
// "all data" search leaves it out so risk events do not mix with raw events.
const RiskModel = "Risk"

// IndexName returns the daily index an event of a model goes to.
func IndexName(prefix, model, day string) string {
	return prefix + "-" + strings.ToLower(model) + "-" + day
}
