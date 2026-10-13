// Package datamodel defines Signalith's common field model. Field names
// follow Splunk's CIM so ES analysts recognize them, and every parser maps
// its source onto one of these models.
package datamodel

import (
	"sort"
	"strings"
)

// SampleField marks every event, risk event and finding the "Load sample
// data" feature writes; its value is the load's ID. The name is one no
// sender uses, so a real event is never mistaken for sample data: the live
// detection scheduler leaves marked documents out, the sample backfill
// reads only its own, and Remove deletes exactly those.
const SampleField = "signalith_sample"

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
			{Name: "process_hash", Type: "string", Description: "Hashes of the executable, as Sysmon lists them"},
			{Name: "process_md5", Type: "string", Description: "MD5 hash of the executable, lower case"},
			{Name: "process_sha1", Type: "string", Description: "SHA-1 hash of the executable, lower case"},
			{Name: "process_sha256", Type: "string", Description: "SHA-256 hash of the executable, lower case"},
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
		Name:        "Malware",
		Description: "Antivirus and endpoint protection: malware found and what was done about it, protection rule blocks, and the health of the antivirus itself.",
		Fields: []Field{
			{Name: "type", Type: "string", Description: "Kind of event: threat (malware found), rule (a protection rule acted) or health (the antivirus itself changed or has a problem)", Examples: []string{"threat", "rule", "health"}},
			{Name: "action", Type: "string", Description: "What happened, such as quarantined, failed, disabled or exclusion_added", Examples: []string{"quarantined", "failed", "disabled"}},
			{Name: "vendor_action", Type: "string", Description: "The action as the product wrote it", Examples: []string{"Quarantine", "Left alone"}},
			{Name: "threat_id", Type: "string", Description: "The product's ID for the threat", Examples: []string{"2147729891"}},
			{Name: "category", Type: "string", Description: "Kind of threat: virus, worm, trojan, ransomware, backdoor, spyware, adware, pua, exploit, hacktool, behavior, test or other", Examples: []string{"trojan", "ransomware"}},
			{Name: "vendor_category", Type: "string", Description: "The threat category as the product wrote it", Examples: []string{"Trojan", "Tool"}},
			{Name: "severity", Type: "string", Description: "How serious the product rates it: low, medium, high or critical", Examples: []string{"high"}},
			{Name: "vendor_severity", Type: "string", Description: "The severity as the product wrote it", Examples: []string{"Severe"}},
			{Name: "dest", Type: "string", Description: "Host the event is about", Examples: []string{"ws-fin-07"}},
			{Name: "dest_ip", Type: "ip", Description: "Address of that host, when the product sends one", Examples: []string{"192.0.2.27"}},
			{Name: "user", Type: "string", Description: "Account involved, such as the user who opened the file", Examples: []string{`CORP\alice.nguyen`}},
			{Name: "src", Type: "ip", Description: "Address the threat came from, when the product says", Examples: []string{"203.0.113.45"}},
			{Name: "src_host", Type: "string", Description: "Host the threat came from, when the product says", Examples: []string{"file-01"}},
			{Name: "url", Type: "string", Description: "Web address the threat came from or was blocked at"},
			{Name: "file_name", Type: "string", Description: "File name of the threat", Examples: []string{"invoice.exe"}},
			{Name: "file_path", Type: "string", Description: "Full path of the threat", Examples: []string{`C:\Users\alice.nguyen\Downloads\invoice.exe`}},
			{Name: "file_hash", Type: "string", Description: "File hash as the product sent it"},
			{Name: "file_md5", Type: "string", Description: "MD5 of the file (lower case)"},
			{Name: "file_sha1", Type: "string", Description: "SHA-1 of the file (lower case)"},
			{Name: "file_sha256", Type: "string", Description: "SHA-256 of the file (lower case)"},
			{Name: "file_size", Type: "number", Description: "File size in bytes", Examples: []string{"68"}},
			{Name: "process", Type: "string", Description: "Command line of the process involved"},
			{Name: "process_name", Type: "string", Description: "Executable file name of the process involved", Examples: []string{"winword.exe"}},
			{Name: "process_path", Type: "string", Description: "Executable path of the process involved"},
			{Name: "process_id", Type: "number", Description: "Process ID", Examples: []string{"4120"}},
			{Name: "rule", Type: "string", Description: "Protection rule that acted", Examples: []string{"Office app started a child process"}},
			{Name: "rule_id", Type: "string", Description: "ID of that rule (for attack surface reduction, its GUID)", Examples: []string{"d4f940ab-401b-4efc-aadc-ad5f3c50688a"}},
			{Name: "setting", Type: "string", Description: "Setting that changed, as the product wrote it", Examples: []string{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Temp = 0x0`}},
			{Name: "exclusion", Type: "string", Description: "What an added or removed exclusion lets through", Examples: []string{`C:\ProgramData\SyncSvc`}},
			{Name: "exclusion_type", Type: "string", Description: "Kind of exclusion: path, extension, process or ip", Examples: []string{"path"}},
			{Name: "signature_version", Type: "string", Description: "Version of the antivirus definitions", Examples: []string{"1.419.2361.0"}},
			{Name: "engine_version", Type: "string", Description: "Version of the scan engine", Examples: []string{"1.1.24090.11"}},
			{Name: "product_version", Type: "string", Description: "Version of the antivirus product", Examples: []string{"4.18.24090.11"}},
			{Name: "signature_age_days", Type: "number", Description: "Age of the definitions in days, when the product reports it", Examples: []string{"9"}},
			{Name: "reason", Type: "string", Description: "Error or reason text from the product", Examples: []string{"The process cannot access the file"}},
			{Name: "detection_source", Type: "string", Description: "Which scan or feature found it", Examples: []string{"Real-Time Protection"}},
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
