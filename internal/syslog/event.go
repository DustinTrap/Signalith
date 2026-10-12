package syslog

import (
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// maxExtraFields caps the vendor-specific fields (cef_* and sd_*) one
// message can add, so one sender cannot explode the index mapping.
const maxExtraFields = 64

var facilityNames = [24]string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

var severityNames = [8]string{"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}

// Event turns a parsed message into an event for the ingest pipeline.
// sender is the address the message came from and received is when it
// arrived; they fill dvc, host when the message names none, and the time
// when the message has no usable timestamp.
func (m *Message) Event(sender netip.Addr, received time.Time) ingest.Event {
	senderIP := ""
	if sender.IsValid() {
		senderIP = sender.Unmap().String()
	}
	host := m.Hostname
	if len(host) > 255 {
		host = host[:255]
	}
	app := m.AppName
	if app == "" && m.Cisco != nil {
		app = m.Cisco.Facility
	}
	extra := 0
	var ev ingest.Event
	t := m.Time
	if m.CEF != nil {
		f := map[string]any{"app": app}
		if ct := cefFieldsFor(m.CEF, f, &extra); !ct.IsZero() {
			t = ct
		}
		if host == "" {
			host, _ = f["dvc_host"].(string)
		}
		model := "Other"
		if f["src"] != nil && f["dest"] != nil {
			model = "Network_Traffic"
		}
		ev = ingest.Event{Model: model, Fields: f}
	} else {
		if host == "" {
			host = senderIP
		}
		ev = ingest.ParseProgram(host, app, m.ProcID, m.Text, "syslog")
	}
	f := ev.Fields
	if host == "" {
		host = senderIP
	}
	f["host"] = host
	f["dvc"] = senderIP
	if m.Priority >= 0 {
		f["facility"] = facilityNames[m.Priority/8]
	}
	if m.CEF == nil {
		switch {
		case m.Priority >= 0:
			f["severity"] = severityNames[m.Priority%8]
			f["severity_id"] = int64(m.Priority % 8)
		case m.Cisco != nil:
			f["severity"] = severityNames[m.Cisco.Severity]
			f["severity_id"] = int64(m.Cisco.Severity)
		}
	}
	if m.MsgID != "" {
		f["msgid"] = m.MsgID
	}
	if m.Sequence != "" {
		if n, err := strconv.ParseInt(m.Sequence, 10, 64); err == nil {
			f["sequence"] = n
		}
	}
	if m.Cisco != nil {
		f["signature_id"] = m.Cisco.Facility + "-" + strconv.Itoa(m.Cisco.Severity) + "-" + m.Cisco.Mnemonic
		if f["vendor_product"] == nil {
			f["vendor_product"] = ciscoProduct(m.Cisco.Facility)
		}
	}
	for _, el := range m.Data {
		if el.ID == "timeQuality" {
			continue // about the sender's clock, not the event
		}
		id := fieldName(el.ID)
		for _, p := range el.Params {
			if p.Value != "" {
				addExtra(f, "sd_"+id+"_", p.Name, p.Value, &extra)
			}
		}
	}
	f["message"] = m.Raw
	ev.Time = eventTime(t, received)
	return ev
}

func ciscoProduct(facility string) string {
	switch strings.ToUpper(facility) {
	case "ASA", "PIX", "FWSM":
		return "Cisco ASA"
	case "FTD":
		return "Cisco Firepower Threat Defense"
	}
	return "Cisco"
}

// eventTime uses the message time unless it is missing or implausible: a
// clock that was never set (before 2000) or more than a day in the future.
func eventTime(t, received time.Time) time.Time {
	if t.IsZero() || t.Year() < 2000 || t.After(received.Add(24*time.Hour)) {
		return received.UTC()
	}
	return t.UTC()
}

// isExtra reports whether a field is vendor-specific (cef_* or sd_*), the
// kind the receiver limits per day so the index mapping stays small.
func isExtra(name string) bool {
	return strings.HasPrefix(name, "cef_") || strings.HasPrefix(name, "sd_")
}
