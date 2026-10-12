package syslog

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// RFC 3164 timestamps are read in the server's local time zone; pin it
	// so the expected times hold on any machine.
	time.Local = time.UTC
	os.Exit(m.Run())
}

var (
	now    = time.Date(2026, 10, 12, 14, 0, 0, 0, time.UTC)
	sender = netip.MustParseAddr("192.0.2.50")
)

// doc parses a line as if it arrived now from sender and returns the
// document that would be indexed.
func doc(line string) map[string]any {
	m := Parse([]byte(line), now)
	ev := m.Event(sender, now)
	d := ev.Document()
	d["_model"] = ev.Model
	d["_format"] = m.Format
	return d
}

func check(t *testing.T, line string, d map[string]any, want map[string]any) {
	t.Helper()
	for k, v := range want {
		if v == nil {
			if got, ok := d[k]; ok {
				t.Errorf("%q: %s = %#v, want no value", line, k, got)
			}
			continue
		}
		if d[k] != v {
			t.Errorf("%q: %s = %#v, want %#v", line, k, d[k], v)
		}
	}
}

func TestParseFormats(t *testing.T) {
	cases := []struct {
		name string
		line string
		want map[string]any
	}{
		{"RFC 5424 example with BOM", "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - \ufeff'su root' failed for lonvick on /dev/pts/8",
			map[string]any{"_format": "rfc5424", "host": "mymachine.example.com", "app": "su", "msgid": "ID47", "facility": "auth",
				"severity": "critical", "severity_id": int64(2), "@timestamp": "2003-10-11T22:14:15.003Z", "dvc": "192.0.2.50",
				"sourcetype": "syslog", "_model": "Other", "process_id": nil}},
		{"RFC 5424 structured data", `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"] An application event log entry`,
			map[string]any{"host": "192.0.2.1", "app": "myproc", "process_id": int64(8710), "facility": "local4", "severity": "notice",
				"@timestamp": "2003-08-24T12:14:15.000003Z", "sd_examplesdid_32473_iut": "3", "sd_examplesdid_32473_eventsource": "Application",
				"sd_exampleprioritysd_32473_class": nil, "sd_examplepriority_32473_class": "high"}},
		{"RFC 5424 escaped structured data", `<13>1 2026-10-12T13:00:00Z h app - - [x@1 a="q\"uote" b="back\\slash" c="br\]acket"] msg`,
			map[string]any{"sd_x_1_a": `q"uote`, "sd_x_1_b": `back\slash`, "sd_x_1_c": "br]acket"}},
		{"RFC 5424 all nil", "<13>1 - - - - - -",
			map[string]any{"_format": "rfc5424", "host": "192.0.2.50", "@timestamp": "2026-10-12T14:00:00Z", "app": nil, "facility": "user", "severity": "notice"}},
		{"RFC 5424 sshd", "<38>1 2026-10-12T13:00:00Z web1 sshd 811 - - Failed password for invalid user oracle from 192.0.2.4 port 40122 ssh2",
			map[string]any{"_model": "Authentication", "action": "failure", "user": "oracle", "src": "192.0.2.4", "host": "web1", "dest": "web1",
				"app": "sshd", "process_id": int64(811), "facility": "auth", "severity": "informational", "vendor_product": "Linux"}},
		{"RFC 5424 from logger", `<13>1 2026-10-12T14:51:46.052245+00:00 vm root - - [timeQuality tzKnown="1" isSynced="0"] hello 5424`,
			map[string]any{"host": "vm", "app": "root", "sd_timequality_tzknown": nil, "@timestamp": "2026-10-12T14:51:46.052245Z"}},
		{"RFC 5424 missing structured data", "<13>1 2026-10-12T13:00:00Z h app - - message right away",
			map[string]any{"_format": "rfc5424", "host": "h", "app": "app"}},
		{"RFC 3164", "<38>Oct 12 13:59:00 web1 sshd[811]: Failed password for root from 192.0.2.4 port 40122 ssh2",
			map[string]any{"_format": "rfc3164", "_model": "Authentication", "user": "root", "host": "web1", "app": "sshd",
				"process_id": int64(811), "@timestamp": "2026-10-12T13:59:00Z", "facility": "auth", "severity": "informational"}},
		{"RFC 3164 from logger", "<13>Oct 12 14:51:45 vm root: hello 3164",
			map[string]any{"host": "vm", "app": "root", "@timestamp": "2026-10-12T14:51:45Z"}},
		{"no PRI", "Oct 12 13:59:00 web1 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
			map[string]any{"_format": "rfc3164", "_model": "Authentication", "src_user": "alice", "user": "root", "facility": nil, "severity": nil}},
		{"no hostname", "<4>Oct 12 13:59:00 kernel: eth0: link up",
			map[string]any{"host": "192.0.2.50", "app": "kernel", "facility": "kern", "severity": "warning"}},
		{"single-digit day", "<13>Oct  2 13:59:00 h app: x", map[string]any{"@timestamp": "2026-10-02T13:59:00Z", "host": "h"}},
		{"ISO timestamp", "<86>2026-10-12T13:59:00.123+02:00 web1 useradd[900]: new user: name=backdoor, UID=1002, GID=1002, home=/home/backdoor, shell=/bin/bash",
			map[string]any{"_model": "Change", "object": "backdoor", "@timestamp": "2026-10-12T11:59:00.123Z", "facility": "authpriv", "host": "web1"}},
		{"ISO timestamp with a space", "<13>2026-10-12 13:59:00 h app: x", map[string]any{"@timestamp": "2026-10-12T13:59:00Z", "host": "h", "app": "app"}},
		{"year after the time", "<13>Oct 12 13:59:00 2025 h app: x", map[string]any{"@timestamp": "2025-10-12T13:59:00Z", "host": "h"}},
		{"upper-case host is not a zone", "<13>Oct 12 13:59:00 MAIL app: x", map[string]any{"host": "MAIL", "app": "app"}},
		{"IPv6 host", "<13>Oct 12 13:59:00 2001:db8::1 app[7]: x", map[string]any{"host": "2001:db8::1", "app": "app", "process_id": int64(7)}},
		{"tag with slash", "<22>Oct 12 13:59:00 mail postfix/smtpd[1234]: connect from unknown[192.0.2.1]",
			map[string]any{"app": "postfix/smtpd", "process_id": int64(1234), "facility": "mail"}},
		{"no timestamp, host and tag", "<13>web1 sshd[5]: Accepted publickey for deploy from 10.0.0.1 port 22 ssh2",
			map[string]any{"_model": "Authentication", "host": "web1", "user": "deploy"}},
		{"tag only", "<13>myapp: started", map[string]any{"app": "myapp", "host": "192.0.2.50"}},
		{"Cisco ASA", "<166>Oct 12 2026 13:59:00: %ASA-6-302013: Built inbound TCP connection 1 for outside:198.51.100.7/4444 (198.51.100.7/4444) to inside:10.0.0.5/22 (10.0.0.5/22)",
			map[string]any{"host": "192.0.2.50", "app": "ASA", "signature_id": "ASA-6-302013", "vendor_product": "Cisco ASA",
				"severity": "informational", "facility": "local4", "@timestamp": "2026-10-12T13:59:00Z"}},
		{"Cisco ASA with host", "<164>Oct 12 2026 13:59:00 asa1 : %ASA-4-106023: Deny tcp src outside:203.0.113.9/5000 dst inside:10.0.0.5/22",
			map[string]any{"host": "asa1", "signature_id": "ASA-4-106023", "severity": "warning"}},
		{"Cisco IOS unsynced clock", "<189>123: *Mar  1 00:01:02.345: %SYS-5-CONFIG_I: Configured from console by console",
			map[string]any{"sequence": int64(123), "signature_id": "SYS-5-CONFIG_I", "app": "SYS", "vendor_product": "Cisco",
				"severity": "notice", "facility": "local7", "@timestamp": "2026-10-12T14:00:00Z", "host": "192.0.2.50"}},
		{"Cisco IOS origin-id", "<189>45: router1: Oct 12 13:59:00.123 UTC: %LINEPROTO-5-UPDOWN: Line protocol on Interface Gi0/1, changed state to up",
			map[string]any{"sequence": int64(45), "host": "router1", "@timestamp": "2026-10-12T13:59:00.123Z", "signature_id": "LINEPROTO-5-UPDOWN"}},
		{"Cisco relayed with its own timestamp", "<187>Oct 12 13:59:00 rtr2 1234: Oct 12 13:58:59 EST: %MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user 'admin'",
			map[string]any{"host": "rtr2", "sequence": int64(1234), "signature_id": "MGBL-CONFIG-6-DB_COMMIT", "@timestamp": "2026-10-12T13:59:00Z", "severity": "error"}},
		{"Cisco without PRI", "%LINK-3-UPDOWN: Interface Gi0/2, changed state to down",
			map[string]any{"signature_id": "LINK-3-UPDOWN", "severity": "error", "severity_id": int64(3), "facility": nil}},
		{"trailing NUL and CRLF", "<13>Oct 12 13:59:00 h app: hi\r\n\x00", map[string]any{"message": "<13>Oct 12 13:59:00 h app: hi"}},
		{"garbage", "hello world", map[string]any{"_format": "raw", "message": "hello world", "host": "192.0.2.50", "dest": "192.0.2.50",
			"_model": "Other", "sourcetype": "syslog", "facility": nil, "app": nil}},
		{"PRI out of range", "<999>hello", map[string]any{"_format": "raw", "facility": nil, "message": "<999>hello"}},
		{"PRI only", "<13>", map[string]any{"facility": "user", "message": "<13>"}},
		{"clock never set", "<13>1 1970-01-01T00:00:00Z h a - - - boot", map[string]any{"@timestamp": "2026-10-12T14:00:00Z"}},
		{"clock far ahead", "<13>1 2099-01-01T00:00:00Z h a - - - x", map[string]any{"@timestamp": "2026-10-12T14:00:00Z"}},
		{"impossible date", "<13>Feb 30 13:59:00 h app: x", map[string]any{"@timestamp": "2026-10-12T14:00:00Z"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := doc(c.line)
			check(t, c.line, d, c.want)
			if _, ok := c.want["message"]; !ok && d["message"] != strings.TrimRight(c.line, "\x00\r\n") {
				t.Errorf("message = %q, want the line", d["message"])
			}
		})
	}
}

func TestYearlessTimestampAtNewYear(t *testing.T) {
	m := Parse([]byte("<13>Dec 31 23:59:59 h app: x"), time.Date(2027, 1, 1, 0, 0, 30, 0, time.UTC))
	if got := m.Time.Format(time.RFC3339); got != "2026-12-31T23:59:59Z" {
		t.Errorf("time = %s, want last year", got)
	}
}

func TestStrangeInputNeverFails(t *testing.T) {
	long := "<13>Oct 12 13:59:00 h app: " + strings.Repeat("a", 64<<10)
	inputs := []string{
		"", " ", "\x00\x00", "<", "<>", "<1", "<13", "<13>1", "<13>1 ", "<13>1 -", "<13>1 - - - - - [", "<13>1 - - - - - [a",
		`<13>1 - - - - - [a b="c`, `<13>1 - - - - - [a b=c]`, "\x00\x01\xff\xfe<>", "Oct", "Oct 12", "Oct 12 99:99:99 h a: x",
		"*", "*Oct 12 13:59:00", "123: ", "%", "%A-9-B: x", "CEF:", "CEF:0|", "CEF:0|a|b|c|d|e|f|", "CEF:0|a|b|c|d|e|f|=x ==y \\",
		long, strings.Repeat("<13>", 1000), strings.Repeat("[", 1000), "<13>1 2026-10-12T13:00:00Z " + strings.Repeat("x ", 5000),
	}
	for _, in := range inputs {
		m := Parse([]byte(in), now)
		d := m.Event(sender, now).Document()
		if _, err := json.Marshal(d); err != nil {
			t.Errorf("%q: %v", in, err)
		}
		if strings.TrimSpace(strings.Trim(in, "\x00")) != "" && d["message"] == nil {
			t.Errorf("%q: message dropped", in)
		}
	}
	if d := doc("\x00\x01\xff\xfe<>"); !strings.Contains(d["message"].(string), "\uFFFD") {
		t.Errorf("invalid UTF-8 not replaced: %q", d["message"])
	}
	if d := doc(long); len(d["message"].(string)) != len(long) || d["app"] != "app" {
		t.Errorf("long message: app %v, %d bytes", d["app"], len(d["message"].(string)))
	}
}

func TestCEF(t *testing.T) {
	cases := []struct {
		name string
		line string
		want map[string]any
	}{
		{"spec example", "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232",
			map[string]any{"_model": "Network_Traffic", "sourcetype": "cef", "src": "10.0.0.1", "dest": "2.1.2.2", "src_port": int64(1232),
				"severity": "critical", "severity_id": int64(10), "signature": "worm successfully stopped", "signature_id": "100",
				"vendor_product": "Security threatmanager", "cef_vendor": "Security", "cef_product": "threatmanager", "cef_version": "0",
				"cef_device_version": "1.0", "host": "192.0.2.50", "dvc": "192.0.2.50"}},
		{"after a syslog header", `<134>Oct 12 13:59:00 fw1 CEF:0|Palo Alto Networks|PAN-OS|10.1|TRAFFIC|end|3|rt=Oct 12 2026 13:58:59 GMT src=10.1.1.5 dst=203.0.113.9 spt=50000 dpt=4444 proto=TCP act=allow in=100 out=2000 suser=CORP\\alice cs1Label=Rule cs1=Allow-Out deviceDirection=1`,
			map[string]any{"_model": "Network_Traffic", "host": "fw1", "@timestamp": "2026-10-12T13:58:59Z", "transport": "tcp", "action": "allowed",
				"vendor_action": "allow", "bytes_in": int64(100), "bytes_out": int64(2000), "bytes": int64(2100), "src_user": `CORP\alice`,
				"user": `CORP\alice`, "cef_cs1label": "Rule", "cef_cs1": "Allow-Out", "cef_rt": "Oct 12 2026 13:58:59 GMT", "dest_port": int64(4444),
				"severity": "low", "facility": "local0", "vendor_product": "Palo Alto Networks PAN-OS", "direction": "outbound"}},
		{"escapes", `CEF:0|Ven\|dor|Prod\\uct|1|sig|Name with \| pipe|5|msg=a\=b c\\d\nline2 request=http://x/?a=b&c=d filePath=C:\\Windows\\x.exe`,
			map[string]any{"cef_vendor": "Ven|dor", "cef_product": `Prod\uct`, "signature": "Name with | pipe", "cef_msg": "a=b c\\d\nline2",
				"url": "http://x/?a=b&c=d", "file_path": `C:\Windows\x.exe`, "severity": "medium", "_model": "Other"}},
		{"values with spaces", "CEF:0|V|P|1|1|N|Low|msg=hello big world act=blocked dst=1.2.3.4 duser=bob suser=alice",
			map[string]any{"cef_msg": "hello big world", "action": "blocked", "severity": "low", "severity_id": nil, "dest": "1.2.3.4",
				"user": "bob", "dest_user": "bob", "src_user": "alice", "_model": "Other"}},
		{"RFC 5424 header", "<134>1 2026-10-12T13:59:00Z fw1 CEF - - - CEF:0|Fortinet|Fortigate|7.2|0000000013|forward traffic|5|src=10.0.0.9 dst=8.8.8.8 dpt=53 proto=17 act=accept app=DNS dvchost=fgt1",
			map[string]any{"host": "fw1", "app": "DNS", "transport": "udp", "action": "allowed", "dvc_host": "fgt1", "@timestamp": "2026-10-12T13:59:00Z",
				"vendor_product": "Fortinet Fortigate"}},
		{"device host name when the header has none", "<134>CEF:0|V|P|1|1|N|Very-High|dvchost=sensor1 rt=1791813540000",
			map[string]any{"host": "sensor1", "severity": "critical", "@timestamp": "2026-10-12T13:59:00Z"}},
		{"bad numbers stay as text", "CEF:0|V|P|1|1|N|3|spt=abc dpt=80", map[string]any{"cef_spt": "abc", "dest_port": int64(80), "src_port": nil}},
		{"not enough header fields", "CEF:0|only|three|fields", map[string]any{"sourcetype": "syslog", "cef_vendor": nil}},
		{"not a version", "CEF:x|a|b|c|d|e|f|src=1", map[string]any{"sourcetype": "syslog"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			check(t, c.line, doc(c.line), c.want)
		})
	}
}

func TestCEFExtraFieldsAreCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString("CEF:0|V|P|1|1|N|1|src=10.0.0.1 ")
	for i := range 100 {
		fmt.Fprintf(&b, "custom%d=v%d ", i, i)
	}
	d := doc(b.String())
	n := 0
	for k := range d {
		if strings.HasPrefix(k, "cef_") {
			n++
		}
	}
	// The four header fields plus the capped extension keys.
	if n != 4+maxExtraFields || d["src"] != "10.0.0.1" {
		t.Errorf("cef_ fields = %d, src = %v", n, d["src"])
	}
}

func TestFieldNameBudget(t *testing.T) {
	b := nameBudget{max: 3, seen: map[string]struct{}{}}
	f := map[string]any{"cef_a": "1", "cef_b": "2", "src": "x"}
	b.limit(f, now)
	g := map[string]any{"cef_a": "1", "cef_c": "3", "cef_d": "4", "sd_e": "5", "dest": "y"}
	b.limit(g, now)
	extras := 0
	for k := range g {
		if isExtra(k) {
			extras++
		}
	}
	if g["cef_a"] == nil || extras != 2 || g["dest"] == nil {
		t.Errorf("after budget: %v", g)
	}
	h := map[string]any{"cef_z": "1"}
	b.limit(h, now.Add(24*time.Hour))
	if h["cef_z"] == nil {
		t.Error("budget did not reset the next day")
	}
}
