package ingest

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Linux sources arrive either as syslog lines (Fluent Bit tail on
// /var/log/auth.log or /var/log/secure, or the syslog input) or as journald
// records (Fluent Bit systemd input). Both reduce to host, program, pid and
// message, and the program decides which parser applies.

var syslogLine = regexp.MustCompile(`^(?:<\d+>)?(?:(\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})|(\d{4}-\d{2}-\d{2}T\S+))\s+(\S+)\s+([^\s\[:]+)(?:\[(\d+)\])?:\s?(.*)$`)

func parseSyslogLine(line, sourcetype string, now time.Time) Event {
	m := syslogLine.FindStringSubmatch(line)
	if m == nil {
		return Event{Model: "Other", Fields: map[string]any{"sourcetype": sourcetype, "message": line}}
	}
	var ts time.Time
	if m[1] != "" {
		if t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(m[1]), " "), time.Local); err == nil {
			ts = GuessYear(t, now)
		}
	} else if t, ok := parseTime(m[2]); ok {
		ts = t
	}
	ev := ParseProgram(m[3], m[4], m[5], m[6], sourcetype)
	ev.Fields["message"] = line
	ev.Time = ts
	return ev
}

// GuessYear gives a timestamp that has no year, as in RFC 3164 syslog
// ("Oct 11 09:15:02"), the current year, or last year when that would put
// it more than a day in the future. The clock time and location of t are
// kept; the result is in UTC.
func GuessYear(t, now time.Time) time.Time {
	y := time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	if y.After(now.Add(24 * time.Hour)) {
		y = y.AddDate(-1, 0, 0)
	}
	return y.UTC()
}

func parseJournal(r map[string]any) Event {
	program := str(r, "SYSLOG_IDENTIFIER", "_COMM")
	ev := ParseProgram(str(r, "_HOSTNAME"), program, str(r, "_PID"), str(r, "MESSAGE"), "linux:journal")
	if us, err := strconv.ParseInt(str(r, "__REALTIME_TIMESTAMP", "_SOURCE_REALTIME_TIMESTAMP"), 10, 64); err == nil {
		ev.Time = time.UnixMicro(us).UTC()
	}
	ev.Fields["message"] = program + ": " + str(r, "MESSAGE")
	return ev
}

var (
	sshdAuth      = regexp.MustCompile(`^(Accepted|Failed) (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	sshdInvalid   = regexp.MustCompile(`^Invalid user (\S*) from (\S+)(?: port (\d+))?`)
	sudoCommand   = regexp.MustCompile(`^\s*(\S+) : (?:(\d+) incorrect password attempts? ; )?TTY=\S+ ; PWD=\S+ ; USER=(\S+) ; COMMAND=(.*)$`)
	sudoAuthFail  = regexp.MustCompile(`pam_unix\(sudo:auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)`)
	suSession     = regexp.MustCompile(`pam_unix\(su(?:-l)?:session\): session opened for user (\S+?)(?:\(uid=\d+\))? by (\S+?)(?:\(uid=\d+\))?$`)
	suFail        = regexp.MustCompile(`pam_unix\(su(?:-l)?:auth\): authentication failure;.*\bruser=(\S*).*\buser=(\S+)`)
	useraddNew    = regexp.MustCompile(`^new user: name=([^,]+),`)
	userdelDelete = regexp.MustCompile(`^delete user '([^']+)'`)
	groupAdd      = regexp.MustCompile(`^add '([^']+)' to (?:shadow )?group '([^']+)'`)
)

// ParseProgram maps one syslog program's message onto a data model: sshd
// (including OpenSSH 9.8+ sshd-session), sudo and su logons become Authentication events; useradd, userdel,
// usermod and gpasswd become Change events; anything else is Other. Agent
// logs and the syslog receiver both use it, so the built-in detections fire
// whichever way Linux auth logs arrive.
func ParseProgram(host, program, pid, msg, sourcetype string) Event {
	f := map[string]any{
		"host":       host,
		"dest":       host,
		"sourcetype": sourcetype,
		"app":        program,
		"process_id": atoi(pid),
	}
	ev := Event{Model: "Other", Fields: f}
	switch program {
	case "sshd", "sshd-session", "sshd-auth":
		// OpenSSH 9.8 and later log logons from sshd-session (and 10.0
		// from sshd-auth); they are still sshd to detections and searches.
		f["app"] = "sshd"
		if m := sshdAuth.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = map[string]string{"Accepted": "success", "Failed": "failure"}[m[1]]
			f["authentication_method"] = m[2]
			f["user"] = m[3]
			f["src"] = m[4]
			f["src_port"] = atoi(m[5])
			f["signature"] = "SSH " + strings.ToLower(m[1]) + " " + m[2]
			if strings.Contains(msg, "invalid user") {
				f["reason"] = "unknown user"
			} else if m[1] == "Failed" && m[2] == "password" {
				f["reason"] = "bad password"
			}
		} else if m := sshdInvalid.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "failure"
			f["user"] = m[1]
			f["src"] = m[2]
			f["src_port"] = atoi(m[3])
			f["reason"] = "unknown user"
			f["signature"] = "SSH invalid user"
		}
	case "sudo":
		if m := sudoCommand.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["src_user"] = m[1]
			f["user"] = m[3]
			f["process"] = m[4]
			if m[2] != "" {
				f["action"] = "failure"
				f["reason"] = "bad password"
				f["signature"] = "sudo incorrect password"
			} else {
				f["action"] = "success"
				f["signature"] = "sudo command"
			}
		} else if m := sudoAuthFail.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "failure"
			f["src_user"] = m[1]
			f["user"] = m[2]
			f["signature"] = "sudo authentication failure"
		}
	case "su":
		if m := suSession.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "success"
			f["user"] = m[1]
			f["src_user"] = m[2]
			f["signature"] = "su session opened"
		} else if m := suFail.FindStringSubmatch(msg); m != nil {
			ev.Model = "Authentication"
			f["action"] = "failure"
			f["src_user"] = m[1]
			f["user"] = m[2]
			f["signature"] = "su authentication failure"
		}
	case "useradd":
		if m := useraddNew.FindStringSubmatch(msg); m != nil {
			ev.Model = "Change"
			f["action"] = "created"
			f["object"] = m[1]
			f["object_category"] = "user"
			f["signature"] = "User account created"
		}
	case "userdel":
		if m := userdelDelete.FindStringSubmatch(msg); m != nil {
			ev.Model = "Change"
			f["action"] = "deleted"
			f["object"] = m[1]
			f["object_category"] = "user"
			f["signature"] = "User account deleted"
		}
	case "usermod", "gpasswd":
		if m := groupAdd.FindStringSubmatch(msg); m != nil {
			ev.Model = "Change"
			f["action"] = "modified"
			f["member"] = m[1]
			f["object"] = m[2]
			f["object_category"] = "group"
			f["signature"] = "User added to group"
		}
	}
	if ev.Model == "Authentication" || ev.Model == "Change" {
		f["vendor_product"] = "Linux"
	}
	return ev
}
