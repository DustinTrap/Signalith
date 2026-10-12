package main

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// A command run by hand does not see the Environment= lines of the
// signalith systemd unit, which put the server's own files (directory.json,
// intel_feeds.yaml, a master key it made) in /var/lib/signalith. So when
// the service runs with the same config file, "signalith secrets" uses the
// unit's folder and file settings too.

// serviceVar matches the settings taken from the unit: folders and files
// only, never secrets.
var serviceVar = regexp.MustCompile(`^SIGNALITH_[A-Z_]+_(DIR|FILE)$`)

// systemctlShow returns what systemd knows about the signalith service.
var systemctlShow = func() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "systemctl", "show", "signalith.service",
		"--property=ExecStart", "--property=Environment", "--property=LoadCredential").Output()
}

// keyIsCredential is set when the service gets its master key as a
// systemd credential, which it reads only when it starts.
var keyIsCredential bool

// applyServiceEnv sets, in this process, the folder and file settings the
// signalith systemd service has, when it runs with the config file path
// and the variable is not set here already. It returns what it set, as
// NAME=value.
func applyServiceEnv(path string) []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	out, err := systemctlShow()
	if err != nil {
		return nil
	}
	env, cred := serviceEnv(out, path)
	var set []string
	for k, v := range env {
		if os.Getenv(k) == "" {
			os.Setenv(k, v)
			set = append(set, k+"="+v)
		}
	}
	keyIsCredential = cred != "" && os.Getenv("SIGNALITH_MASTER_KEY_FILE") == cred
	sort.Strings(set)
	return set
}

// serviceEnv reads "systemctl show" output and returns the unit's folder
// and file settings when its ExecStart uses the config file path. A
// master key passed with LoadCredential=master.key:<file> is returned as
// SIGNALITH_MASTER_KEY_FILE, since the credential folder exists only for
// the service, and as cred.
func serviceEnv(show []byte, path string) (env map[string]string, cred string) {
	var execArgs []string
	unit := map[string]string{}
	var credFile string
	sc := bufio.NewScanner(bytes.NewReader(show))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		key, value, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ExecStart":
			// { path=/usr/local/bin/signalith ; argv[]=/usr/local/bin/signalith serve -c /etc/... ; ... }
			if _, rest, ok := strings.Cut(value, "argv[]="); ok {
				argv, _, _ := strings.Cut(rest, " ;")
				execArgs = strings.Fields(argv)
			}
		case "Environment":
			for _, kv := range splitQuoted(value) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					unit[k] = v
				}
			}
		case "LoadCredential":
			if id, file, ok := strings.Cut(value, ":"); ok && id == "master.key" && filepath.IsAbs(file) {
				credFile = file
			}
		}
	}
	if len(execArgs) == 0 {
		return nil, ""
	}
	served := unit["SIGNALITH_CONFIG"]
	if served == "" {
		served = "/etc/signalith/signalith.yaml"
	}
	for i, a := range execArgs {
		switch {
		case (a == "-c" || a == "--c") && i+1 < len(execArgs):
			served = execArgs[i+1]
		case strings.HasPrefix(a, "-c="):
			served = strings.TrimPrefix(a, "-c=")
		case strings.HasPrefix(a, "--c="):
			served = strings.TrimPrefix(a, "--c=")
		}
	}
	if !sameFile(served, path) {
		return nil, ""
	}
	env = map[string]string{}
	for k, v := range unit {
		if serviceVar.MatchString(k) && v != "" {
			env[k] = v
		}
	}
	// $CREDENTIALS_DIRECTORY/master.key comes before SIGNALITH_MASTER_KEY_FILE.
	if credFile != "" {
		env["SIGNALITH_MASTER_KEY_FILE"] = credFile
	}
	return env, credFile
}

// splitQuoted splits a systemctl Environment= value: space-separated
// NAME=value items, an item with spaces in double quotes.
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	quoted, started := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && quoted && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == '"':
			quoted, started = !quoted, true
		case c == ' ' && !quoted:
			if cur.Len() > 0 || started {
				out = append(out, cur.String())
			}
			cur.Reset()
			started = false
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 || started {
		out = append(out, cur.String())
	}
	return out
}

// sameFile reports whether two paths name the same file.
func sameFile(a, b string) bool {
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	if filepath.Clean(aa) == filepath.Clean(bb) {
		return true
	}
	sa, err1 := os.Stat(aa)
	sb, err2 := os.Stat(bb)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}
