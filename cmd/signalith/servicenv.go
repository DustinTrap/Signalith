package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// A command run by hand does not see the environment the signalith
// service is given: the Environment= and EnvironmentFile= lines of its
// systemd unit on Linux, or the Environment value of the Signalith service
// in the Windows registry. Those put the server's own files
// (directory.json, intel_feeds.yaml, a master key it made) in its state
// folder, and may name its master key (SIGNALITH_MASTER_KEY_FILE). So when
// the service runs with the same config file, "signalith secrets",
// "signalith validate" and "signalith init" use the service's folder,
// file and master key settings too, and find the same files and key.

// serviceVar matches the settings taken from the service: folders, files
// and the master key; never other secrets.
var serviceVar = regexp.MustCompile(`^SIGNALITH_([A-Z_]+_(DIR|FILE)|MASTER_KEY)$`)

// serviceSettings is what the service is given.
type serviceSettings struct {
	// where says where the settings were read, for people.
	where string
	// args is the service's command line, after the program.
	args []string
	// env is its environment, as NAME=value.
	env map[string]string
	// cred is the file of a master key passed to it as a systemd
	// credential (LoadCredential=master.key:<file>).
	cred string
}

// readServiceSettings returns the service's settings, or nil when there
// is no service here. Tests replace it.
var readServiceSettings = platformServiceSettings

// keyIsCredential is set when the service gets its master key as a
// systemd credential, which it reads only when it starts.
var keyIsCredential bool

// applyServiceEnv sets, in this process, the folder, file and master key
// settings the signalith service has, when it runs with the config file
// path and the variable is not set here already. It returns where they
// were read and what it set, as NAME=value (a key itself is not shown).
func applyServiceEnv(path string) (where string, set []string) {
	s := readServiceSettings()
	if s == nil {
		return "", nil
	}
	env := s.envFor(path)
	if env == nil {
		return "", nil
	}
	for k, v := range env {
		if os.Getenv(k) != "" {
			continue
		}
		os.Setenv(k, v)
		if k == "SIGNALITH_MASTER_KEY" {
			v = "(the key itself, not shown)"
		}
		set = append(set, k+"="+v)
	}
	keyIsCredential = s.cred != "" && os.Getenv("SIGNALITH_MASTER_KEY_FILE") == s.cred
	sort.Strings(set)
	return s.where, set
}

// envFor returns the service's folder, file and master key settings when
// it runs with the config file path, or nil. A master key passed with
// LoadCredential=master.key:<file> is returned as
// SIGNALITH_MASTER_KEY_FILE, since the credential folder exists only for
// the service.
func (s *serviceSettings) envFor(path string) map[string]string {
	if s == nil || s.args == nil {
		return nil
	}
	served := s.env["SIGNALITH_CONFIG"]
	if served == "" {
		served = defaultConfigPath()
	}
	for i, a := range s.args {
		switch {
		case (a == "-c" || a == "--c") && i+1 < len(s.args):
			served = s.args[i+1]
		case strings.HasPrefix(a, "-c="):
			served = strings.TrimPrefix(a, "-c=")
		case strings.HasPrefix(a, "--c="):
			served = strings.TrimPrefix(a, "--c=")
		}
	}
	if !sameFile(served, path) {
		return nil
	}
	env := map[string]string{}
	for k, v := range s.env {
		if serviceVar.MatchString(k) && v != "" {
			env[k] = v
		}
	}
	// $CREDENTIALS_DIRECTORY/master.key comes before SIGNALITH_MASTER_KEY_FILE.
	if s.cred != "" {
		env["SIGNALITH_MASTER_KEY_FILE"] = s.cred
		delete(env, "SIGNALITH_MASTER_KEY")
	}
	return env
}

// parseSystemctlShow reads "systemctl show" output: the service's command
// line, its Environment= settings, the files EnvironmentFile= names (read
// with readFile, later ones winning, as systemd does), and a master key
// passed as a credential.
func parseSystemctlShow(show []byte, readFile func(string) ([]byte, error)) *serviceSettings {
	s := &serviceSettings{where: "systemctl show signalith", env: map[string]string{}}
	var files []string
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
				if f := strings.Fields(argv); len(f) > 0 {
					s.args = f[1:]
				}
			}
		case "Environment":
			for _, kv := range splitQuoted(value) {
				if k, v, ok := strings.Cut(kv, "="); ok {
					s.env[k] = v
				}
			}
		case "EnvironmentFiles":
			// /etc/signalith/signalith.env (ignore_errors=yes)
			if f, _, _ := strings.Cut(value, " ("); filepath.IsAbs(f) {
				files = append(files, f)
			}
		case "LoadCredential":
			if id, file, ok := strings.Cut(value, ":"); ok && id == "master.key" && filepath.IsAbs(file) {
				s.cred = file
			}
		}
	}
	if s.args == nil {
		return nil
	}
	for _, f := range files {
		data, err := readFile(f)
		if err != nil {
			continue
		}
		for k, v := range parseEnvFile(data) {
			s.env[k] = v
		}
		clear(data)
	}
	return s
}

// parseEnvFile reads a systemd EnvironmentFile: NAME=value lines, with #
// and ; comments, and values optionally in quotes.
func parseEnvFile(data []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(strings.TrimPrefix(k, "export ")), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out[k] = v
	}
	return out
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
	// Windows paths ignore case.
	if ca, cb := filepath.Clean(aa), filepath.Clean(bb); ca == cb || runtime.GOOS == "windows" && strings.EqualFold(ca, cb) {
		return true
	}
	sa, err1 := os.Stat(aa)
	sb, err2 := os.Stat(bb)
	return err1 == nil && err2 == nil && os.SameFile(sa, sb)
}
