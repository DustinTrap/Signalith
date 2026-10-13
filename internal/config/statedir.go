package config

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

// The state folder holds what Signalith makes for itself and keeps on one
// server: its master key (keys/), its HTTPS certificate and certificate
// authority (tls/), the built-in admin's password set with signalith
// passwd (admin-password-hash), and this server's identity (node.id) with
// its lock (cluster/). StateDir picks it, for the server and for every
// command, so these always sit together.

// stateFiles are the files and folders whose presence shows that a folder
// is already some install's state folder.
var stateFiles = []string{"keys", "tls", "admin-password-hash", "node.id"}

// insteadOfFile, in a fallback state folder, lists the folders it is used
// instead of, one per line, so every later start and every command run by
// hand (which may run as another user, for whom the usual folder can be
// written) finds the same folder.
const insteadOfFile = "used_instead_of"

// HoldsState reports whether dir already holds Signalith's own files: a
// master key, an HTTPS certificate, a password set with signalith passwd,
// or a server identity.
func HoldsState(dir string) bool {
	for _, f := range stateFiles {
		if _, err := os.Lstat(filepath.Join(dir, f)); err == nil {
			return true
		}
	}
	return false
}

// StateDir returns the state folder (see StateDirChoice).
func (c *Config) StateDir() string {
	dir, _ := c.StateDirChoice()
	return dir
}

// StateDirChoice returns the state folder and, when it is not the usual
// one, why, for the log:
//
//  1. SIGNALITH_STATE_DIR when it is set.
//  2. Else the folder that holds lookups.dir when it already holds
//     Signalith's own files (HoldsState), so an upgrade never leaves a
//     master key or a certificate behind.
//  3. Else a fallback folder used before instead of that one.
//  4. Else that folder, when it is on a local disk this user can write.
//  5. Else the first fallback that is (systemd's $STATE_DIRECTORY, then
//     /var/lib/signalith on Linux; %ProgramData%\Signalith on Windows),
//     which notes that it is used instead.
//  6. Else the folder that holds lookups.dir anyway; using it then says
//     what is wrong.
//
// The answer is kept for the life of the process, so a restart in place
// or a folder that becomes writable later never moves it.
func (c *Config) StateDirChoice() (dir, why string) {
	if d := os.Getenv("SIGNALITH_STATE_DIR"); d != "" {
		return d, ""
	}
	return pickStateDir(filepath.Dir(c.LookupsDir()), fallbackStateDirs())
}

// StateDirFallbacks are the folders a state folder falls back to here.
func StateDirFallbacks() []string { return fallbackStateDirs() }

type stateChoice struct{ dir, why string }

var (
	stateMu    sync.Mutex
	stateCache = map[string]stateChoice{}
)

// forgetStateDirs empties the kept answers, for tests.
func forgetStateDirs() {
	stateMu.Lock()
	clear(stateCache)
	stateMu.Unlock()
}

func pickStateDir(def string, fallbacks []string) (string, string) {
	abs, err := filepath.Abs(def)
	if err != nil {
		return def, ""
	}
	key := abs + "\x00" + strings.Join(fallbacks, "\x00")
	stateMu.Lock()
	defer stateMu.Unlock()
	if ch, ok := stateCache[key]; ok {
		return ch.dir, ch.why
	}
	ch := chooseStateDir(def, abs, fallbacks)
	stateCache[key] = ch
	return ch.dir, ch.why
}

func chooseStateDir(def, abs string, fallbacks []string) stateChoice {
	if HoldsState(abs) {
		return stateChoice{dir: def}
	}
	var others []string
	for _, d := range fallbacks {
		if d != "" && !samePath(d, abs) {
			others = append(others, d)
		}
	}
	for _, d := range others {
		if usedInsteadOf(d, abs) {
			return stateChoice{d, fmt.Sprintf("Signalith keeps its own files (master key, HTTPS certificate and this server's identity) in %s, "+
				"used instead of %s since that folder could not be used; set SIGNALITH_STATE_DIR to choose the folder", d, abs)}
		}
	}
	problem := stateDirProblem(abs)
	if problem == "" {
		return stateChoice{dir: def}
	}
	for _, d := range others {
		if stateDirProblem(d) != "" {
			continue
		}
		if err := noteInsteadOf(d, abs); err != nil {
			continue
		}
		return stateChoice{d, fmt.Sprintf("Signalith keeps its own files (master key, HTTPS certificate and this server's identity) in %s, "+
			"because %s; set SIGNALITH_STATE_DIR to choose the folder", d, problem)}
	}
	return stateChoice{dir: def}
}

// stateDirProblem is StateDirProblem; tests replace it.
var stateDirProblem = StateDirProblem

// StateDirProblem says why dir cannot be a state folder (it is on a
// network share, or this user cannot write in it), or "". A folder that
// does not exist yet is checked where it would be made.
func StateDirProblem(dir string) string {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err.Error()
	}
	at := nearestExisting(abs)
	if network, _, err := FolderFilesystem(at); err == nil && network != "" {
		return fmt.Sprintf("the folder that holds lookups.dir, %s, is on a network share (%s)", abs, network)
	}
	if st, err := os.Stat(at); err != nil || !st.IsDir() {
		return fmt.Sprintf("this user cannot write in %s", at)
	}
	f, err := os.CreateTemp(at, ".signalith-write-check-*")
	if err != nil {
		return fmt.Sprintf("this user cannot write in %s", at)
	}
	name := f.Name()
	f.Close()
	_ = os.Remove(name)
	return ""
}

// nearestExisting returns dir, or the nearest folder above it that exists.
func nearestExisting(dir string) string {
	at := dir
	for {
		if _, err := os.Stat(at); err == nil || filepath.Dir(at) == at {
			return at
		}
		at = filepath.Dir(at)
	}
}

// NearestExisting is nearestExisting, for the cluster package.
func NearestExisting(dir string) string { return nearestExisting(dir) }

// usedInsteadOf reports whether the fallback folder dir was used instead
// of the folder def before.
func usedInsteadOf(dir, def string) bool {
	f, err := os.Open(filepath.Join(dir, insteadOfFile))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") && samePath(line, def) {
			return true
		}
	}
	return false
}

// noteInsteadOf records in the fallback folder dir that it is used
// instead of def.
func noteInsteadOf(dir, def string) error {
	if usedInsteadOf(dir, def) {
		return nil
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	path := filepath.Join(dir, insteadOfFile)
	_, err := os.Stat(path)
	f, ferr := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
	if ferr != nil {
		return ferr
	}
	if errors.Is(err, os.ErrNotExist) {
		_, ferr = f.WriteString("# Signalith keeps its own files here instead of in these folders, which could not be used.\n")
	}
	if ferr == nil {
		_, ferr = f.WriteString(def + "\n")
	}
	if cerr := f.Close(); ferr == nil {
		ferr = cerr
	}
	return ferr
}

// samePath reports whether two folder names are the same, ignoring case
// on Windows.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	return a == b || runtime.GOOS == "windows" && strings.EqualFold(a, b)
}
