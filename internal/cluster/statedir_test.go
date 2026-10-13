package cluster

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// When the folder that holds lookups.dir cannot be written, the identity
// goes to a local folder that can, and the log says why.
func TestPickStateDir(t *testing.T) {
	ok := t.TempDir()
	if dir, why := PickStateDir(ok); dir != ok || why != "" {
		t.Errorf("a usable folder: %q %q", dir, why)
	}
	// Below a file: nothing can be made there.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(file, "state")
	fallback := t.TempDir()
	switch runtime.GOOS {
	case "linux":
		t.Setenv("STATE_DIRECTORY", fallback)
	case "windows":
		t.Setenv("ProgramData", fallback)
		fallback = filepath.Join(fallback, "Signalith")
	default:
		if dir, _ := PickStateDir(bad); dir != bad {
			t.Errorf("no fallback here, got %q", dir)
		}
		return
	}
	dir, why := PickStateDir(bad)
	if dir != fallback || !strings.Contains(why, "cannot write in") || !strings.Contains(why, "SIGNALITH_STATE_DIR") {
		t.Errorf("fallback: %q %q", dir, why)
	}
	l, err := OpenLocal(dir, testOptions("x"))
	if err != nil {
		t.Fatalf("open the fallback: %v", err)
	}
	l.Close()
}
