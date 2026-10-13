package security

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// mixedFacts have something in every state.
func mixedFacts(t *testing.T) *Facts {
	f := goodFacts(t, "syslog:\n  udp: 0.0.0.0:5514\n  public_port: 514\n")
	f.Config.OpenSearch.TLSSkipVerify = true
	f.Admin.DockerFirst = true
	f.Disks = []Disk{{Kind: DiskVirtual, Provider: "Amazon EC2"}}
	f.TLS.Next = &tlsauto.CAInfo{Scope: "strict", At: now.Add(-time.Hour)}
	f.Runtime.SyslogSenders = map[string]int{"udp": 4}
	return f
}

func TestTextGolden(t *testing.T) {
	f := mixedFacts(t)
	r := Evaluate(f)
	// The config file is in a folder of the test's own.
	got := strings.ReplaceAll(Text(r), filepath.Dir(f.Config.Path()), "/etc/signalith")
	file := filepath.Join("testdata", "report.txt")
	if *update {
		if err := os.WriteFile(file, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if norm := strings.ReplaceAll(string(want), "\r\n", "\n"); got != norm {
		t.Errorf("text report changed (go test -run TestTextGolden -update to accept):\n%s", got)
	}
	checkText(t, got)
}

// checkText checks the rules of the text report: ASCII only, lines of
// 78 columns at most, except a link or a command, which is never broken.
func checkText(t *testing.T, text string) {
	t.Helper()
	inRun := false
	for i, line := range strings.Split(text, "\n") {
		for _, r := range line {
			if r > 126 || r < 32 && r != '\t' {
				t.Errorf("line %d is not ASCII: %q", i+1, line)
				break
			}
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "Run:" {
			inRun = true
			continue
		}
		if inRun && strings.HasPrefix(line, "     ") && !strings.HasPrefix(trimmed, "Docs:") {
			continue
		}
		inRun = false
		if len(line) > textWidth {
			fields := strings.Fields(line)
			long := fields[len(fields)-1]
			if !strings.HasPrefix(long, "https://") || len(strings.Join(fields[:len(fields)-1], " "))+1 > textWidth {
				t.Errorf("line %d is %d long: %q", i+1, len(line), line)
			}
		}
	}
}

func TestTextAllGood(t *testing.T) {
	f := goodFacts(t, "")
	f.Runtime = nil
	text := Text(Evaluate(f))
	checkText(t, text)
	for _, want := range []string{
		"Signalith security report for siem-1\n",
		"Checked 2026-10-13 14:02 UTC. Signalith v0.9.0 (go1.26.9). Linux, systemd\nservice.\n",
		"Summary: nothing needs attention, 18 good.\n",
		"In transit\n  [good]        Connection to OpenSearch\n",
		"  [good]        HTTPS\n                The web page, the API and agents use HTTPS, with Signalith's\n                own certificate.\n",
		"                Standard or strict?\n                - Computers that trust",
		"                Signalith's own certificate is valid until 2027-08-09 and\n",
		"Not checked here\n  - Firewalls: which computers can reach Signalith's ports.\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "Fix first") {
		t.Error("Fix first with nothing to fix")
	}
}

func TestWrap(t *testing.T) {
	long := "https://github.com/jrsamsanchez/signalith/blob/main/docs/opensearch-security.md#4-point-signalith-at-it"
	got := wrap("Docs: "+long+" and more words after it", "   ", "   ")
	lines := strings.Split(strings.TrimSuffix(got, "\n"), "\n")
	if len(lines) != 3 || lines[1] != "   "+long {
		t.Errorf("%q", lines)
	}
	if got := wrap("", "  ", "  "); got != "  \n" {
		t.Errorf("%q", got)
	}
}

func TestISODates(t *testing.T) {
	if got := isoDates("valid until 9 Aug 2027 and 12 Nov 2026."); got != "valid until 2027-08-09 and 2026-11-12." {
		t.Error(got)
	}
	if got := isoDates("port 8080 Jan"); got != "port 8080 Jan" {
		t.Error(got)
	}
}
