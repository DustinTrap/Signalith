package security

import (
	"path"
	"strings"
)

// Deployments: how Signalith runs, as ServerInfo.Deployment says.
const (
	DeployDocker         = "docker"
	DeployContainer      = "container"
	DeployLinuxSystemd   = "linux-systemd"
	DeployLinux          = "linux"
	DeployWindowsService = "windows-service"
	DeployWindows        = "windows"
	DeployOther          = "other"
)

// Deployment works out how Signalith runs: goos is runtime.GOOS; docker
// is true for the Docker quick start's image, container for any other
// container; systemd for a systemd service; service for a Windows
// service.
func Deployment(goos string, docker, container, systemd, service bool) (id, label string) {
	switch {
	case docker:
		return DeployDocker, "Docker container"
	case container:
		return DeployContainer, "Container"
	case goos == "linux" && systemd:
		return DeployLinuxSystemd, "Linux, systemd service"
	case goos == "linux":
		return DeployLinux, "Linux, started by hand"
	case goos == "windows" && service:
		return DeployWindowsService, "Windows service"
	case goos == "windows":
		return DeployWindows, "Windows, started by hand"
	}
	return DeployOther, otherLabel(goos)
}

func otherLabel(goos string) string {
	switch goos {
	case "darwin":
		return "macOS"
	case "":
		return "Other"
	}
	return strings.ToUpper(goos[:1]) + goos[1:]
}

// Family is the key of Fix.Commands for a deployment: linux, windows or
// docker, or "" when none applies (macOS).
func Family(deployment string) string {
	switch {
	case deployment == DeployDocker || deployment == DeployContainer:
		return "docker"
	case strings.HasPrefix(deployment, "linux"):
		return "linux"
	case strings.HasPrefix(deployment, "windows"):
		return "windows"
	}
	return ""
}

// The Docker quick start's volume for Signalith's own files, and where
// the container has it.
const (
	dockerVolume  = "docker_signalith-data"
	dockerMount   = "/var/lib/signalith"
	dockerCompose = "docker compose -f deploy/docker/docker-compose.yml"
	winExe        = `& "$env:ProgramFiles\Signalith\signalith.exe"`
	// dockerRun runs a signalith command on the configuration in
	// deploy/docker, from that folder, as encryption.md#docker shows.
	dockerRun = `docker compose run --rm --no-deps --user 0 --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add FOWNER -v "${PWD}:/work" signalith`
)

// cmds builds Fix.Commands, leaving out empty ones.
func cmds(linux, windows, docker string) map[string]string {
	out := map[string]string{}
	if linux != "" {
		out["linux"] = linux
	}
	if windows != "" {
		out["windows"] = windows
	}
	if docker != "" {
		out["docker"] = docker
	}
	return out
}

// sh quotes s for a POSIX shell: as it is when it holds only characters
// that need no quoting, else in single quotes.
func sh(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:@%+=,", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ps quotes s for PowerShell, in single quotes, where nothing is
// expanded.
func ps(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// inVolume returns where p is in the Docker volume (mounted at /data by
// the commands), or "" when p is not in it.
func inVolume(p string) string {
	p = path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if p == dockerMount {
		return "/data"
	}
	if rest, ok := strings.CutPrefix(p, dockerMount+"/"); ok {
		return "/data/" + rest
	}
	return ""
}

// busybox runs a command over the Docker volume.
func busybox(command string) string {
	return "docker run --rm -v " + dockerVolume + ":/data busybox " + command
}

// Windows access commands: SYSTEM and Administrators get full control,
// the service its own access.
func icaclsFile(p, svc string) string {
	return "icacls " + ps(p) + ` /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" "NT SERVICE\Signalith:` + svc + `"`
}

func icaclsDir(p, svc string) string {
	return "icacls " + ps(p) + ` /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "NT SERVICE\Signalith:(OI)(CI)` + svc + `"`
}

// restartCommands restart Signalith and show what its log says about
// certificates.
func restartCommands() map[string]string {
	return cmds(
		"sudo systemctl restart signalith && journalctl -u signalith -n 50 | grep -i certificate",
		`Restart-Service Signalith; Select-String certificate C:\ProgramData\Signalith\signalith.log | Select-Object -Last 20`,
		dockerCompose+" restart signalith && "+dockerCompose+" logs --tail 50 signalith")
}

// signalithCommands run "signalith args" on each deployment, with
// suffixes for after it (such as a restart).
func signalithCommands(args string) map[string]string {
	return cmds("sudo signalith "+args, winExe+" "+args, dockerRun+" "+args+" -c /work/signalith.yaml")
}
