package main

import (
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// platformServiceSettings reads the Signalith service's command line and
// environment from the registry (HKLM\SYSTEM\CurrentControlSet\Services\
// Signalith: ImagePath, and Environment, a list of NAME=value set with
// Set-ItemProperty as docs/encryption.md shows).
func platformServiceSettings() *serviceSettings {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+serviceName, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	image, _, err := k.GetStringValue("ImagePath")
	if err != nil {
		return nil
	}
	argv, err := windows.DecomposeCommandLine(image)
	if err != nil || len(argv) == 0 {
		return nil
	}
	s := &serviceSettings{where: `the Signalith service's settings in the registry`, args: argv[1:], env: map[string]string{}}
	if list, _, err := k.GetStringsValue("Environment"); err == nil {
		for _, kv := range list {
			if name, v, ok := strings.Cut(kv, "="); ok && name != "" {
				s.env[name] = v
			}
		}
	}
	return s
}

// serviceStartedAfter is for systemd credentials, which Windows does not
// have.
func serviceStartedAfter(time.Time) (bool, error) { return true, nil }
