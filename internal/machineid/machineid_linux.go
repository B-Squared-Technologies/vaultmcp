//go:build linux

package machineid

import (
	"os"
	"strings"
)

// idFiles are tried in order. systemd writes the first; the second is the
// older D-Bus location still found on systems without systemd.
var idFiles = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// Get returns the machine id systemd or D-Bus generated at install time.
func Get() (string, error) {
	return firstID(idFiles)
}

func firstID(files []string) (string, error) {
	for _, f := range files {
		// #nosec G304 -- f is one of the fixed system paths above, not user input.
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if id := strings.TrimSpace(string(data)); id != "" {
			return id, nil
		}
	}
	return "", ErrUnavailable
}
