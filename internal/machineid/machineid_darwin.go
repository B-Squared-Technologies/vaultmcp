//go:build darwin

package machineid

import (
	"os/exec"
	"regexp"
)

// ioregPath is absolute on purpose: a PATH lookup would let a planted `ioreg`
// earlier in PATH choose the machine id, and with it the capture key.
const ioregPath = "/usr/sbin/ioreg"

var platformUUID = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// Get returns the Hardware UUID. `sysctl kern.uuid` is NOT used: it is the
// kernel build id and is identical on different Macs running the same build.
func Get() (string, error) {
	out, err := exec.Command(ioregPath, "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", err
	}
	return parsePlatformUUID(out)
}

func parsePlatformUUID(ioregOutput []byte) (string, error) {
	m := platformUUID.FindSubmatch(ioregOutput)
	if m == nil {
		return "", ErrUnavailable
	}
	return string(m[1]), nil
}
