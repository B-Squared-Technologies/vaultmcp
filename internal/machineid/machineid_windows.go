//go:build windows

package machineid

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Get returns MachineGuid, which Windows generates once at install time.
func Get() (string, error) {
	// WOW64_64KEY: a 32-bit build must read the real key, not the redirected
	// 32-bit view, where this value does not exist.
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return "", err
	}
	defer k.Close()
	id, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return "", err
	}
	if id = strings.TrimSpace(id); id == "" {
		return "", ErrUnavailable
	}
	return id, nil
}
