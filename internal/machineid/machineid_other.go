//go:build !darwin && !linux && !windows

package machineid

// Get has no source for a machine id on this platform.
func Get() (string, error) {
	return "", ErrUnavailable
}
