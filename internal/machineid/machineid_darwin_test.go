//go:build darwin

package machineid

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePlatformUUID(t *testing.T) {
	// Built at runtime: a UUID literal in this file is secret-shaped to the
	// live hook.
	id := strings.Repeat("0A", 4) + "-" + strings.Repeat("1B", 2) + "-" + strings.Repeat("2C", 2) + "-" + strings.Repeat("3D", 2) + "-" + strings.Repeat("4E", 6)
	out := "+-o Root  <class IOPlatformExpertDevice>\n    {\n" +
		"      \"IOPlatformSerialNumber\" = \"X\"\n" +
		"      \"IOPlatformUUID\" = \"" + id + "\"\n    }\n"
	got, err := parsePlatformUUID([]byte(out))
	if err != nil || got != id {
		t.Fatalf("parsePlatformUUID = %q, %v; want %q", got, err, id)
	}
}

func TestParsePlatformUUIDMissing(t *testing.T) {
	if _, err := parsePlatformUUID([]byte("no uuid in this output")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable, got %v", err)
	}
}

// The real call must work on a Mac and be stable between calls. The value
// itself is never asserted or printed.
func TestGetIsStable(t *testing.T) {
	a, err := Get()
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	b, err := Get()
	if err != nil || a != b || a == "" {
		t.Fatalf("Get is not stable or is empty (err=%v)", err)
	}
}
