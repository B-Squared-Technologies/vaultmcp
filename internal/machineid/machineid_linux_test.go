//go:build linux

package machineid

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFirstIDOrderAndFallback(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	empty := filepath.Join(dir, "empty")
	first := filepath.Join(dir, "first")
	second := filepath.Join(dir, "second")
	for path, content := range map[string]string{empty: "\n", first: "id-one\n", second: "id-two\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cases := []struct {
		name  string
		files []string
		want  string
	}{
		{"first file wins", []string{first, second}, "id-one"},
		{"missing file falls through", []string{missing, second}, "id-two"},
		{"empty file falls through", []string{empty, second}, "id-two"},
	}
	for _, c := range cases {
		got, err := firstID(c.files)
		if err != nil || got != c.want {
			t.Errorf("%s: firstID = %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	if _, err := firstID([]string{missing, empty}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no usable file must be ErrUnavailable, got %v", err)
	}
}
