package hook

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestShellPath(t *testing.T) {
	for _, c := range []struct {
		name, in string
		windows  bool
		want     string
	}{
		{"plain", "/usr/local/bin/vaultmcp", false, "/usr/local/bin/vaultmcp"},
		{"a space", "/Users/jo smith/bin/vaultmcp", false, "'/Users/jo smith/bin/vaultmcp'"},
		{"a quote", "/Users/o'neil/vaultmcp", false, `'/Users/o'\''neil/vaultmcp'`},
		{"a dollar", "/opt/$HOME/vaultmcp", false, "'/opt/$HOME/vaultmcp'"},
		{"windows", `C:\Users\jo\bin\vaultmcp.exe`, true, "C:/Users/jo/bin/vaultmcp.exe"},
		{"windows, a space", `C:\Users\Jo Smith\vaultmcp.exe`, true, "'C:/Users/Jo Smith/vaultmcp.exe'"},
		// Off Windows a backslash is part of a file name. It is kept, quoted.
		{"a backslash off windows", `/opt/odd\name/vaultmcp`, false, `'/opt/odd\name/vaultmcp'`},
	} {
		if got := shellPath(c.in, c.windows); got != c.want {
			t.Errorf("%s: shellPath(%q) = %s, want %s", c.name, c.in, got, c.want)
		}
	}
}

// TestHelperProcess is not a test: it is the program the next test runs.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("VAULTMCP_TEST_HELPER") == "1" {
		os.Stdout.WriteString("ran")
		os.Exit(0)
	}
}

// The rewritten command has to run in a real shell: on Windows that is Git
// Bash, handed a path with backslashes and, here, a space.
func TestShellPathRunsInARealShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on this machine")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(t.TempDir(), "a folder", "vault mcp")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.MkdirAll(filepath.Dir(exe), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, blob, 0o700); err != nil {
		t.Fatal(err)
	}
	script := "printf %s \"$(" + shellPath(exe, runtime.GOOS == "windows") + " -test.run='^TestHelperProcess$')\""
	cmd := exec.Command(bash, "-c", script)
	cmd.Env = append(os.Environ(), "VAULTMCP_TEST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.HasPrefix(string(out), "ran") {
		t.Fatalf("the shell did not run the binary at %q: %v\n%s\nscript: %s", exe, err, out, script)
	}
}
