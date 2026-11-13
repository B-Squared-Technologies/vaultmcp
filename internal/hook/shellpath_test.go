package hook

import (
	"encoding/json"
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
		{"a space", "/Users/jo smith/bin/vaultmcp", false, `/Users/jo\ smith/bin/vaultmcp`},
		{"an apostrophe", "/Users/o'neil/vaultmcp", false, `/Users/o\'neil/vaultmcp`},
		{"a double quote", `/Users/o"neil/vaultmcp`, false, `/Users/o\"neil/vaultmcp`},
		{"a dollar", "/opt/$HOME/vaultmcp", false, `/opt/\$HOME/vaultmcp`},
		{"an ampersand", "/opt/R&D/vaultmcp", false, `/opt/R\&D/vaultmcp`},
		{"not ASCII", "/Users/zoë/vaultmcp", false, "/Users/zoë/vaultmcp"},
		// Plain in the middle of a word, and PowerShell has no backslash
		// escape: a Windows short name (RUNNER~1) has to stay as it is.
		{"a short name and friends", "C:/Users/RUNNER~1/a+b=c@d%e/vaultmcp.exe", true, "C:/Users/RUNNER~1/a+b=c@d%e/vaultmcp.exe"},
		{"a newline", "/opt/a\nb/vaultmcp", false, "/opt/a\"\n\"b/vaultmcp"},
		{"windows", `C:\Users\jo\bin\vaultmcp.exe`, true, "C:/Users/jo/bin/vaultmcp.exe"},
		{"windows, a space", `C:\Users\Jo Smith\vaultmcp.exe`, true, `C:/Users/Jo\ Smith/vaultmcp.exe`},
		// Off Windows a backslash is part of a file name, so it is escaped.
		{"a backslash off windows", `/opt/odd\name/vaultmcp`, false, `/opt/odd\\name/vaultmcp`},
	} {
		if got := shellPath(c.in, c.windows); got != c.want {
			t.Errorf("%s: shellPath(%q) = %s, want %s", c.name, c.in, got, c.want)
		}
	}
}

// The substitution is written into tool input that is still JSON text. With a
// path that needs escaping, a rewrite that is not valid JSON is thrown away
// and the secret goes through unhidden, with nothing to show for it. Every
// path here has to come back as a rewrite, and decode to the exact command.
func TestSubstitutionWithAnAwkwardBinaryPathStaysValidJSON(t *testing.T) {
	for _, exe := range []string{
		"/Users/jo smith/bin/vaultmcp",
		"/Users/o'neil/bin/vaultmcp",
		`/Users/o"neil/bin/vaultmcp`,
		`/opt/odd\name/vaultmcp`,
		`/opt/odd\qame/vaultmcp`,
		"/opt/R&D <x>/vaultmcp",
		"/opt/two\nlines/vaultmcp",
	} {
		d := testDeps(t)
		d.ExePath = exe
		out := runPre(t, d, "Bash", `{"command":"aws configure set key `+awsKey+`"}`)
		if out == "" {
			t.Errorf("%s: the hook gave no rewrite, so the secret went through", exe)
			continue
		}
		if strings.Contains(out, awsKey) {
			t.Errorf("%s: the secret is still in the answer: %s", exe, out)
		}
		var got struct {
			HookSpecificOutput struct {
				UpdatedInput struct {
					Command string `json:"command"`
				} `json:"updatedInput"`
			} `json:"hookSpecificOutput"`
		}
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Errorf("%s: the answer is not JSON: %v\n%s", exe, err, out)
			continue
		}
		want := "aws configure set key $(" + shellPath(exe, runtime.GOOS == "windows") + " get " + awsAlias(d) + ")"
		if got.HookSpecificOutput.UpdatedInput.Command != want {
			t.Errorf("%s: command = %s\nwant      %s", exe, got.HookSpecificOutput.UpdatedInput.Command, want)
		}
	}
}

// TestHelperProcess is not a test: it is the program the next test runs.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("VAULTMCP_TEST_HELPER") == "1" {
		_, _ = os.Stdout.WriteString("ran")
		os.Exit(0)
	}
}

// realBash finds the shell the rewritten command runs in. On Windows that is
// Git Bash, not the WSL launcher that can sit earlier on PATH. With no bash
// the test is skipped, except on a CI runner: all three have one, and a skip
// there would let the test go quiet without anyone noticing.
func realBash(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files\Git\bin\bash.exe`, `C:\Program Files\Git\usr\bin\bash.exe`} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	} else if p, err := exec.LookPath("bash"); err == nil {
		return p
	}
	if os.Getenv("CI") != "" {
		t.Fatal("no bash on a CI runner: this test must not be skipped there")
	}
	t.Skip("no bash on this machine")
	return ""
}

// copySelf puts a copy of this test binary at dir/name and returns its path.
func copySelf(t *testing.T, dir, name string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, name)
	// #nosec G306 -- a program the test runs.
	if err := os.WriteFile(exe, blob, 0o700); err != nil {
		t.Fatal(err)
	}
	return exe
}

// The rewritten command has to run in a real shell: on Windows that is Git
// Bash, handed a path with backslashes. The path here also has a space, an
// apostrophe and an ampersand in it.
func TestShellPathRunsInARealShell(t *testing.T) {
	bash := realBash(t)
	windows := runtime.GOOS == "windows"
	run := func(script string) string {
		t.Helper()
		cmd := exec.Command(bash, "-c", script)
		cmd.Env = append(os.Environ(), "VAULTMCP_TEST_HELPER=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("the shell failed: %v\n%s\nscript: %s", err, out, script)
		}
		return string(out)
	}

	exe := copySelf(t, filepath.Join(t.TempDir(), "jo's R&D folder"), "vault mcp")
	sub := "$(" + shellPath(exe, windows) + " -test.run=TestHelperProcess)"
	if out := run("printf %s " + sub); out != "ran" {
		t.Errorf("on its own: got %q from %s", out, sub)
	}
	if out := run(`printf %s "token ` + sub + `"`); out != "token ran" {
		t.Errorf("inside double quotes: got %q from %s", out, sub)
	}

	// Inside single quotes the shell runs nothing, and the text has to stay
	// the one word the command meant it to be. (An apostrophe in the path
	// itself ends such a string whatever is done, so this path has none.)
	exe = copySelf(t, filepath.Join(t.TempDir(), "a R&D folder~1+b=c@d%e"), "vault mcp")
	sub = "$(" + shellPath(exe, windows) + " -test.run=TestHelperProcess)"
	if out := run("set -- 'token " + sub + "'; printf %s $#"); out != "1" {
		t.Errorf("inside single quotes: the text became %s words: %s", out, sub)
	}

	// A newline in the path. Windows has no such file names.
	if !windows {
		exe = copySelf(t, filepath.Join(t.TempDir(), "two\nlines"), "vaultmcp")
		sub = "$(" + shellPath(exe, false) + " -test.run=TestHelperProcess)"
		if out := run(`printf %s "token ` + sub + `"`); out != "token ran" {
			t.Errorf("a newline in the path: got %q from %q", out, sub)
		}
	}
}

// PowerShell is the other shell an agent on Windows may hand a command to.
// A plain path works there. A path with a space does not: PowerShell has no
// backslash escape, the command fails, and the secret is not put in. That is
// a known limit in the changelog, and this test says when it stops being true.
func TestSubstitutionInPowerShell(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("PowerShell is the Windows case")
	}
	ps, err := exec.LookPath("pwsh")
	if err != nil {
		ps, err = exec.LookPath("powershell")
	}
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatal("no PowerShell on a Windows CI runner: this test must not be skipped there")
		}
		t.Skip("no PowerShell on this machine")
	}
	// The temp folder can come in its short form (RUNNER~1), which is not a
	// plain path. The long form is.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	run := func(exe string) string {
		t.Helper()
		// The argument is in single quotes only because PowerShell would
		// split this test flag at its dot. "get NAME" has no such trouble.
		sub := "$(" + shellPath(exe, true) + " '-test.run=TestHelperProcess')"
		cmd := exec.Command(ps, "-NoProfile", "-NonInteractive", "-Command", "Write-Output "+sub)
		cmd.Env = append(os.Environ(), "VAULTMCP_TEST_HELPER=1")
		out, _ := cmd.CombinedOutput()
		return strings.TrimSpace(string(out))
	}

	// The plain case needs a temp folder with nothing to escape in its path.
	// A user name with a space rules that out on some machines. Not on CI.
	plain := copySelf(t, filepath.Join(dir, "plain"), "vaultmcp")
	if p := shellPath(plain, true); strings.Contains(p, `\`) {
		if os.Getenv("CI") != "" {
			t.Fatalf("the CI temp folder is no longer a plain path: %s", p)
		}
		t.Logf("skipping the plain-path case: the temp folder needs escaping: %s", p)
	} else if got := run(plain); got != "ran" {
		t.Errorf("a plain path in PowerShell: got %q", got)
	}
	spaced := copySelf(t, filepath.Join(dir, "jo smith"), "vaultmcp")
	if got := run(spaced); got == "ran" {
		t.Error("a path with a space now works in PowerShell: take the known limit out of the changelog")
	}
}
