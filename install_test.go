package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteClaudeStyleHooksRegistersPreOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := writeClaudeStyleHooks(path, "/bin/vaultmcp hook"); err != nil {
		t.Fatal(err)
	}
	hooks := readHooks(t, path)
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatalf("PreToolUse missing: %v", hooks)
	}
	if _, ok := hooks["PostToolUse"]; ok {
		t.Fatalf("Codex must not register PostToolUse: %v", hooks)
	}
}

func TestWriteClaudeStyleHooksRemovesLeftoverPostToolUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	seed := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []any{
				map[string]any{
					"matcher": ".*",
					"hooks": []any{
						map[string]any{"type": "command", "command": "/bin/vaultmcp hook"},
					},
				},
			},
			"PreToolUse": []any{
				map[string]any{
					"matcher": ".*",
					"hooks": []any{
						map[string]any{"type": "command", "command": "other-hook"},
					},
				},
			},
		},
	}
	raw, err := json.Marshal(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeClaudeStyleHooks(path, "/bin/vaultmcp hook"); err != nil {
		t.Fatal(err)
	}
	hooks := readHooks(t, path)
	if _, ok := hooks["PostToolUse"]; ok {
		t.Fatalf("leftover vaultmcp PostToolUse not removed: %v", hooks)
	}
	pre, _ := hooks["PreToolUse"].([]any)
	if len(pre) != 2 {
		t.Fatalf("expected existing PreToolUse kept plus vaultmcp, got %d: %v", len(pre), pre)
	}
}

func TestWriteClaudeStyleHooksRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	orig := []byte("{not json")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeClaudeStyleHooks(path, "/bin/vaultmcp hook"); err == nil {
		t.Fatal("expected parse error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("overwrote malformed file: %s", got)
	}
}

func TestWriteClaudeStyleHooksEmptyFileOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := os.WriteFile(path, []byte("  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeClaudeStyleHooks(path, "/bin/vaultmcp hook"); err != nil {
		t.Fatal(err)
	}
	hooks := readHooks(t, path)
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatalf("PreToolUse missing after empty file: %v", hooks)
	}
}

func TestWriteCursorHooksNestsUnderHooks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	if err := writeCursorHooks(path, "/bin/vaultmcp hook"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["preToolUse"]; ok {
		t.Fatalf("preToolUse must be under hooks, not root: %s", raw)
	}
	hooks, _ := got["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatalf("missing hooks container: %s", raw)
	}
	for _, ev := range []string{"preToolUse", "postToolUse", "beforeShellExecution", "afterShellExecution"} {
		if _, ok := hooks[ev]; !ok {
			t.Fatalf("missing %s: %s", ev, raw)
		}
	}
}

func TestWriteCursorHooksRejectsMalformedJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	orig := []byte("[1, 2, 3]")
	if err := os.WriteFile(path, orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeCursorHooks(path, "/bin/vaultmcp hook"); err == nil {
		t.Fatal("expected parse error")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("overwrote malformed file: %s", got)
	}
}

func TestCmdInstallFailsOnMalformedSettings(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(".claude", 0o750); err != nil {
		t.Fatal(err)
	}
	orig := []byte("{not json")
	if err := os.WriteFile(filepath.Join(".claude", "settings.json"), orig, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdInstall(nil); err == nil {
		t.Fatal("expected parse error")
	}
	got, err := os.ReadFile(filepath.Join(".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, orig) {
		t.Fatalf("overwrote malformed settings: %s", got)
	}
}

func TestCmdInstallRegistersClaudePreAndPost(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := cmdInstall(nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"PreToolUse"`) || !strings.Contains(string(raw), `"PostToolUse"`) {
		t.Fatalf("Claude install must register Pre and Post: %s", raw)
	}
}

func readHooks(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse %s: %v\n%s", path, err, raw)
	}
	hooks, _ := got["hooks"].(map[string]any)
	if hooks == nil {
		t.Fatalf("missing hooks in %s: %s", path, raw)
	}
	return hooks
}

// A matcher entry can group vaultmcp with a command that is not ours. Taking
// vaultmcp out must leave the other command, and its matcher, where they are.
func TestRemoveVaultHookKeepsOtherCommandsInTheSameEntry(t *testing.T) {
	other := map[string]any{"type": "command", "command": "/usr/local/bin/lint-hook"}
	ours := map[string]any{"type": "command", "command": "/bin/vaultmcp hook"}
	hooks := map[string]any{"PostToolUse": []any{
		map[string]any{"matcher": "Bash", "hooks": []any{other, ours}},
		map[string]any{"matcher": ".*", "hooks": []any{ours}},
		map[string]any{"matcher": "Write", "hooks": []any{other}},
	}}
	if !removeVaultHook(hooks, "PostToolUse", "") {
		t.Fatal("nothing was removed")
	}
	list, _ := hooks["PostToolUse"].([]any)
	if len(list) != 2 {
		t.Fatalf("want the grouped entry and the unrelated entry, got %d: %v", len(list), list)
	}
	first, _ := list[0].(map[string]any)
	inner, _ := first["hooks"].([]any)
	if first["matcher"] != "Bash" || len(inner) != 1 {
		t.Fatalf("the grouped entry lost its other command or its matcher: %v", first)
	}
	if cmd, _ := inner[0].(map[string]any)["command"].(string); cmd != "/usr/local/bin/lint-hook" {
		t.Fatalf("the wrong command was kept: %v", inner)
	}
	if removeVaultHook(hooks, "PostToolUse", "") {
		t.Fatal("a second run reported a removal")
	}
}

// The same through the Codex writer, which removes a leftover PostToolUse hook.
func TestCodexInstallKeepsAnotherHookGroupedWithOurs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	body := `{"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/usr/local/bin/lint-hook"},{"type":"command","command":"/bin/vaultmcp hook"}]}]}}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeClaudeStyleHooks(path, "/bin/vaultmcp hook"); err != nil {
		t.Fatal(err)
	}
	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Hooks map[string]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	post := string(got.Hooks["PostToolUse"])
	if !strings.Contains(post, "/usr/local/bin/lint-hook") || !strings.Contains(post, `"Bash"`) || strings.Contains(post, "vaultmcp") {
		t.Fatalf("PostToolUse after install: %s", post)
	}
	if !strings.Contains(string(got.Hooks["PreToolUse"]), "/bin/vaultmcp hook") {
		t.Fatalf("PreToolUse was not registered: %s", out)
	}
}

func TestIsVaultHook(t *testing.T) {
	for cmd, want := range map[string]bool{
		"/usr/local/bin/vaultmcp hook":      true,
		"C:/Users/jo/bin/vaultmcp.exe hook": true,
		// Without quotes a shell runs "C:/Users/Jo", so this is not a working
		// hook of ours. install now writes the quoted form below.
		"C:/Users/Jo Smith/bin/vaultmcp.exe hook":   false,
		`"C:/Users/Jo Smith/bin/vaultmcp.exe" hook`: true,
		// Somebody else's hooks that only have the words in them.
		"make -C /Users/me/src/vaultmcp hook":      false,
		"git -C /repos/vaultmcp hook":              false,
		"lint > /tmp/vaultmcp-hook":                false,
		"lint >> /tmp/vaultmcp-hook":               false,
		"> /tmp/vaultmcp-hook lint":                false,
		">/tmp/h.log /usr/local/bin/vaultmcp hook": true,
		"tee -a /var/log/vaultmcp-hook":            false,
		"printf '%s' /bin/vaultmcp hook":           false,
		// Ours, handed to a shell or kept in a script.
		"zsh -lic '/usr/local/bin/vaultmcp hook'":          true,
		`bash -lc "/usr/local/bin/vaultmcp hook"`:          true,
		`cmd /c "C:\tools\vaultmcp.exe hook"`:              true,
		"bash /Users/jo/.claude/hooks/vaultmcp-hook.sh":    true,
		"C:/tools/vaultmcp-hook.cmd":                       true,
		"pwsh -File C:/tools/vaultmcp-hook.ps1":            true,
		"C:/Tools/VAULTMCP.EXE hook":                       true,
		"C:/tools/vaultmcp-hook.exe":                       true,
		"env VAULTMCP_DIR=/x /usr/local/bin/vaultmcp hook": true,
		"true && /usr/local/bin/vaultmcp hook":             true,
		// A script is one word, judged by its name. What follows it is its own.
		"bash /opt/audit.sh /tmp/vaultmcp-hook":                         false,
		`bash "/Users/Jo Smith/.claude/hooks/vaultmcp-hook.sh"`:         true,
		"pwsh -ExecutionPolicy Bypass -File C:/tools/vaultmcp-hook.ps1": true,
		`cmd /c C:\tools\vaultmcp.exe hook`:                             true,
		"bash -c 'true' vaultmcp-hook":                                  false,
		// Empty words, which a shell allows.
		"bash -c ''":                                     false,
		`cmd /c start "" C:/x.exe`:                       false,
		`sh ""`:                                          false,
		"bash -c 'make -C /src/vaultmcp hook'":           false,
		"'/Users/jo smith/bin/vaultmcp' hook":            true,
		"VAULTMCP_DIR=/x/y /usr/local/bin/vaultmcp hook": true,
		"/usr/local/bin/vaultmcp hook 2>>/tmp/hook.log":  true,
		"/usr/local/bin/vaultmcp hook>>/tmp/hook.log":    true,
		"/usr/local/bin/vaultmcp hook; true":             true,
		"/Users/jo/.local/bin/vaultmcp-hook>>/tmp/h.log": true,
		"/usr/local/bin/vaultmcp hooks":                  false,
		"'/opt/R&D/vaultmcp' hook":                       true,
		`/opt/R\&D/vaultmcp hook`:                        true,
		"'/opt/R&D dir/vaultmcp' hook":                   true,
		"'/opt/a b/R&D/vaultmcp' hook":                   true,
		`"/opt/a b/R&D/vaultmcp" hook`:                   true,
		`/opt/R\&D\ dir/vaultmcp hook`:                   true,
		`C:\Users\jo\bin\vaultmcp.exe hook`:              true,
		`"C:\Users\Jo Smith\vaultmcp.exe" hook`:          true,
		`"/opt/vaultmcp-hook scripts/audit.sh"`:          false,
		"'/usr/local/bin/vaultmcp hook'":                 false,
		"/usr/local/bin/vaultmcp; hook":                  false,
		"/usr/local/bin/vaultmcp-darwin-arm64 hook":      true,
		"C:/tools/vaultmcp-windows-amd64.exe hook":       true,
		"/usr/local/bin/vaultmcp-darwin-arm64 status":    false,
		"/usr/local/bin/myvaultmcp hook":                 false,
		"/Users/jo/.local/bin/vaultmcp-hook":             true,
		"/Users/me/gitrepos/vaultmcp/scripts/lint.sh":    false,
		"python3 ~/.claude/hooks/vaultmcp-audit.py":      false,
		"node ~/work/vaultmcp-tools/check.js":            false,
		"cd vaultmcp && make hook":                       false,
		"/usr/local/bin/vaultmcp status":                 false,
		"/usr/local/bin/lint-hook":                       false,
		"":                                               false,
	} {
		if got := isVaultHook(cmd); got != want {
			t.Errorf("isVaultHook(%q) = %v, want %v", cmd, got, want)
		}
	}
}

// Somebody else's hook can live in a folder named vaultmcp. Install must not
// take it for its own: it registers next to it, removes nothing of it, and a
// second run changes nothing.
func TestInstallLeavesAHookThatOnlyHasVaultmcpInItsPath(t *testing.T) {
	const theirs = "/Users/me/gitrepos/vaultmcp/scripts/lint.sh"
	const ours = "/bin/vaultmcp hook"
	entry := func(cmd string) map[string]any {
		return map[string]any{"matcher": "Bash", "hooks": []any{map[string]any{"type": "command", "command": cmd}}}
	}
	commands := func(list any) []string {
		var out []string
		for _, e := range list.([]any) {
			for _, h := range e.(map[string]any)["hooks"].([]any) {
				out = append(out, h.(map[string]any)["command"].(string))
			}
		}
		return out
	}

	hooks := map[string]any{"PreToolUse": []any{entry(theirs)}, "PostToolUse": []any{entry(theirs)}}
	if !ensureHook(hooks, "PreToolUse", ours) {
		t.Fatal("install took their hook for its own and did not register")
	}
	if got := commands(hooks["PreToolUse"]); len(got) != 2 || got[0] != theirs || got[1] != ours {
		t.Fatalf("PreToolUse commands = %q", got)
	}
	if ensureHook(hooks, "PreToolUse", ours) {
		t.Fatal("a second run registered again")
	}
	if removeVaultHook(hooks, "PostToolUse", "") {
		t.Fatal("their hook was removed as if it were ours")
	}
	if got := commands(hooks["PostToolUse"]); len(got) != 1 || got[0] != theirs {
		t.Fatalf("PostToolUse commands = %q", got)
	}

	cursor := map[string]any{"preToolUse": []any{map[string]any{"command": "node ~/work/vaultmcp-tools/check.js"}}}
	if !ensureCursorHook(cursor, "preToolUse", ours) {
		t.Fatal("Cursor: install took their hook for its own and did not register")
	}
	if list := cursor["preToolUse"].([]any); len(list) != 2 {
		t.Fatalf("Cursor entries = %v", list)
	}
}

// A person can dress our command up, with a vault folder in front or a log
// behind. It is still ours: install must not add a second one beside it.
func TestInstallKnowsItsOwnHookWithWordsAroundIt(t *testing.T) {
	for _, cmd := range []string{
		"VAULTMCP_DIR=/x/y /usr/local/bin/vaultmcp hook",
		"/usr/local/bin/vaultmcp hook 2>>/tmp/hook.log",
	} {
		hooks := map[string]any{"PreToolUse": []any{
			map[string]any{"matcher": ".*", "hooks": []any{map[string]any{"type": "command", "command": cmd}}},
		}}
		if ensureHook(hooks, "PreToolUse", "/bin/vaultmcp hook") {
			t.Errorf("%s: a second vaultmcp hook was registered", cmd)
		}
		if got := hooks["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)["command"]; got != cmd {
			t.Errorf("%s: the command was changed to %v", cmd, got)
		}
	}
}

func TestShellWords(t *testing.T) {
	for cmd, want := range map[string][]string{
		"/bin/vaultmcp hook":                 {"/bin/vaultmcp", "hook"},
		"  /bin/vaultmcp \t hook  ":          {"/bin/vaultmcp", "hook"},
		"'/a b/vaultmcp' hook":               {"/a b/vaultmcp", "hook"},
		`"/a \"b\"/vaultmcp" hook`:           {`/a "b"/vaultmcp`, "hook"},
		`/a\ b/vaultmcp hook`:                {"/a b/vaultmcp", "hook"},
		`C:\Users\jo\vaultmcp.exe hook`:      {`C:\Users\jo\vaultmcp.exe`, "hook"},
		"/bin/vaultmcp hook>>/tmp/log":       {"/bin/vaultmcp", "hook", ">", ">", "/tmp/log"},
		"X=1 /bin/vaultmcp hook 2>/dev/null": {"X=1", "/bin/vaultmcp", "hook", "2", ">", "/dev/null"},
		"a && b":                             {"a", "&", "&", "b"},
		"'' x":                               {"", "x"},
		"'never closed":                      {"never closed"},
		"":                                   nil,
	} {
		got := shellWords(cmd)
		if len(got) != len(want) {
			t.Errorf("shellWords(%q) = %q, want %q", cmd, got, want)
			continue
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("shellWords(%q) = %q, want %q", cmd, got, want)
				break
			}
		}
	}
}

// A binary somebody renamed to something else entirely is still the one
// running install. Its own command, already registered, is not added twice.
func TestInstallIsIdempotentForARenamedBinary(t *testing.T) {
	const command = "/usr/local/bin/vm hook"
	hooks := map[string]any{}
	if !ensureHook(hooks, "PreToolUse", command) {
		t.Fatal("first run did not register")
	}
	if ensureHook(hooks, "PreToolUse", command) {
		t.Fatal("second run registered the same command again")
	}
	if list := hooks["PreToolUse"].([]any); len(list) != 1 {
		t.Fatalf("entries = %v", list)
	}
	cursor := map[string]any{}
	if !ensureCursorHook(cursor, "preToolUse", command) || ensureCursorHook(cursor, "preToolUse", command) {
		t.Fatal("Cursor: not registered exactly once")
	}
}

func TestHookCommand(t *testing.T) {
	for exe, want := range map[string]string{
		"/usr/local/bin/vaultmcp":            "/usr/local/bin/vaultmcp hook",
		"C:/Users/jo/bin/vaultmcp.exe":       "C:/Users/jo/bin/vaultmcp.exe hook",
		"C:/Users/Jo Smith/bin/vaultmcp.exe": `"C:/Users/Jo Smith/bin/vaultmcp.exe" hook`,
		"/opt/R&D/vaultmcp":                  `"/opt/R&D/vaultmcp" hook`,
		"/Users/o'neil/bin/vaultmcp":         `"/Users/o'neil/bin/vaultmcp" hook`,
		"/opt/a$b/c`d/e\"f/g\\h/vaultmcp":    "\"/opt/a\\$b/c\\`d/e\\\"f/g\\\\h/vaultmcp\" hook",
	} {
		got := hookCommand(exe)
		if got != want {
			t.Errorf("hookCommand(%q) = %s, want %s", exe, got, want)
		}
		if !isVaultHook(got) {
			t.Errorf("install would not know its own command: %s", got)
		}
	}
}

// TestInstallHelperProcess is not a test: it is the program the next test runs.
func TestInstallHelperProcess(t *testing.T) {
	if os.Getenv("VAULTMCP_TEST_HELPER") == "1" {
		_, _ = os.Stdout.WriteString("ran")
		os.Exit(0)
	}
}

// The registered command has to run in a real shell when the binary sits
// under a path with a space, an apostrophe, a dollar and an ampersand in it.
// Tools hand the command to sh, or to Git Bash on Windows.
func TestHookProgramRunsInARealShell(t *testing.T) {
	shell := ""
	if runtime.GOOS == "windows" {
		for _, p := range []string{`C:\Program Files\Git\bin\bash.exe`, `C:\Program Files\Git\usr\bin\bash.exe`} {
			if _, err := os.Stat(p); err == nil {
				shell = p
				break
			}
		}
	} else if p, err := exec.LookPath("sh"); err == nil {
		shell = p
	}
	if shell == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("no shell on a CI runner: this test must not be skipped there")
		}
		t.Skip("no shell on this machine")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "jo smith's $HOME R&D")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "vault mcp"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	exe := filepath.Join(dir, name)
	// #nosec G306 -- a program the test runs.
	if err := os.WriteFile(exe, blob, 0o700); err != nil {
		t.Fatal(err)
	}
	script := hookProgram(filepath.ToSlash(exe)) + " -test.run=TestInstallHelperProcess"
	cmd := exec.Command(shell, "-c", script)
	cmd.Env = append(os.Environ(), "VAULTMCP_TEST_HELPER=1")
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "ran" {
		t.Fatalf("the shell did not run the binary: %v\n%s\nscript: %s", err, out, script)
	}
}

// install's own command for a path with an apostrophe, as an earlier version
// wrote it (no quotes), does not split into words. Cleaning up still knows it,
// because it is the exact text this binary registers.
func TestRemoveVaultHookKnowsTheExactCommand(t *testing.T) {
	const command = "/Users/o'neil/bin/vaultmcp hook"
	if isVaultHook(command) {
		t.Skip("the word splitter now reads this command: the exact match is no longer what saves it")
	}
	hooks := map[string]any{"PostToolUse": []any{map[string]any{
		"matcher": ".*",
		"hooks":   []any{map[string]any{"type": "command", "command": command}},
	}}}
	if !removeVaultHook(hooks, "PostToolUse", command) {
		t.Fatal("the leftover entry was not removed")
	}
	if _, ok := hooks["PostToolUse"]; ok {
		t.Fatalf("still there: %v", hooks)
	}
}

// The commands read here were written by other tools and by people. None of
// them may crash install.
func FuzzIsVaultHook(f *testing.F) {
	for _, seed := range []string{
		"", "bash -c ''", `cmd /c start "" C:/x.exe`, `sh ""`, "'", `"`, `\`, "a ; | & < >",
		"/usr/local/bin/vaultmcp hook", "zsh -lic '/usr/local/bin/vaultmcp hook'", `"C:/Users/Jo Smith/vaultmcp.exe" hook`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		_ = isVaultHook(cmd)
	})
}

// Whatever folder the binary is in, install knows the command it wrote. The
// path is absolute, as os.Executable gives it: a relative one could begin
// with NAME=, which a shell reads as a variable being set.
func FuzzHookCommandIsKnown(f *testing.F) {
	for _, seed := range []string{"usr/local/bin", "Users/Jo Smith/bin", "opt/R&D", "Users/o'neil", "opt/a$b/c`d/e\"f/g\\h", "two\nlines", "tmp/x y;z|w<v>u", "A="} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, dir string) {
		cmd := hookCommand("/" + dir + "/vaultmcp")
		if !isVaultHook(cmd) {
			t.Errorf("install would not know its own command: %q", cmd)
		}
	})
}
