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

	"github.com/B-Squared-Technologies/vaultmcp/internal/hook"
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
	if !removeVaultHook(hooks, "PostToolUse") {
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
	if removeVaultHook(hooks, "PostToolUse") {
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

// noZsh stands in, for one test, for a machine that has no zsh.
func noZsh(t *testing.T) {
	t.Helper()
	old := zshPath
	zshPath = filepath.Join(t.TempDir(), "no-zsh-here")
	t.Cleanup(func() { zshPath = old })
}

// fakeBinary writes a stand-in for the vaultmcp binary that reports what it
// was started with: the value of MARK, its first argument, then its stdin.
func fakeBinary(t *testing.T, dir string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(dir, "vaultmcp")
	// #nosec G306 -- a script the test runs.
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nprintf '%s|%s|' \"$MARK\" \"$1\"\ncat\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return exe
}

// The wrapper is the whole point of the install on a Mac: run the way an app
// from the Dock runs it, with no shell settings loaded, it has to pick up what
// ~/.zshenv exports and hand the tool call through byte for byte.
func TestTheWrapperLoadsZshenvAndPassesTheCallThrough(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no wrapper on Windows")
	}
	if _, err := os.Stat(zshPath); err != nil {
		t.Skip("no zsh on this machine")
	}
	// A space, a quote and a dollar sign: the script and the registered
	// command both have to carry the path through all three.
	exe := fakeBinary(t, filepath.Join(t.TempDir(), "jo's $HOME bin"))
	home := t.TempDir()
	// This ~/.zshenv prints on both streams and reads stdin, which a real one
	// can do. None of it may reach the hook's input or output.
	zshenv := "echo noise\necho more noise >&2\ncat >/dev/null\nexport MARK=from-zshenv\n"
	if err := os.WriteFile(filepath.Join(home, ".zshenv"), []byte(zshenv), 0o600); err != nil {
		t.Fatal(err)
	}

	command := hookCommand(exe)
	wrapper := filepath.Join(filepath.Dir(exe), "vaultmcp-hook")
	if command != hook.ShellPath(wrapper, false) {
		t.Fatalf("registered command = %s, want the wrapper at %s", command, wrapper)
	}
	info, err := os.Stat(wrapper)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("wrapper mode = %v, want executable by the owner only", info.Mode().Perm())
	}

	// The agent tools hand the registered command to a shell.
	run := exec.Command("/bin/sh", "-c", command)
	run.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
	run.Stdin = strings.NewReader(`{"tool_name":"Bash"}`)
	var stderr bytes.Buffer
	run.Stderr = &stderr
	out, err := run.Output()
	if err != nil {
		t.Fatalf("wrapper failed: %v\n%s", err, stderr.String())
	}
	if want := `from-zshenv|hook|{"tool_name":"Bash"}`; string(out) != want {
		t.Fatalf("wrapper output = %q, want %q", out, want)
	}
	if stderr.Len() != 0 {
		t.Fatalf("wrapper wrote to stderr: %q", stderr.String())
	}
}

// No ~/.zshenv is the normal case for someone in keychain mode.
func TestTheWrapperRunsWithoutAZshenv(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no wrapper on Windows")
	}
	if _, err := os.Stat(zshPath); err != nil {
		t.Skip("no zsh on this machine")
	}
	exe := fakeBinary(t, t.TempDir())
	run := exec.Command("/bin/sh", "-c", hookCommand(exe))
	run.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
	run.Stdin = strings.NewReader("in")
	out, err := run.CombinedOutput()
	if err != nil || string(out) != "|hook|in" {
		t.Fatalf("wrapper output = %q, err %v", out, err)
	}
}

// Install must keep working where it works today: no zsh means the binary is
// registered directly and no script is written.
func TestHookCommandWithoutZshRegistersTheBinary(t *testing.T) {
	noZsh(t)
	dir := t.TempDir()
	command := hookCommand(filepath.Join(dir, "vaultmcp"))
	if !strings.HasSuffix(command, "vaultmcp hook") {
		t.Fatalf("command = %s, want the binary run directly", command)
	}
	if _, err := os.Stat(filepath.Join(dir, "vaultmcp-hook")); err == nil {
		t.Fatal("a wrapper was written on a machine with no zsh")
	}
}

// A binary in a folder install cannot write to (a system folder, say) is the
// same: say so and register the binary.
func TestHookCommandInAReadOnlyFolderRegistersTheBinary(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a folder this user cannot write to")
	}
	if _, err := os.Stat(zshPath); err != nil {
		t.Skip("no zsh on this machine")
	}
	dir := t.TempDir()
	exe := fakeBinary(t, dir)
	// #nosec G302 -- the test needs a folder it can read and enter but not write.
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- put it back so the test folder can be removed.
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	var command string
	stdout, _ := output(t, func() { command = hookCommand(exe) })
	if command != exe+" hook" {
		t.Fatalf("command = %s, want the binary run directly", command)
	}
	if !strings.Contains(stdout, "could not write") {
		t.Fatalf("install did not say the wrapper was skipped: %q", stdout)
	}
}

// An install made before the wrapper existed points at the binary. Running
// install again has to move that entry to the new command where it stands:
// same matcher, same neighbours, and no second vaultmcp entry.
func TestEnsureHookBringsAnOldCommandUpToDateInPlace(t *testing.T) {
	other := map[string]any{"type": "command", "command": "/usr/local/bin/lint-hook"}
	hooks := map[string]any{"PreToolUse": []any{
		map[string]any{"matcher": "Bash", "hooks": []any{
			other,
			map[string]any{"type": "command", "command": "/old/vaultmcp hook"},
		}},
	}}
	if !ensureHook(hooks, "PreToolUse", "/new/vaultmcp-hook") {
		t.Fatal("the old command was reported as up to date")
	}
	list, _ := hooks["PreToolUse"].([]any)
	if len(list) != 1 {
		t.Fatalf("want the one entry kept, got %d: %v", len(list), list)
	}
	entry, _ := list[0].(map[string]any)
	inner, _ := entry["hooks"].([]any)
	if entry["matcher"] != "Bash" || len(inner) != 2 {
		t.Fatalf("the entry lost its matcher or a neighbour: %v", entry)
	}
	if first, _ := inner[0].(map[string]any)["command"].(string); first != "/usr/local/bin/lint-hook" {
		t.Fatalf("the neighbour changed: %v", inner)
	}
	if ours, _ := inner[1].(map[string]any)["command"].(string); ours != "/new/vaultmcp-hook" {
		t.Fatalf("our command = %q", ours)
	}
	if ensureHook(hooks, "PreToolUse", "/new/vaultmcp-hook") {
		t.Fatal("a second run reported a change")
	}
}

func TestEnsureCursorHookBringsAnOldCommandUpToDateInPlace(t *testing.T) {
	hooks := map[string]any{"preToolUse": []any{
		map[string]any{"command": "/usr/local/bin/lint-hook"},
		map[string]any{"command": "/old/vaultmcp hook"},
	}}
	if !ensureCursorHook(hooks, "preToolUse", "/new/vaultmcp-hook") {
		t.Fatal("the old command was reported as up to date")
	}
	list, _ := hooks["preToolUse"].([]any)
	if len(list) != 2 {
		t.Fatalf("want two entries, got %v", list)
	}
	if ours, _ := list[1].(map[string]any)["command"].(string); ours != "/new/vaultmcp-hook" {
		t.Fatalf("our command = %q", ours)
	}
	if ensureCursorHook(hooks, "preToolUse", "/new/vaultmcp-hook") {
		t.Fatal("a second run reported a change")
	}
}

// Codex skips a hook whose definition changed until the person trusts it, and
// shows nothing. Install has to say so when it adds or changes the hook, and
// only then.
func TestCodexInstallSaysWhenTheHookNeedsTrust(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	install := func(command string) string {
		stdout, _ := output(t, func() {
			if err := writeClaudeStyleHooks(path, command); err != nil {
				t.Fatal(err)
			}
		})
		return stdout
	}
	const notice = "until you trust it"
	if out := install("/bin/vaultmcp hook"); !strings.Contains(out, notice) {
		t.Fatalf("a new hook: no word about trust: %q", out)
	}
	if out := install("/bin/vaultmcp hook"); strings.Contains(out, notice) {
		t.Fatalf("an unchanged hook asked for trust again: %q", out)
	}
	if out := install("/bin/vaultmcp-hook"); !strings.Contains(out, notice) {
		t.Fatalf("a changed hook: no word about trust: %q", out)
	}
}
