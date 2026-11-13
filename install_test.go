package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestIsVaultHook(t *testing.T) {
	for cmd, want := range map[string]bool{
		"/usr/local/bin/vaultmcp hook":                   true,
		"C:/Users/jo/bin/vaultmcp.exe hook":              true,
		"C:/Users/Jo Smith/bin/vaultmcp.exe hook":        true,
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
	if removeVaultHook(hooks, "PostToolUse") {
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
