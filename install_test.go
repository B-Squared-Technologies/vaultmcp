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
