package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// settingsPath returns the Claude Code settings file to register hooks in.
// It defaults to the project-local .claude/settings.json in the current
// directory (creating the .claude dir if needed). The global ~/.claude file is
// used ONLY when explicitly requested, so `vaultmcp install` can never silently
// clobber a user's global config.
func settingsPath(global bool) (string, error) {
	base, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if global {
		if base, err = os.UserHomeDir(); err != nil {
			return "", err
		}
	}
	dir := filepath.Join(base, ".claude")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	return filepath.Join(dir, "settings.json"), nil
}

// cmdInstall registers PreToolUse and PostToolUse hooks (idempotently) that
// invoke this binary's absolute path. The path is forward-slashed so it stays
// valid JSON on Windows.
func cmdInstall(args []string) error {
	global := false
	for _, a := range args {
		if a == "--global" || a == "-g" {
			global = true
		}
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe = filepath.ToSlash(exe)
	command := exe + " hook"

	sp, err := settingsPath(global)
	if err != nil {
		return err
	}

	settings, err := readJSONObject(sp)
	if err != nil {
		return err
	}

	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}

	added := 0
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		if ensureHook(hooks, event, command) {
			added++
		}
	}
	settings["hooks"] = hooks

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(sp, out, 0o600); err != nil {
		return err
	}

	if added == 0 {
		fmt.Printf("  hooks already registered in %s\n", sp)
	} else {
		fmt.Printf("  registered %d hook(s) in %s\n", added, sp)
	}
	if global {
		if err := installSiblingHooks(command); err != nil {
			return err
		}
	}
	fmt.Println("  VaultMCP intercepts credentials in Claude, Grok (via Claude compat), Codex, and Cursor.")
	if !keyringReady() {
		fmt.Println("  note: OS keychain unavailable — run 'vaultmcp set' to use passphrase mode.")
	}
	return nil
}

// installSiblingHooks registers Codex (PreToolUse only) and Cursor hooks.
// Grok already loads ~/.claude/settings.json hooks when Claude compat is on.
func installSiblingHooks(command string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	codex := filepath.Join(home, ".codex", "hooks.json")
	cursor := filepath.Join(home, ".cursor", "hooks.json")
	if err := writeClaudeStyleHooks(codex, command); err != nil {
		return err
	}
	return writeCursorHooks(cursor, command)
}

func writeClaudeStyleHooks(path, command string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	settings, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	added := 0
	// Codex PreToolUse can rewrite input via hookSpecificOutput.updatedInput.
	// Codex PostToolUse has no updatedToolOutput, so a registered post hook
	// cannot redact results; skip it and drop a leftover vaultmcp entry.
	if ensureHook(hooks, "PreToolUse", command) {
		added++
	}
	if removeVaultHook(hooks, "PostToolUse") {
		added++
	}
	settings["hooks"] = hooks
	return writeJSON(path, settings, added)
}

// Cursor's hooks.json is {version, hooks: {preToolUse: [{command}]}} — not
// Claude's nested matcher/hooks/type shape. See cursor.com/docs/agent/hooks.
func writeCursorHooks(path, command string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	settings, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, _ := settings["hooks"].(map[string]any)
	if hooks == nil {
		hooks = map[string]any{}
	}
	delete(hooks, "PreToolUse")
	delete(hooks, "PostToolUse")
	added := 0
	for _, event := range []string{"preToolUse", "postToolUse", "beforeShellExecution", "afterShellExecution"} {
		if ensureCursorHook(hooks, event, command) {
			added++
		}
	}
	settings["hooks"] = hooks
	settings["version"] = 1
	return writeJSON(path, settings, added)
}

// readJSONObject loads an existing JSON object from path. Missing or empty
// files become {}. Non-empty invalid JSON is an error so install cannot
// clobber a user's hooks file.
func readJSONObject(path string) (map[string]any, error) {
	// #nosec G304 -- path is a resolved settings/hooks.json, not user input.
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]any{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]any{}, nil
	}
	settings := map[string]any{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return settings, nil
}

func writeJSON(path string, settings map[string]any, added int) error {
	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		return err
	}
	if added == 0 {
		fmt.Printf("  hooks already registered in %s\n", path)
	} else {
		fmt.Printf("  registered %d hook(s) in %s\n", added, path)
	}
	return nil
}

func ensureCursorHook(hooks map[string]any, event, command string) bool {
	list, _ := hooks[event].([]any)
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		if cmd, _ := m["command"].(string); strings.Contains(cmd, "vaultmcp") {
			return false
		}
	}
	hooks[event] = append(list, map[string]any{"command": command})
	return true
}

// removeVaultHook drops matcher entries whose command references vaultmcp.
func removeVaultHook(hooks map[string]any, event string) bool {
	list, _ := hooks[event].([]any)
	if len(list) == 0 {
		return false
	}
	kept := make([]any, 0, len(list))
	removed := false
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		drop := false
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "vaultmcp") {
				drop = true
				break
			}
		}
		if drop {
			removed = true
			continue
		}
		kept = append(kept, entry)
	}
	if !removed {
		return false
	}
	if len(kept) == 0 {
		delete(hooks, event)
	} else {
		hooks[event] = kept
	}
	return true
}

// ensureHook adds a {matcher:".*", hooks:[{type:command, command}]} entry for
// event if an equivalent vaultmcp command is not already present. Returns true
// if it added one.
func ensureHook(hooks map[string]any, event, command string) bool {
	list, _ := hooks[event].([]any)
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "vaultmcp") {
				return false // already registered
			}
		}
	}
	hooks[event] = append(list, map[string]any{
		"matcher": ".*",
		"hooks": []any{
			map[string]any{"type": "command", "command": command},
		},
	})
	return true
}
