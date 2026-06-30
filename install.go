package main

import (
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

	settings := map[string]any{}
	// #nosec G304 -- sp is a resolved .claude/settings.json path, not user input.
	if data, err := os.ReadFile(sp); err == nil {
		_ = json.Unmarshal(data, &settings) // tolerate/overwrite malformed
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
		fmt.Println("  VaultMCP will now intercept credentials in Claude Code.")
	}
	if !keyringReady() {
		fmt.Println("  note: OS keychain unavailable — run 'vaultmcp set' to use passphrase mode.")
	}
	return nil
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
