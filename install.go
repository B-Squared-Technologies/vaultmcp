package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/B-Squared-Technologies/vaultmcp/internal/hook"
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
// run the command hookCommand returns for this binary. Running it again
// brings an older vaultmcp command up to date where it stands.
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
	command := hookCommand(exe)

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
	pre := ensureHook(hooks, "PreToolUse", command)
	if pre {
		added++
	}
	if removeVaultHook(hooks, "PostToolUse") {
		added++
	}
	settings["hooks"] = hooks
	if err := writeJSON(path, settings, added); err != nil {
		return err
	}
	if pre {
		// Codex records trust against the exact hook definition and skips a
		// new or changed one. Left unsaid, the hook is off and nothing shows.
		fmt.Println("  Codex skips a new or changed hook until you trust it: open Codex, run /hooks, and trust the vaultmcp hook.")
	}
	return nil
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

// zshPath is the shell the wrapper script runs under. It is a variable so a
// test can stand in for a machine that has no zsh.
var zshPath = "/bin/zsh"

// hookCommand returns the command the agent tools are told to run.
//
// An app opened from the Dock or a launcher does not load the shell's
// settings, so a VAULTMCP_KEY exported in ~/.zshenv never reaches a hook that
// app starts, and the hook has to let every call through with nothing hidden.
// Where zsh exists, install therefore writes a small script next to the binary
// that loads ~/.zshenv and then becomes the hook, and registers the script.
// On Windows, without zsh, or when the script cannot be written, the binary is
// registered directly, as it always was.
func hookCommand(exe string) string {
	if runtime.GOOS == "windows" {
		return filepath.ToSlash(exe) + " hook"
	}
	direct := hook.ShellPath(exe, false) + " hook"
	if _, err := os.Stat(zshPath); err != nil {
		return direct
	}
	wrapper := filepath.Join(filepath.Dir(exe), "vaultmcp-hook")
	if err := writeWrapper(wrapper, exe); err != nil {
		fmt.Printf("  note: could not write %s (%v). The hook will run the binary directly, so an app that does not load your shell settings will not get VAULTMCP_KEY.\n", wrapper, err)
		return direct
	}
	return hook.ShellPath(wrapper, false)
}

// wrapperScript is the script hookCommand registers. zsh is started with -f
// so it loads no startup file by itself; ~/.zshenv is then loaded with its
// input and output closed off, because the hook's stdin is the tool call and
// its stdout is the answer the agent tool parses: a line ~/.zshenv printed, or
// a command in it that read stdin, would break one or the other. exec hands
// stdin and stdout to the binary untouched.
func wrapperScript(exe string) string {
	return "#!" + zshPath + " -f\n" +
		"# Written by `vaultmcp install`, which rewrites it. Do not edit.\n" +
		"# An app opened from the Dock does not load your shell settings, so a\n" +
		"# VAULTMCP_KEY set in ~/.zshenv would not reach the hook. This loads that\n" +
		"# file, then becomes the hook.\n" +
		"[[ -r \"${HOME}/.zshenv\" ]] && source \"${HOME}/.zshenv\" </dev/null >/dev/null 2>&1\n" +
		"exec '" + strings.ReplaceAll(exe, "'", `'\''`) + "' hook \"$@\"\n"
}

// writeWrapper puts the script in place in one step, so a hook that fires
// while install runs never reads half a file.
func writeWrapper(path, exe string) error {
	tmp := fmt.Sprintf("%s.new-%d", path, os.Getpid())
	// #nosec G306 -- a script has to be executable. Owner only.
	if err := os.WriteFile(tmp, []byte(wrapperScript(exe)), 0o700); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// ensureCursorHook registers command for event. A vaultmcp command already
// there is kept where it is and brought up to date. Returns true when it
// changed anything.
func ensureCursorHook(hooks map[string]any, event, command string) bool {
	list, _ := hooks[event].([]any)
	found, changed := false, false
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		if cmd, _ := m["command"].(string); strings.Contains(cmd, "vaultmcp") {
			found = true
			if cmd != command {
				m["command"] = command
				changed = true
			}
		}
	}
	if found {
		return changed
	}
	hooks[event] = append(list, map[string]any{"command": command})
	return true
}

// removeVaultHook takes the vaultmcp command out of event's matcher entries.
// An entry can group several commands under one matcher; the others are not
// ours and stay. An entry goes only when vaultmcp was all it held.
func removeVaultHook(hooks map[string]any, event string) bool {
	list, _ := hooks[event].([]any)
	kept := make([]any, 0, len(list))
	removed := false
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		others := make([]any, 0, len(inner))
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); !strings.Contains(cmd, "vaultmcp") {
				others = append(others, h)
			}
		}
		if len(others) == len(inner) {
			kept = append(kept, entry)
			continue
		}
		removed = true
		if len(others) > 0 {
			m["hooks"] = others
			kept = append(kept, entry)
		}
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
// event. A vaultmcp command already there is kept where it is, with its
// matcher and its neighbours, and brought up to date: an install made before
// the wrapper existed points at the binary. Returns true when it changed
// anything.
func ensureHook(hooks map[string]any, event, command string) bool {
	list, _ := hooks[event].([]any)
	found, changed := false, false
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); strings.Contains(cmd, "vaultmcp") {
				found = true
				if cmd != command {
					hm["command"] = command
					changed = true
				}
			}
		}
	}
	if found {
		return changed
	}
	hooks[event] = append(list, map[string]any{
		"matcher": ".*",
		"hooks": []any{
			map[string]any{"type": "command", "command": command},
		},
	})
	return true
}
