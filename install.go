package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	if ensureHook(hooks, "PreToolUse", command) {
		added++
	}
	if removeVaultHook(hooks, "PostToolUse", command) {
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
		if cmd, _ := m["command"].(string); cmd == command || isVaultHook(cmd) {
			return false
		}
	}
	hooks[event] = append(list, map[string]any{"command": command})
	return true
}

// hookCommand is the command line registered with each tool: the binary's
// path and the word hook.
func hookCommand(exe string) string {
	return hookProgram(exe) + " hook"
}

// hookProgram writes the binary's path as one word of a command. A plain path
// goes in as it is, so a registration made by an earlier version stays the
// same text. A path with a space or another character a shell would act on
// goes in double quotes, which sh and bash (Git Bash on Windows) read as one
// word. PowerShell does not run a quoted path written this way.
func hookProgram(exe string) string {
	if hook.PlainPath(exe) {
		return exe
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(exe); i++ {
		if strings.IndexByte("\"\\$`", exe[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(exe[i])
	}
	b.WriteByte('"')
	return b.String()
}

// shells are programs that run the command line or the script they are given.
var shells = map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "cmd": true, "pwsh": true, "powershell": true}

// programName is the name a command word runs under: no folder, lower case,
// and without the endings a program or a script file carries.
func programName(word string) string {
	name := strings.ToLower(word[strings.LastIndexAny(word, `/\`)+1:])
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1", ".sh"} {
		name = strings.TrimSuffix(name, ext)
	}
	return name
}

// isAssignment reports whether a word is a NAME=value in front of a command.
func isAssignment(word string) bool {
	eq := strings.IndexByte(word, '=')
	if eq < 1 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := word[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// isVaultHook reports whether a registered hook command is vaultmcp's own.
// It is ours when the program it runs has a name that starts with vaultmcp
// (the release binaries are named vaultmcp-<os>-<arch>) and is given the
// argument "hook", or is a script named vaultmcp-hook that some setups put in
// front of the binary. A shell handed such a command or script (zsh -c '...',
// bash some/vaultmcp-hook.sh) counts too.
//
// Only the program counts, not a word further along. "make -C src/vaultmcp
// hook" and "lint > /tmp/vaultmcp-hook" are somebody else's hooks: taking one
// for ours meant install skipped its own registration because of it, and
// removed it when cleaning up. A NAME=value, env, exec or command in front,
// and a redirect or another command behind, do not change whose hook it is.
func isVaultHook(cmd string) bool {
	return runsVaultHook(shellWords(cmd))
}

func isOperator(word string) bool {
	return len(word) == 1 && strings.IndexByte("<>;&|", word[0]) >= 0
}

func runsVaultHook(words []string) bool {
	start, file := true, false
	for i, w := range words {
		switch {
		case w == "<" || w == ">":
			file = true // the next word is a file name, not a program
			continue
		case isOperator(w):
			start, file = true, false
			continue
		case file:
			file = false
			continue
		case !start:
			continue
		case isAssignment(w) || w == "env" || w == "exec" || w == "command":
			continue
		}
		start = false
		name := programName(w)
		if name == "vaultmcp-hook" {
			return true
		}
		if strings.HasPrefix(name, "vaultmcp") && i+1 < len(words) && words[i+1] == "hook" {
			return true
		}
		if shells[name] {
			args := words[i+1:]
			for j, a := range args {
				if isOperator(a) {
					args = args[:j]
					break
				}
			}
			if shellRunsVaultHook(name, args) {
				return true
			}
		}
	}
	return false
}

// shellRunsVaultHook looks at what a shell was told to run. That is either
// command text (after -c, /c or -Command), which is read as a command of its
// own, or a script file, which is one word and is judged by its name. Words
// after the script are the script's own and say nothing.
func shellRunsVaultHook(shell string, args []string) bool {
	for j, a := range args {
		low := strings.ToLower(a)
		switch {
		case shell == "cmd":
			if low == "/c" || low == "/k" {
				return textRunsVaultHook(args[j+1:])
			}
			if !strings.HasPrefix(a, "/") {
				return false
			}
		case shell == "pwsh" || shell == "powershell":
			if low == "-file" || low == "-f" {
				return j+1 < len(args) && programName(args[j+1]) == "vaultmcp-hook"
			}
			if low == "-command" || low == "-c" {
				return textRunsVaultHook(args[j+1:])
			}
		case strings.HasPrefix(a, "--"):
		case strings.HasPrefix(a, "-"):
			if strings.Contains(a, "c") {
				return textRunsVaultHook(args[j+1:])
			}
		default:
			return programName(a) == "vaultmcp-hook"
		}
	}
	return false
}

// textRunsVaultHook reads command text handed to a shell: one quoted word that
// holds a whole command, or the rest of the line.
func textRunsVaultHook(rest []string) bool {
	return len(rest) > 0 && (isVaultHook(rest[0]) || runsVaultHook(rest))
}

// shellWords splits a command into words as a shell would: on blanks that are
// not inside quotes, with the quotes taken off. A redirect or a separator
// (< > ; & |) outside quotes ends a word and stands as a word of its own, so
// "hook>>log" gives "hook", ">", ">", "log". A backslash outside quotes takes
// the next character literally when that character is one a shell would act
// on; before anything else it is kept, because on Windows it is part of a
// path.
func shellWords(cmd string) []string {
	var words []string
	var cur strings.Builder
	inWord := false
	end := func() {
		if inWord {
			words = append(words, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	var quote byte
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(cmd) && strings.IndexByte("\"\\$`", cmd[i+1]) >= 0:
				i++
				cur.WriteByte(cmd[i])
			default:
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(cmd) && strings.IndexByte(" \t'\"<>;&|", cmd[i+1]) >= 0:
			i++
			cur.WriteByte(cmd[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			end()
		case strings.IndexByte("<>;&|", c) >= 0:
			end()
			words = append(words, string(c))
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	end()
	return words
}

// removeVaultHook takes the vaultmcp command out of event's matcher entries.
// An entry can group several commands under one matcher; the others are not
// ours and stay. An entry goes only when vaultmcp was all it held.
func removeVaultHook(hooks map[string]any, event, command string) bool {
	list, _ := hooks[event].([]any)
	kept := make([]any, 0, len(list))
	removed := false
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		others := make([]any, 0, len(inner))
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); cmd != command && !isVaultHook(cmd) {
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
// event if an equivalent vaultmcp command is not already present. Returns true
// if it added one.
func ensureHook(hooks map[string]any, event, command string) bool {
	list, _ := hooks[event].([]any)
	for _, entry := range list {
		m, _ := entry.(map[string]any)
		inner, _ := m["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if cmd, _ := hm["command"].(string); cmd == command || isVaultHook(cmd) {
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
