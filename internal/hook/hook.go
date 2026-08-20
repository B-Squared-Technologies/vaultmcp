// Package hook implements the Claude Code PreToolUse and PostToolUse logic.
//
// PreToolUse: rewrite a tool's input before it runs.
//   - Egress (Bash only): pre-existing [vault:ALIAS] -> $(<abs> get ALIAS), a
//     command substitution resolved at shell-execution time. The raw secret
//     never appears in the transcript.
//   - Ingress: detected raw secrets are vaulted and replaced — with
//     $(<abs> get ALIAS) for Bash, or a static [vault:ALIAS] placeholder
//     otherwise.
//
// PostToolUse: redact secrets that appear in a tool's RESULT before Claude
// sees them (e.g. `cat .env`), via updatedToolOutput. This is the fully
// transcript-safe path.
//
// Every path fails open: on any error the hook emits nothing and the tool call
// proceeds untouched, so a VaultMCP bug can never break Claude Code.
package hook

import (
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/detect"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

const bashTool = "Bash"

var aliasRe = regexp.MustCompile(`\[vault:([A-Za-z0-9_]+)\]`)

// Shell-equivalent tool names across harnesses. Alias expansion to
// $(vaultmcp get ALIAS) is only safe in a real shell command.
var shellTools = map[string]bool{
	"Bash":                 true, // Claude, Codex
	"run_terminal_command": true, // Grok
	"Shell":                true,
	"shell":                true,
}

// Deps are the runtime dependencies for processing a hook event.
type Deps struct {
	Paths     vault.Paths
	MasterKey []byte
	ExePath   string // absolute path to this binary, for $(... get ALIAS)
	Now       time.Time
}

type envelope struct {
	Event     string
	ToolName  string
	ToolInput json.RawMessage
	ToolResp  json.RawMessage
}

type preOutput struct {
	HookSpecificOutput struct {
		HookEventName      string          `json:"hookEventName"`
		PermissionDecision string          `json:"permissionDecision"`
		UpdatedInput       json.RawMessage `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

type postOutput struct {
	HookSpecificOutput struct {
		HookEventName     string          `json:"hookEventName"`
		UpdatedToolOutput json.RawMessage `json:"updatedToolOutput"`
	} `json:"hookSpecificOutput"`
}

// Process handles one hook invocation. It returns the JSON bytes to write to
// stdout, or nil to emit nothing (no change / fail open).
func Process(stdin []byte, d Deps) []byte {
	env, ok := parseEnvelope(stdin)
	if !ok {
		return nil
	}
	switch env.Event {
	case "PreToolUse":
		return d.preToolUse(env)
	case "PostToolUse":
		return d.postToolUse(env)
	default:
		return nil
	}
}

func parseEnvelope(stdin []byte) (envelope, bool) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(stdin, &raw); err != nil {
		return envelope{}, false
	}
	get := func(keys ...string) json.RawMessage {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				return v
			}
		}
		return nil
	}
	str := func(keys ...string) string {
		v := get(keys...)
		if len(v) == 0 {
			return ""
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return ""
		}
		return s
	}

	env := envelope{
		Event:     normalizeEvent(str("hook_event_name", "hookEventName", "event")),
		ToolName:  str("tool_name", "toolName"),
		ToolInput: firstRaw(get("tool_input", "toolInput")),
		ToolResp:  firstRaw(get("tool_response", "toolResponse", "tool_result", "toolResult")),
	}

	// Cursor beforeShellExecution often puts the command at the top level.
	if len(env.ToolInput) == 0 {
		if cmd := get("command"); len(cmd) > 0 {
			wrapped, err := json.Marshal(map[string]json.RawMessage{"command": cmd})
			if err == nil {
				env.ToolInput = wrapped
			}
			if env.ToolName == "" {
				env.ToolName = bashTool
			}
		}
	}
	if env.Event == "" {
		return envelope{}, false
	}
	return env, true
}

func firstRaw(v json.RawMessage) json.RawMessage {
	if len(v) == 0 || string(v) == "null" {
		return nil
	}
	return v
}

func normalizeEvent(s string) string {
	switch s {
	case "PreToolUse", "pre_tool_use", "preToolUse", "beforeShellExecution", "beforeMCPExecution":
		return "PreToolUse"
	case "PostToolUse", "post_tool_use", "postToolUse", "afterShellExecution", "afterMCPExecution", "afterFileEdit":
		return "PostToolUse"
	default:
		return ""
	}
}

func isShellTool(name string) bool {
	return shellTools[name]
}

func (d Deps) sub(alias string) string {
	return "$(" + d.ExePath + " get " + alias + ")"
}

func (d Deps) preToolUse(env envelope) []byte {
	if len(env.ToolInput) == 0 {
		return nil
	}
	store, err := vault.Load(d.Paths.Store, d.MasterKey)
	if err != nil {
		return nil // fail open
	}
	text := string(env.ToolInput)
	isBash := isShellTool(env.ToolName)
	changed := false
	created := false

	// Egress: expand pre-existing aliases (Bash only) to command substitutions.
	if isBash {
		text = aliasRe.ReplaceAllStringFunc(text, func(m string) string {
			name := aliasRe.FindStringSubmatch(m)[1]
			if _, ok := store[name]; ok {
				changed = true
				return d.sub(name)
			}
			return m // unknown alias: leave untouched
		})
	}

	// Ingress: vault freshly-detected secrets and replace them.
	var rawSecrets []string
	for _, match := range detect.Find(text) {
		alias, isNew := vault.SetByValue(store, match.Value, match.Type)
		if isNew {
			created = true
			_ = audit.Log(d.Paths.Audit, "vault", alias, env.ToolName, d.Now)
		}
		replacement := "[vault:" + alias + "]"
		if isBash {
			replacement = d.sub(alias)
		}
		if newText := strings.ReplaceAll(text, match.Value, replacement); newText != text {
			text = newText
			changed = true
		}
		rawSecrets = append(rawSecrets, match.Value)
	}

	// Safety invariant: never emit a payload that still contains a raw secret.
	// If any detected value survived replacement (e.g. an escaping mismatch),
	// fail open rather than leak it into the transcript.
	if leaks(text, rawSecrets) {
		return nil
	}

	if created {
		_ = d.Paths.EnsureDir()
		if err := vault.Save(d.Paths.Store, store, d.MasterKey); err != nil {
			return nil // fail open — don't emit a redaction we couldn't persist
		}
	}
	if !changed {
		return nil
	}
	// Confirm the rewritten input is still valid JSON before emitting.
	if !json.Valid([]byte(text)) {
		return nil
	}

	var out preOutput
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "allow"
	out.HookSpecificOutput.UpdatedInput = json.RawMessage(text)
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

func (d Deps) postToolUse(env envelope) []byte {
	if len(env.ToolResp) == 0 {
		return nil
	}
	store, err := vault.Load(d.Paths.Store, d.MasterKey)
	if err != nil {
		return nil
	}
	// Claude Code validates updatedToolOutput against the tool's OWN output
	// schema, so we must emit the same shape we received: a Bash result stays
	// {stdout,stderr,…}, a plain-string result stays a string. Emitting a bare
	// string for an object-shaped result is rejected ("does not match <Tool>'s
	// output shape") and the redaction is dropped. Parse into a generic value
	// and redact every string it contains, preserving structure.
	var resp any
	if err := json.Unmarshal(env.ToolResp, &resp); err != nil {
		return nil // not JSON we can safely rewrite — fail open
	}
	created := false
	changed := false
	var rawSecrets []string
	var redacted []string
	redact := func(s string) string {
		for _, match := range detect.Find(s) {
			alias, isNew := vault.SetByValue(store, match.Value, match.Type)
			if isNew {
				created = true
				_ = audit.Log(d.Paths.Audit, "vault", alias, env.ToolName, d.Now)
			}
			if ns := strings.ReplaceAll(s, match.Value, "[vault:"+alias+"]"); ns != s {
				s = ns
				changed = true
			}
			rawSecrets = append(rawSecrets, match.Value)
		}
		redacted = append(redacted, s)
		return s
	}
	resp = walkStrings(resp, redact)
	if !changed {
		return nil
	}
	// Safety invariant: never emit a payload where a raw secret survived
	// replacement (\x00 keeps a value from matching across two fields).
	if leaks(strings.Join(redacted, "\x00"), rawSecrets) {
		return nil
	}
	if created {
		_ = d.Paths.EnsureDir()
		if err := vault.Save(d.Paths.Store, store, d.MasterKey); err != nil {
			return nil
		}
	}
	redactedResp, err := json.Marshal(resp)
	if err != nil {
		return nil
	}

	var out postOutput
	out.HookSpecificOutput.HookEventName = "PostToolUse"
	out.HookSpecificOutput.UpdatedToolOutput = json.RawMessage(redactedResp)
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// walkStrings returns v with f applied to every string it contains, recursing
// through JSON objects and arrays so the overall shape is preserved.
func walkStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case map[string]any:
		for k, val := range x {
			x[k] = walkStrings(val, f)
		}
		return x
	case []any:
		for i, val := range x {
			x[i] = walkStrings(val, f)
		}
		return x
	default:
		return v
	}
}

// leaks reports whether any raw secret value still appears in text — the guard
// that prevents emitting a payload that failed to fully redact.
func leaks(text string, secrets []string) bool {
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			return true
		}
	}
	return false
}
