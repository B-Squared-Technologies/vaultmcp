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

	"github.com/dubb-b/vaultmcp/internal/audit"
	"github.com/dubb-b/vaultmcp/internal/detect"
	"github.com/dubb-b/vaultmcp/internal/vault"
)

const bashTool = "Bash"

var aliasRe = regexp.MustCompile(`\[vault:([A-Za-z0-9_]+)\]`)

// Deps are the runtime dependencies for processing a hook event.
type Deps struct {
	Paths     vault.Paths
	MasterKey []byte
	ExePath   string // absolute path to this binary, for $(... get ALIAS)
	Now       time.Time
}

type envelope struct {
	Event     string          `json:"hook_event_name"`
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
	ToolResp  json.RawMessage `json:"tool_response"`
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
		HookEventName     string `json:"hookEventName"`
		UpdatedToolOutput string `json:"updatedToolOutput"`
	} `json:"hookSpecificOutput"`
}

// Process handles one hook invocation. It returns the JSON bytes to write to
// stdout, or nil to emit nothing (no change / fail open).
func Process(stdin []byte, d Deps) []byte {
	var env envelope
	if err := json.Unmarshal(stdin, &env); err != nil {
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
	isBash := env.ToolName == bashTool
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
	// tool_response is usually a JSON string (e.g. Bash stdout). Unwrap it so we
	// redact the decoded text and emit a single-encoded string — not a string
	// that still carries its outer JSON quotes (which would double-encode).
	text := string(env.ToolResp)
	var unwrapped string
	if json.Unmarshal(env.ToolResp, &unwrapped) == nil {
		text = unwrapped
	}
	matches := detect.Find(text)
	if len(matches) == 0 {
		return nil
	}
	created := false
	var rawSecrets []string
	for _, match := range matches {
		alias, isNew := vault.SetByValue(store, match.Value, match.Type)
		if isNew {
			created = true
			_ = audit.Log(d.Paths.Audit, "vault", alias, env.ToolName, d.Now)
		}
		text = strings.ReplaceAll(text, match.Value, "[vault:"+alias+"]")
		rawSecrets = append(rawSecrets, match.Value)
	}
	if leaks(text, rawSecrets) {
		return nil
	}
	if created {
		_ = d.Paths.EnsureDir()
		if err := vault.Save(d.Paths.Store, store, d.MasterKey); err != nil {
			return nil
		}
	}

	var out postOutput
	out.HookSpecificOutput.HookEventName = "PostToolUse"
	out.HookSpecificOutput.UpdatedToolOutput = text
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
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
