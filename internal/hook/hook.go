// Package hook implements the Claude Code PreToolUse and PostToolUse logic.
//
// PreToolUse: rewrite a tool's input before it runs.
//   - Egress (Bash only): pre-existing [vault:ALIAS] -> $(<abs> get ALIAS), a
//     command substitution resolved at shell-execution time. The raw secret
//     never appears in the transcript. In any other tool the placeholder
//     stays as text, and naming a capture there marks that capture as used.
//   - Ingress: detected raw secrets are vaulted and replaced — with
//     $(<abs> get ALIAS) for Bash, or a static [vault:ALIAS] placeholder
//     otherwise.
//
// A detected secret that a person already stored keeps that name. Any other
// is captured into its own file under captured/ (see the capture package).
// The hook only ever READS store.enc: parallel hook processes rewriting one
// shared file is how captures used to get lost.
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
	"errors"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
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
	"Shell":                true, // Cursor
	"shell":                true,
}

// Deps are the runtime dependencies for processing a hook event.
type Deps struct {
	Paths     vault.Paths
	MasterKey []byte
	// CaptureKey returns capture.Key(master, machine id), which names and
	// seals new captures. It is a function because reading the machine id
	// costs a process launch on macOS and most hook runs meet no new secret:
	// it is called only when one has to be captured.
	CaptureKey func() []byte
	ExePath    string // absolute path to this binary, for $(... get ALIAS)
	Now        time.Time
	// Session and Cwd are recorded on new captures so a capture can be traced
	// to where it came from. Process fills them from the hook JSON; either may
	// be empty.
	Session string
	Cwd     string
	// StoreFailed, when set, is called if the named store does not open with
	// MasterKey. Process then emits nothing, as for any failure, and the
	// caller can tell that apart from "nothing to redact".
	StoreFailed func()
}

type envelope struct {
	Event     string
	ToolName  string
	ToolInput json.RawMessage
	ToolResp  json.RawMessage
	Cursor    bool
	Grok      bool
	Session   string
	Cwd       string
}

// claudePreOutput is the PreToolUse response Claude, Grok, and Codex accept.
// Extra root fields (Cursor's permission / updated_input) are omitted so a
// strict decoder cannot reject the whole rewrite.
type claudePreOutput struct {
	HookSpecificOutput struct {
		HookEventName      string          `json:"hookEventName"`
		PermissionDecision string          `json:"permissionDecision"`
		UpdatedInput       json.RawMessage `json:"updatedInput"`
	} `json:"hookSpecificOutput"`
}

type cursorPreOutput struct {
	Permission   string          `json:"permission,omitempty"`
	UpdatedInput json.RawMessage `json:"updated_input,omitempty"`
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
	d.Session, d.Cwd = env.Session, env.Cwd
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

	rawEvent := str("hook_event_name", "hookEventName", "event")
	env := envelope{
		Event:     normalizeEvent(rawEvent),
		ToolName:  str("tool_name", "toolName"),
		ToolInput: firstRaw(get("tool_input", "toolInput")),
		ToolResp:  firstRaw(get("tool_response", "toolResponse", "tool_result", "toolResult", "tool_output", "output")),
		Cursor:    isCursorEvent(rawEvent),
		Session:   str("session_id", "sessionId"),
		Cwd:       str("cwd"),
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
	// Grok sends camelCase keys (beside the snake_case event name); Claude
	// and Codex send snake_case only; Cursor is known by its event names.
	_, camelTool := raw["toolName"]
	_, camelEvent := raw["hookEventName"]
	env.Grok = !env.Cursor && (camelTool || camelEvent)
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

func isCursorEvent(s string) bool {
	switch s {
	case "preToolUse", "postToolUse", "beforeShellExecution", "afterShellExecution", "beforeMCPExecution", "afterMCPExecution", "afterFileEdit":
		return true
	default:
		return false
	}
}

func isShellTool(name string) bool {
	return shellTools[name]
}

func (d Deps) sub(alias string) string {
	s := "$(" + shellPath(d.ExePath, runtime.GOOS == "windows") + " get " + alias + ")"
	// The substitution is put into tool input that is still JSON text, inside
	// one of its strings. A backslash or a double quote from the path has to
	// be escaped for JSON first, or the rewrite stops being valid JSON and is
	// thrown away, and the secret goes through unhidden.
	b, err := json.Marshal(s)
	if err != nil {
		return s
	}
	return string(b[1 : len(b)-1])
}

// plainPathByte reports whether a shell reads c as an ordinary character of a
// word, with nothing to split on or expand.
func plainPathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("_./:-", c) >= 0
}

// shellPath writes a path so that the shell running the command it is put
// into reads it back as that one path: every ASCII character a shell could
// treat specially (a space in a user's name is the common case) gets a
// backslash in front. A plain path comes out as it went in, so most commands
// look the way they always did.
//
// Quotes are not used, on purpose. The substitution often lands inside a
// string the command already quoted, and a quote of ours would end that
// string early and hand the shell the rest as loose words. The one exception
// is a newline, which no backslash can escape: it gets double quotes, and
// those sit inside the $( ), where they do not end a string outside it.
//
// On Windows the shell is Git Bash, which takes a backslash as an escape, so
// backslashes become forward slashes there first. Elsewhere a backslash is an
// ordinary character of a file name and is escaped like the rest.
func shellPath(p string, windows bool) string {
	if windows {
		p = strings.ReplaceAll(p, `\`, "/")
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\n' {
			// A backslash before a newline joins two lines and drops both
			// characters, so a newline goes in quotes of its own.
			b.WriteString("\"\n\"")
			continue
		}
		if c < 0x80 && !plainPathByte(c) {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// known reports whether alias resolves: a named secret, or a capture file.
// The capture check is a stat, with no decrypt and no directory listing.
//
// A capture that is known here is marked as in use now, whatever its age. In
// a shell command it is about to be read, and the daily prune, which runs at
// the end of this same hook call, could otherwise delete an old never-read
// capture before the shell gets to it. In any other tool the placeholder is
// most likely being written into a file, and from then on that file's
// placeholder and this capture are all that is left of the value.
func (d Deps) known(store vault.Store, alias string) bool {
	if _, ok := store[alias]; ok {
		return true
	}
	if !capture.Exists(d.Paths.Captured, alias) {
		return false
	}
	capture.Mention(d.Paths.Captured, alias, d.Now)
	return true
}

// namedAlias returns the named secret holding exactly value. When several do,
// the smallest name wins so every run picks the same one.
func namedAlias(store vault.Store, value string) (string, bool) {
	best, found := "", false
	for a, v := range store {
		if v == value && (!found || a < best) {
			best, found = a, true
		}
	}
	return best, found
}

// aliasFor returns the alias to put in place of a detected secret, capturing
// the secret first if nobody stored it under a name. ok is false when the
// secret could not be persisted; the caller must then emit nothing, because a
// redaction that cannot be resolved later would lose the value.
func (d Deps) aliasFor(store vault.Store, m detect.Match, tool string) (alias string, ok bool) {
	if a, found := namedAlias(store, m.Value); found {
		return a, true
	}
	key := d.CaptureKey()
	alias = capture.Alias(key, m.Type, m.Value)
	// Named secrets are looked up first, so a named entry that already uses
	// this alias (for a different value) would make the placeholder resolve
	// to the wrong secret.
	if _, clash := store[alias]; clash {
		return "", false
	}
	e := capture.Entry{
		Value:   m.Value,
		Kind:    m.Type,
		Created: d.Now.UTC().Format(time.RFC3339),
		Tool:    tool,
		Session: d.Session,
		Cwd:     d.Cwd,
	}
	created, err := capture.Write(d.Paths.Captured, key, alias, e)
	if err != nil {
		return "", false
	}
	if !created {
		if created, ok = d.reuse(key, alias, e); !ok {
			return "", false
		}
	}
	if created {
		// The hook has always tightened the vault folder to owner-only when
		// it stored something; a folder that predates the vault may be wider.
		_ = d.Paths.EnsureDir()
		_ = audit.Log(d.Paths.Audit, "vault", alias, tool, d.Now)
	}
	return alias, true
}

// reuse decides whether the capture file that is already at alias can stand
// for e.Value. ok is false when it cannot, and the caller then emits nothing.
// rewritten reports that the file had to be written again.
//
// The mark comes first and the read second, so the read is also the check
// that the file is still there after the mark. A prune running beside this
// hook can delete an old never-used capture up to the moment it is marked;
// reading first would let the alias go out for a file that is already gone.
//
// A file that opens to another value is never touched: the alias is taken.
// A file that is gone, or that no longer opens, is written again from the
// value in hand. The alias is derived from the value under this same key, so
// a file here that does not open can only be damaged (cut short by a crash,
// or copied in from another name), and leaving it would switch redaction of
// this value off until the file expired a month later.
func (d Deps) reuse(key []byte, alias string, e capture.Entry) (rewritten, ok bool) {
	capture.Seen(d.Paths.Captured, alias, d.Now)
	got, err := capture.Read(d.Paths.Captured, key, alias)
	if err == nil {
		return false, got.Value == e.Value
	}
	if !errors.Is(err, crypto.ErrDecrypt) && !os.IsNotExist(err) {
		return false, false
	}
	if err := capture.Replace(d.Paths.Captured, key, alias, e); err != nil {
		return false, false
	}
	got, err = capture.Read(d.Paths.Captured, key, alias)
	return true, err == nil && got.Value == e.Value
}

func (d Deps) preToolUse(env envelope) []byte {
	if len(env.ToolInput) == 0 {
		return nil
	}
	store, err := vault.Load(d.Paths.Store, d.MasterKey)
	if err != nil {
		d.storeFailed()
		return nil // fail open
	}
	text := string(env.ToolInput)
	isBash := isShellTool(env.ToolName)
	changed := false

	// Egress: expand pre-existing aliases (Bash only) to command substitutions.
	if isBash {
		text = aliasRe.ReplaceAllStringFunc(text, func(m string) string {
			name := aliasRe.FindStringSubmatch(m)[1]
			if d.known(store, name) {
				changed = true
				return d.sub(name)
			}
			return m // unknown alias: leave untouched
		})
	} else {
		// Not a shell: the placeholders stay as they are, but each known one
		// still marks its capture as used. This runs before the ingress step
		// on purpose, so it sees only the placeholders the tool input came
		// with, not the ones about to be put in for new captures.
		for _, m := range aliasRe.FindAllStringSubmatch(text, -1) {
			d.known(store, m[1])
		}
	}

	// Ingress: vault freshly-detected secrets and replace them.
	var rawSecrets []string
	for _, match := range detect.Find(text) {
		alias, ok := d.aliasFor(store, match, env.ToolName)
		if !ok {
			return nil // fail open — don't emit a redaction we couldn't persist
		}
		replacement := "[vault:" + alias + "]"
		if isBash {
			replacement = d.sub(alias)
		}
		// The replacement goes where the secret was headed: into a file, or
		// into a command. From now on it and this capture may be all that is
		// left of the value, so the capture starts out as used and gets the
		// 30-day rule, not the 7-day one. A shell is no exception: inside
		// single quotes or a quoted heredoc the substitution is never run,
		// so nothing reads the capture, and the text may be on its way into
		// a file all the same.
		capture.Mention(d.Paths.Captured, alias, d.Now)
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

	if !changed {
		return nil
	}
	// Confirm the rewritten input is still valid JSON before emitting.
	if !json.Valid([]byte(text)) {
		return nil
	}

	return marshalPre(env, json.RawMessage(text))
}

func marshalPre(env envelope, rewritten json.RawMessage) []byte {
	if env.Cursor {
		b, err := json.Marshal(cursorPreOutput{
			Permission:   "allow",
			UpdatedInput: rewritten,
		})
		if err != nil {
			return nil
		}
		return b
	}
	var out claudePreOutput
	out.HookSpecificOutput.HookEventName = "PreToolUse"
	out.HookSpecificOutput.PermissionDecision = "allow"
	out.HookSpecificOutput.UpdatedInput = rewritten
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
		d.storeFailed()
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
	changed := false
	persisted := true
	var rawSecrets []string
	var redacted []string
	redact := func(s string) string {
		for _, match := range detect.Find(s) {
			alias, ok := d.aliasFor(store, match, env.ToolName)
			if !ok {
				persisted = false
				continue
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
	// Fail open — don't emit a redaction we couldn't persist.
	if !persisted || !changed {
		return nil
	}
	// Safety invariant: never emit a payload where a raw secret survived
	// replacement (\x00 keeps a value from matching across two fields).
	if leaks(strings.Join(redacted, "\x00"), rawSecrets) {
		return nil
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

func (d Deps) storeFailed() {
	if d.StoreFailed != nil {
		d.StoreFailed()
	}
}

// claudeDenyOutput is the documented PreToolUse denial for Claude, Codex and
// Grok. It carries nothing but the decision and its reason: an extra root
// field one of them does not know could get the whole answer rejected, and a
// rejected answer lets the tool call through.
type claudeDenyOutput struct {
	HookSpecificOutput struct {
		HookEventName            string `json:"hookEventName"`
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

type cursorDenyOutput struct {
	Permission   string `json:"permission"`
	UserMessage  string `json:"user_message"`
	AgentMessage string `json:"agent_message"`
}

// Stop returns the hook answer that denies the tool call in stdin, with
// reason as the message. It answers only a PreToolUse event: a call that has
// already run cannot be stopped, and for anything else it returns nil.
//
// This is the one place the hook ever blocks. The caller uses it only for a
// vault its owner locked on purpose.
func Stop(stdin []byte, reason string) []byte {
	env, ok := parseEnvelope(stdin)
	if !ok || env.Event != "PreToolUse" {
		return nil
	}
	var out any
	if env.Cursor {
		out = cursorDenyOutput{Permission: "deny", UserMessage: reason, AgentMessage: reason}
	} else {
		var deny claudeDenyOutput
		deny.HookSpecificOutput.HookEventName = "PreToolUse"
		deny.HookSpecificOutput.PermissionDecision = "deny"
		deny.HookSpecificOutput.PermissionDecisionReason = reason
		out = deny
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// SessionID returns the agent session the hook event in stdin belongs to, or
// "" if it names none.
func SessionID(stdin []byte) string {
	env, _ := parseEnvelope(stdin)
	return env.Session
}

// Warn returns a hook answer that lets the tool call in stdin go ahead and
// shows msg to the person at the screen. Claude and Codex document a field
// for that on PreToolUse. Grok shows nothing from a hook that allowed, and
// Cursor has no documented field and blocks the call on an answer it does not
// know, so for those two, and for every other event, it returns nil.
func Warn(stdin []byte, msg string) []byte {
	env, ok := parseEnvelope(stdin)
	if !ok || env.Event != "PreToolUse" || env.Cursor || env.Grok {
		return nil
	}
	b, err := json.Marshal(struct {
		SystemMessage string `json:"systemMessage"`
	}{msg})
	if err != nil {
		return nil
	}
	return b
}
