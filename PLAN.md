# VaultMCP — Go Rewrite Plan

Rewrite the Python VaultMCP as a single cross-platform Go binary. Target **Go 1.26.4**.
Scope: **Layer 1 (ingress redaction) + Layer 2 (egress expansion / run_with_secrets)**.
Key storage: **OS keychain (go-keyring) with passphrase-encrypted-file fallback**.

## Goals (definition of done)
- One static binary, no runtime, installs + works on macOS, Windows, Linux.
- `vaultmcp install` self-registers the PreToolUse hook in Claude Code settings.
- Real, audited crypto. No hand-rolled cipher. No plaintext passphrase on disk.
- Secrets never enter the Claude transcript; aliased secrets still work at execution.
- Thoroughly tested, including a dedicated security test. Passes `/code-review` + `/simplify`.

## Module / file layout
```
go.mod                      // module github.com/dubb-b/vaultmcp, go 1.26
main.go                     // CLI entry, subcommand router
internal/detect/detect.go   // regex patterns + Shannon entropy scan
internal/vault/vault.go     // store load/save, alias mgmt
internal/crypto/crypto.go   // Argon2id KDF + ChaCha20-Poly1305 AEAD
internal/keyring/keyring.go // OS keychain w/ encrypted-file fallback
internal/audit/audit.go     // hash-chained append-only audit log
internal/hook/hook.go       // PreToolUse logic (ingress redact + egress expand)
cmd_*.go                    // set/get/list/delete/status/audit/unlock/lock/install/hook
*_test.go                   // unit + security tests
```
Single binary, subcommands (`vaultmcp hook`, `vaultmcp set`, ...). Kills the duplicated-crypto problem from the Python version (hook.py + vaultmcp.py each had their own copy).

## Dependencies (minimal, vetted)
- `golang.org/x/crypto/chacha20poly1305` — AEAD
- `golang.org/x/crypto/argon2` — Argon2id KDF
- `github.com/zalando/go-keyring` — macOS Keychain / Windows Cred Manager / Linux Secret Service
- stdlib for everything else (json, regexp, math, encoding, os).

## Crypto design (replaces hand-rolled HMAC-CTR + PBKDF2-260k)
- **KDF:** Argon2id (m=64 MiB, t=3, p=1) over the passphrase + 16-byte random salt.
- **AEAD:** ChaCha20-Poly1305 (XChaCha20 variant for 24-byte random nonce → no nonce-reuse worry).
- **Store file format:** `magic(4) || version(1) || salt(16) || nonce(24) || ciphertext+tag`. File mode 0600, dir 0700.
- **Master key model (simplified per architect fix #4 — no token indirection):** a random 32-byte master key encrypts the store. Hooks are short-lived processes and cannot hold in-memory state between calls, so persistent unlock state is either the OS keychain or a file — nothing else works. Two explicit modes:
  1. **Keychain mode (default):** master key stored directly in OS keychain (`go-keyring`, service `vaultmcp`, account `master`). The OS gates access; nothing secret on disk. Argon2id is NOT used in this mode — so the per-tool-call hook just fetches the key (fast) and does an AEAD open; the 0.4s Argon2id cost never hits the hot path.
  2. **Passphrase mode (fallback, e.g. headless Linux with no Secret Service):** master key is wrapped by an Argon2id-derived KEK and stored in `~/.vaultmcp/key.enc` (salt + sealed master key). Unlock = prompt passphrase once, derive KEK, unwrap master key, **store the unwrapped master key in keychain if available, else require `VAULTMCP_KEY`/prompt per session**. The passphrase is NEVER written to disk. Documented tradeoff: passphrase mode without a keychain prompts each session (or uses `VAULTMCP_KEY`).
- Mode is auto-detected (keychain probe at first run) and recorded in `meta.json`.

## Detection (port + keep parity)
- Same known-pattern regexes (AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, private key, DB URLs, JWT).
- Shannon entropy scan: threshold 3.5 bits/char, token length 20–2048.
- Allowlist: URLs, `${...}`, `$(...)`, `[vault:...]`, `<tag`, localhost, UUIDs.
- Known false-positive tax (long paths) acknowledged; add a path-like allowlist heuristic to reduce it.

## RESOLVED: Claude Code hook semantics (verified against docs source, 1.26-era)
Read verbatim from https://code.claude.com/docs/en/hooks.md:
- `PreToolUse` → `hookSpecificOutput.updatedInput` "replaces a tool's arguments before it runs." It **replaces the entire input object** (must echo unchanged fields). No display-only caveat → the modified input is what executes and what surfaces.
- `PostToolUse` → `hookSpecificOutput.updatedToolOutput` "replaces the tool's result" before Claude sees it. **Transcript-safe.**
- The "display-only, transcript keeps the original" behavior applies ONLY to `MessageDisplay`, not to updatedInput/updatedToolOutput.
- Hook output format is `{"hookSpecificOutput": {"hookEventName": ..., ...}}`. The Python `{"action","tool_input"}` shape is WRONG and is not ported. (Architect fix #2.)
- Honest limitation: a secret the **model itself typed** is in its own assistant turn before the hook runs; PreToolUse changes execution + downstream display but cannot guarantee scrubbing the model's already-emitted token. The high-value, fully transcript-safe protection is therefore **tool results via PostToolUse** — which the Python original missed entirely.

## Threat model (explicit)
1. **Secret in a tool RESULT** (Claude runs `cat .env`, `env`, reads a config) → enters context. **PostToolUse `updatedToolOutput`** redacts to `[vault:ALIAS]` before Claude sees it. Primary, fully transcript-safe.
2. **Secret in an outbound tool INPUT** (Claude builds a command/file containing a key) → **PreToolUse `updatedInput`** vaults it and rewrites so the raw value never executes and never displays.
3. Out of scope for v1: a secret the user pastes directly into a chat message (no tool call fires; nothing to hook). Documented honestly.

## Hook design (single `vaultmcp hook` dispatches on hookEventName)
**PreToolUse:**
1. Parse stdin (`hook_event_name`, `tool_name`, `tool_input`).
2. **Egress first** (Bash only): replace any pre-existing `[vault:ALIAS]` with `$(<abs>/vaultmcp get ALIAS)` — a command substitution, NOT the raw value. Transcript shows the harmless `$(...)`; the shell resolves the real secret at execution (vault unlocked via keychain). Same shape as `op run`/`doppler run`.
3. **Ingress second**: run detection on the (post-egress) input. For each new secret: vault it (idempotent by value — re-seeing the same secret reuses its existing alias, so repeated `cat .env` does NOT spawn duplicate aliases; architect nit #2), audit it. Bash → replace with `$(<abs>/vaultmcp get NEW_ALIAS)`; other tools → replace with `[vault:NEW_ALIAS]` placeholder.

**Bash gate + absolute path (architect fix #1):** the Bash path triggers ONLY when `tool_name == "Bash"` (exact string; all other tools get the static `[vault:ALIAS]` placeholder). The substitution uses the hook's own absolute executable path from `os.Executable()` — `$(/Users/.../vaultmcp get ALIAS)` — so it works regardless of whether `vaultmcp` is on `$PATH` (GUI-launched Claude Code frequently has a minimal PATH). `vaultmcp install` records that same absolute path.
4. Return `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","updatedInput":<full object>}}`. If nothing changed, emit nothing (exit 0).

**PostToolUse:**
1. Parse stdin (`tool_response`/output).
2. Detect secrets in the result, vault them, replace with `[vault:ALIAS]`.
3. Return `{"hookSpecificOutput":{"hookEventName":"PostToolUse","updatedToolOutput":<redacted>}}`.

**Ordering safety (architect fix #3):** egress runs before ingress; egress emits `$(vaultmcp get ...)` which the detector's `^\$\(` allowlist skips, and ingress replacements are likewise `$(...)` or `[vault:...]` — both allowlisted. So a token created in one step is never re-processed by the other in the same pass. No loop, no re-exposure.

**Fail-open always** — any parse/IO/crypto error exits 0 with no output, leaving the tool call untouched. A bug in VaultMCP must never break Claude Code.

## Layer 2 = the Bash egress path above (run_with_secrets)
`$(<abs>/vaultmcp get ALIAS)` IS run_with_secrets: aliases resolve to real values only at shell-execution time, never in the transcript. Bash-only by design (`tool_name == "Bash"`) — only a shell has a deferred-execution context to defer into; other tools get the static `[vault:ALIAS]` placeholder. If the vault is locked at execution time, `vaultmcp get` exits non-zero with a stderr hint to unlock; the command fails loudly rather than running with an empty secret.

## CLI surface (parity + install)
`set`, `get`, `list`, `delete`, `status`, `audit [--last N]`, `unlock`, `lock`, `install`, `export-aliases`, `help`. `get` prints raw value only (pipe-friendly). `install` registers `<binpath> hook` as a PreToolUse matcher `.*` in `.claude/settings.json` (idempotent).

## Install / distribution ("very simple")
- `go install github.com/dubb-b/vaultmcp@latest` OR prebuilt binaries via `goreleaser` for darwin/linux/windows × amd64/arm64.
- `vaultmcp install` registers BOTH `PreToolUse` and `PostToolUse` hooks (matcher `.*`), idempotently.
- **Windows (architect fix #5):** the binary path written into `settings.json` is normalized with `filepath.ToSlash` so backslashes never corrupt the JSON. `go-keyring` uses Windows Credential Manager, which requires an interactive desktop session — if unavailable (service/unattended context) the tool fails with a clear, actionable error and points to passphrase mode, never a silent insecure fallback.
- `.go-version` pins 1.26.4 for source builds.

## Testing
- Unit: entropy scoring, every regex detector, allowlist, path heuristic, alias generation.
- Crypto round-trip: encrypt→decrypt, wrong key rejected, tampered ciphertext rejected (AEAD auth fail), salt/nonce uniqueness across saves. (done, green)
- Hook flow: real PreToolUse payloads → correct `updatedInput` redaction + Bash `$(vaultmcp get)` egress/ingress + fail-open on garbage. PostToolUse payloads → correct `updatedToolOutput` redaction. Validate exact JSON output shape against the doc spec (not the Python shape).
- Audit chain integrity (full-length SHA-256 chain, architect optional C — improvement over Python's 16-char truncation).
- **Security test (dedicated, `security_test.go`):** no plaintext secret ever written to store file (scan the encrypted bytes for the secret), no passphrase persisted to disk anywhere under `~/.vaultmcp`, file perms 0600/0700 enforced, tamper detection, AEAD rejects bit-flips, hook output never contains a raw vaulted value. Plus `gosec` + `staticcheck` clean.

## Sequence
1. Architect reviews & approves THIS plan. ← gate
2. Scaffold module + crypto + tests (crypto first, TDD).
3. Detection + vault + audit.
4. Layer 1 hook + CLI.
5. Verify Claude Code hook transcript semantics → build Layer 2 accordingly.
6. Security test + `gosec`/lint.
7. `/code-review` → fix. `/simplify` → fold in.
8. End-to-end install test on a clean settings.json. Loop until simple + green.
9. Replace Python files; update README.
```
