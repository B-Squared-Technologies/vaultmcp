# VaultMCP

Keep credentials out of coding-agent transcripts. VaultMCP is a single Go binary that runs as a PreToolUse / PostToolUse hook, detects secrets before they reach the conversation, and swaps them for aliases. The agent does its job; it just never sees the raw value.

Works with **Claude Code, Grok, Codex, and Cursor**. One static binary, no runtime dependencies. macOS, Linux, and Windows. The Go toolchain is needed only to build it.

## Install

```bash
go install github.com/B-Squared-Technologies/vaultmcp@latest
vaultmcp install --global
```

`--global` registers hooks in:

| Harness | File | Shape |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | nested `PreToolUse` / `PostToolUse` |
| Grok | same Claude file (compat on by default) | camelCase stdin (`run_terminal_command`, `toolResult`) |
| Codex | `~/.codex/hooks.json` | nested `PreToolUse` / `PostToolUse` (Claude-shaped) |
| Cursor | `~/.cursor/hooks.json` | `{version: 1, preToolUse, beforeShellExecution, postToolUse, afterShellExecution}` with a flat `command` |

`vaultmcp install` without `--global` still writes only the project's `.claude/settings.json`.

No Go toolchain? Grab a prebuilt binary from the [releases page](https://github.com/B-Squared-Technologies/vaultmcp/releases), put it on your `PATH`, and run `vaultmcp install --global`.

Restart each agent after install. Codex `/hooks` may ask you to trust the new file.

## How the hook is wired

`vaultmcp hook` reads one JSON event on stdin. It accepts Claude snake_case, Grok camelCase, Codex `Bash`, and Cursor `preToolUse` / `beforeShellExecution` (top-level `command` or `tool_input`). Shell tools (`Bash`, `run_terminal_command`, `Shell`) expand `[vault:ALIAS]` to `$(vaultmcp get ALIAS)`. Other tools get a `[vault:ALIAS]` placeholder.

You can paste the JSON by hand instead of using `install`. The hook needs no arguments.

## Limits

- Cursor `afterShellExecution` has no documented way to rewrite what the model sees. Pre-rewrite still works. Post-redact of `cat .env` may not stick in Cursor.
- Codex hooks can be off (`[features] hooks = false`) or waiting on `/hooks` trust.
- Fail-open: if VaultMCP errors, the tool call proceeds untouched.

## How it works

- **PreToolUse** (and Cursor `beforeShellExecution` / `preToolUse`) — scans tool inputs before they run. A detected secret is vaulted and replaced:
  - In **shell** commands → `$(vaultmcp get ALIAS)`, a command substitution. The transcript shows the harmless `$(...)`; the shell resolves the real value only at execution time (like `op run` / `doppler run`).
  - In other tools → a `[vault:ALIAS]` placeholder.
- **PostToolUse** (and Cursor `afterShellExecution` / `postToolUse`) — scans tool *results* (e.g. `cat .env`) and redacts secrets to `[vault:ALIAS]` before the model sees them, when the harness honors a rewritten result.

Detection is two-layered: **known-pattern regexes** (AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, JWTs, DB URLs, private keys) **plus a Shannon-entropy scan** that catches custom, high-randomness secrets no regex would know.

If VaultMCP ever errors, it **fails open** — the tool call proceeds untouched. A bug here can never break the agent.

## Usage

```bash
vaultmcp set STRIPE_KEY          # store a secret (prompts — no echo)
vaultmcp get STRIPE_KEY          # print a value (pipe-friendly)
vaultmcp list                    # list aliases (values masked)
vaultmcp delete STRIPE_KEY       # remove a secret (--yes to skip confirm)
vaultmcp status                  # vault + hook health
vaultmcp audit --last 50         # view the hash-chained audit log
vaultmcp unlock                  # cache the key for this machine
vaultmcp lock                    # clear the cached key
vaultmcp export-aliases          # print alias list for AGENTS.md / CLAUDE.md
```

Reference an alias directly in a prompt:

```
Deploy the Lambda using [vault:AWS_ACCESS_KEY] and [vault:AWS_SECRET]
```

In a shell tool call, the alias resolves to the real value at execution; the value never appears in the conversation. The CLI (`set` / `get` / `$(vaultmcp get ALIAS)`) works in any agent that can run a shell command, even if hooks are off.

## Unlocking the vault

The master key that encrypts your vault lives in your **OS keychain** by default — macOS Keychain, Windows Credential Manager, or Linux Secret Service (via `go-keyring`). Nothing secret touches disk.

**Headless or no keychain** (e.g. a Linux server with no Secret Service): VaultMCP falls back to **passphrase mode**. The master key is wrapped by an Argon2id-derived key in `~/.vaultmcp/key.enc` (your passphrase is never written to disk). For non-interactive use, set:

```bash
export VAULTMCP_KEY="your-passphrase"
```

Understand the tradeoff: anyone who can read your environment can read that passphrase.

## What gets detected

| Type | Pattern |
|---|---|
| AWS access key | `AKIA…` |
| GitHub token | `ghp_…`, `ghs_…` |
| OpenAI / Anthropic key | `sk-…`, `sk-ant-…` |
| Slack token | `xoxb-…`, `xoxp-…` |
| Stripe key | `stripe_sk_live_…` |
| Private key | `-----BEGIN … PRIVATE KEY-----` |
| JWT | `eyJ….….…` |
| DB / Redis / Mongo URI | `postgres://…:…@`, `redis://…@`, … |
| **Any high-entropy string** | 20+ chars, ≥3.5 bits/char Shannon entropy, ≥2 digits (code identifiers exempt) |

Not flagged: URLs, `${VARS}`, `$(cmd)`, existing `[vault:…]` aliases, UUIDs, long file paths, and ordinary prose.

## Security design

- **Encryption:** XChaCha20-Poly1305 (AEAD) — a 24-byte random nonce per write, encrypt-then-authenticate. Tampered stores are rejected.
- **Key derivation:** Argon2id (64 MiB, t=3) — memory-hard, well beyond PBKDF2.
- **Key storage:** OS keychain, or an Argon2id-wrapped key file. Never a plaintext passphrase on disk.
- **At rest:** `~/.vaultmcp/` is `0700`, `store.enc` is `0600`.
- **Audit:** every vault operation is logged to `~/.vaultmcp/audit.log`, hash-chained so tampering is detectable. Values are never logged — only alias names.

Run `vaultmcp audit` to review.

## Build from source

```bash
git clone https://github.com/B-Squared-Technologies/vaultmcp
cd vaultmcp
go build -o vaultmcp .   # Go 1.26+ (pinned via .go-version)
./vaultmcp install
```

## Philosophy

Secrets should never appear in an AI's context window — not because the AI isn't trusted, but because the context window is a transcript, and transcripts get stored, logged, and leaked. VaultMCP makes the secure path the path of least resistance.

## License

MIT
