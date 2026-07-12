# VaultMCP

Keep credentials out of Claude Code's transcript. VaultMCP is a single Go binary that runs as a Claude Code hook, detects secrets before they reach the conversation, and swaps them for aliases. Claude does its job; it just never sees the raw value.

Works on **macOS, Linux, and Windows** — one static binary, no runtime to install.

## Install

```bash
go install github.com/dubb-b/vaultmcp@latest
vaultmcp install
```

`vaultmcp install` registers the hooks in your Claude Code `settings.json` (idempotent). That's it — VaultMCP now intercepts credentials in every session.

No Go toolchain? Grab a prebuilt binary from the releases page, put it on your `PATH`, and run `vaultmcp install`.

## How it works

VaultMCP registers two Claude Code hooks:

- **PreToolUse** — scans tool inputs before they run. A detected secret is vaulted and replaced:
  - In **Bash** commands → `$(vaultmcp get ALIAS)`, a command substitution. The transcript shows the harmless `$(...)`; your shell resolves the real value only at execution time (like `op run` / `doppler run`).
  - In other tools → a `[vault:ALIAS]` placeholder.
- **PostToolUse** — scans tool *results* (e.g. when Claude runs `cat .env`) and redacts secrets to `[vault:ALIAS]` before Claude ever sees them.

Detection is two-layered: **known-pattern regexes** (AWS, GitHub, OpenAI, Anthropic, Slack, Stripe, JWTs, DB URLs, private keys) **plus a Shannon-entropy scan** that catches custom, high-randomness secrets no regex would know.

If VaultMCP ever errors, it **fails open** — the tool call proceeds untouched. A bug here can never break Claude Code.

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
vaultmcp export-aliases          # print alias list for CLAUDE.md
```

Reference an alias directly in a prompt:

```
Deploy the Lambda using [vault:AWS_ACCESS_KEY] and [vault:AWS_SECRET]
```

In a Bash tool call, the alias resolves to the real value at execution; the value never appears in the conversation.

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
| **Any high-entropy string** | 20+ chars, ≥3.5 bits/char Shannon entropy |

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
git clone https://github.com/dubb-b/vaultmcp
cd vaultmcp
go build -o vaultmcp .   # Go 1.26+ (pinned via .go-version)
./vaultmcp install
```

## Philosophy

Secrets should never appear in an AI's context window — not because the AI isn't trusted, but because the context window is a transcript, and transcripts get stored, logged, and leaked. VaultMCP makes the secure path the path of least resistance.
