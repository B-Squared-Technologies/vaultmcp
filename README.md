# VaultMCP

Credential security for Claude Code. Intercepts secrets before they hit your session transcript.

## How it works

VaultMCP runs as a Claude Code `PreToolUse` hook. Every time Claude is about to execute a tool, the hook scans the payload for credentials using two methods:

1. **Known pattern matching** — AWS keys, GitHub tokens, OpenAI keys, JWTs, DB connection strings, private keys, and more
2. **Shannon entropy scoring** — catches custom internal API keys and any high-randomness string that looks like a secret, even with no known prefix

When a credential is detected:
- It's stored in an encrypted local vault (`~/.vaultmcp/store.enc`)
- Replaced with a human-readable alias like `[vault:AWS_ACCESS_KEY]`
- Claude receives the alias, not the value
- An append-only audit entry is written

Claude can still do its job — it just never sees the raw credential.

---

## Install

```bash
git clone https://github.com/yourname/vaultmcp
cd vaultmcp
bash setup.sh
```

That's it. The setup script:
- Detects your Python version
- Detects your platform (macOS keychain, Linux libsecret, or encrypted file)
- Registers the hook in your Claude Code settings
- Creates a `vaultmcp` CLI command

---

## Usage

### Automatic (the whole point)

Just use Claude Code normally. If you type or paste a credential, VaultMCP intercepts it automatically. Claude sees `[vault:ALIAS]` instead.

### Manual secret management

```bash
# Store a secret manually
vaultmcp set STRIPE_KEY

# List all aliases (no values shown)
vaultmcp list

# Retrieve a value (for piping into scripts)
vaultmcp get STRIPE_KEY

# Delete a secret
vaultmcp delete STRIPE_KEY

# Check vault health
vaultmcp status

# View audit log
vaultmcp audit
vaultmcp audit --last 50

# Unlock for this terminal session (skips per-use prompts)
vaultmcp unlock

# Lock (clear cached passphrase)
vaultmcp lock
```

### Reference aliases in Claude prompts

Instead of pasting a key, just use the alias directly in your message:

```
Use [vault:AWS_ACCESS_KEY] and [vault:AWS_SECRET] to deploy the Lambda function
```

Claude will call `run_with_secrets` (Layer 2, coming soon) to inject the values at execution time.

---

## Vault storage

Secrets are stored in `~/.vaultmcp/store.enc`:

- Key derived via **PBKDF2-HMAC-SHA256** (260,000 iterations)
- Encrypted with a **HMAC-based stream cipher** using stdlib only (no pip install)
- MAC-authenticated — tampered stores are rejected
- File permissions: `600` (owner read/write only)

On macOS, the vault directory is `~/.vaultmcp/` with `700` permissions.

### Passphrase options

**Option 1 — prompt on first use (default)**
VaultMCP prompts once per terminal session and caches for the session.

**Option 2 — env var (convenience tradeoff)**
```bash
export VAULTMCP_KEY="your-passphrase"
```
Add to your `~/.zshrc` or `~/.bashrc`. Understand the tradeoff: anyone who can read your environment can read your passphrase.

---

## What gets detected

| Type | Example pattern |
|---|---|
| AWS access key | `AKIA...` |
| GitHub token | `ghp_...`, `ghs_...` |
| OpenAI key | `sk-...` |
| Anthropic key | `sk-ant-...` |
| Slack token | `xoxb-...`, `xoxp-...` |
| Stripe key | `stripe_sk_live_...` |
| Private key | `-----BEGIN ... PRIVATE KEY-----` |
| JWT | `eyJ...` (three-part) |
| DB connection string | `postgres://user:pass@...` |
| Redis URL | `redis://:pass@...` |
| MongoDB URI | `mongodb://user:pass@...` |
| **Any high-entropy string** | 20+ chars, >3.5 bits/char Shannon entropy |

The last row is the important one — it catches custom internal API keys that no regex would know about.

---

## What does NOT get flagged

- URLs (`https://...`)
- Template variables (`${MY_VAR}`, `$(command)`)
- UUIDs
- Existing vault aliases (`[vault:...]`)
- Strings shorter than 20 characters
- Normal English text (low entropy)

---

## Audit log

Every vault operation is logged to `~/.vaultmcp/audit.log`:

```json
{"ts": "2026-04-14T10:23:11Z", "action": "vault", "alias": "AWS_ACCESS_KEY", "context": "Bash", "chain": "a3f9b2c1"}
```

Entries are hash-chained — each entry includes a hash of the previous entry, making tampering detectable.

View with `vaultmcp audit`.

---

## Claude Code settings

VaultMCP adds this to your `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 /path/to/vaultmcp/hook.py"
          }
        ]
      }
    ]
  }
}
```

The hook receives every tool call as JSON on stdin and returns a (possibly mutated) JSON response. If VaultMCP errors for any reason, it fails open — Claude Code continues normally.

---

## Running tests

```bash
python3 test_vaultmcp.py
```

Tests cover:
- Entropy scoring accuracy
- All known credential pattern detectors
- Allowlist (things that should NOT be flagged)
- Encrypt/decrypt round-trip
- Tamper detection
- Full hook flow with real payloads
- Audit log chain integrity

---

## Roadmap

- **Layer 2** — Go binary, OS keychain backend, `run_with_secrets` MCP tool
- **Layer 3** — OIDC agent identity, cloud federation, team vaults

---

## Philosophy

Secrets should never appear in an AI's context window. Not because we don't trust the AI — because the context window is a transcript, and transcripts get stored, logged, and leaked. VaultMCP makes the secure path the path of least resistance.
