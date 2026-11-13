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
| Codex | `~/.codex/hooks.json` | nested `PreToolUse` only (Claude-shaped) |
| Cursor | `~/.cursor/hooks.json` | `{version: 1, hooks: {preToolUse, beforeShellExecution, postToolUse, afterShellExecution}}` with a flat `command` |

`vaultmcp install` without `--global` still writes only the project's `.claude/settings.json`.

No Go toolchain? Grab a prebuilt binary from the [releases page](https://github.com/B-Squared-Technologies/vaultmcp/releases), put it on your `PATH`, and run `vaultmcp install --global`.

Restart each agent after install. Codex `/hooks` may ask you to trust the new file.

## How the hook is wired

`vaultmcp hook` reads one JSON event on stdin. It accepts Claude snake_case, Grok camelCase, Codex `Bash`, and Cursor `preToolUse` / `beforeShellExecution` (top-level `command` or `tool_input`). Shell tools (`Bash`, `run_terminal_command`, `Shell`) expand `[vault:ALIAS]` to `$(vaultmcp get ALIAS)`. Other tools get a `[vault:ALIAS]` placeholder.

You can paste the JSON by hand instead of using `install`. The hook needs no arguments.

## Limits

- Cursor `afterShellExecution` has no documented way to rewrite what the model sees. Pre-rewrite still works. Post-redact of `cat .env` may not stick in Cursor.
- Grok treats `PostToolUse` as passive: hook stdout is recorded but does not replace the result shown to the model. `cat .env` still reaches Grok; rely on Pre rewrite.
- Codex PostToolUse cannot rewrite tool results (`updatedToolOutput` is not in the schema). Only PreToolUse is registered. Codex hooks can also be off (`[features] hooks = false`) or waiting on `/hooks` trust.
- Fail-open: if VaultMCP errors, the tool call proceeds untouched. The one exception is a vault you locked yourself with `vaultmcp lock`: then every tool call is stopped until `vaultmcp unlock`.
- When the hook cannot reach the vault key and nobody locked the vault (for example an app that never loaded `VAULTMCP_KEY` from your shell profile), secrets are not hidden. The fix, on any system with an OS keychain: run `vaultmcp unlock` in a terminal and put the key in the keychain, where every app can reach it. Claude and Codex show a warning that says why and names that fix, at most once every 10 minutes in each session. Grok and Cursor have no documented way for a hook to show a warning on a call it allows, so there the hook stays silent: run `vaultmcp status` if in doubt.

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
vaultmcp list                    # list named secrets (values masked)
vaultmcp list --captured         # list what the hook captured by itself
vaultmcp delete STRIPE_KEY       # remove a secret (--yes to skip confirm)
vaultmcp prune --dry-run         # show which captures have expired (omit the flag to delete them)
vaultmcp migrate-captures        # move old hook captures out of store.enc (dry run; add --apply, --names lists every one)
vaultmcp status                  # vault + hook health
vaultmcp audit --last 50         # view the hash-chained audit log
vaultmcp lock                    # move the key out of the keychain into key.enc, behind a passphrase
vaultmcp unlock                  # type the passphrase, the key goes back into the keychain
vaultmcp recovery-code           # make a recovery code, shown once (--replace for a new one)
vaultmcp recover                 # bring the key back with the recovery code
vaultmcp export-aliases          # print alias list for AGENTS.md / CLAUDE.md
```

Reference an alias directly in a prompt:

```
Deploy the Lambda using [vault:AWS_ACCESS_KEY] and [vault:AWS_SECRET]
```

In a shell tool call, the alias resolves to the real value at execution; the value never appears in the conversation. The CLI (`set` / `get` / `$(vaultmcp get ALIAS)`) works in any agent that can run a shell command, even if hooks are off.

## Named secrets and captures

VaultMCP keeps two kinds of secret apart.

- **Named secrets** are the ones you store with `vaultmcp set NAME`. They live together in `store.enc`, they never expire, and only you change them. The hook reads that file and never writes it.
- **Captures** are secrets the hook found by itself in a tool input or result. Each one gets its own sealed file in `~/.vaultmcp/captured/`. Its alias is the kind of secret followed by 16 letters and digits taken from a keyed hash of the value. The same value always gets the same alias, and an alias never comes to mean a different value, so an old placeholder cannot quietly resolve to another secret. (One exception to "the same alias": a capture moved over from an older vault keeps its old name, so a value that is captured again after the move has two.) Each file is bound to its own alias and does not open under any other name. Because every capture is its own file, hooks running in parallel cannot lose each other's captures.

An alias is always looked up among the named secrets first, then among the captures. `vaultmcp list` shows the named secrets and a count of captures; `vaultmcp list --captured` shows the captures. If a secret you named turns up in a tool call, the hook uses your name for it and captures nothing.

**A capture can be the only copy of a value.** When the hook takes a secret out of a file an agent is writing, the file gets the placeholder and the capture holds the value. Nothing else does. Captures expire (see below), so if you want to keep such a value, store it under a name with `vaultmcp set`.

**Locked to the machine.** Capture files are sealed with a key derived from the master key and an identifier of the machine: the Hardware UUID on macOS, `/etc/machine-id` on Linux, `MachineGuid` on Windows. A copy of the vault folder does not open captures on another machine, even where the master key is known. The honest limits: a capture made in a moment when the identifier could not be read is sealed without it, and that one does open elsewhere with the master key. And the machine identifier is not a secret, so someone who holds the master key and also learns that machine's identifier can still open them. Named secrets in `store.enc` are not machine-locked. On a machine that exposes no identifier, captures still work but are not locked, and `vaultmcp status` says so.

**Expiry.** Captures are deleted when they stop being used. Named secrets never expire.

- A capture that was never used is deleted after 7 days. In practice that is a secret the hook only ever saw in a tool result.
- A capture that was used is deleted once it has gone 30 days without being used again.
- "Used" means any of: it was read (`vaultmcp get`, which is also what a shell substitution runs); its placeholder appeared in a tool input; the hook took its value out of a tool input, which is where a secret is on its way into a file or a command; or the hook met its value again an hour or more after the last time.
- Reading a file that contains a placeholder does not count. A placeholder that sits in a file for 30 days with no agent touching it stops resolving.
- A capture file that no longer opens (sealed on another machine, or damaged) is deleted after 30 days untouched. Temp files left by a killed hook are deleted after a day.

The hook does this cleanup at most once a day, up to 2000 files at a time, after it has answered the tool call. `vaultmcp prune` does all of it at once, and `vaultmcp prune --dry-run` only reports. Each pass that deletes something leaves one line in the audit log with the counts.

**Migrating an older vault.** Before captures had their own files, the hook stored them in `store.enc` beside your named secrets. `vaultmcp migrate-captures` shows what it would move, by name, and `vaultmcp migrate-captures --apply` moves it. Past 40 names it prints a count per kind, and `--names` prints them all. An entry moves only when its name is one the hook generates, the audit log shows the hook stored it, and the audit log never shows you setting it. Anything else stays where it is and is listed by name. Read the list before you apply: a moved secret expires like any other capture, and the choice is made from the audit log, so the command warns when lines of that log cannot be read. Moved captures keep their old alias, so placeholders already written into files and transcripts keep working until the capture expires. Before changing anything, `--apply` copies `store.enc` to `store.enc.pre-captures-<date>-<time>`. That backup still holds every capture in the old format, so delete it once you have confirmed the move.

## Unlocking the vault

The master key that encrypts your vault lives in your **OS keychain** by default — macOS Keychain, Windows Credential Manager, or Linux Secret Service (via `go-keyring`). In this mode the key is on disk only in sealed form: `recovery.enc`, which the recovery code opens, and, once you have used `vaultmcp lock`, `key.enc`, which your passphrase opens.

**Headless or no keychain** (e.g. a Linux server with no Secret Service): VaultMCP falls back to **passphrase mode**. The master key is wrapped by an Argon2id-derived key in `~/.vaultmcp/key.enc` (your passphrase is never written to disk). For non-interactive use, set:

```bash
export VAULTMCP_KEY="your-passphrase"
```

Understand the tradeoff: anyone who can read your environment can read that passphrase.

**The key is never replaced by accident.** A vault that already holds secrets was sealed with a key that exists somewhere. If VaultMCP cannot find that key, it stops and says so; it does not make a new one, because a new key would open nothing and would hide the old one. The usual cause is setting `VAULTMCP_KEY` on a machine whose key is in the keychain: unset it and the vault opens again.

## Recovery code

Every vault has one key. If the keychain entry is wiped or the passphrase is forgotten, the secrets are still on disk and nothing can open them. The recovery code is the way back in.

- **When you get it.** The first `vaultmcp set` makes the vault's key, and with it a recovery code: eight groups of four letters and digits, shown once. Save it away from the machine, in a password manager. VaultMCP keeps `recovery.enc`, a copy of the key that only the code opens, and never the code itself.
- **If nobody is at a terminal** (a setup script, a pipe), no code is made, because it would end up in a log. `vaultmcp status` says `NO RECOVERY CODE` until you run `vaultmcp recovery-code`.
- **Older vaults** have none. Run `vaultmcp recovery-code` once. It prints the notice on stderr and the code alone on stdout, so `vaultmcp recovery-code | your-password-manager` stores it without showing it.
- **Using it.** `vaultmcp recover` asks for the code at a prompt (never as an argument) and puts the same key back: into the keychain, or into a new `key.enc` under a passphrase you choose. Nothing is re-encrypted and every placeholder keeps working. A wrong code changes nothing.
- **A new code.** `vaultmcp recovery-code --replace` replaces `recovery.enc`, and the old code stops opening this folder. Without `--replace` the command refuses, so the code you saved cannot be ended by accident. Do not let an agent run this command: the code would be in its transcript.

The limits: the code is as powerful as the key, so anyone with the code and a copy of the vault folder can open everything. It opens the vault's files; it is not a backup of them. And because the key itself never changes, a new code does not shut out someone who already has the old code together with an old copy of the folder.

## Lock and unlock

Locking takes the key out of the keychain. It never deletes it.

- `vaultmcp lock` writes the key into `key.enc` behind a passphrase (it asks you to choose one the first time), reads the file back to prove the key is in it, and only then takes the key out of the OS keychain. It refuses if the vault has no recovery code, because a locked vault with a forgotten passphrase would otherwise be lost.
- `vaultmcp unlock` asks for the passphrase and puts the key back into the keychain. `key.enc` stays on disk after that, so choose the passphrase with care: from the first lock on, it protects a copy of the key.
- With `VAULTMCP_KEY` set, the vault is never locked for a program that has the variable. Run there at a terminal, `unlock` asks for no passphrase: it ends a lock that was left for the other programs, and, if the OS keychain is empty, asks whether to put the key there as well. Run there by a script or an agent, it refuses to end a lock. Say yes on a machine where some programs are not given the variable, such as an app started from the desktop: the keychain is the one place all of them can reach. The question goes only to a terminal, and anything but a typed yes leaves the keychain alone. A program that runs `unlock` under a pseudo-terminal counts as a person, here as at every prompt.
- `lock` always needs a person: the passphrase is typed at a prompt, so a script or an agent cannot lock the vault. Ending a lock with `unlock` needs a person too: it asks for the passphrase at a prompt, or, where `VAULTMCP_KEY` is set, has to be run at a terminal. That keeps an agent from ending a lock by running `unlock`. It is not a wall against a program that holds the variable: such a program is never stopped by a lock itself, and the lock marker is a file in the vault folder that it could delete. On a machine where `lock` should stop every agent, keep the key in the OS keychain and do not set the variable.
- While the vault is locked, the hook cannot hide secrets, so it **stops agent tool calls** with a message that says to run `vaultmcp unlock`. That is deliberate: an agent running with redaction silently off is the opposite of what locking is for.
- A vault that uses `VAULTMCP_KEY` cannot be locked, and `lock` says so: the passphrase is in the environment, so the vault is open to anything running as you. For the same reason, a session that has `VAULTMCP_KEY` set to the passphrase still opens a locked vault.
- The OS keychain holds one VaultMCP key per user, not one per vault folder. If you use several folders through `VAULTMCP_DIR`, give them passphrases with `VAULTMCP_KEY`.

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
- **What the keychain does not do:** it keeps the key encrypted on disk, which protects it from someone who has the disk and not your login. It does not hide the key from other programs running as you, and locking the screen does not change that. On macOS the key is saved through the system `security` tool, and any program can ask that tool for it with no prompt. The Linux Secret Service gives it to your programs in the same way, and Windows Credential Manager is expected to (not tested here). An agent's own shell could do that, just as it could run `vaultmcp get`. VaultMCP keeps secrets out of what the model reads. It is not a wall against a program that sets out to read them.
- **At rest:** `~/.vaultmcp/` and `captured/` are `0700`, `store.enc` and every capture file are `0600`.
- **Machine lock:** capture files use a key derived (HKDF-SHA256) from the master key and the machine's identifier. See [Named secrets and captures](#named-secrets-and-captures) for what that does and does not protect.
- **Bound to the alias:** each capture file is sealed with its alias as associated data, so a file copied to another name does not open there.
- **Recovery:** `recovery.enc` holds the master key sealed (Argon2id, XChaCha20-Poly1305) under a 160-bit recovery code that is shown once and never stored. Key files are written to a temp file, synced, and renamed into place.
- **Audit:** `set`, `get`, `delete`, `lock`, `unlock`, `recover`, a new recovery code, each capture, each migration and each prune that deleted something are logged to `~/.vaultmcp/audit.log`, hash-chained so tampering is detectable. A prune is logged as counts, without names. Values are never logged — only alias names. Hooks that write at the same moment can break the chain without anyone tampering, so a failed check is a reason to look, not proof.

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
