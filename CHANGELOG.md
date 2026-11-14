# Changelog

## 0.2.0

### Upgrade now if you use the default (keychain) setup

In 0.1.3 and earlier, `vaultmcp lock` could destroy a vault. With no
passphrase set, the vault's key lives in the OS keychain and nowhere else.
`lock` was documented as "clear the cached key", but it deleted that only
copy, and every stored secret became unreadable for good.

A second path led to the same place: on a machine whose key was in the
keychain, setting `VAULTMCP_KEY` and then running `vaultmcp set` created a
new key over the existing vault. The old secrets no longer opened and the
hook stopped redacting.

0.2.0 closes both, and adds the thing that was missing all along: a
recovery code, so that a lost key is no longer the end of a vault. It cannot
bring back a key that is already gone. If `set` once made a second key on
your machine, the first one is still in the keychain: when `vaultmcp list`
fails with a decryption error while `VAULTMCP_KEY` is set, unset it and try
again.

Versions 0.1.0 through 0.1.3 are withdrawn: their release downloads are
removed and `go.mod` retracts them, so Go marks them as retracted and shows
the reason.

### What changed, and why

**Secrets the hook finds are kept apart from the ones you store.**
Before, both lived in one file, `store.enc`. The hook rewrote that file on
every capture, so hooks running side by side could lose each other's work,
captures piled up forever, and a busy machine ended up with thousands of
entries nobody chose to keep. Now:

- Secrets you store with `vaultmcp set` stay in `store.enc`. The hook reads
  that file and never writes it.
- Each secret the hook finds gets its own sealed file in
  `~/.vaultmcp/captured/`, named from a keyed hash of the value. The same
  value gets the same name, and a name never comes to mean another value.
- Capture files are sealed for the machine that made them, and each one is
  bound to its own name.

**Captures expire.** Never used: 7 days. Used: 30 days after the last use.
A secret the hook took out of a tool input counts as used from the start,
because the placeholder left behind may be the only pointer to it. Named
secrets never expire. The README section "Named secrets and captures" has
the exact rules. If you want to keep a captured value, store it under a
name.

**Vaults have a recovery code.** One key seals everything, and until
now nothing could replace it. The first `vaultmcp set` now also shows a
recovery code, once. `vaultmcp recover` uses it to bring the same key back.
Existing vaults: run `vaultmcp recovery-code` and save what it prints.

**`lock` and `unlock` are a real pair.** `lock` takes the key out of the OS
keychain and leaves it in `key.enc` behind a passphrase, and `unlock` puts
it back. The key is never deleted. Before, `unlock` stored nothing and
`lock` only deleted. `lock` asks for the passphrase at a prompt on every
path, so a script or an agent cannot lock a vault. `unlock` needs a person
too: it asks for the passphrase, or, where `VAULTMCP_KEY` is set, has to be
run at a terminal.

**The hook says when it is not protecting you.** It used to stay silent
whenever it could not reach the key. Now a vault you locked on purpose stops
agent tool calls until you unlock it, and a key that is merely out of reach
(or that does not open the vault) gets a warning in Claude. Codex is sent
the same warning, but `codex exec` does not display it.

**New commands**

- `vaultmcp list --captured` lists what the hook captured.
- `vaultmcp prune [--dry-run]` deletes expired captures.
- `vaultmcp recovery-code` makes a recovery code. With `--replace` it makes
  a new one in place of the old.
- `vaultmcp recover` brings the key back with it.
- `vaultmcp migrate-captures [--apply] [--names]` moves captures made by
  older versions out of `store.enc`. It backs the file up first, shows what
  it will move by name, and changes nothing without `--apply`. Old
  placeholders keep resolving.

### Changes in behaviour

- `vaultmcp lock` no longer deletes anything. It needs a recovery code to
  exist, asks for a passphrase, and refuses when `VAULTMCP_KEY` is set.
- `vaultmcp unlock` puts the key back into the keychain. Where there is
  nothing to unlock, it says that and no longer prints "vault unlocked".
- With `VAULTMCP_KEY` set and the OS keychain empty, `vaultmcp unlock` asks
  whether to put the key in the keychain as well, so that a program which
  was not given the variable can reach it. Only a person at a terminal is
  asked, and anything but a typed yes leaves the keychain alone.
- The warning for a key that is out of reach now names the fix: run
  `vaultmcp unlock` in a terminal, or `vaultmcp recover` when there is no
  `key.enc` for a passphrase to open.
- Run where `VAULTMCP_KEY` is set, `vaultmcp unlock` ends a lock that was
  left for other programs only at a terminal, and says that it did. Run by
  a script or an agent it refuses, and the lock stays. With no lock, it
  says where to run it to be asked about the keychain.
- A lock never stops a program that has `VAULTMCP_KEY`: that program holds
  a working key, and could delete the lock marker, which is a file. To have
  `vaultmcp lock` stop every agent on a machine, keep the key in the OS
  keychain there and do not set the variable.
- Not verified on Windows: Git Bash's default window is expected to report
  no terminal to a native program. If so, every prompt here (`set`, `lock`,
  `unlock`, `recover`) has to be run from cmd, PowerShell or under `winpty`.
- While a vault is locked with `vaultmcp lock`, the hook stops agent tool
  calls. In every other case it still never blocks.
- The first `vaultmcp set` prints a recovery code on stderr when a person is
  at the terminal.
- `vaultmcp set` refuses to create a new key over a vault that already
  holds secrets.
- `prune` and `migrate-captures` reject arguments they do not know. Before,
  a mistyped `--dry-run` ran as a real prune.
- `vaultmcp status` counts named secrets and captures separately, and says
  whether captures are locked to this machine.
- `vaultmcp install` no longer removes another tool's hook when that hook
  shares a matcher entry with vaultmcp's.
- `vaultmcp install` no longer takes a hook for its own because its path
  has `vaultmcp` in it somewhere. Before, such a hook made install skip its
  own registration, and could be removed. A hook is ours when the program it
  runs is vaultmcp with the argument `hook`, or a script named
  `vaultmcp-hook`, also when a shell is handed one of those.
- `vaultmcp install` puts the binary's path in double quotes when it has a
  space or another special character in it, so the hook command runs in sh
  and in Git Bash. A plain path is registered exactly as before. A bare
  registration that an earlier version made for such a path never ran:
  `install` now replaces it with the quoted one.
- A binary path with a space or another special character in it now works
  in the commands the hook rewrites, when bash runs them (Git Bash on
  Windows, where backslashes are also handled). In PowerShell a plain path
  works. A path with a space or special character does not: the
  substitution fails there and the command gets an empty value in place of
  the secret.

### Upgrading

1. Replace the binary. Nothing changes on disk until a secret is captured.
2. Run `vaultmcp recovery-code` and save the code away from the machine.
3. Run `vaultmcp migrate-captures` and read the list.
4. Run `vaultmcp migrate-captures --apply`.
5. When you are satisfied, delete the `store.enc.pre-captures-*` backup. It
   still holds every old capture.

Do not change the vault's master key on a machine that has capture files:
captures are sealed with a key derived from it.

### Known limits

- A binary path with an apostrophe in it still breaks a rewritten command
  when the secret sat inside single quotes: the shell reports a syntax
  error and the command does not run. Nothing is exposed.
- A hook command with a quoted path (a binary under a path with a space)
  does not run where a tool hands hook commands to PowerShell. cmd.exe is
  not tested.
- `install` knows vaultmcp's hook in its plain forms, behind `env`, and
  handed to a shell with `-c`. A hook wrapped some other way (inside an
  `if`, a subshell, a wrapper program) is not known, and `install` adds its
  own registration beside it, so the hook runs twice. Take one out by hand.
- Inside backticks, a binary path with `$`, a backtick or a backslash in it
  is not escaped correctly. Use `$( )` in such a command.
- An app that was not started from a terminal does not get a
  `VAULTMCP_KEY` set in a shell profile. Put the key in the OS keychain for
  such apps: see "Limits" in the README.
- A placeholder that sits in a file for 30 days without an agent using it
  stops resolving. Reading the file does not count as use.
- If two hooks repair the same damaged capture file in the same moment and
  something reads it in between, its "used" mark can be lost, and that
  capture then expires after 7 days where it would have had 30.
- An agent that runs `vaultmcp recovery-code` gets the code in its
  transcript. Run it yourself.
- Two vault commands run in the same instant (two `recovery-code
  --replace`, or `lock` against another folder's `unlock`) are not kept
  apart by a lock. Each one checks the keychain again just before it
  changes it and stages its files under its own name, which leaves a gap
  of milliseconds. Run them one at a time.
- Cursor support has not been run in a live Cursor. It is written from
  Cursor's hook documentation and checked only by this project's tests.
- Grok and Cursor give a hook no documented way to show a warning on a
  call it allows. When the key is out of reach there, the hook is silent.
- Codex accepts the warning for a key that is out of reach, but
  `codex exec` (0.162.1 and 0.169.0) does not display it. An interactive
  Codex session is unconfirmed.
- Codex skips a new or changed hook, with no message, until it is approved
  in Codex `/hooks`.
- Codex runs shell commands in a sandbox that cannot read the macOS
  keychain. With the key only in the keychain, the hook still hides a
  secret, but the command that should fetch it gets an empty value. Give
  Codex's shell `VAULTMCP_KEY` as well. It holds the passphrase for
  `key.enc`, and a keychain-only vault has no `key.enc` until its first
  `vaultmcp lock`, which has to be run before the variable is set.
- The OS keychain holds one VaultMCP key per user, not one per vault
  folder.
- "A person at the terminal" means stderr is a terminal. An agent's shell
  that runs under a pseudo-terminal counts, so a first `vaultmcp set` run
  by an agent there shows the recovery code in that agent's transcript.
  Make the first key yourself.
- A new recovery code does not shut out someone who already holds the old
  code together with an old copy of the vault folder: the key itself never
  changes.
