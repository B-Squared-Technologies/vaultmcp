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

**Every vault gets a recovery code.** One key seals everything, and until
now nothing could replace it. The first `vaultmcp set` now also shows a
recovery code, once. `vaultmcp recover` uses it to bring the same key back.
Existing vaults: run `vaultmcp recovery-code` and save what it prints.

**`lock` and `unlock` are a real pair.** `lock` moves the key from the OS
keychain into `key.enc` behind a passphrase, and `unlock` moves it back. The
key is never deleted. Before, `unlock` stored nothing and `lock` only
deleted.

**The hook says when it is not protecting you.** It used to stay silent
whenever it could not reach the key. Now a vault you locked on purpose stops
agent tool calls until you unlock it, and a key that is merely out of reach
(or that does not open the vault) gets a warning in Claude and Codex.

**New commands**

- `vaultmcp list --captured` lists what the hook captured.
- `vaultmcp prune [--dry-run]` deletes expired captures.
- `vaultmcp recovery-code` makes a recovery code, or a new one.
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

- A placeholder that sits in a file for 30 days without an agent using it
  stops resolving. Reading the file does not count as use.
- If two hooks repair the same damaged capture file in the same moment and
  something reads it in between, its "used" mark can be lost, and that
  capture then expires after 7 days where it would have had 30.
- Grok and Cursor give a hook no documented way to show a warning on a
  call it allows. When the key is out of reach there, the hook is silent.
- The OS keychain holds one VaultMCP key per user, not one per vault
  folder.
- A new recovery code does not shut out someone who already holds the old
  code together with an old copy of the vault folder: the key itself never
  changes.
- On Windows, a binary path with backslashes or spaces still breaks the
  shell rewrite. That fix is next.
