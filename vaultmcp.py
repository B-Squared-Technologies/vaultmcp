#!/usr/bin/env python3
"""
vaultmcp - CLI for managing your vaulted secrets
Usage:
  vaultmcp set <alias> <value>     Store a secret manually
  vaultmcp set <alias>             Store a secret (prompts for value)
  vaultmcp get <alias>             Retrieve a secret value
  vaultmcp list                    List all aliases (no values)
  vaultmcp delete <alias>          Remove a secret
  vaultmcp status                  Show vault health and stats
  vaultmcp audit [--last N]        View audit log
  vaultmcp unlock                  Cache passphrase for this session
  vaultmcp lock                    Clear cached passphrase
  vaultmcp export-aliases          Print alias list for CLAUDE.md injection
"""

import sys
import os
import json
import getpass
import hashlib
import hmac
import math
import struct
import secrets
import datetime
from pathlib import Path

VAULT_DIR  = Path.home() / ".vaultmcp"
STORE_FILE = VAULT_DIR / "store.enc"
AUDIT_FILE = VAULT_DIR / "audit.log"
LOCK_FILE  = VAULT_DIR / ".unlocked"

SALT_SIZE  = 32
KEY_SIZE   = 32
ITERATIONS = 260000

# --- Terminal colors ---
class C:
    RESET  = '\033[0m'
    BOLD   = '\033[1m'
    RED    = '\033[91m'
    GREEN  = '\033[92m'
    YELLOW = '\033[93m'
    BLUE   = '\033[94m'
    PURPLE = '\033[95m'
    CYAN   = '\033[96m'
    GRAY   = '\033[90m'
    WHITE  = '\033[97m'

def c(color, text):
    if not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.RESET}"

def ok(msg):    print(c(C.GREEN,  f"  + {msg}"))
def err(msg):   print(c(C.RED,    f"  x {msg}"), file=sys.stderr)
def info(msg):  print(c(C.CYAN,   f"  > {msg}"))
def warn(msg):  print(c(C.YELLOW, f"  ! {msg}"))
def dim(msg):   print(c(C.GRAY,   f"    {msg}"))

def header(title):
    print()
    print(c(C.BOLD + C.WHITE, f"  {title}"))
    print(c(C.GRAY, "  " + "─" * (len(title) + 2)))

# --- Crypto (same as hook.py, kept in sync) ---

def derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, ITERATIONS, dklen=KEY_SIZE)

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < len(data):
        stream_block = hmac.new(key, struct.pack('>Q', counter), 'sha512').digest()
        output.extend(stream_block)
        counter += 1
    keystream = bytes(output[:len(data)])
    return bytes(a ^ b for a, b in zip(data, keystream))

def _mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, 'sha256').digest()

def encrypt_store(data: dict, passphrase: str) -> bytes:
    salt       = secrets.token_bytes(SALT_SIZE)
    key        = derive_key(passphrase, salt)
    enc_key    = key[:16]
    mac_key    = key[16:]
    plaintext  = json.dumps(data).encode()
    ciphertext = _xor_encrypt(plaintext, enc_key)
    tag        = _mac(mac_key, salt + ciphertext)
    return salt + tag + ciphertext

def decrypt_store(blob: bytes, passphrase: str) -> dict:
    salt       = blob[:SALT_SIZE]
    stored_tag = blob[SALT_SIZE:SALT_SIZE+32]
    ciphertext = blob[SALT_SIZE+32:]
    key        = derive_key(passphrase, salt)
    enc_key    = key[:16]
    mac_key    = key[16:]
    expected   = _mac(mac_key, salt + ciphertext)
    if not hmac.compare_digest(stored_tag, expected):
        raise ValueError("Wrong passphrase or tampered store")
    return json.loads(_xor_encrypt(ciphertext, enc_key).decode())

# --- Auth ---

def get_passphrase(confirm=False) -> str:
    env = os.environ.get('VAULTMCP_KEY')
    if env:
        return env
    if LOCK_FILE.exists():
        return LOCK_FILE.read_text().strip()
    pw = getpass.getpass(c(C.CYAN, "  Passphrase: "))
    if confirm:
        pw2 = getpass.getpass(c(C.CYAN, "  Confirm:    "))
        if pw != pw2:
            err("Passphrases don't match.")
            sys.exit(1)
    LOCK_FILE.write_text(pw)
    LOCK_FILE.chmod(0o600)
    return pw

def load_store(passphrase: str) -> dict:
    if not STORE_FILE.exists():
        return {}
    try:
        return decrypt_store(STORE_FILE.read_bytes(), passphrase)
    except ValueError as e:
        err(str(e))
        sys.exit(1)

def save_store(store: dict, passphrase: str):
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    blob = encrypt_store(store, passphrase)
    STORE_FILE.write_bytes(blob)
    STORE_FILE.chmod(0o600)

# --- Audit ---

def audit(action: str, alias: str, context: str = ""):
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    entry = {
        "ts":      datetime.datetime.utcnow().isoformat() + "Z",
        "action":  action,
        "alias":   alias,
        "context": context[:120]
    }
    prev_hash = ""
    if AUDIT_FILE.exists():
        lines = AUDIT_FILE.read_text().strip().splitlines()
        if lines:
            prev_hash = hashlib.sha256(lines[-1].encode()).hexdigest()[:16]
    entry["chain"] = prev_hash
    with open(AUDIT_FILE, 'a') as f:
        f.write(json.dumps(entry) + "\n")

# --- Commands ---

def cmd_set(args):
    alias = args[0] if args else None
    value = args[1] if len(args) > 1 else None

    if not alias:
        err("Usage: vaultmcp set <alias> [value]")
        sys.exit(1)

    alias = alias.upper().replace('-', '_')

    if not value:
        value = getpass.getpass(c(C.CYAN, f"  Value for {alias}: "))

    if not value:
        err("Value cannot be empty.")
        sys.exit(1)

    pw    = get_passphrase(confirm=not STORE_FILE.exists())
    store = load_store(pw)
    existed = alias in store
    store[alias] = value
    save_store(store, pw)
    audit("set", alias, "cli")
    if existed:
        ok(f"Updated [{alias}]")
    else:
        ok(f"Stored  [{alias}]")

def cmd_get(args):
    if not args:
        err("Usage: vaultmcp get <alias>")
        sys.exit(1)
    alias = args[0].upper()
    pw    = get_passphrase()
    store = load_store(pw)
    if alias not in store:
        err(f"No secret found for alias [{alias}]")
        sys.exit(1)
    audit("get", alias, "cli")
    # Only print value (no decoration) so it can be piped
    print(store[alias])

def cmd_list(args):
    pw    = get_passphrase()
    store = load_store(pw)
    if not store:
        info("Vault is empty.")
        return
    header(f"Vault — {len(store)} secret(s)")
    for alias in sorted(store.keys()):
        val_preview = store[alias]
        masked = val_preview[:4] + "..." + val_preview[-4:] if len(val_preview) > 12 else "****"
        print(f"  {c(C.CYAN, alias):<40} {c(C.GRAY, masked)}")
    print()

def cmd_delete(args):
    if not args:
        err("Usage: vaultmcp delete <alias>")
        sys.exit(1)
    alias = args[0].upper()
    pw    = get_passphrase()
    store = load_store(pw)
    if alias not in store:
        err(f"[{alias}] not found in vault.")
        sys.exit(1)
    confirm = input(c(C.YELLOW, f"  Delete [{alias}]? (yes/no): ")).strip().lower()
    if confirm != 'yes':
        info("Cancelled.")
        return
    del store[alias]
    save_store(store, pw)
    audit("delete", alias, "cli")
    ok(f"Deleted [{alias}]")

def cmd_status(args):
    header("VaultMCP status")

    # Store
    if STORE_FILE.exists():
        pw    = get_passphrase()
        store = load_store(pw)
        ok(f"Store: {STORE_FILE}")
        info(f"Secrets: {len(store)} alias(es)")
    else:
        warn("Store: not initialized yet")

    # Hook — resolve the symlink so we find the real script dir, not ~/.local/bin
    hook_path = Path(__file__).resolve().parent / "hook.py"
    if hook_path.exists():
        ok(f"Hook:  {hook_path}")
    else:
        warn("Hook:  hook.py not found in same directory")

    # Claude settings
    settings_paths = [
        Path.cwd() / ".claude" / "settings.json",
        Path.home() / ".claude" / "settings.json",
    ]
    hook_registered = False
    for sp in settings_paths:
        if sp.exists():
            try:
                s = json.loads(sp.read_text())
                hooks = s.get('hooks', {}).get('PreToolUse', [])
                for h in hooks:
                    cmd = h.get('hooks', [{}])[0].get('command', '') if isinstance(h, dict) else ''
                    if 'vaultmcp' in cmd or 'hook.py' in cmd:
                        hook_registered = True
            except Exception:
                pass

    if hook_registered:
        ok("Claude Code: hook registered")
    else:
        warn("Claude Code: hook NOT registered — run 'vaultmcp install' to fix")

    # Session
    if LOCK_FILE.exists():
        ok("Session: unlocked (passphrase cached)")
    elif os.environ.get('VAULTMCP_KEY'):
        ok("Session: unlocked (VAULTMCP_KEY env var)")
    else:
        info("Session: locked (will prompt on next use)")

    # Audit
    if AUDIT_FILE.exists():
        lines = AUDIT_FILE.read_text().strip().splitlines()
        info(f"Audit log: {len(lines)} entries")
    else:
        info("Audit log: empty")

    print()

def cmd_audit(args):
    n = 20
    if '--last' in args:
        idx = args.index('--last')
        if idx + 1 < len(args):
            n = int(args[idx + 1])

    if not AUDIT_FILE.exists():
        info("Audit log is empty.")
        return

    lines = AUDIT_FILE.read_text().strip().splitlines()
    recent = lines[-n:]

    header(f"Audit log — last {len(recent)} entries")
    for line in recent:
        try:
            e = json.loads(line)
            ts     = e.get('ts', '')[:19].replace('T', ' ')
            action = e.get('action', '').upper()
            alias  = e.get('alias', '')
            ctx    = e.get('context', '')
            action_color = {
                'VAULT':  C.GREEN,
                'SET':    C.CYAN,
                'GET':    C.BLUE,
                'DELETE': C.RED,
            }.get(action, C.GRAY)
            print(f"  {c(C.GRAY, ts)}  {c(action_color, f'{action:<8}')}  {c(C.WHITE, alias):<35}  {c(C.GRAY, ctx)}")
        except Exception:
            dim(line)
    print()

def cmd_unlock(args):
    if LOCK_FILE.exists():
        info("Already unlocked for this session.")
        return
    if os.environ.get('VAULTMCP_KEY'):
        info("Unlocked via VAULTMCP_KEY env var.")
        return
    pw = getpass.getpass(c(C.CYAN, "  Passphrase: "))
    # Verify by attempting a load
    if STORE_FILE.exists():
        try:
            decrypt_store(STORE_FILE.read_bytes(), pw)
        except ValueError:
            err("Wrong passphrase.")
            sys.exit(1)
    LOCK_FILE.write_text(pw)
    LOCK_FILE.chmod(0o600)
    ok("Vault unlocked for this session.")

def cmd_lock(args):
    if LOCK_FILE.exists():
        LOCK_FILE.unlink()
        ok("Session passphrase cleared.")
    else:
        info("Already locked.")

def cmd_install(args):
    """Register the hook into .claude/settings.json"""
    hook_path = str(Path(__file__).resolve().parent / "hook.py")

    # Find or create settings file
    claude_dir = Path.cwd() / ".claude"
    settings_path = claude_dir / "settings.json"

    if not settings_path.exists():
        # Try global
        global_settings = Path.home() / ".claude" / "settings.json"
        if global_settings.exists():
            settings_path = global_settings
        else:
            claude_dir.mkdir(parents=True, exist_ok=True)

    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_text())
        except Exception:
            settings = {}
    else:
        settings = {}

    # Build hook entry
    hook_entry = {
        "matcher": ".*",
        "hooks": [
            {
                "type": "command",
                "command": f"python3 {hook_path}"
            }
        ]
    }

    hooks = settings.setdefault('hooks', {})
    pre   = hooks.setdefault('PreToolUse', [])

    # Check if already registered
    for h in pre:
        if isinstance(h, dict):
            for inner in h.get('hooks', []):
                if 'hook.py' in inner.get('command', '') or 'vaultmcp' in inner.get('command', ''):
                    ok("Hook already registered in settings.json")
                    return

    pre.append(hook_entry)
    settings_path.write_text(json.dumps(settings, indent=2))
    ok(f"Hook registered in {settings_path}")
    info("VaultMCP will now intercept credentials in all Claude Code sessions.")
    info("Run 'vaultmcp status' to verify.")

def cmd_export_aliases(args):
    """Print an alias reference block suitable for pasting into CLAUDE.md"""
    pw    = get_passphrase()
    store = load_store(pw)
    if not store:
        info("No secrets in vault yet.")
        return
    print()
    print("# VaultMCP — available secret aliases")
    print("# These aliases can be used in prompts. The values are secured locally.")
    print()
    for alias in sorted(store.keys()):
        print(f"- [vault:{alias}]")
    print()

def cmd_help(args):
    print(__doc__)

# --- Router ---

COMMANDS = {
    'set':            cmd_set,
    'get':            cmd_get,
    'list':           cmd_list,
    'delete':         cmd_delete,
    'remove':         cmd_delete,
    'status':         cmd_status,
    'audit':          cmd_audit,
    'unlock':         cmd_unlock,
    'lock':           cmd_lock,
    'install':        cmd_install,
    'export-aliases': cmd_export_aliases,
    'help':           cmd_help,
    '--help':         cmd_help,
    '-h':             cmd_help,
}

def main():
    if len(sys.argv) < 2:
        cmd_status([])
        return

    cmd  = sys.argv[1]
    args = sys.argv[2:]

    handler = COMMANDS.get(cmd)
    if not handler:
        err(f"Unknown command: {cmd}")
        cmd_help([])
        sys.exit(1)

    handler(args)

if __name__ == '__main__':
    main()
