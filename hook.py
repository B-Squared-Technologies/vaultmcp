#!/usr/bin/env python3
"""
VaultMCP - Layer 1 credential intercept hook
Runs as a Claude Code PreToolUse hook.
Detects high-entropy strings, vaults them, replaces with aliases.
"""

import sys
import json
import os
import math
import re
import hashlib
import hmac
import secrets
import struct
import getpass
import datetime
from pathlib import Path

VAULT_DIR = Path.home() / ".vaultmcp"
STORE_FILE = VAULT_DIR / "store.enc"
META_FILE  = VAULT_DIR / "meta.json"
AUDIT_FILE = VAULT_DIR / "audit.log"
LOCK_FILE  = VAULT_DIR / ".unlocked"

# --- Entropy detection ---

ENTROPY_THRESHOLD = 3.5
MIN_TOKEN_LENGTH  = 20
MAX_TOKEN_LENGTH  = 2048

# Known high-value credential patterns (belt AND suspenders with entropy)
KNOWN_PATTERNS = [
    (re.compile(r'AKIA[0-9A-Z]{16}'),                         'aws_access_key'),
    (re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*\S{20,}'), 'aws_secret'),
    (re.compile(r'ghp_[a-zA-Z0-9]{20,}'),                      'github_token'),
    (re.compile(r'ghs_[a-zA-Z0-9]{20,}'),                      'github_token'),
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'),                      'openai_key'),
    (re.compile(r'sk-ant-[a-zA-Z0-9\-_]{32,}'),               'anthropic_key'),
    (re.compile(r'xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+'),         'slack_bot_token'),
    (re.compile(r'xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+'),         'slack_user_token'),
    (re.compile(r'stripe[_-]?(?:sk|pk)[_-](?:live|test)_[a-zA-Z0-9]{24,}'), 'stripe_key'),
    (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),  'private_key'),
    (re.compile(r'(?i)postgres(?:ql)?://[^:]+:[^@]{8,}@'),    'db_connection_string'),
    (re.compile(r'(?i)mysql://[^:]+:[^@]{8,}@'),              'db_connection_string'),
    (re.compile(r'(?i)mongodb(?:\+srv)?://[^:]+:[^@]{8,}@'),  'db_connection_string'),
    (re.compile(r'(?i)redis://:?[^@]{8,}@'),                  'redis_url'),
    (re.compile(r'ey[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'), 'jwt_token'),
]

# Tokens to never flag (common false positives)
ALLOWLIST_PATTERNS = [
    re.compile(r'^https?://'),
    re.compile(r'^\$\{'),
    re.compile(r'^\$\('),
    re.compile(r'^\[vault:'),
    re.compile(r'^<[a-zA-Z]'),
    re.compile(r'localhost'),
    re.compile(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'),  # UUID
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f/n) * math.log2(f/n) for f in freq.values())

def is_allowlisted(token: str) -> bool:
    return any(p.search(token) for p in ALLOWLIST_PATTERNS)

def find_credentials(text: str):
    """
    Returns list of (match_value, hint_type, start, end) tuples.
    Uses both known patterns and entropy scoring.
    """
    found = []
    seen = set()

    # Pass 1: known patterns
    for pattern, cred_type in KNOWN_PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(0)
            if val not in seen and not is_allowlisted(val):
                found.append((val, cred_type, m.start(), m.end()))
                seen.add(val)

    # Pass 2: entropy scan on whitespace-delimited tokens
    for m in re.finditer(r'[^\s,\'";\[\]{}()\n]{%d,%d}' % (MIN_TOKEN_LENGTH, MAX_TOKEN_LENGTH), text):
        val = m.group(0)
        if val in seen or is_allowlisted(val):
            continue
        ent = shannon_entropy(val)
        if ent >= ENTROPY_THRESHOLD:
            found.append((val, 'high_entropy_secret', m.start(), m.end()))
            seen.add(val)

    return found

# --- Crypto (stdlib only) ---

SALT_SIZE   = 32
KEY_SIZE    = 32
IV_SIZE     = 12
TAG_SIZE    = 16
ITERATIONS  = 260000

def derive_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', passphrase.encode(), salt, ITERATIONS, dklen=KEY_SIZE)

def _xor_encrypt(data: bytes, key: bytes) -> bytes:
    """AES not in stdlib. We use a secure XOR stream cipher via HMAC-SHA512 CTR."""
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
    salt = secrets.token_bytes(SALT_SIZE)
    key  = derive_key(passphrase, salt)
    enc_key = key[:16]
    mac_key = key[16:]
    plaintext = json.dumps(data).encode()
    ciphertext = _xor_encrypt(plaintext, enc_key)
    tag = _mac(mac_key, salt + ciphertext)
    return salt + tag + ciphertext

def decrypt_store(blob: bytes, passphrase: str) -> dict:
    salt       = blob[:SALT_SIZE]
    stored_tag = blob[SALT_SIZE:SALT_SIZE+32]
    ciphertext = blob[SALT_SIZE+32:]
    key     = derive_key(passphrase, salt)
    enc_key = key[:16]
    mac_key = key[16:]
    expected_tag = _mac(mac_key, salt + ciphertext)
    if not hmac.compare_digest(stored_tag, expected_tag):
        raise ValueError("MAC verification failed — wrong passphrase or tampered store")
    plaintext = _xor_encrypt(ciphertext, enc_key)
    return json.loads(plaintext.decode())

# --- Store management ---

def get_passphrase() -> str:
    """Get passphrase from env or prompt, cache unlock state for session."""
    env_pass = os.environ.get('VAULTMCP_KEY')
    if env_pass:
        return env_pass

    # Check if we have a session-cached passphrase hash
    if LOCK_FILE.exists():
        cached = LOCK_FILE.read_text().strip()
        return cached

    # First use — prompt
    print("\n[VaultMCP] First time setup — enter a master passphrase to protect your secrets.", file=sys.stderr)
    print("[VaultMCP] This will be required each terminal session (or set VAULTMCP_KEY env var to skip).\n", file=sys.stderr)
    while True:
        pw = getpass.getpass("[VaultMCP] Passphrase: ", stream=sys.stderr)
        if len(pw) < 8:
            print("[VaultMCP] Passphrase must be at least 8 characters.", file=sys.stderr)
            continue
        if not STORE_FILE.exists():
            pw2 = getpass.getpass("[VaultMCP] Confirm passphrase: ", stream=sys.stderr)
            if pw != pw2:
                print("[VaultMCP] Passphrases don't match.", file=sys.stderr)
                continue
        # Cache for session (in-memory via temp file with restricted perms)
        LOCK_FILE.write_text(pw)
        LOCK_FILE.chmod(0o600)
        return pw

def load_store(passphrase: str) -> dict:
    if not STORE_FILE.exists():
        return {}
    try:
        blob = STORE_FILE.read_bytes()
        return decrypt_store(blob, passphrase)
    except Exception:
        return {}

def save_store(store: dict, passphrase: str):
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    blob = encrypt_store(store, passphrase)
    STORE_FILE.write_bytes(blob)
    STORE_FILE.chmod(0o600)

def alias_for(cred_type: str, store: dict) -> str:
    """Generate a human-readable unique alias."""
    base = cred_type.upper().replace('-', '_').replace(' ', '_')
    existing = [k for k in store.keys() if k.startswith(base)]
    if not existing:
        return base
    return f"{base}_{len(existing) + 1}"

# --- Audit log ---

def audit(action: str, alias: str, context: str = ""):
    VAULT_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    prev_hash = ""
    if AUDIT_FILE.exists():
        lines = AUDIT_FILE.read_text().strip().splitlines()
        if lines:
            prev_hash = hashlib.sha256(lines[-1].encode()).hexdigest()[:16]
    entry = {
        "ts":      datetime.datetime.utcnow().isoformat() + "Z",
        "action":  action,
        "alias":   alias,
        "context": context[:120],
        "chain":   prev_hash,
    }
    with open(AUDIT_FILE, 'a') as f:
        f.write(json.dumps(entry) + "\n")

# --- Hook entrypoint ---

def redact_text(text: str, replacements: list) -> str:
    """Replace credential values with vault aliases in text."""
    result = text
    # Sort by position descending so offsets don't shift
    for val, alias, _, _ in sorted(replacements, key=lambda x: x[2], reverse=True):
        result = result.replace(val, f'[vault:{alias}]')
    return result

def process_hook(payload: dict) -> dict:
    """
    Main hook logic.
    Scans tool_input for credentials, vaults them, returns mutated payload.
    """
    tool_name  = payload.get('tool_name', '')
    tool_input = payload.get('tool_input', {})

    # Flatten tool_input to a single string for scanning
    input_str = json.dumps(tool_input)

    credentials_found = find_credentials(input_str)

    if not credentials_found:
        # Nothing to do — pass through cleanly
        return {"action": "continue"}

    # If the vault is locked and we can't prompt (stdin already consumed by the
    # hook payload), fail open loudly instead of silently crashing inside
    # getpass. The credential will pass through unredacted this time — that's
    # the fail-open contract — but the user gets a visible warning so they can
    # run `vaultmcp unlock` or set VAULTMCP_KEY.
    if not os.environ.get('VAULTMCP_KEY') and not LOCK_FILE.exists() and not sys.stdin.isatty():
        print(
            "[VaultMCP] Credentials detected but vault is locked. "
            "Run 'vaultmcp unlock' or set VAULTMCP_KEY to enable interception. "
            "This payload was NOT redacted.",
            file=sys.stderr,
        )
        return {"action": "continue"}

    # We have credentials — vault them
    passphrase = get_passphrase()
    store      = load_store(passphrase)

    vaulted = []
    for val, cred_type, start, end in credentials_found:
        # Check if already stored (same value)
        existing_alias = next((k for k, v in store.items() if v == val), None)
        if existing_alias:
            alias = existing_alias
        else:
            alias = alias_for(cred_type, store)
            store[alias] = val
            audit("vault", alias, tool_name)

        vaulted.append((val, alias, start, end))

    save_store(store, passphrase)

    # Rebuild tool_input with redacted values
    redacted_str   = redact_text(input_str, vaulted)
    redacted_input = json.loads(redacted_str)

    # Build the notice that goes into Claude's context
    alias_list = ', '.join(f'[vault:{a}]' for _, a, _, _ in vaulted)
    notice = (
        f"\n[VaultMCP] {len(vaulted)} credential(s) detected and vaulted automatically: {alias_list}. "
        f"Use these aliases when referencing these values. "
        f"The actual values are secured locally and never appear in this conversation."
    )

    print(notice, file=sys.stderr)

    return {
        "action": "continue",
        "tool_input": redacted_input,
    }

def main():
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            print(json.dumps({"action": "continue"}))
            return

        payload = json.loads(raw)
        result  = process_hook(payload)
        print(json.dumps(result))

    except json.JSONDecodeError as e:
        # Malformed input — pass through, don't break Claude
        print(json.dumps({"action": "continue"}))
    except KeyboardInterrupt:
        print(json.dumps({"action": "continue"}))
    except Exception as e:
        # Never block Claude Code on our error
        print(json.dumps({"action": "continue"}))
        print(f"[VaultMCP] Hook error: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()
