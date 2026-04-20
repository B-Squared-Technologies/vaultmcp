#!/usr/bin/env bash
# VaultMCP setup script
# Detects your environment and wires everything up automatically
# Usage: bash setup.sh

set -e

VAULT_DIR="$HOME/.vaultmcp"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/hook.py"
CLI="$SCRIPT_DIR/vaultmcp.py"

# --- Colors ---
RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; GRAY='\033[90m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "${GREEN}  + $1${RESET}"; }
err()  { echo -e "${RED}  x $1${RESET}" >&2; }
info() { echo -e "${CYAN}  > $1${RESET}"; }
warn() { echo -e "${YELLOW}  ! $1${RESET}"; }
dim()  { echo -e "${GRAY}    $1${RESET}"; }
hdr()  { echo -e "\n${BOLD}  $1${RESET}\n${GRAY}  ──────────────────────────${RESET}"; }

hdr "VaultMCP setup"

# --- Python detection ---
hdr "Detecting Python"

PYTHON=""
for candidate in python3 python3.12 python3.11 python3.10 python3.9 python; do
    if command -v "$candidate" &>/dev/null; then
        VER=$("$candidate" -c 'import sys; print(sys.version_info.major, sys.version_info.minor)')
        MAJOR=$(echo $VER | cut -d' ' -f1)
        MINOR=$(echo $VER | cut -d' ' -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 8 ]; then
            PYTHON="$candidate"
            ok "Found: $candidate ($(${candidate} --version 2>&1 | head -1))"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    err "Python 3.8+ is required but not found."
    echo ""
    echo "  Install via Homebrew:  brew install python3"
    echo "  Or download:           https://python.org"
    exit 1
fi

# --- Platform detection ---
hdr "Detecting platform"

PLATFORM=""
if [[ "$OSTYPE" == "darwin"* ]]; then
    PLATFORM="macos"
    ok "macOS detected"
    if command -v security &>/dev/null; then
        ok "Keychain available (security CLI found)"
        KEYCHAIN_BACKEND="macos_keychain"
    else
        warn "security CLI not found — using encrypted file store"
        KEYCHAIN_BACKEND="file"
    fi
elif grep -qi microsoft /proc/version 2>/dev/null; then
    PLATFORM="wsl2"
    ok "WSL2 detected"
    warn "No keychain access in WSL2 — using encrypted file store"
    KEYCHAIN_BACKEND="file"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    PLATFORM="linux"
    ok "Linux detected"
    if command -v secret-tool &>/dev/null; then
        ok "libsecret available (secret-tool found)"
        KEYCHAIN_BACKEND="linux_keychain"
    else
        warn "secret-tool not found — using encrypted file store"
        dim "Install with: sudo apt install libsecret-tools"
        KEYCHAIN_BACKEND="file"
    fi
else
    warn "Unknown platform — using encrypted file store"
    KEYCHAIN_BACKEND="file"
fi

# --- Vault directory ---
hdr "Initializing vault"

mkdir -p "$VAULT_DIR"
chmod 700 "$VAULT_DIR"
ok "Vault directory: $VAULT_DIR"

# Write platform config
cat > "$VAULT_DIR/config.json" << EOF
{
  "platform": "$PLATFORM",
  "keychain_backend": "$KEYCHAIN_BACKEND",
  "python": "$PYTHON",
  "hook": "$HOOK",
  "cli": "$CLI",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
chmod 600 "$VAULT_DIR/config.json"
ok "Config written: $VAULT_DIR/config.json"

# --- Claude Code hook registration ---
hdr "Registering Claude Code hook"

# Find Claude settings — prefer project-local, fall back to global
CLAUDE_SETTINGS=""
if [ -f ".claude/settings.json" ]; then
    CLAUDE_SETTINGS=".claude/settings.json"
    info "Using project-local settings: .claude/settings.json"
elif [ -f "$HOME/.claude/settings.json" ]; then
    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    info "Using global settings: ~/.claude/settings.json"
else
    # Create global settings
    mkdir -p "$HOME/.claude"
    echo '{}' > "$HOME/.claude/settings.json"
    CLAUDE_SETTINGS="$HOME/.claude/settings.json"
    info "Created global settings: ~/.claude/settings.json"
fi

# Use Python to safely inject the hook (handles existing JSON properly)
$PYTHON - <<PYEOF
import json, sys
from pathlib import Path

settings_path = Path("$CLAUDE_SETTINGS")
hook_cmd = "$PYTHON $HOOK"

try:
    settings = json.loads(settings_path.read_text())
except Exception:
    settings = {}

hook_entry = {
    "matcher": ".*",
    "hooks": [{"type": "command", "command": hook_cmd}]
}

hooks = settings.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])

# Check if already registered
already = False
for h in pre:
    if isinstance(h, dict):
        for inner in h.get("hooks", []):
            if "hook.py" in inner.get("command", "") or "vaultmcp" in inner.get("command", ""):
                already = True

if already:
    print("  already_registered")
else:
    pre.append(hook_entry)
    settings_path.write_text(json.dumps(settings, indent=2))
    print("  registered")
PYEOF

ok "Hook registered in $CLAUDE_SETTINGS"

# --- CLI symlink ---
hdr "Installing CLI"

# Make vaultmcp.py executable
chmod +x "$CLI"

# Try to create a symlink in a PATH location
CLI_LINK=""
for dir in "$HOME/.local/bin" "$HOME/bin" "/usr/local/bin"; do
    if [ -d "$dir" ] && echo "$PATH" | grep -q "$dir"; then
        CLI_LINK="$dir/vaultmcp"
        break
    fi
done

if [ -n "$CLI_LINK" ]; then
    ln -sf "$CLI" "$CLI_LINK"
    ok "CLI symlink: $CLI_LINK"
    info "Run 'vaultmcp status' from anywhere"
else
    warn "Could not find a writable PATH directory for CLI symlink"
    info "Add this alias to your shell profile:"
    dim "alias vaultmcp='$PYTHON $CLI'"
    echo ""
    SHELL_PROFILE=""
    if [ -f "$HOME/.zshrc" ]; then SHELL_PROFILE="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then SHELL_PROFILE="$HOME/.bashrc"
    elif [ -f "$HOME/.bash_profile" ]; then SHELL_PROFILE="$HOME/.bash_profile"
    fi

    if [ -n "$SHELL_PROFILE" ]; then
        read -p "  Auto-add alias to $SHELL_PROFILE? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "" >> "$SHELL_PROFILE"
            echo "# VaultMCP" >> "$SHELL_PROFILE"
            echo "alias vaultmcp='$PYTHON $CLI'" >> "$SHELL_PROFILE"
            ok "Alias added to $SHELL_PROFILE"
            warn "Run 'source $SHELL_PROFILE' or open a new terminal to activate"
        fi
    fi
fi

# --- Shell session tip ---
hdr "Optional: passphrase shortcut"

echo "  VaultMCP will prompt for your passphrase on first use each session."
echo "  To skip the prompt, add this to your shell profile:"
echo ""
dim "  export VAULTMCP_KEY='your-passphrase'"
echo ""
warn "  Only do this if you trust your machine's security."
echo ""

# --- Done ---
hdr "Setup complete"

ok "VaultMCP is installed and active"
echo ""
echo -e "  ${CYAN}Next steps:${RESET}"
dim "  vaultmcp status          — verify everything is working"
dim "  vaultmcp set MY_KEY      — manually store a secret"
dim "  vaultmcp list            — see all your aliases"
dim "  vaultmcp audit           — view access log"
echo ""
echo -e "  ${GRAY}VaultMCP will silently intercept credentials you type or paste"
echo -e "  into Claude Code and vault them automatically.${RESET}"
echo ""
