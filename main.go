// Command vaultmcp keeps credentials out of Claude Code's transcript. It runs
// as PreToolUse/PostToolUse hooks and provides a CLI to manage vaulted secrets.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/hook"
	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
	"golang.org/x/term"
)

const usage = `vaultmcp — keep secrets out of Claude Code's transcript

Usage:
  vaultmcp set <alias> [value]   Store a secret (prompts for value if omitted)
  vaultmcp get <alias>           Print a secret value (pipe-friendly)
  vaultmcp list                  List aliases (values masked)
  vaultmcp delete <alias> [--yes]  Remove a secret (--yes skips the confirm)
  vaultmcp status                Show vault + hook health
  vaultmcp audit [--last N]      Show the audit log
  vaultmcp unlock                Cache the key for this machine/session
  vaultmcp lock                  Clear the cached key
  vaultmcp install [--global]    Register hooks in this project (or ~/.claude with --global)
  vaultmcp export-aliases        Print alias list for CLAUDE.md
  vaultmcp hook                  (internal) run as a Claude Code hook`

func main() {
	if len(os.Args) < 2 {
		_ = cmdStatus(nil)
		return
	}
	args := os.Args[2:]
	var err error
	switch os.Args[1] {
	case "hook":
		err = cmdHook()
	case "set":
		err = cmdSet(args)
	case "get":
		err = cmdGet(args)
	case "list":
		err = cmdList(args)
	case "delete", "remove":
		err = cmdDelete(args)
	case "status":
		err = cmdStatus(args)
	case "audit":
		err = cmdAudit(args)
	case "unlock":
		err = cmdUnlock(args)
	case "lock":
		err = cmdLock(args)
	case "install":
		err = cmdInstall(args)
	case "export-aliases":
		err = cmdExportAliases(args)
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s\n", os.Args[1], usage)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}
}

func paths() vault.Paths {
	p, err := vault.DefaultPaths()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		os.Exit(1)
	}
	return p
}

// cmdHook is the Claude Code entrypoint. It must always exit 0 and must never
// emit anything but valid hook JSON (or nothing) — failing open on any problem.
func cmdHook() error {
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil || len(stdin) == 0 {
		return nil
	}
	p := paths()
	key, err := masterKeyNonInteractive(p)
	if err != nil {
		// Locked and non-interactive: cannot vault now. Fail open silently so
		// we never block the tool call. (status/unlock guide the user.)
		return nil
	}
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	out := hook.Process(stdin, hook.Deps{Paths: p, MasterKey: key, ExePath: exe, Now: time.Now()})
	if out != nil {
		_, _ = os.Stdout.Write(out)
	}
	return nil
}

func cmdSet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vaultmcp set <alias> [value]")
	}
	alias := normalizeAlias(args[0])
	p := paths()
	key, err := masterKeyInteractive(p, true)
	if err != nil {
		return err
	}
	var value string
	if len(args) > 1 {
		value = args[1]
		fmt.Fprintln(os.Stderr, "  warning: passing a secret as an argument is visible in `ps` and shell history.")
		fmt.Fprintln(os.Stderr, "           omit the value to be prompted securely instead.")
	} else {
		v, err := passphrase(fmt.Sprintf("Value for %s: ", alias), false)
		if err != nil {
			return err
		}
		value = v
	}
	if value == "" {
		return fmt.Errorf("value cannot be empty")
	}
	store, err := vault.Load(p.Store, key)
	if err != nil {
		return err
	}
	_, existed := store[alias]
	store[alias] = value
	if err := vault.Save(p.Store, store, key); err != nil {
		return err
	}
	_ = audit.Log(p.Audit, "set", alias, "cli", time.Now())
	if existed {
		fmt.Printf("  updated [%s]\n", alias)
	} else {
		fmt.Printf("  stored  [%s]\n", alias)
	}
	return nil
}

func cmdGet(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: vaultmcp get <alias>")
	}
	alias := normalizeAlias(args[0])
	p := paths()
	key, err := masterKeyNonInteractive(p)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock' or set VAULTMCP_KEY")
	}
	store, err := vault.Load(p.Store, key)
	if err != nil {
		return err
	}
	val, ok := store[alias]
	if !ok {
		return fmt.Errorf("no secret for alias [%s]", alias)
	}
	_ = audit.Log(p.Audit, "get", alias, "cli", time.Now())
	// Raw value when piped, so $(vaultmcp get X) is clean; add a newline on a
	// terminal so the shell prompt doesn't run into the value.
	fmt.Print(val)
	if term.IsTerminal(int(os.Stdout.Fd())) {
		fmt.Println()
	}
	return nil
}

func cmdList(args []string) error {
	p := paths()
	key, err := masterKeyInteractive(p, false)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock'")
	}
	store, err := vault.Load(p.Store, key)
	if err != nil {
		return err
	}
	if len(store) == 0 {
		fmt.Println("  vault is empty")
		return nil
	}
	aliases := sortedKeys(store)
	fmt.Printf("\n  Vault — %d secret(s)\n\n", len(store))
	for _, a := range aliases {
		fmt.Printf("  %-36s %s\n", a, mask(store[a]))
	}
	fmt.Println()
	return nil
}

func cmdDelete(args []string) error {
	var alias string
	yes := false
	for _, a := range args {
		switch a {
		case "--yes", "-y":
			yes = true
		default:
			if alias == "" {
				alias = normalizeAlias(a)
			}
		}
	}
	if alias == "" {
		return fmt.Errorf("usage: vaultmcp delete <alias> [--yes]")
	}
	p := paths()
	key, err := masterKeyInteractive(p, false)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock'")
	}
	store, err := vault.Load(p.Store, key)
	if err != nil {
		return err
	}
	if _, ok := store[alias]; !ok {
		return fmt.Errorf("[%s] not found", alias)
	}
	if !yes {
		fmt.Printf("  delete [%s]? (yes/no): ", alias)
		var confirm string
		_, _ = fmt.Scanln(&confirm)
		if strings.ToLower(strings.TrimSpace(confirm)) != "yes" {
			fmt.Println("  cancelled")
			return nil
		}
	}
	delete(store, alias)
	if err := vault.Save(p.Store, store, key); err != nil {
		return err
	}
	_ = audit.Log(p.Audit, "delete", alias, "cli", time.Now())
	fmt.Printf("  deleted [%s]\n", alias)
	return nil
}

func cmdAudit(args []string) error {
	n := 20
	for i, a := range args {
		if a == "--last" && i+1 < len(args) {
			if v, err := strconv.Atoi(args[i+1]); err == nil {
				n = v
			}
		}
	}
	p := paths()
	data, err := os.ReadFile(p.Audit)
	if err != nil {
		fmt.Println("  audit log is empty")
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if n < len(lines) {
		lines = lines[len(lines)-n:]
	}
	ok, _ := audit.Verify(p.Audit)
	fmt.Printf("\n  Audit log — last %d entries (chain %s)\n\n", len(lines), tern(ok, "intact", "BROKEN"))
	for _, line := range lines {
		var e audit.Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		ts := strings.Replace(e.TS, "T", " ", 1)
		if len(ts) > 19 {
			ts = ts[:19]
		}
		fmt.Printf("  %s  %-8s %-32s %s\n", ts, strings.ToUpper(e.Action), e.Alias, e.Context)
	}
	fmt.Println()
	return nil
}

func cmdUnlock(args []string) error {
	p := paths()
	if _, ok := keyring.FromKeychain(); ok {
		fmt.Println("  already unlocked")
		return nil
	}
	if _, err := masterKeyInteractive(p, false); err != nil {
		return err
	}
	fmt.Println("  vault unlocked")
	return nil
}

func cmdLock(args []string) error {
	if err := keyring.DeleteFromKeychain(); err != nil {
		return err
	}
	fmt.Println("  cached key cleared")
	return nil
}

func cmdExportAliases(args []string) error {
	p := paths()
	key, err := masterKeyInteractive(p, false)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock'")
	}
	store, err := vault.Load(p.Store, key)
	if err != nil {
		return err
	}
	if len(store) == 0 {
		fmt.Println("  vault is empty")
		return nil
	}
	fmt.Println("\n# VaultMCP — available secret aliases")
	fmt.Println("# Use these in prompts; values are secured locally.")
	fmt.Println()
	for _, a := range sortedKeys(store) {
		fmt.Printf("- [vault:%s]\n", a)
	}
	fmt.Println()
	return nil
}

// --- helpers ---

func normalizeAlias(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", "_"))
}

func sortedKeys(m vault.Store) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func mask(v string) string {
	if len(v) > 12 {
		return v[:4] + "…" + v[len(v)-4:]
	}
	return "****"
}

func tern(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}
