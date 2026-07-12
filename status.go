package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dubb-b/vaultmcp/internal/keyring"
)

// keyringReady reports whether the OS keychain is usable here.
func keyringReady() bool { return keyring.Available() }

func cmdStatus(args []string) error {
	p := paths()
	fmt.Println("\n  VaultMCP status")
	fmt.Println("  ───────────────")

	// Store
	if fileExists(p.Store) {
		fmt.Printf("  store:   %s\n", p.Store)
	} else {
		fmt.Println("  store:   not initialized (run 'vaultmcp set')")
	}

	// Session / key — mirror the resolver's precedence: VAULTMCP_KEY wins
	// over the keychain, so report it first.
	_, inKeychain := keyring.FromKeychain()
	switch {
	case os.Getenv("VAULTMCP_KEY") != "":
		fmt.Println("  session: unlocked (VAULTMCP_KEY)")
	case inKeychain:
		fmt.Println("  session: unlocked (OS keychain)")
	case fileExists(p.Key):
		fmt.Println("  session: locked (passphrase mode — run 'vaultmcp unlock')")
	default:
		fmt.Println("  session: locked")
	}
	if !keyring.Available() {
		fmt.Println("  keychain: unavailable — passphrase mode")
	}

	// Hook registration
	if where := hookRegistered(); where != "" {
		fmt.Printf("  hooks:   registered (%s)\n", where)
	} else {
		fmt.Println("  hooks:   NOT registered — run 'vaultmcp install'")
	}

	// Audit
	if data, err := os.ReadFile(p.Audit); err == nil {
		n := len(strings.Split(strings.TrimSpace(string(data)), "\n"))
		fmt.Printf("  audit:   %d entries\n", n)
	} else {
		fmt.Println("  audit:   empty")
	}
	fmt.Println()
	return nil
}

// hookRegistered returns the settings file a vaultmcp hook is registered in, or
// "" if none.
func hookRegistered() string {
	candidates := []string{}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, filepath.Join(cwd, ".claude", "settings.json"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".claude", "settings.json"))
	}
	for _, sp := range candidates {
		// #nosec G304 -- sp is a resolved .claude/settings.json path, not user input.
		data, err := os.ReadFile(sp)
		if err != nil {
			continue
		}
		var settings map[string]any
		if json.Unmarshal(data, &settings) != nil {
			continue
		}
		hooks, _ := settings["hooks"].(map[string]any)
		for _, event := range hooks {
			list, _ := event.([]any)
			for _, entry := range list {
				m, _ := entry.(map[string]any)
				inner, _ := m["hooks"].([]any)
				for _, h := range inner {
					hm, _ := h.(map[string]any)
					if cmd, _ := hm["command"].(string); strings.Contains(cmd, "vaultmcp") {
						return sp
					}
				}
			}
		}
	}
	return ""
}
