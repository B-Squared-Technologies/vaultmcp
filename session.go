package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
	"golang.org/x/term"
)

// errLocked is returned when no master key is reachable without prompting.
var errLocked = errors.New("vault is locked")

// masterKeyInteractive resolves the master key, prompting if needed. Used by
// CLI commands a human runs. On true first use it mints and persists a new key.
//
// Resolution precedence:
//  1. VAULTMCP_KEY env  -> passphrase mode, key.enc. NEVER touches the keychain.
//     Explicitly choosing an env passphrase must not write to the OS keychain
//     (which may be flaky and pop GUI dialogs), and keeps env/test use isolated.
//  2. OS keychain       -> the stored master key.
//  3. key.enc on disk   -> prompt for the passphrase and unwrap.
//  4. first use         -> mint a key; keychain if usable, else passphrase file.
func masterKeyInteractive(p vault.Paths, create bool) ([]byte, error) {
	if env := os.Getenv("VAULTMCP_KEY"); env != "" {
		return masterKeyFromPassphrase(p, env, create)
	}
	if k, ok := keyring.FromKeychain(); ok {
		return k, nil
	}
	if fileExists(p.Key) {
		pass, err := passphrase("Passphrase: ", false)
		if err != nil {
			return nil, err
		}
		k, err := keyring.UnwrapFromFile(p.Key, pass)
		if err != nil {
			return nil, errors.New("wrong passphrase or tampered key file")
		}
		return k, nil
	}
	if !create {
		return nil, errLocked
	}
	if err := p.EnsureDir(); err != nil {
		return nil, err
	}
	k := crypto.NewKey()
	if keyring.Available() {
		if err := keyring.ToKeychain(k); err == nil {
			return k, nil
		}
		// Available() probed true but the write still failed (e.g. a locked
		// keychain in an SSH session). Fall back rather than hard-fail.
		fmt.Fprintln(os.Stderr, "  warning: keychain write failed — using passphrase mode.")
	} else {
		fmt.Fprintln(os.Stderr, "  No OS keychain available — using passphrase mode.")
	}
	pass, err := passphrase("Create passphrase: ", true)
	if err != nil {
		return nil, errors.New("cannot prompt for a passphrase here — set VAULTMCP_KEY for headless use")
	}
	if err := keyring.WrapToFile(p.Key, k, pass); err != nil {
		return nil, err
	}
	return k, nil
}

// masterKeyFromPassphrase resolves (or, on first use, creates) the master key
// in passphrase mode using pass — wrapped into key.enc, never the keychain.
func masterKeyFromPassphrase(p vault.Paths, pass string, create bool) ([]byte, error) {
	if fileExists(p.Key) {
		k, err := keyring.UnwrapFromFile(p.Key, pass)
		if err != nil {
			return nil, errors.New("wrong passphrase or tampered key file")
		}
		return k, nil
	}
	if !create {
		return nil, errLocked
	}
	if err := p.EnsureDir(); err != nil {
		return nil, err
	}
	k := crypto.NewKey()
	if err := keyring.WrapToFile(p.Key, k, pass); err != nil {
		return nil, err
	}
	return k, nil
}

// masterKeyNonInteractive resolves the key without any prompt. Used by `get`
// (command substitution at execution) and the hook. Same precedence as the
// interactive path minus the prompts: VAULTMCP_KEY first, then keychain.
func masterKeyNonInteractive(p vault.Paths) ([]byte, error) {
	if env := os.Getenv("VAULTMCP_KEY"); env != "" && fileExists(p.Key) {
		if k, err := keyring.UnwrapFromFile(p.Key, env); err == nil {
			return k, nil
		}
	}
	if k, ok := keyring.FromKeychain(); ok {
		return k, nil
	}
	return nil, errLocked
}

// passphrase reads a passphrase from the terminal without echo. When confirm is
// true the user must enter it twice and it must be ≥8 chars. It does NOT consult
// VAULTMCP_KEY — env-passphrase handling lives in the master-key resolvers, so
// this stays a pure interactive prompt (also used for secret values).
func passphrase(prompt string, confirm bool) (string, error) {
	fmt.Fprint(os.Stderr, "  "+prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		if len(pw) < 8 {
			return "", errors.New("passphrase must be at least 8 characters")
		}
		fmt.Fprint(os.Stderr, "  Confirm passphrase: ")
		pw2, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(pw) != string(pw2) {
			return "", errors.New("passphrases do not match")
		}
	}
	return string(pw), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
