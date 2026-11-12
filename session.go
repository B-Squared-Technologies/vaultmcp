package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"

	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
	"golang.org/x/term"
)

// errLocked is returned when no master key is reachable without prompting.
var errLocked = errors.New("vault is locked")

// holdsSecrets reports whether the vault folder already has something sealed
// in it: store.enc, or at least one capture file. Whatever is there was
// sealed under a master key that already exists somewhere, so a new key must
// not be made over it.
func holdsSecrets(p vault.Paths) bool {
	// A captures folder that cannot be listed counts as holding secrets: not
	// being able to look is no proof that nothing is there.
	captures, err := capture.Count(p.Captured)
	return fileExists(p.Store) || captures > 0 || err != nil
}

// keyHasFileCopy returns nil only when key.enc in this vault folder holds the
// same master key as the keychain entry, which is what makes that entry safe
// to remove. Whether this folder holds secrets is deliberately not asked: the
// keychain entry is one per user, shared by every vault folder, so an empty
// folder here says nothing about what the key seals elsewhere. A key.enc that
// merely exists is not enough either: it can hold another key.
func keyHasFileCopy(p vault.Paths, inKeychain []byte) error {
	if !fileExists(p.Key) {
		return fmt.Errorf("the OS keychain holds the only copy of the master key: there is no key.enc in %s. Every vault folder of this user shares that keychain entry, and removing it would make whatever it sealed unreadable for good, so nothing was changed. If you are certain nothing uses it, delete the %q entry in the OS keychain by hand", p.Dir, "vaultmcp")
	}
	pass := os.Getenv("VAULTMCP_KEY")
	if pass == "" {
		var err error
		if pass, err = passphrase("Passphrase for key.enc: ", false); err != nil {
			return errors.New("key.enc could not be checked against the key in the OS keychain without its passphrase, so nothing was changed")
		}
	}
	inFile, err := keyring.UnwrapFromFile(p.Key, pass)
	if err != nil {
		return errors.New("key.enc did not open with that passphrase, so it could not be confirmed as a copy of the key in the OS keychain. Nothing was changed")
	}
	if subtle.ConstantTimeCompare(inFile, inKeychain) != 1 {
		return fmt.Errorf("key.enc in %s holds a different key from the one in the OS keychain. Removing the keychain entry would make whatever it sealed unreadable for good, so nothing was changed", p.Dir)
	}
	return nil
}

// refuseNewKey is the error for a `set` that would have had to make a new
// master key over a vault that already holds secrets. A new key opens none of
// them, and once stored it is the key every later command finds first, which
// leaves the hook unable to read the store and redacting nothing. why says
// where the existing key was looked for, fix how to bring it back.
func refuseNewKey(p vault.Paths, why, fix string) error {
	return fmt.Errorf("%s, but %s already holds secrets sealed with an earlier key. A new key would not open them, so none was created and nothing was changed. %s, or move the folder away to start an empty vault", why, p.Dir, fix)
}

// masterKeyInteractive resolves the master key, prompting if needed. Used by
// CLI commands a human runs. On true first use it mints and persists a new key.
// First use means an empty vault: see holdsSecrets.
//
// Resolution precedence:
//  1. VAULTMCP_KEY env  -> passphrase mode, key.enc. NEVER touches the keychain.
//     Explicitly choosing an env passphrase must not write to the OS keychain
//     (which may be flaky and pop GUI dialogs), and keeps env/test use isolated.
//  2. OS keychain       -> the stored master key.
//  3. key.enc on disk   -> prompt for the passphrase and unwrap.
//  4. first use         -> mint a key; keychain if usable, else passphrase file.
//     Refused when the vault already holds secrets.
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
	if holdsSecrets(p) {
		return nil, refuseNewKey(p, "no master key was found in the OS keychain and there is no key.enc", "Restore the keychain entry or key.enc")
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
	if holdsSecrets(p) {
		return nil, refuseNewKey(p, "VAULTMCP_KEY is set and there is no key.enc for it to open", "If the key is in the OS keychain, unset VAULTMCP_KEY; otherwise restore key.enc")
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
