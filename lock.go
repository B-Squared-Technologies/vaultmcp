package main

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// Locking moves the master key; it never deletes it. An unlocked vault has
// its key in the OS keychain, where the hook reads it without asking anyone.
// `lock` makes sure key.enc holds that same key behind a passphrase and only
// then takes the key out of the keychain. `unlock` asks for the passphrase
// and puts it back. At every moment the key is in at least one of the two.
//
// The marker file p.Locked records that the vault was locked on purpose: only
// `lock` writes it. The
// hook stops agent tool calls only when it finds that marker AND cannot reach
// the key: a vault whose key is merely out of reach (a keychain that is not
// available in this session, a passphrase that was never exported) looks the
// same from the key's side, and must not bring every agent to a halt.

func cmdLock(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unknown argument %q: usage: vaultmcp lock", args[0])
	}
	p := paths()
	if os.Getenv("VAULTMCP_KEY") != "" {
		return errors.New("this vault cannot be locked while VAULTMCP_KEY is set: the passphrase is in the environment, so anything running as this user can open the vault. Take VAULTMCP_KEY out of the environment first")
	}
	inKeychain, ok := keyring.FromKeychain()
	if !ok {
		if fileExists(p.Key) {
			// The key is already out of the keychain, but nobody has said yet
			// that this is on purpose. Running `lock` says it.
			if !fileExists(p.Locked) {
				if err := writeLockMarker(p); err != nil {
					return fmt.Errorf("the lock marker could not be written, so agent tool calls are not stopped: %w", err)
				}
				_ = audit.Log(p.Audit, "lock", "MASTER", "cli", time.Now())
			}
			fmt.Println("  already locked: the key is in key.enc behind its passphrase and not in the OS keychain")
			fmt.Println("  Agent tool calls are stopped until you run 'vaultmcp unlock'.")
			return nil
		}
		fmt.Println("  nothing to lock: there is no vault key in the OS keychain")
		return nil
	}
	if !opensStore(p, inKeychain) {
		return fmt.Errorf("the key in the OS keychain does not open store.enc in %s: it is most likely another vault folder's key. Nothing was changed", p.Dir)
	}
	// A locked vault whose passphrase is forgotten can only be opened with
	// the recovery code. Without one, locking is how a vault gets lost.
	if !fileExists(p.Recovery) {
		return errors.New("this vault has no recovery code yet, and a locked vault whose passphrase is forgotten cannot be opened without one. Run 'vaultmcp recovery-code' first, save the code, then lock")
	}
	if fileExists(p.Key) {
		pass, err := askSecret("Passphrase: ", false)
		if err != nil {
			return errors.New("the passphrase has to be typed at a terminal. Nothing was changed")
		}
		inFile, err := keyring.UnwrapFromFile(p.Key, pass)
		if err != nil {
			return errors.New("key.enc did not open with that passphrase. Nothing was changed")
		}
		if subtle.ConstantTimeCompare(inFile, inKeychain) != 1 {
			return fmt.Errorf("key.enc in %s holds a different key from the one in the OS keychain. Taking the keychain entry away would make whatever it sealed unreadable, so nothing was changed", p.Dir)
		}
	} else {
		pass, err := askSecret("Create passphrase: ", true)
		if err != nil {
			return fmt.Errorf("no passphrase was set (%w). Nothing was changed", err)
		}
		// Read back and compared inside writeKeyCopy, before the keychain
		// entry is touched.
		if err := writeKeyCopy(p.Key, inKeychain, pass); err != nil {
			return err
		}
	}
	// The marker goes down first. While the key is still in the keychain the
	// hook ignores it, so there is no moment in which the key is gone and a
	// tool call is let through unredacted.
	if err := writeLockMarker(p); err != nil {
		return fmt.Errorf("the lock marker could not be written, so nothing was locked and the key is still in the OS keychain: %w", err)
	}
	if err := keyring.DeleteFromKeychain(); err != nil {
		_ = os.Remove(p.Locked)
		return fmt.Errorf("the key could not be taken out of the OS keychain, so the vault is still unlocked: %w", err)
	}
	_ = audit.Log(p.Audit, "lock", "MASTER", "cli", time.Now())
	fmt.Println("  vault locked: the key is now only in key.enc, behind your passphrase")
	fmt.Println("  Agent tool calls are stopped until you run 'vaultmcp unlock'.")
	return nil
}

func writeLockMarker(p vault.Paths) error {
	return os.WriteFile(p.Locked, []byte(time.Now().UTC().Format(time.RFC3339)+"\n"), 0o600)
}

func cmdUnlock(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("unknown argument %q: usage: vaultmcp unlock", args[0])
	}
	p := paths()
	if env := os.Getenv("VAULTMCP_KEY"); env != "" {
		if !fileExists(p.Key) {
			return errors.New("VAULTMCP_KEY is set, but there is no key.enc for it to open")
		}
		if _, err := keyring.UnwrapFromFile(p.Key, env); err != nil {
			return errors.New("VAULTMCP_KEY is set, but it does not open key.enc: wrong passphrase or tampered key file")
		}
		_ = os.Remove(p.Locked)
		fmt.Println("  nothing to unlock: VAULTMCP_KEY is set and opens this vault, so it is never locked")
		return nil
	}
	if inKeychain, ok := keyring.FromKeychain(); ok {
		if !opensStore(p, inKeychain) {
			return fmt.Errorf("the OS keychain holds a key, but it does not open store.enc in %s: it is most likely another vault folder's key, and it was left alone. The keychain holds one key per user. To open this folder beside the other, give it a passphrase with VAULTMCP_KEY", p.Dir)
		}
		_ = os.Remove(p.Locked)
		fmt.Println("  already unlocked: the key is in the OS keychain")
		return nil
	}
	if !fileExists(p.Key) {
		if fileExists(p.Recovery) {
			return errors.New("no key was found in the OS keychain and there is no key.enc. Run 'vaultmcp recover' and type the recovery code")
		}
		return errors.New("nothing to unlock: no vault key was found in the OS keychain and there is no key.enc")
	}
	pass, err := askSecret("Passphrase: ", false)
	if err != nil {
		return errors.New("the passphrase has to be typed at a terminal")
	}
	master, err := keyring.UnwrapFromFile(p.Key, pass)
	if err != nil {
		return errors.New("wrong passphrase or tampered key file")
	}
	if !keyring.Available() {
		// The passphrase proved who is asking, so a lock set on purpose is
		// over, but there is nowhere to keep the vault open.
		_ = os.Remove(p.Locked)
		fmt.Println("  the passphrase is right, but this machine has no OS keychain to keep the vault unlocked in.")
		fmt.Println("  Commands will ask for the passphrase each time. For unattended use, set VAULTMCP_KEY.")
		return nil
	}
	if err := keyring.ToKeychain(master); err != nil {
		return fmt.Errorf("the passphrase is right, but the OS keychain refused the key, so the vault is still locked: %w", err)
	}
	_ = os.Remove(p.Locked)
	_ = audit.Log(p.Audit, "unlock", "MASTER", "cli", time.Now())
	fmt.Println("  vault unlocked: the key is in the OS keychain again")
	return nil
}
