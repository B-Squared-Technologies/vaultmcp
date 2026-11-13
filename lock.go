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
		// Not echoed: what follows the command may be a passphrase.
		return errors.New("unexpected argument: usage: vaultmcp lock (the passphrase is typed at a prompt, never given as an argument)")
	}
	p := paths()
	if os.Getenv("VAULTMCP_KEY") != "" {
		return errors.New("this vault cannot be locked while VAULTMCP_KEY is set: the passphrase is in the environment, so anything running as this user can open the vault. Take VAULTMCP_KEY out of the environment first")
	}
	inKeychain, ok := keyring.FromKeychain()
	if !ok {
		return lockWithoutKeychainKey(p)
	}
	if !opensStore(p, inKeychain) {
		return fmt.Errorf("the key in the OS keychain does not open store.enc in %s: it is most likely another vault folder's key. Nothing was changed", p.Dir)
	}
	if !fileExists(p.Recovery) {
		return errNoRecoveryCode
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
	// The entry was read before the passphrase prompt. It is one per user, so
	// look again: a key another vault folder put there meanwhile is not ours
	// to delete.
	if now, ok := keyring.FromKeychain(); !ok || subtle.ConstantTimeCompare(now, inKeychain) != 1 {
		_ = os.Remove(p.Locked)
		return errors.New("the key in the OS keychain changed while this command was running, so it was left alone and nothing was locked")
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

// errWrongKeyFile is for a key.enc that opens but holds a key store.enc was
// not sealed with: the file an earlier version left behind when VAULTMCP_KEY
// was set on a keychain vault. Calling such a vault unlocked would end a lock
// while the hook still cannot hide anything.
func errWrongKeyFile(p vault.Paths) error {
	return fmt.Errorf("key.enc opened, but the key in it does not open store.enc in %s, so nothing was changed. If you have the recovery code, run 'vaultmcp recover'", p.Dir)
}

// keychainPut stores master in the OS keychain unless another key is there.
// The entry is read again here, at the last moment: the caller looked before
// it asked for a passphrase, and in the time a person takes to type one,
// another vault folder's command may have put its own key there. The entry is
// one per user, and that key may have no other copy.
func keychainPut(master []byte) error {
	if now, ok := keyring.FromKeychain(); ok {
		if subtle.ConstantTimeCompare(now, master) == 1 {
			return nil
		}
		return errors.New("the OS keychain now holds a different key, most likely another vault folder's, and it was left alone")
	}
	return keyring.ToKeychain(master)
}

// writeLockMarker puts the marker on the disk before it returns. The caller
// removes the key from the keychain next, and a marker lost to a power cut
// after that would leave a locked vault that lets tool calls through.
func writeLockMarker(p vault.Paths) error {
	f, err := os.OpenFile(p.Locked, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(time.Now().UTC().Format(time.RFC3339) + "\n")
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(p.Locked)
		return err
	}
	syncDir(p.Dir)
	return nil
}

// errNoRecoveryCode: a locked vault whose passphrase is forgotten can only be
// opened with the recovery code. Without one, locking is how a vault gets lost.
var errNoRecoveryCode = errors.New("this vault has no recovery code yet, and a locked vault whose passphrase is forgotten cannot be opened without one. Run 'vaultmcp recovery-code' first, save the code, then lock")

// lockWithoutKeychainKey is `lock` when no key was found in the OS keychain.
// If key.enc is there, the key is already behind its passphrase, but nobody
// has said that this is on purpose, and saying so makes the hook stop tool
// calls. So it takes the passphrase: a script or an agent's shell must not be
// able to bring every agent session to a halt, and only someone who can also
// unlock may lock.
func lockWithoutKeychainKey(p vault.Paths) error {
	if !fileExists(p.Key) {
		fmt.Println("  nothing to lock: no vault key was found in the OS keychain")
		if holdsSecrets(p) {
			fmt.Println("  This folder holds secrets. If their key is lost, run 'vaultmcp recover'.")
		}
		return nil
	}
	if fileExists(p.Locked) {
		fmt.Println("  already locked: agent tool calls are stopped until you run 'vaultmcp unlock'")
		return nil
	}
	if !fileExists(p.Recovery) {
		return errNoRecoveryCode
	}
	pass, err := askSecret("Passphrase: ", false)
	if err != nil {
		return errors.New("the passphrase has to be typed at a terminal. Nothing was changed")
	}
	inFile, err := keyring.UnwrapFromFile(p.Key, pass)
	if err != nil {
		return errors.New("key.enc did not open with that passphrase. Nothing was changed")
	}
	if !opensStore(p, inFile) {
		return errWrongKeyFile(p)
	}
	if err := writeLockMarker(p); err != nil {
		return fmt.Errorf("the lock marker could not be written, so nothing was locked: %w", err)
	}
	_ = audit.Log(p.Audit, "lock", "MASTER", "cli", time.Now())
	fmt.Println("  vault locked: the key is in key.enc, behind your passphrase, and no key was found in the OS keychain")
	fmt.Println("  Agent tool calls are stopped until you run 'vaultmcp unlock'.")
	return nil
}

// endLock removes the marker and, if there was one, records that the lock
// ended. A marker that is there and cannot be removed is an error. It matters
// only to a caller that leaves the key out of the hook's reach: where the hook
// can reach the vault's key, it does not look at the marker.
func endLock(p vault.Paths) error {
	err := os.Remove(p.Locked)
	if err == nil {
		_ = audit.Log(p.Audit, "unlock", "MASTER", "cli", time.Now())
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func cmdUnlock(args []string) error {
	if len(args) > 0 {
		return errors.New("unexpected argument: usage: vaultmcp unlock (the passphrase is typed at a prompt, never given as an argument)")
	}
	p := paths()
	if env := os.Getenv("VAULTMCP_KEY"); env != "" {
		if !fileExists(p.Key) {
			return errors.New("VAULTMCP_KEY is set, but there is no key.enc for it to open")
		}
		inFile, err := keyring.UnwrapFromFile(p.Key, env)
		if err != nil {
			return errors.New("VAULTMCP_KEY is set, but it does not open key.enc: wrong passphrase or tampered key file")
		}
		if !opensStore(p, inFile) {
			return errWrongKeyFile(p)
		}
		_ = endLock(p)
		fmt.Println("  nothing to unlock: VAULTMCP_KEY is set and opens this vault, so it is never locked")
		return nil
	}
	if inKeychain, ok := keyring.FromKeychain(); ok {
		if !opensStore(p, inKeychain) {
			return fmt.Errorf("the OS keychain holds a key, but it does not open store.enc in %s: it is most likely another vault folder's key, and it was left alone. The keychain holds one key per user. To open this folder beside the other, give it a passphrase with VAULTMCP_KEY", p.Dir)
		}
		_ = endLock(p)
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
	if !opensStore(p, master) {
		return errWrongKeyFile(p)
	}
	if !keyring.Available() {
		// The passphrase proved who is asking, and on this machine there is
		// no keychain for the key to go back to: this is the only way the
		// owner can end a lock here without putting the passphrase in the
		// environment. So the lock ends, and the message says what that means.
		if err := endLock(p); err != nil {
			return fmt.Errorf("the passphrase is right, but the lock marker could not be removed, so agent tool calls stay stopped: %w", err)
		}
		fmt.Println("  the passphrase is right, but this machine has no OS keychain to keep the vault unlocked in.")
		fmt.Println("  Commands will ask for the passphrase each time. For unattended use, set VAULTMCP_KEY.")
		fmt.Println("  Agent tool calls are no longer stopped, and the hook cannot hide secrets from them until it can reach the key.")
		return nil
	}
	if err := keychainPut(master); err != nil {
		return fmt.Errorf("the passphrase is right, but the OS keychain refused the key, so the vault is still locked: %w. To open the vault without the keychain, set VAULTMCP_KEY to the passphrase and run 'vaultmcp unlock' again", err)
	}
	_ = os.Remove(p.Locked)
	_ = audit.Log(p.Audit, "unlock", "MASTER", "cli", time.Now())
	fmt.Println("  vault unlocked: the key is in the OS keychain again")
	return nil
}
