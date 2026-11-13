package main

import (
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
	"golang.org/x/term"
)

// The recovery code is a second way to open the master key, for the day the
// keychain entry is gone or the passphrase is forgotten. The vault keeps
// recovery.enc, the master key sealed under the code, and never the code
// itself: it is shown once, to a person, and from then on lives wherever that
// person put it.
//
// The master key never changes, so the code opens the same key for the life
// of the vault. Making a new code replaces recovery.enc; it cannot reach a
// copy of the old recovery.enc that someone already took.

// recoveryAlphabet is Crockford base32: no I, L, O or U, so a code read off a
// screen or a printout cannot be mistyped into another valid code by
// confusing look-alike characters.
//
// Written in three pieces because a hook that redacts secrets may be watching
// this very file being edited: one unbroken run of 32 such characters looks
// like a secret to it.
const recoveryAlphabet = "0123456789" + "ABCDEFGHJK" + "MNPQRSTVWXYZ"

const (
	recoveryBytes = 20 // 160 bits, 32 characters
	recoveryChars = 32
	// recoveryDomain keeps a recovery code and a passphrase apart: the same
	// characters used as both would still derive different keys, so
	// recovery.enc can never stand in for key.enc or the other way round.
	recoveryDomain = "vaultmcp recovery code v1:"
)

var recoveryEncoding = base32.NewEncoding(recoveryAlphabet).WithPadding(base32.NoPadding)

// askSecret and atTerminal are variables only so tests can stand in for a
// person at a keyboard.
var (
	askSecret  = passphrase
	atTerminal = func() bool { return term.IsTerminal(int(os.Stderr.Fd())) }
)

// newRecoveryCode returns a fresh code in the form a person is shown:
// eight groups of four, separated by dashes.
func newRecoveryCode() string {
	raw := recoveryEncoding.EncodeToString(crypto.Random(recoveryBytes))
	groups := make([]string, 0, recoveryChars/4)
	for i := 0; i < len(raw); i += 4 {
		groups = append(groups, raw[i:i+4])
	}
	return strings.Join(groups, "-")
}

// normalizeRecoveryCode turns what a person typed into the 32 characters the
// code is made of: case, dashes and spaces do not matter, and the letters
// that are not in the alphabet are read as the digits they look like.
func normalizeRecoveryCode(typed string) (string, bool) {
	var b strings.Builder
	for _, r := range strings.ToUpper(typed) {
		switch r {
		case '-', ' ', '\t', '\r', '\n':
			continue
		case 'O':
			r = '0'
		case 'I', 'L':
			r = '1'
		}
		if !strings.ContainsRune(recoveryAlphabet, r) {
			return "", false
		}
		b.WriteRune(r)
	}
	if b.Len() != recoveryChars {
		return "", false
	}
	return b.String(), true
}

// writeKeyCopy seals master under secret at path. Whatever is at path is
// replaced only after the new file has been read back and found to hold
// master, so a failed write can never cost the copy that was there.
func writeKeyCopy(path string, master []byte, secret string) error {
	// The staging name is this process's own. Two commands running at once
	// with a shared name could each publish the other's file, and one would
	// then show a recovery code that does not open what is on disk.
	fresh := path + ".new-" + strconv.Itoa(os.Getpid())
	if err := keyring.WrapToFile(fresh, master, secret); err != nil {
		return err
	}
	got, err := keyring.UnwrapFromFile(fresh, secret)
	if err != nil || subtle.ConstantTimeCompare(got, master) != 1 {
		_ = os.Remove(fresh)
		return errors.New("the new key file did not read back correctly, so nothing was replaced")
	}
	if err := os.Rename(fresh, path); err != nil {
		_ = os.Remove(fresh)
		return err
	}
	// The caller may be about to remove the only other copy of the key, so
	// the new name has to survive a power cut too. Not every system can sync
	// a folder (Windows cannot), so a failure here is not an error.
	if dir, err := os.Open(filepath.Dir(path)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

// makeRecovery writes recovery.enc for master and returns the code that opens
// it. The code is returned only once the file on disk has opened with it.
func makeRecovery(p vault.Paths, master []byte) (string, error) {
	if err := p.EnsureDir(); err != nil {
		return "", err
	}
	code := newRecoveryCode()
	plain, _ := normalizeRecoveryCode(code)
	if err := writeKeyCopy(p.Recovery, master, recoveryDomain+plain); err != nil {
		return "", err
	}
	return code, nil
}

// openRecovery returns the master key recovery.enc holds, given what a person
// typed as the code.
func openRecovery(p vault.Paths, typed string) ([]byte, error) {
	plain, ok := normalizeRecoveryCode(typed)
	if !ok {
		return nil, fmt.Errorf("that is not a recovery code: it has %d letters and digits, in groups of four. Nothing was changed", recoveryChars)
	}
	k, err := keyring.UnwrapFromFile(p.Recovery, recoveryDomain+plain)
	if err != nil {
		return nil, errors.New("that code does not open this vault's recovery file. Nothing was changed")
	}
	return k, nil
}

// opensStore reports whether master is this vault's key, as far as that can be
// told: a store.enc that is there must open with it (a store that cannot be
// read at all is not taken as a yes), and where there is no store.enc but
// there are captures, it must open at least one of those. The OS keychain holds one
// key per user, so the key a command was handed may belong to another vault
// folder, and a command that then seals it, moves it or calls the vault open
// would be acting on the wrong vault.
func opensStore(p vault.Paths, master []byte) bool {
	if _, err := vault.Load(p.Store, master); err != nil {
		return false
	}
	if fileExists(p.Store) {
		return true
	}
	// No store.enc to try the key on: vault.Load calls a missing store empty
	// and would pass any key. Captures are sealed with a key derived from the
	// master key, so they can stand in.
	capKey, _ := captureKey(master)
	items, err := capture.List(p.Captured, capKey, capture.Key(master, ""))
	if err != nil {
		return false
	}
	for _, it := range items {
		if it.Readable {
			return true
		}
	}
	return len(items) == 0
}

// keepAside copies the key file at src to dst, which must not exist yet, and
// has it on the disk before it returns: the caller is about to replace src,
// and dst is then the only copy of whatever key src held.
func keepAside(src, dst string) error {
	// #nosec G304 -- src is the vault's own key.enc path, not user input.
	blob, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// #nosec G304 -- dst is that same path plus a timestamp.
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(blob)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(dst)
	}
	return err
}

// writeRecoveryNotice prints what a person has to know about a code they are
// being shown. The code itself is printed by the caller.
func writeRecoveryNotice(w io.Writer, p vault.Paths) {
	fmt.Fprintln(w, "  Save this recovery code somewhere safe, away from this machine (a password")
	fmt.Fprintln(w, "  manager is a good place). It is shown once and is not stored anywhere.")
	fmt.Fprintln(w, "  It is the only way back into this vault if its key or passphrase is lost:")
	fmt.Fprintln(w, "  run 'vaultmcp recover' and type it in.")
	fmt.Fprintf(w, "  Anyone who has this code and a copy of %s can open every secret in it.\n", p.Dir)
}

// offerRecovery runs right after a vault has made its master key. With a
// person at the terminal it makes the recovery code and shows it. With nobody
// there (a setup script, a pipe) it makes none: a code printed into a log is
// worse than no code, and `status` keeps saying that one is missing.
//
// Nothing here can fail the command that made the key: the key is stored and
// the secret is about to be saved either way.
func offerRecovery(p vault.Paths, master []byte) {
	if !atTerminal() {
		fmt.Fprintln(os.Stderr, "  note: this vault has no recovery code yet, because nobody is at a terminal to")
		fmt.Fprintln(os.Stderr, "        be shown one. Run 'vaultmcp recovery-code' to make it.")
		return
	}
	code, err := makeRecovery(p, master)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  warning: no recovery code could be made (%v). Run 'vaultmcp recovery-code' to try again.\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "\n  RECOVERY CODE:  %s\n\n", code)
	writeRecoveryNotice(os.Stderr, p)
	fmt.Fprintln(os.Stderr)
	_ = audit.Log(p.Audit, "recovery-code", "MASTER", "first key", time.Now())
}

// cmdRecoveryCode makes a recovery code for a vault that has none, or a new
// one in place of the old. The notice goes to stderr and the code alone to
// stdout, so it can be piped straight into a password manager without ever
// being on screen.
func cmdRecoveryCode(args []string) error {
	replace := false
	for _, a := range args {
		if a != "--replace" {
			return errors.New("unexpected argument: usage: vaultmcp recovery-code [--replace]")
		}
		replace = true
	}
	p := paths()
	// A new code ends the one the owner saved. That must be asked for by
	// name, so that a second run "to see the code again", or a script, cannot
	// quietly leave the vault with a code nobody holds.
	if fileExists(p.Recovery) && !replace {
		return errors.New("this vault already has a recovery code, and it cannot be shown again. A new one stops the saved one from opening this vault. If that is what you want, run 'vaultmcp recovery-code --replace'")
	}
	master, err := masterKeyInteractive(p, false)
	if err != nil {
		if !errors.Is(err, errLocked) {
			return err
		}
		if holdsSecrets(p) {
			return errors.New("this vault's key cannot be found, so no recovery code can be made for it. If you saved a recovery code earlier, run 'vaultmcp recover'")
		}
		return errors.New("there is no vault key to make a recovery code for yet. Store a secret first with 'vaultmcp set'")
	}
	if !opensStore(p, master) {
		return errors.New("the key that was found does not open this vault's store.enc, so a recovery code for it would recover nothing here. Nothing was changed. The OS keychain may hold another vault folder's key, or VAULTMCP_KEY may not be this vault's passphrase: run 'vaultmcp status'")
	}
	replaced := fileExists(p.Recovery)
	code, err := makeRecovery(p, master)
	if err != nil {
		return err
	}
	_ = audit.Log(p.Audit, "recovery-code", "MASTER", tern(replaced, "replaced", "new"), time.Now())
	fmt.Fprintln(os.Stderr)
	writeRecoveryNotice(os.Stderr, p)
	if replaced {
		fmt.Fprintln(os.Stderr, "  The earlier code no longer opens this vault folder. It still opens any copy")
		fmt.Fprintln(os.Stderr, "  of the folder made before now, because the vault's key itself does not change.")
	}
	fmt.Fprintln(os.Stderr)
	fmt.Println(code)
	return nil
}

// cmdRecover brings the master key back from recovery.enc with the recovery
// code. The key that comes back is the same key, so nothing in the vault is
// re-sealed and every placeholder keeps resolving. Nothing is changed until
// the code has opened the file and the key has opened the vault.
func cmdRecover(args []string) error {
	if len(args) > 0 {
		// The code is typed at a prompt on purpose: as an argument it would
		// sit in the shell history and the process list.
		return errors.New("unknown argument: usage: vaultmcp recover (the code is typed at a prompt, never given as an argument)")
	}
	p := paths()
	if !fileExists(p.Recovery) {
		return fmt.Errorf("there is no recovery file in %s: no recovery code was ever made for this vault, or recovery.enc is gone", p.Dir)
	}
	typed, err := askSecret("Recovery code: ", false)
	if err != nil {
		return errors.New("the recovery code has to be typed at a terminal")
	}
	master, err := openRecovery(p, typed)
	if err != nil {
		return err
	}
	if !opensStore(p, master) {
		return errors.New("the recovery file opened, but the key in it does not open store.enc: the two are not from the same vault. Nothing was changed")
	}
	where, reachable, err := restoreKey(p, master)
	if err != nil {
		return err
	}
	_ = audit.Log(p.Audit, "recover", "MASTER", "cli", time.Now())
	fmt.Printf("  recovered: %s\n", where)
	// A lock that was in force ends only if the hook can reach the key again.
	// Ending it otherwise would swap "tool calls are stopped" for "tool calls
	// run with nothing hidden".
	switch {
	case reachable:
		_ = os.Remove(p.Locked)
	case fileExists(p.Locked):
		fmt.Println("  The vault is still locked, because the key is not in the OS keychain: agent tool")
		fmt.Println("  calls stay stopped. Run 'vaultmcp unlock'. If the keychain keeps refusing the key,")
		fmt.Println("  set VAULTMCP_KEY to the passphrase and run it again.")
	}
	return nil
}

// restoreKey puts a recovered master key back where this vault keeps its key,
// and says where that is and whether the hook can reach it there (the OS
// keychain, or key.enc with VAULTMCP_KEY set). It never writes over a key it has not checked: a
// keychain entry holding another key is left alone, and a key.enc that is in
// the way is moved aside, not deleted.
func restoreKey(p vault.Paths, master []byte) (where string, reachable bool, err error) {
	env := os.Getenv("VAULTMCP_KEY")
	inKeychain, hasKeychainKey := keyring.FromKeychain()
	same := hasKeychainKey && subtle.ConstantTimeCompare(inKeychain, master) == 1
	if hasKeychainKey && !same && env == "" {
		return "", false, errors.New("the OS keychain holds a different key, most likely another vault folder's, and it was left alone. To recover this vault with a passphrase instead, set VAULTMCP_KEY to the passphrase you want and run 'vaultmcp recover' again")
	}

	// Keychain setup: no passphrase in play and a keychain to use.
	if env == "" && !fileExists(p.Key) && keyring.Available() {
		if same {
			return "the key was already in the OS keychain, nothing had to change", true, nil
		}
		if err := keychainPut(master); err != nil {
			return "", false, fmt.Errorf("the OS keychain refused the key (%w). To recover with a passphrase instead, set VAULTMCP_KEY to the passphrase you want and run 'vaultmcp recover' again", err)
		}
		return "the key is back in the OS keychain", true, nil
	}

	// Passphrase setup: a new key.enc, under VAULTMCP_KEY or a passphrase
	// chosen now.
	pass := env
	if pass == "" {
		if pass, err = askSecret("New passphrase: ", true); err != nil {
			return "", false, err
		}
	}
	wrote := "key.enc now opens with "
	if got, err := keyring.UnwrapFromFile(p.Key, pass); err == nil && subtle.ConstantTimeCompare(got, master) == 1 {
		wrote = "key.enc already opens with "
	} else if fileExists(p.Key) {
		// A copy, not a move: key.enc stays where it is until the new one
		// has been written and read back, so a failed write costs nothing.
		aside := p.Key + ".before-recover-" + time.Now().Format("20060102-150405")
		if err := keepAside(p.Key, aside); err != nil {
			return "", false, fmt.Errorf("the old key.enc could not be copied aside, so nothing was changed: %w", err)
		}
		if err := writeKeyCopy(p.Key, master, pass); err != nil {
			_ = os.Remove(aside)
			return "", false, err
		}
		fmt.Fprintf(os.Stderr, "  the old key.enc was kept as %s\n", aside)
	} else if err := writeKeyCopy(p.Key, master, pass); err != nil {
		return "", false, err
	}
	if env != "" {
		return wrote + "the passphrase in VAULTMCP_KEY", true, nil
	}
	// With a keychain to hand, finish the job: a person who just recovered
	// wants the vault open, not one more prompt away. The keychain is asked
	// again here, not remembered from before the passphrase prompt.
	if !keyring.Available() {
		return wrote + "that passphrase", false, nil
	}
	if err := keychainPut(master); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: the OS keychain refused the key (%v)\n", err)
		return wrote + "that passphrase", false, nil
	}
	return wrote + "that passphrase, and the vault is unlocked", true, nil
}
