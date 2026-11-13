package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/hook"
	"github.com/B-Squared-Technologies/vaultmcp/internal/machineid"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// machineID is a variable only so tests can stand in for the hardware lookup.
// Nothing else assigns it, and no environment variable feeds it: an override
// would let anyone who can set one open a copied vault.
var machineID = machineid.Get

// captureKey derives the key for captured/. locked is false when this machine
// has no id: the key then depends on the master key alone, so the hook can
// still redact, and `status` says the captures are not locked to the machine.
func captureKey(master []byte) (key []byte, locked bool) {
	id, err := machineID()
	if err != nil {
		id = ""
	}
	return capture.Key(master, id), err == nil
}

// runHook handles one hook event. It writes valid hook JSON or nothing, and
// fails open on any problem.
func runHook(stdin []byte, stdout io.Writer, p vault.Paths, now time.Time) {
	key, err := masterKeyNonInteractive(p)
	if err != nil {
		// No key, so nothing can be vaulted. What the hook says depends on
		// why. The key is always tried first: a key that can be reached wins
		// over any marker.
		switch {
		case fileExists(p.Locked):
			// Locked on purpose. The owner wants nothing near the secrets, and
			// an agent running with redaction off is the opposite, so the
			// call is stopped. The hook blocks only for a vault that was
			// locked on purpose and whose key it cannot use.
			write(stdout, hook.Stop(stdin, lockedMessage))
		case fileExists(p.Key) || holdsSecrets(p):
			// A vault that is in use, but its key is out of reach (a keychain
			// this session cannot see, a passphrase that was not exported).
			// The call goes ahead, and the person is told why here: `status`
			// run in a terminal that does have the passphrase would say that
			// all is well.
			why := "this session has no VAULTMCP_KEY and no vault key was found in the OS keychain"
			fix := " Run 'vaultmcp unlock' in a terminal to put the key in the OS keychain, where every program can reach it. On a machine with no OS keychain, start this program with VAULTMCP_KEY set."
			if os.Getenv("VAULTMCP_KEY") != "" {
				why = "VAULTMCP_KEY is set in this session but does not open key.enc"
				fix = ""
			}
			warn(stdout, stdin, p, now, "VaultMCP cannot reach the vault key ("+why+"), so secrets are NOT being hidden."+fix)
		}
		// Otherwise the vault was never set up: nothing to say.
		return
	}
	// A vault locked on purpose stays stopped unless the key that was found is
	// its own. The keychain entry is one per user, so another vault folder's
	// key may be in it, and another vault being open must not undo this lock.
	// The extra look at the store happens only while a marker is there.
	if fileExists(p.Locked) && !opensStore(p, key) {
		write(stdout, hook.Stop(stdin, lockedMessage))
		return
	}
	exe, err := os.Executable()
	if err != nil {
		return
	}
	// Derived on demand, at most once: see hook.Deps.CaptureKey.
	capKey := sync.OnceValue(func() []byte {
		k, _ := captureKey(key)
		return k
	})
	storeFailed := false
	out := hook.Process(stdin, hook.Deps{Paths: p, MasterKey: key, CaptureKey: capKey, ExePath: exe, Now: now, StoreFailed: func() { storeFailed = true }})
	write(stdout, out)
	if storeFailed {
		// A key was found, but it is not this vault's, and nobody locked the
		// vault: the keychain holds another folder's key, or VAULTMCP_KEY
		// opens a key.enc that was made over an existing vault. Process
		// answers nothing when the store fails, so this is the only answer.
		warn(stdout, stdin, p, now, "VaultMCP found a key, but it does not open this vault (store.enc), so secrets are NOT being hidden. Run 'vaultmcp status' in a terminal.")
	}
	// Expire old captures, at most once a day. Only now, with the answer
	// already written: what AutoPrune returns goes to the audit log and
	// nowhere else, so it cannot change the output or the exit code.
	auditPrune(p, capture.AutoPrune(p.Captured, capKey, now), "hook", now)
}

func write(w io.Writer, out []byte) {
	if out != nil {
		_, _ = w.Write(out)
	}
}

const lockedMessage = "VaultMCP: the vault is locked, so secrets cannot be hidden and this tool call was stopped. Run 'vaultmcp unlock' in a terminal, then try again."

// warnEvery is how often the hook repeats a warning that redaction is off. It
// runs on every tool call, and a warning on every one would be noise that
// teaches people to ignore it.
const warnEvery = 10 * time.Minute

// warn shows msg to the person through the hook answer, at most once every
// warnEvery in each agent session: a warning one session used up would
// otherwise never reach the person sitting at another. The time of the last
// warning is the mtime of a marker file in the vault folder. If that file
// cannot be written the warning is shown anyway: said too often is better
// than never said.
func warn(w io.Writer, stdin []byte, p vault.Paths, now time.Time, msg string) {
	marker := filepath.Join(p.Dir, "warned")
	if id := hook.SessionID(stdin); id != "" {
		sum := sha256.Sum256([]byte(id))
		marker += "-" + hex.EncodeToString(sum[:6])
	}
	if fi, err := os.Stat(marker); err == nil {
		if age := now.Sub(fi.ModTime()); age >= 0 && age < warnEvery {
			return
		}
	}
	out := hook.Warn(stdin, msg)
	if out == nil {
		return
	}
	if err := os.WriteFile(marker, nil, 0o600); err == nil {
		_ = os.Chtimes(marker, now, now)
	}
	write(w, out)
	// Sessions end and their markers stay. Clear out the day-old ones.
	old, _ := filepath.Glob(filepath.Join(p.Dir, "warned-*"))
	for _, f := range old {
		if fi, err := os.Stat(f); err == nil && now.Sub(fi.ModTime()) > 24*time.Hour {
			_ = os.Remove(f)
		}
	}
}

// auditPrune leaves one audit line for a prune that deleted something. Expiry
// removes secrets, so the log has to show when it happened and how many went.
// It is one line for the whole pass, with counts and no aliases, and a pass
// that deleted nothing leaves no line.
func auditPrune(p vault.Paths, r capture.PruneResult, who string, now time.Time) {
	if r.Deleted() == 0 {
		return
	}
	counts := fmt.Sprintf("%s: deleted %d never used, %d unused 30 days, %d not readable, %d temp", who, r.Unused, r.Stale, r.Orphaned, r.Temps)
	_ = audit.Log(p.Audit, "prune", "CAPTURES", counts, now)
}

// resolve returns the value for alias: a named secret first, then a capture.
// The named lookup is finished before the captures folder is touched, so
// `get NAME` works whatever state that folder is in.
func resolve(p vault.Paths, master []byte, alias string, now time.Time) (string, error) {
	store, err := vault.Load(p.Store, master)
	if err != nil {
		return "", err
	}
	if val, ok := store[alias]; ok {
		return val, nil
	}
	capKey, locked := captureKey(master)
	e, err := capture.Read(p.Captured, capKey, alias)
	if locked && errors.Is(err, crypto.ErrDecrypt) {
		// A hook run that could not read the machine id sealed its capture
		// with the key that is not tied to a machine. Without this second try
		// that one failed lookup would leave a capture nothing can open.
		e, err = capture.Read(p.Captured, capture.Key(master, ""), alias)
	}
	switch {
	case err == nil:
	case os.IsNotExist(err), errors.Is(err, capture.ErrInvalidAlias):
		return "", fmt.Errorf("no secret for alias [%s]", alias)
	case errors.Is(err, crypto.ErrDecrypt):
		return "", fmt.Errorf("capture [%s] does not open here: it was sealed on another machine or with another key, or its file is damaged", alias)
	default:
		return "", fmt.Errorf("capture [%s] could not be read: %w", alias, err)
	}
	// A failed touch only lets the capture expire sooner; the read stands.
	_ = capture.Touch(p.Captured, alias, e, now)
	return e.Value, nil
}

// listNamed prints the secrets a person stored, then how many captures exist.
func listNamed(w io.Writer, p vault.Paths, master []byte) error {
	store, err := vault.Load(p.Store, master)
	if err != nil {
		return err
	}
	// The count is a courtesy line: a broken captures folder must not stop the
	// named list.
	captures, _ := capture.Count(p.Captured)
	if len(store) == 0 && captures == 0 {
		fmt.Fprintln(w, "  vault is empty")
		return nil
	}
	fmt.Fprintf(w, "\n  Vault — %d secret(s)\n\n", len(store))
	for _, a := range sortedKeys(store) {
		fmt.Fprintf(w, "  %-36s %s\n", a, mask(store[a]))
	}
	fmt.Fprintf(w, "\n  + %d captured by the hook — vaultmcp list --captured\n\n", captures)
	return nil
}

// listCaptured prints the hook's captures: alias, kind, age and whether the
// capture was ever read. Values are masked exactly like named ones.
func listCaptured(w io.Writer, p vault.Paths, master []byte, now time.Time) error {
	// The second key opens captures made in a moment when the machine id
	// could not be read, the same ones `get` falls back to.
	capKey, locked := captureKey(master)
	keys := [][]byte{capKey}
	if locked {
		keys = append(keys, capture.Key(master, ""))
	}
	items, err := capture.List(p.Captured, keys...)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Fprintln(w, "  no captured secrets")
		return nil
	}
	fmt.Fprintf(w, "\n  Captured by the hook — %d secret(s)\n\n", len(items))
	for _, it := range items {
		if !it.Readable {
			fmt.Fprintf(w, "  %-44s (does not open here: another machine, another key, or damaged)\n", it.Alias)
			continue
		}
		fmt.Fprintf(w, "  %-44s %-22s %-5s %-11s %s\n", it.Alias, it.Entry.Kind, age(it.Entry.Created, now), tern(it.Used, "used", "never used"), mask(it.Entry.Value))
	}
	fmt.Fprintln(w)
	return nil
}

// age renders how long ago an RFC3339 time was, in the largest whole unit.
func age(created string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return "?"
	}
	d := now.Sub(t)
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	}
}

func cmdPrune(args []string) error {
	dryRun := false
	for _, a := range args {
		// Anything but the one known flag stops here, before a file is looked
		// at: a mistyped --dry-run must not run as a real prune.
		if a != "--dry-run" {
			return fmt.Errorf("unknown argument %q — usage: vaultmcp prune [--dry-run]", a)
		}
		dryRun = true
	}
	p := paths()
	key, err := masterKeyInteractive(p, false)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock'")
	}
	capKey, _ := captureKey(key)
	now := time.Now()
	r, err := capture.Prune(p.Captured, capKey, now, 0, dryRun)
	writePruneResult(os.Stdout, r, dryRun)
	if !dryRun {
		auditPrune(p, r, "cli", now)
	}
	return err
}

func writePruneResult(w io.Writer, r capture.PruneResult, dryRun bool) {
	deleted := tern(dryRun, "would delete", "deleted")
	fmt.Fprintf(w, "\n  Prune captures%s\n\n", tern(dryRun, " (dry run — nothing deleted)", ""))
	fmt.Fprintf(w, "  older than 7 days:   %d checked\n", r.Candidates)
	fmt.Fprintf(w, "  never used:          %d %s\n", r.Unused, deleted)
	fmt.Fprintf(w, "  unused for 30 days:  %d %s\n", r.Stale, deleted)
	fmt.Fprintf(w, "  used in last 30d:    %d kept\n", r.Kept)
	fmt.Fprintf(w, "  not readable here:   %d left alone, %d untouched for 30 days %s\n", r.Unreadable, r.Orphaned, deleted)
	fmt.Fprintf(w, "  leftover temp files: %d %s\n\n", r.Temps, deleted)
}

// writeVaultCounts reports what the vault holds. master is nil while the
// vault is locked: the named store cannot be opened then, but captures can
// still be counted, and whether they are locked to this machine needs no key.
func writeVaultCounts(w io.Writer, p vault.Paths, master []byte) {
	if master != nil {
		store, err := vault.Load(p.Store, master)
		if err != nil {
			fmt.Fprintln(w, "  named:   WARNING: a key was found, but it does not open store.enc, so secrets are not being hidden.")
			fmt.Fprintln(w, "           The OS keychain may hold another vault folder's key, or VAULTMCP_KEY may not be this vault's passphrase.")
		} else {
			fmt.Fprintf(w, "  named:   %d secret(s)\n", len(store))
			// Only what the migration would really move is counted. A name
			// that merely looks generated (a person's own STRIPE_KEY) stays
			// where it is, and counting it would leave a hint here that no
			// run of the command could ever clear.
			log, _ := audit.Read(p.Audit)
			if n := len(planMigration(store, log).move); n > 0 {
				fmt.Fprintf(w, "           %d were captured by the hook and are still in store.enc — run 'vaultmcp migrate-captures'\n", n)
			}
		}
	}
	captures, _ := capture.Count(p.Captured)
	fmt.Fprintf(w, "  captures: %d\n", captures)
	if _, err := machineID(); err != nil {
		fmt.Fprintln(w, "  lock:    captures are NOT locked to this machine (no machine id available)")
	} else {
		// "New", because a capture made in a moment when the id could not be
		// read was sealed without it and stays that way until it expires.
		fmt.Fprintln(w, "  lock:    new captures are sealed for this machine only")
	}
}
