package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

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
		// Locked and non-interactive: cannot vault now. Fail open silently so
		// we never block the tool call. (status/unlock guide the user.)
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
	out := hook.Process(stdin, hook.Deps{Paths: p, MasterKey: key, CaptureKey: capKey, ExePath: exe, Now: now})
	if out != nil {
		_, _ = stdout.Write(out)
	}
	// Expire old captures, at most once a day. Only now, with the answer
	// already written: AutoPrune returns nothing, so it cannot change the
	// output or the exit code.
	capture.AutoPrune(p.Captured, capKey, now)
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
		return "", fmt.Errorf("capture [%s] does not open on this machine (captures are locked to the machine that made them)", alias)
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
			fmt.Fprintf(w, "  %-44s (does not open on this machine)\n", it.Alias)
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
		if a == "--dry-run" {
			dryRun = true
		}
	}
	p := paths()
	key, err := masterKeyInteractive(p, false)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock'")
	}
	capKey, _ := captureKey(key)
	r, err := capture.Prune(p.Captured, capKey, time.Now(), 0, dryRun)
	writePruneResult(os.Stdout, r, dryRun)
	return err
}

func writePruneResult(w io.Writer, r capture.PruneResult, dryRun bool) {
	deleted := tern(dryRun, "would delete", "deleted")
	fmt.Fprintf(w, "\n  Prune captures%s\n\n", tern(dryRun, " (dry run — nothing deleted)", ""))
	fmt.Fprintf(w, "  older than 7 days:   %d checked\n", r.Candidates)
	fmt.Fprintf(w, "  never used:          %d %s\n", r.Unused, deleted)
	fmt.Fprintf(w, "  unused for 30 days:  %d %s\n", r.Stale, deleted)
	fmt.Fprintf(w, "  used in last 30d:    %d kept\n", r.Kept)
	fmt.Fprintf(w, "  not readable here:   %d left alone, %d untouched for 30 days %s\n\n", r.Unreadable, r.Orphaned, deleted)
}

// writeVaultCounts reports what the vault holds. master is nil while the
// vault is locked: the named store cannot be opened then, but captures can
// still be counted, and whether they are locked to this machine needs no key.
func writeVaultCounts(w io.Writer, p vault.Paths, master []byte) {
	if master != nil {
		if store, err := vault.Load(p.Store, master); err == nil {
			fmt.Fprintf(w, "  named:   %d secret(s)\n", len(store))
			if n := len(autoNamed(store)); n > 0 {
				fmt.Fprintf(w, "           %d have hook-generated names — run 'vaultmcp migrate-captures'\n", n)
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
