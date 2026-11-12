package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/detect"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// Before captures had their own files the hook stored them in store.enc under
// generated names: the detected kind in upper case, then _2, _3, … when the
// name was taken. This file moves those entries to captured/.

var numberSuffix = regexp.MustCompile(`^_[0-9]+$`)

// autoKind reports the kind an alias was generated from, if its name is one
// the hook used to generate. The kinds come from the detector, so the two can
// never disagree about what a generated name looks like.
func autoKind(alias string) (kind string, ok bool) {
	for _, k := range detect.Kinds() {
		rest, found := strings.CutPrefix(alias, strings.ToUpper(k))
		if found && (rest == "" || numberSuffix.MatchString(rest)) {
			return k, true
		}
	}
	return "", false
}

// autoNamed returns the store's aliases with hook-generated names, sorted.
func autoNamed(store vault.Store) []string {
	var out []string
	for alias := range store {
		if _, ok := autoKind(alias); ok {
			out = append(out, alias)
		}
	}
	sort.Strings(out)
	return out
}

// migration is what one run would do.
type migration struct {
	move []string        // captured by the hook, by the audit log's account
	used map[string]bool // of those, the ones that were read at least once
	keep []string        // generated-looking name, but the log does not prove it
}

// planMigration decides which entries move. A generated-looking name is not
// enough: a person may have run `set GITHUB_TOKEN` themselves. An entry moves
// only when the audit log shows the hook vaulted that alias and never shows a
// person setting it.
func planMigration(store vault.Store, log []audit.Entry) migration {
	seen := map[string]map[string]bool{} // alias -> actions on record
	for _, e := range log {
		if seen[e.Alias] == nil {
			seen[e.Alias] = map[string]bool{}
		}
		seen[e.Alias][e.Action] = true
	}
	m := migration{used: map[string]bool{}}
	for _, alias := range autoNamed(store) {
		actions := seen[alias]
		if actions["vault"] && !actions["set"] {
			m.move = append(m.move, alias)
			m.used[alias] = actions["get"]
		} else {
			m.keep = append(m.keep, alias)
		}
	}
	return m
}

func cmdMigrateCaptures(args []string) error {
	apply := false
	for _, a := range args {
		if a == "--apply" {
			apply = true
		}
	}
	p := paths()
	key, err := masterKeyInteractive(p, false)
	if err != nil {
		return fmt.Errorf("vault is locked — run 'vaultmcp unlock'")
	}
	capKey, locked := captureKey(key)
	if !locked {
		fmt.Fprintln(os.Stderr, "  warning: no machine id available — moved captures will NOT be locked to this machine.")
	}
	return migrateCaptures(os.Stdout, p, key, capKey, apply, time.Now())
}

// migrateCaptures moves hook-captured entries out of store.enc. Without apply
// it only reports. With apply the order is what makes it safe to interrupt:
// back up the store, write and verify every capture file, and only then save
// the store without them. Until that one save the store is untouched, and a
// second run picks up whatever an interrupted one left.
func migrateCaptures(w io.Writer, p vault.Paths, master, capKey []byte, apply bool, now time.Time) error {
	store, err := vault.Load(p.Store, master)
	if err != nil {
		return err
	}
	log, err := audit.Read(p.Audit)
	if err != nil {
		return err
	}
	m := planMigration(store, log)

	usedCount := 0
	for _, alias := range m.move {
		if m.used[alias] {
			usedCount++
		}
	}
	fmt.Fprintf(w, "\n  Migrate captures%s\n\n", tern(apply, "", " (dry run)"))
	fmt.Fprintf(w, "  to move:    %d hook-captured secret(s), from store.enc to captured/\n", len(m.move))
	fmt.Fprintf(w, "              read at least once: %d (kept until unused for 30 days)\n", usedCount)
	fmt.Fprintf(w, "              never read:         %d (deleted after 7 days unless read)\n", len(m.move)-usedCount)
	fmt.Fprintf(w, "  stay named: %d secret(s)\n", len(store)-len(m.move))
	if len(m.keep) > 0 {
		fmt.Fprintf(w, "\n  %d of those have a hook-generated name but stay where they are, because the\n", len(m.keep))
		fmt.Fprintln(w, "  audit log does not show the hook captured them (or shows a person set them):")
		for _, alias := range m.keep {
			fmt.Fprintf(w, "    %s\n", alias)
		}
	}
	fmt.Fprintln(w)
	if !apply {
		fmt.Fprintln(w, "  Nothing was changed. Run 'vaultmcp migrate-captures --apply' to do it.")
		fmt.Fprintln(w)
		return nil
	}
	if len(m.move) == 0 {
		fmt.Fprintln(w, "  Nothing to move.")
		fmt.Fprintln(w)
		return nil
	}

	backup := p.Store + ".pre-captures-" + now.Format("20060102-150405")
	if err := copyStore(p.Store, backup); err != nil {
		return fmt.Errorf("backup failed, nothing was changed: %w", err)
	}
	fmt.Fprintf(w, "  backup:     %s\n", backup)
	fmt.Fprintln(w, "              It holds every capture in the old format. Delete it once the")
	fmt.Fprintln(w, "              move is confirmed.")

	created := now.UTC().Format(time.RFC3339)
	for _, alias := range m.move {
		kind, _ := autoKind(alias)
		// The old alias stays the file name, so placeholders already written
		// into transcripts and files keep resolving.
		e := capture.Entry{Value: store[alias], Kind: kind, Created: created, Used: m.used[alias]}
		if _, err := capture.Write(p.Captured, capKey, alias, e); err != nil {
			return fmt.Errorf("writing capture [%s] failed, store.enc was not changed: %w", alias, err)
		}
		// Read it back with the capture key. This also covers a file left by
		// an earlier, interrupted run, which Write does not replace.
		got, err := capture.Read(p.Captured, capKey, alias)
		if err != nil {
			return fmt.Errorf("capture [%s] does not open, store.enc was not changed: %w", alias, err)
		}
		if got.Value != store[alias] {
			return fmt.Errorf("capture [%s] already exists with a different value, store.enc was not changed", alias)
		}
	}
	moved, left, err := dropMoved(p, master, store, m.move)
	if err != nil {
		return err
	}
	_ = audit.Log(p.Audit, "migrate", "CAPTURES", fmt.Sprintf("moved %d", moved), now)
	fmt.Fprintf(w, "\n  Moved %d capture(s). store.enc now holds %d named secret(s).\n\n", moved, left)
	return nil
}

// dropMoved takes the moved entries out of store.enc. Writing thousands of
// capture files takes a moment, and a `vaultmcp set` in that moment must not
// be undone by saving the store as it was read at the start. So the store is
// loaded again here, and only entries that still hold the value that was
// moved are removed: anything set or changed meanwhile stays.
func dropMoved(p vault.Paths, master []byte, asRead vault.Store, move []string) (moved, left int, err error) {
	current, err := vault.Load(p.Store, master)
	if err != nil {
		return 0, 0, fmt.Errorf("re-reading store.enc failed, it was not changed: %w", err)
	}
	for _, alias := range move {
		if v, ok := current[alias]; ok && v == asRead[alias] {
			delete(current, alias)
			moved++
		}
	}
	if err := vault.Save(p.Store, current, master); err != nil {
		return 0, 0, fmt.Errorf("saving store.enc failed, it still holds every entry: %w", err)
	}
	return moved, len(current), nil
}

// copyStore writes an owner-only copy of the sealed store.
func copyStore(storePath, backup string) error {
	// #nosec G304 -- storePath is internally derived (~/.vaultmcp), not user input.
	blob, err := os.ReadFile(storePath)
	if err != nil {
		return err
	}
	// #nosec G703 -- backup is that same internally derived path plus a timestamp.
	return os.WriteFile(backup, blob, 0o600)
}
