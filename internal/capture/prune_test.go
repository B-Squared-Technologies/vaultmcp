package capture

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const day = 24 * time.Hour

// markUsed reads the capture at when, the way `vaultmcp get` does.
func markUsed(t *testing.T, dir string, key []byte, alias string, when time.Time) {
	t.Helper()
	e, err := Read(dir, key, alias)
	if err != nil {
		t.Fatal(err)
	}
	if err := Touch(dir, alias, e, when); err != nil {
		t.Fatal(err)
	}
}

// Expiry with an injected clock: never used goes after 7 days, used goes 30
// days after the last use, and a file that does not open is left alone.
func TestPruneExpiry(t *testing.T) {
	key := testKey("m")
	cases := []struct {
		name     string
		lastUsed time.Duration // after creation; 0 = never used
		migrated bool          // used:true set by the migration, mtime == created
		foreign  bool          // sealed with another machine's key
		age      time.Duration // from creation, or from the last use when used
		wantGone bool
	}{
		{name: "never used, 6 days", age: 6 * day},
		{name: "never used, 8 days", age: 8 * day, wantGone: true},
		{name: "used, 29 days since last use", lastUsed: 3 * day, age: 29 * day},
		{name: "used, 31 days since last use", lastUsed: 3 * day, age: 31 * day, wantGone: true},
		{name: "used within a second of capture, 8 days", lastUsed: 100 * time.Millisecond, age: 8 * day},
		{name: "migrated as used, 8 days", migrated: true, age: 8 * day},
		{name: "migrated as used, 29 days", migrated: true, age: 29 * day},
		{name: "migrated as used, 31 days", migrated: true, age: 31 * day, wantGone: true},
		{name: "another machine's file, 29 days", foreign: true, age: 29 * day},
		{name: "another machine's file, 31 days", foreign: true, age: 31 * day, wantGone: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "captured")
			writeKey := key
			if c.foreign {
				writeKey = testKey("other-machine")
			}
			e := entry("v", t0)
			e.Used = c.migrated
			alias := Alias(writeKey, e.Kind, e.Value)
			if _, err := Write(dir, writeKey, alias, e); err != nil {
				t.Fatal(err)
			}
			last := t0
			if c.lastUsed > 0 {
				last = t0.Add(c.lastUsed)
				markUsed(t, dir, key, alias, last)
			}
			now := last.Add(c.age)

			// A dry run reports the same counts and deletes nothing.
			dry, err := Prune(dir, key, now, 0, true)
			if err != nil {
				t.Fatal(err)
			}
			if !Exists(dir, alias) {
				t.Fatal("dry run deleted a file")
			}
			got, err := Prune(dir, key, now, 0, false)
			if err != nil {
				t.Fatal(err)
			}
			if got != dry {
				t.Fatalf("dry run counts %+v differ from the real run %+v", dry, got)
			}
			if gone := !Exists(dir, alias); gone != c.wantGone {
				t.Fatalf("gone = %v, want %v (result %+v)", gone, c.wantGone, got)
			}
			if deleted := got.Unused + got.Stale + got.Orphaned; (deleted == 1) != c.wantGone {
				t.Fatalf("deleted count = %d, wantGone = %v", deleted, c.wantGone)
			}
			if c.foreign && (got.Unreadable+got.Orphaned != 1 || got.Unused+got.Stale+got.Kept != 0) {
				t.Fatalf("a file that does not open counts as unreadable or orphaned, nothing else: %+v", got)
			}
		})
	}
}

// Only files older than 7 days are opened; younger ones are not even counted.
func TestPruneOpensOnlyOldFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	put(t, dir, key, "young", t0.Add(5*day))
	put(t, dir, key, "old", t0)
	// A young file sealed for another machine would count as unreadable if it
	// were opened.
	put(t, dir, testKey("other-machine"), "young-foreign", t0.Add(5*day))

	got, err := Prune(dir, key, t0.Add(8*day), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	want := PruneResult{Candidates: 1, Unused: 1}
	if got != want {
		t.Fatalf("Prune = %+v, want %+v", got, want)
	}
}

func TestPruneLimitBoundsOnePass(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	for i := 0; i < 5; i++ {
		put(t, dir, key, fmt.Sprintf("v-%d", i), t0)
	}
	got, err := Prune(dir, key, t0.Add(8*day), 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Candidates != 2 || got.Unused != 2 {
		t.Fatalf("limited pass = %+v, want 2 candidates deleted", got)
	}
	if n, _ := Count(dir); n != 3 {
		t.Fatalf("%d captures left, want 3", n)
	}
}

// Used captures stay candidates for weeks without being deleted. A bounded
// pass that always started at the first file would spend its whole budget on
// them every day and never reach the expired files sorted after them.
func TestBoundedPruneReachesEveryFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	created := time.Unix(20000*secondsPerDay, 0).UTC() // a day number divisible by 8
	const limit = 3
	// Six used captures that sort first, two expired never-used ones last.
	for i := 0; i < 6; i++ {
		alias := fmt.Sprintf("A_USED_%d", i)
		if _, err := Write(dir, key, alias, entry("used", created)); err != nil {
			t.Fatal(err)
		}
		markUsed(t, dir, key, alias, created.Add(time.Hour))
	}
	expired := []string{"Z_EXPIRED_0", "Z_EXPIRED_1"}
	for _, alias := range expired {
		if _, err := Write(dir, key, alias, entry("unused", created)); err != nil {
			t.Fatal(err)
		}
	}

	first := created.Add(16 * day) // still a day number divisible by 8
	if _, err := Prune(dir, key, first, limit, false); err != nil {
		t.Fatal(err)
	}
	if !Exists(dir, expired[0]) || !Exists(dir, expired[1]) {
		t.Fatal("test setup: the first bounded pass was expected to be used up by kept files")
	}
	for d := 1; d <= 2; d++ {
		if _, err := Prune(dir, key, first.Add(time.Duration(d)*day), limit, false); err != nil {
			t.Fatal(err)
		}
	}
	for _, alias := range expired {
		if Exists(dir, alias) {
			t.Fatalf("%s was never reached by the daily bounded passes", alias)
		}
	}
	if n, _ := Count(dir); n != 6 {
		t.Fatalf("%d captures left, want the 6 used ones", n)
	}
}

func TestAutoPruneOncePerDay(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "captured")
	key := testKey("m")
	marker := filepath.Join(dir, pruneMarker)
	store := filepath.Join(root, "store.enc")
	if err := os.WriteFile(store, []byte("sealed store bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	// No captures folder: nothing to do, and the folder is not created.
	AutoPrune(dir, func() []byte { return key }, t0)
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("AutoPrune created the captures folder")
	}

	old := put(t, dir, key, "old", t0)
	now := t0.Add(8 * day)

	// First run: no marker yet, so it prunes and leaves the marker at now.
	AutoPrune(dir, func() []byte { return key }, now)
	if Exists(dir, old) {
		t.Fatal("AutoPrune with no marker did not prune")
	}
	if fi, err := os.Stat(marker); err != nil || !fi.ModTime().Equal(now) {
		t.Fatalf("marker not touched to now (err=%v)", err)
	}

	// Within 24h of the marker: no prune, marker unchanged.
	old2 := put(t, dir, key, "old2", t0)
	AutoPrune(dir, func() []byte { return key }, now.Add(23*time.Hour))
	if !Exists(dir, old2) {
		t.Fatal("AutoPrune ran again within 24h")
	}
	if fi, _ := os.Stat(marker); !fi.ModTime().Equal(now) {
		t.Fatal("marker moved by a run that should have been skipped")
	}

	// A day later it runs again.
	AutoPrune(dir, func() []byte { return key }, now.Add(25*time.Hour))
	if Exists(dir, old2) {
		t.Fatal("AutoPrune did not run after 24h")
	}

	// It only ever touches files under the captures folder.
	des, err := os.ReadDir(root)
	if err != nil || len(des) != 2 {
		t.Fatalf("vault folder contents changed: %v, %v", des, err)
	}
	if got, _ := os.ReadFile(store); string(got) != "sealed store bytes" {
		t.Fatal("AutoPrune changed store.enc")
	}
}

// A capture refreshed after the prune judged it (a read, or a hook that met
// the value again) is in use and must survive that prune.
func TestExpireSkipsARefreshedCapture(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	alias := put(t, dir, key, "refreshed-mid-prune", t0)
	path := filepath.Join(dir, alias+ext)

	Seen(dir, alias, t0.Add(8*day)) // lands between the prune's stat and its delete
	gone, err := expire(path, t0, false)
	if err != nil || gone || !Exists(dir, alias) {
		t.Fatalf("a refreshed capture was deleted (gone=%v err=%v)", gone, err)
	}
	gone, err = expire(path, t0.Add(8*day), false)
	if err != nil || !gone || Exists(dir, alias) {
		t.Fatalf("an unchanged capture was not deleted (gone=%v err=%v)", gone, err)
	}
	if gone, err := expire(path, t0, false); err != nil || !gone {
		t.Fatalf("a file already gone must count as gone (gone=%v err=%v)", gone, err)
	}
}
