package capture

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
)

// t0 is a whole second, like every Created the hook writes.
var t0 = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func testKey(machine string) []byte {
	return Key(bytes.Repeat([]byte{7}, crypto.KeySize), machine)
}

func entry(value string, created time.Time) Entry {
	return Entry{Value: value, Kind: "github_token", Created: created.UTC().Format(time.RFC3339), Tool: "Bash"}
}

// put captures value the way the hook does and returns its alias.
func put(t *testing.T, dir string, key []byte, value string, created time.Time) string {
	t.Helper()
	alias := Alias(key, "github_token", value)
	if _, err := Write(dir, key, alias, entry(value, created)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	return alias
}

func fileCount(t *testing.T, dir string) int {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return len(des)
}

func TestKeyIsPerMachine(t *testing.T) {
	master := crypto.NewKey()
	a, b, none := Key(master, "machine-a"), Key(master, "machine-b"), Key(master, "")
	if len(a) != crypto.KeySize || len(none) != crypto.KeySize {
		t.Fatalf("key length = %d and %d, want %d", len(a), len(none), crypto.KeySize)
	}
	if bytes.Equal(a, b) || bytes.Equal(a, none) || bytes.Equal(a, master) {
		t.Fatal("capture keys must differ per machine id and from the master key")
	}
	if !bytes.Equal(a, Key(master, "machine-a")) {
		t.Fatal("the same master key and machine id must give the same key")
	}
	if bytes.Equal(a, Key(crypto.NewKey(), "machine-a")) {
		t.Fatal("a different master key must give a different capture key")
	}
}

// A capture written on machine A does not open with machine B's key, even
// though both hold the same master key.
func TestCaptureDoesNotOpenOnAnotherMachine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	keyA, keyB := testKey("machine-a"), testKey("machine-b")
	alias := put(t, dir, keyA, "value-on-a", t0)

	if _, err := Read(dir, keyB, alias); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("machine B opened machine A's capture (err=%v)", err)
	}
	got, err := Read(dir, keyA, alias)
	if err != nil || got.Value != "value-on-a" {
		t.Fatalf("machine A cannot read its own capture: %+v, %v", got, err)
	}
}

func TestAliasShapeAndDeterminism(t *testing.T) {
	shape := regexp.MustCompile(`^[A-Z][A-Z0-9_]*_[A-Z2-7]{16}$`)
	key := testKey("m")
	seen := map[string]string{}
	for i := 0; i < 500; i++ {
		value := fmt.Sprintf("value-%d", i)
		alias := Alias(key, "db_connection_string", value)
		if !shape.MatchString(alias) || !validAlias.MatchString(alias) {
			t.Fatalf("alias %q has the wrong shape", alias)
		}
		if alias != Alias(key, "db_connection_string", value) {
			t.Fatalf("alias for %q is not stable", value)
		}
		if other, dup := seen[alias]; dup {
			t.Fatalf("values %q and %q share alias %q", other, value, alias)
		}
		seen[alias] = value
	}
	if Alias(key, "jwt_token", "v") == Alias(testKey("other"), "jwt_token", "v") {
		t.Fatal("the alias must depend on the capture key")
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	want := Entry{Value: "the-value", Kind: "jwt_token", Created: t0.Format(time.RFC3339), Tool: "Bash", Session: "s1", Cwd: "/work"}
	alias := Alias(key, want.Kind, want.Value)
	created, err := Write(dir, key, alias, want)
	if err != nil || !created {
		t.Fatalf("Write = %v, %v; want created", created, err)
	}
	got, err := Read(dir, key, alias)
	if err != nil || got != want {
		t.Fatalf("Read = %+v, %v; want %+v", got, err, want)
	}
	// Creation leaves mtime == created: the "never used" mark.
	fi, err := os.Stat(filepath.Join(dir, alias+ext))
	if err != nil || !fi.ModTime().Equal(t0) {
		t.Fatalf("mtime = %v (err %v), want the created time %v", fi.ModTime(), err, t0)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, alias+ext))
	if bytes.Contains(raw, []byte(want.Value)) {
		t.Fatal("plaintext value found in the capture file")
	}
}

// N parallel captures of distinct values must all be readable afterwards.
// This fails on the old design, where every hook process loaded the whole
// store.enc, added its capture and saved the whole file back with no lock, so
// the last writer dropped the others' captures.
func TestParallelCapturesAllResolve(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	const n = 64
	aliases := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := fmt.Sprintf("value-%d", i)
			aliases[i] = Alias(key, "github_token", value)
			if _, err := Write(dir, key, aliases[i], entry(value, t0)); err != nil {
				t.Errorf("Write %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	for i, alias := range aliases {
		got, err := Read(dir, key, alias)
		if err != nil || got.Value != fmt.Sprintf("value-%d", i) {
			t.Fatalf("capture %d lost or wrong: %+v, %v", i, got, err)
		}
	}
	if got := fileCount(t, dir); got != n {
		t.Fatalf("folder holds %d files, want %d (no temp files left behind)", got, n)
	}
}

// The same value gives one alias and one file, whether it is captured twice
// in a row or by two processes at the same moment.
func TestSameValueOneAliasOneFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	alias := Alias(key, "github_token", "same-value")

	first, err := Write(dir, key, alias, entry("same-value", t0))
	if err != nil || !first {
		t.Fatalf("first Write = %v, %v; want created", first, err)
	}
	second, err := Write(dir, key, alias, entry("same-value", t0.Add(time.Hour)))
	if err != nil || second {
		t.Fatalf("second Write = %v, %v; want not created", second, err)
	}

	// Two "processes": independent writers racing on one fresh value.
	raced := Alias(key, "github_token", "raced-value")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Write(dir, key, raced, entry("raced-value", t0)); err != nil {
				t.Errorf("racing Write: %v", err)
			}
		}()
	}
	wg.Wait()
	if got, err := Read(dir, key, raced); err != nil || got.Value != "raced-value" {
		t.Fatalf("raced capture unreadable: %+v, %v", got, err)
	}
	if n, err := Count(dir); err != nil || n != 2 {
		t.Fatalf("Count = %d, %v; want 2 captures", n, err)
	}
	if got := fileCount(t, dir); got != 2 {
		t.Fatalf("folder holds %d files, want exactly 2", got)
	}
}

// Deleting a capture frees nothing: a different value never gets its alias,
// and the same value gets the same alias back. On the old design the lowest
// free number was reused, so an old placeholder could resolve to a new secret.
func TestDeletedAliasIsNeverReused(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	old := put(t, dir, key, "first-value", t0)
	if err := Delete(dir, old); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if Exists(dir, old) {
		t.Fatal("deleted capture still exists")
	}
	for i := 0; i < 50; i++ {
		if next := put(t, dir, key, fmt.Sprintf("other-value-%d", i), t0); next == old {
			t.Fatalf("value %d reused the deleted alias %q", i, old)
		}
	}
	if again := put(t, dir, key, "first-value", t0); again != old {
		t.Fatalf("the same value must keep its alias: %q vs %q", again, old)
	}
}

// An alias is checked before any path is built from it.
func TestInvalidAliasNeverBuildsAPath(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "captured")
	key := testKey("m")
	outside := filepath.Join(root, "ESCAPED"+ext)
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, alias := range []string{"", "../ESCAPED", "..", "A/B", `A\B`, "lower_case", "A.B", "A B"} {
		if _, err := Write(dir, key, alias, entry("v", t0)); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("Write(%q) err = %v, want ErrInvalidAlias", alias, err)
		}
		if _, err := Read(dir, key, alias); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("Read(%q) err = %v, want ErrInvalidAlias", alias, err)
		}
		if err := Delete(dir, alias); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("Delete(%q) err = %v, want ErrInvalidAlias", alias, err)
		}
		if err := Touch(dir, alias, Entry{}, t0); !errors.Is(err, ErrInvalidAlias) {
			t.Errorf("Touch(%q) err = %v, want ErrInvalidAlias", alias, err)
		}
		if Exists(dir, alias) {
			t.Errorf("Exists(%q) = true", alias)
		}
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("a file outside the captures folder was touched: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("an invalid alias must not even create the captures folder")
	}
}

func TestCaptureFilePermissions(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX permission check")
	}
	root := t.TempDir()
	dir := filepath.Join(root, "vault", "captured")
	key := testKey("m")
	alias := put(t, dir, key, "v", t0)
	for path, want := range map[string]os.FileMode{
		filepath.Join(root, "vault"):  0o700,
		dir:                           0o700,
		filepath.Join(dir, alias+ext): 0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s perms = %o, want %o", path, got, want)
		}
	}
}

func TestListAndCountSkipForeignFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	mine := put(t, dir, key, "mine", t0)
	theirs := put(t, dir, testKey("other-machine"), "theirs", t0)
	// Things that are not captures: a leftover temp file, the prune marker, a
	// lower-case name, a directory with a capture-like name.
	for _, name := range []string{"tmp-123", pruneMarker, "notes.enc"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "A_DIR"+ext), 0o700); err != nil {
		t.Fatal(err)
	}

	if n, err := Count(dir); err != nil || n != 2 {
		t.Fatalf("Count = %d, %v; want 2", n, err)
	}
	items, err := List(dir, key)
	if err != nil || len(items) != 2 {
		t.Fatalf("List = %+v, %v; want 2 items", items, err)
	}
	for _, it := range items {
		switch it.Alias {
		case mine:
			if !it.Readable || it.Entry.Value != "mine" || it.Used {
				t.Errorf("own capture listed wrong: %+v", it)
			}
		case theirs:
			if it.Readable || it.Entry.Value != "" {
				t.Errorf("another machine's capture must list as not readable: %+v", it)
			}
		default:
			t.Errorf("unexpected item %q", it.Alias)
		}
	}
	if n, err := Count(filepath.Join(dir, "missing")); err != nil || n != 0 {
		t.Fatalf("a missing folder is zero captures, got %d, %v", n, err)
	}
}

// A read marks the capture used, even when it comes right after creation,
// which is the normal case: the shell runs its substitution moments after the
// hook captured the value.
func TestTouchMarksUsed(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	isUsed := func(alias string) bool {
		t.Helper()
		items, err := List(dir, key)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range items {
			if it.Alias == alias {
				return it.Used
			}
		}
		t.Fatalf("alias %q not listed", alias)
		return false
	}
	for name, delay := range map[string]time.Duration{
		"read 200ms after capture": 200 * time.Millisecond,
		"read a day after capture": 24 * time.Hour,
	} {
		alias := put(t, dir, key, name, t0)
		if isUsed(alias) {
			t.Fatalf("%s: a fresh capture must be never-used", name)
		}
		e, err := Read(dir, key, alias)
		if err != nil {
			t.Fatal(err)
		}
		if err := Touch(dir, alias, e, t0.Add(delay)); err != nil {
			t.Fatalf("Touch: %v", err)
		}
		if !isUsed(alias) {
			t.Fatalf("%s: capture not marked used", name)
		}
	}
}

// Meeting a capture's value again counts as a use, but only once the file's
// mtime is stale enough to be worth a write.
func TestSeenCountsAsUse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "captured")
	key := testKey("m")
	alias := put(t, dir, key, "seen-again", t0)
	mtime := func() time.Time {
		t.Helper()
		fi, err := os.Stat(filepath.Join(dir, alias+ext))
		if err != nil {
			t.Fatal(err)
		}
		return fi.ModTime()
	}

	Seen(dir, alias, t0.Add(30*time.Minute))
	if !mtime().Equal(t0) {
		t.Fatal("a capture met again within the hour must not be rewritten")
	}
	Seen(dir, alias, t0.Add(2*time.Hour))
	if !mtime().Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("mtime = %v, want the time it was met again", mtime())
	}
	// Eight days on it would be gone as never-used; met again, it is kept.
	got, err := Prune(dir, key, t0.Add(8*24*time.Hour), 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if want := (PruneResult{Candidates: 1, Kept: 1}); got != want {
		t.Fatalf("Prune = %+v, want %+v", got, want)
	}
	Seen(dir, "../escape", t0) // an invalid alias is ignored, not a panic
}
