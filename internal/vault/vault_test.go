package vault

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
)

func tempPaths(t *testing.T) Paths {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".vaultmcp")
	return Paths{
		Dir:   dir,
		Store: filepath.Join(dir, "store.enc"),
		Key:   filepath.Join(dir, "key.enc"),
		Meta:  filepath.Join(dir, "meta.json"),
		Audit: filepath.Join(dir, "audit.log"),
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	p := tempPaths(t)
	key := crypto.NewKey()
	if err := p.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	want := Store{"AWS_KEY": "AKIA-secret", "GH": "ghp_secret"}
	if err := Save(p.Store, want, key); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := Load(p.Store, key)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got["AWS_KEY"] != "AKIA-secret" || got["GH"] != "ghp_secret" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

func TestLoadMissingReturnsEmpty(t *testing.T) {
	p := tempPaths(t)
	s, err := Load(p.Store, crypto.NewKey())
	if err != nil {
		t.Fatalf("missing store should not error: %v", err)
	}
	if len(s) != 0 {
		t.Fatalf("expected empty store, got %+v", s)
	}
}

func TestLoadWrongKeyErrors(t *testing.T) {
	p := tempPaths(t)
	_ = p.EnsureDir()
	_ = Save(p.Store, Store{"X": "y"}, crypto.NewKey())
	if _, err := Load(p.Store, crypto.NewKey()); err == nil {
		t.Fatal("loading with the wrong key must error")
	}
}

func TestSetByValueIdempotent(t *testing.T) {
	s := Store{}
	a1, new1 := SetByValue(s, "secret-value", "aws_access_key")
	a2, new2 := SetByValue(s, "secret-value", "aws_access_key")
	if !new1 || new2 {
		t.Fatalf("first should be new, second reused: new1=%v new2=%v", new1, new2)
	}
	if a1 != a2 {
		t.Fatalf("same value should map to same alias: %s vs %s", a1, a2)
	}
	if len(s) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(s))
	}
}

func TestAliasForCollisionSuffixes(t *testing.T) {
	s := Store{"AWS_ACCESS_KEY": "v1"}
	a := AliasFor("aws_access_key", s)
	if a != "AWS_ACCESS_KEY_2" {
		t.Fatalf("expected AWS_ACCESS_KEY_2 on collision, got %s", a)
	}
}

func TestSaveSetsOwnerOnlyPerms(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX only")
	}
	p := tempPaths(t)
	_ = p.EnsureDir()
	if err := Save(p.Store, Store{"X": "y"}, crypto.NewKey()); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p.Store)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("store perms = %o, want 600", fi.Mode().Perm())
	}
}

func TestVaultDirEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VAULTMCP_DIR", dir)
	p, err := DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if p.Dir != dir {
		t.Fatalf("VAULTMCP_DIR ignored: got %s want %s", p.Dir, dir)
	}
}
