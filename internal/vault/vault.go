// Package vault is the encrypted secret store: an alias→value map sealed with
// the master key via the crypto package. It also owns the on-disk layout under
// ~/.vaultmcp.
package vault

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
)

// Store maps alias -> secret value.
type Store map[string]string

// Paths holds the resolved on-disk locations for a vault.
type Paths struct {
	Dir   string
	Store string
	Key   string
	Meta  string
	Audit string
}

// DefaultPaths returns the vault layout. The directory is ~/.vaultmcp by
// default, or $VAULTMCP_DIR when set — which lets a test project (or CI) run
// against a fully isolated vault without touching the user's real secrets.
func DefaultPaths() (Paths, error) {
	dir := os.Getenv("VAULTMCP_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, err
		}
		dir = filepath.Join(home, ".vaultmcp")
	}
	return Paths{
		Dir:   dir,
		Store: filepath.Join(dir, "store.enc"),
		Key:   filepath.Join(dir, "key.enc"),
		Meta:  filepath.Join(dir, "meta.json"),
		Audit: filepath.Join(dir, "audit.log"),
	}, nil
}

// EnsureDir creates the vault directory with 0700 perms. MkdirAll does not
// tighten an already-existing directory, so we chmod explicitly to guarantee
// owner-only access regardless of how the directory came to exist.
func (p Paths) EnsureDir() error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	// #nosec G302 -- 0700 is correct for a directory; 0600 would drop the
	// execute bit required to traverse it.
	return os.Chmod(p.Dir, 0o700)
}

// Load decrypts and returns the store. A missing store file is an empty store.
func Load(storePath string, masterKey []byte) (Store, error) {
	// #nosec G304 -- storePath is internally derived (~/.vaultmcp), not user input.
	blob, err := os.ReadFile(storePath)
	if err != nil {
		if os.IsNotExist(err) {
			return Store{}, nil
		}
		return nil, err
	}
	pt, err := crypto.Open(masterKey, blob)
	if err != nil {
		return nil, err
	}
	var s Store
	if err := json.Unmarshal(pt, &s); err != nil {
		return nil, err
	}
	if s == nil {
		s = Store{}
	}
	return s, nil
}

// Save encrypts and atomically writes the store with 0600 perms.
func Save(storePath string, s Store, masterKey []byte) error {
	pt, err := json.Marshal(s)
	if err != nil {
		return err
	}
	blob, err := crypto.Seal(masterKey, pt)
	if err != nil {
		return err
	}
	// Write to a randomized temp file in the same (0700) directory, then rename
	// atomically. os.CreateTemp avoids a predictable temp path.
	f, err := os.CreateTemp(filepath.Dir(storePath), "store-*.enc")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// os.CreateTemp already creates the file with mode 0600.
	return os.Rename(tmp, storePath)
}

// AliasFor returns a unique alias derived from a credential-type hint.
func AliasFor(kind string, s Store) string {
	base := strings.ToUpper(strings.NewReplacer("-", "_", " ", "_").Replace(kind))
	if _, exists := s[base]; !exists {
		return base
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s_%d", base, i)
		if _, exists := s[candidate]; !exists {
			return candidate
		}
	}
}

// SetByValue stores value (idempotent by value): if the exact value is already
// vaulted, its existing alias is returned and the store is unchanged. Otherwise
// a new alias is minted from kind. The bool reports whether a new entry was
// created (so the caller knows when to audit/persist).
func SetByValue(s Store, value, kind string) (alias string, created bool) {
	for a, v := range s {
		if v == value {
			return a, false
		}
	}
	alias = AliasFor(kind, s)
	s[alias] = value
	return alias, true
}
