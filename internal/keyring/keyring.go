// Package keyring manages the 32-byte master key that encrypts the vault.
//
// Two modes (see PLAN):
//   - Keychain mode (default): the master key lives in the OS keychain via
//     go-keyring. Nothing secret touches disk; the per-tool-call hook fetches
//     it directly with no Argon2id cost.
//   - Passphrase mode (fallback): the master key is wrapped by an Argon2id KEK
//     and stored in key.enc. The passphrase itself is never written to disk.
package keyring

import (
	"encoding/base64"
	"errors"
	"os"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	zk "github.com/zalando/go-keyring"
)

const (
	service = "vaultmcp"
	account = "master"
)

// ErrNoKey means no master key is available without interaction (used by the
// hook, which cannot prompt).
var ErrNoKey = errors.New("vaultmcp: master key unavailable")

// FromKeychain returns the master key from the OS keychain, if present.
func FromKeychain() ([]byte, bool) {
	s, err := zk.Get(service, account)
	if err != nil {
		return nil, false
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != crypto.KeySize {
		return nil, false
	}
	return key, true
}

// ToKeychain stores the master key in the OS keychain.
func ToKeychain(key []byte) error {
	return zk.Set(service, account, base64.StdEncoding.EncodeToString(key))
}

// DeleteFromKeychain removes the cached master key (used by `lock`).
func DeleteFromKeychain() error {
	err := zk.Delete(service, account)
	if errors.Is(err, zk.ErrNotFound) {
		return nil
	}
	return err
}

// Available reports whether the OS keychain is usable in this context.
//
// It probes with a READ, never a write: on macOS, a write to a missing or
// broken keychain pops a blocking "a keychain cannot be found to store …"
// GUI dialog, whereas a read of an absent item returns ErrNotFound silently.
// A reachable keychain returns either a value or ErrNotFound; any other error
// (no Secret Service, unattended Windows, broken login keychain) means
// unavailable, and the caller falls back to passphrase mode.
func Available() bool {
	_, err := zk.Get(service, account)
	return err == nil || errors.Is(err, zk.ErrNotFound)
}

// WrapToFile seals the master key with a passphrase-derived KEK and writes
// salt||sealed to keyPath (mode 0600). The passphrase is never persisted.
func WrapToFile(keyPath string, master []byte, passphrase string) error {
	salt := crypto.NewSalt()
	kek := crypto.DeriveKey(passphrase, salt)
	sealed, err := crypto.Seal(kek, master)
	if err != nil {
		return err
	}
	blob := append(append([]byte{}, salt...), sealed...)
	return os.WriteFile(keyPath, blob, 0o600)
}

// UnwrapFromFile reverses WrapToFile. Returns crypto.ErrDecrypt on a wrong
// passphrase or a tampered file.
func UnwrapFromFile(keyPath, passphrase string) ([]byte, error) {
	// #nosec G304 -- keyPath is internally derived (~/.vaultmcp/key.enc).
	blob, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(blob) < crypto.SaltSize {
		return nil, crypto.ErrDecrypt
	}
	salt, sealed := blob[:crypto.SaltSize], blob[crypto.SaltSize:]
	kek := crypto.DeriveKey(passphrase, salt)
	return crypto.Open(kek, sealed)
}
