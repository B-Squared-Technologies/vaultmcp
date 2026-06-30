// Package crypto provides authenticated encryption and key derivation for the
// vault. It uses XChaCha20-Poly1305 (AEAD) for confidentiality + integrity and
// Argon2id for passphrase-based key derivation. No hand-rolled primitives.
package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Argon2id parameters. Memory-hard; far stronger than PBKDF2. Tunable here if
// per-invocation latency proves too high (see PLAN: drop time to 1).
//
// argonThreads (the Argon2 parallelism p) is intentionally a FIXED constant,
// not runtime.NumCPU(): Argon2id's output depends on p, so a runtime-variable
// value would make a passphrase-wrapped key.enc created on an 8-core machine
// undecryptable on a 2-core one. Portability of the vault requires p be stable.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 1
	KeySize      = chacha20poly1305.KeySize // 32
	SaltSize     = 16
	nonceSize    = chacha20poly1305.NonceSizeX // 24 (XChaCha20)
)

// ErrDecrypt is returned when authentication fails: wrong key, or tampered
// ciphertext. The two are deliberately indistinguishable to the caller.
var ErrDecrypt = errors.New("vaultmcp: decryption failed (wrong key or tampered data)")

// Random returns n cryptographically secure random bytes, or panics — a failure
// of the system CSPRNG is not a recoverable condition.
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("vaultmcp: system CSPRNG unavailable: " + err.Error())
	}
	return b
}

// NewSalt returns a fresh random salt for key derivation.
func NewSalt() []byte { return Random(SaltSize) }

// NewKey returns a fresh random 32-byte master key.
func NewKey() []byte { return Random(KeySize) }

// DeriveKey derives a 32-byte key from a passphrase and salt using Argon2id.
func DeriveKey(passphrase string, salt []byte) []byte {
	return argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemory, argonThreads, KeySize)
}

// Seal encrypts plaintext with key using XChaCha20-Poly1305. A fresh random
// 24-byte nonce is generated per call and prepended to the output, so callers
// never manage nonces and reuse is statistically impossible.
func Seal(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := Random(nonceSize)
	// Seal appends ciphertext+tag to nonce, giving nonce||ct||tag.
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Open reverses Seal. It returns ErrDecrypt on any authentication failure.
func Open(key, blob []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < nonceSize {
		return nil, ErrDecrypt
	}
	nonce, ct := blob[:nonceSize], blob[nonceSize:]
	pt, err := aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
