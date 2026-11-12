package crypto

import (
	"bytes"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key := NewKey()
	msg := []byte(`{"AWS_KEY":"AKIAIOSFODNN7EXAMPLE"}`)

	blob, err := Seal(key, msg)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := Open(key, blob)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, msg)
	}
}

func TestOpenWrongKeyFails(t *testing.T) {
	blob, _ := Seal(NewKey(), []byte("secret"))
	if _, err := Open(NewKey(), blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt with wrong key, got %v", err)
	}
}

func TestOpenTamperedFails(t *testing.T) {
	key := NewKey()
	blob, _ := Seal(key, []byte("secret value here"))
	// Flip a bit in the ciphertext region (past the 24-byte nonce).
	blob[len(blob)-1] ^= 0x01
	if _, err := Open(key, blob); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt on tampered ciphertext, got %v", err)
	}
}

func TestOpenTruncatedFails(t *testing.T) {
	key := NewKey()
	blob, _ := Seal(key, []byte("secret"))
	if _, err := Open(key, blob[:nonceSize-1]); err != ErrDecrypt {
		t.Fatalf("expected ErrDecrypt on truncated blob, got %v", err)
	}
}

func TestNonceUniquePerSeal(t *testing.T) {
	key := NewKey()
	msg := []byte("same message both times")
	a, _ := Seal(key, msg)
	b, _ := Seal(key, msg)
	if bytes.Equal(a, b) {
		t.Fatal("two Seals of identical plaintext produced identical output — nonce reuse")
	}
	if bytes.Equal(a[:nonceSize], b[:nonceSize]) {
		t.Fatal("nonce repeated across Seals")
	}
}

func TestDeriveKeyDeterministicAndSaltSensitive(t *testing.T) {
	salt := NewSalt()
	k1 := DeriveKey("correct horse battery staple", salt)
	k2 := DeriveKey("correct horse battery staple", salt)
	if !bytes.Equal(k1, k2) {
		t.Fatal("DeriveKey not deterministic for same passphrase+salt")
	}
	if len(k1) != KeySize {
		t.Fatalf("derived key length = %d, want %d", len(k1), KeySize)
	}
	if bytes.Equal(k1, DeriveKey("correct horse battery staple", NewSalt())) {
		t.Fatal("different salt produced same key")
	}
	if bytes.Equal(k1, DeriveKey("wrong passphrase", salt)) {
		t.Fatal("different passphrase produced same key")
	}
}

// Security invariant: the plaintext secret must never appear in the ciphertext.
func TestPlaintextNotPresentInCiphertext(t *testing.T) {
	key := NewKey()
	secret := []byte("AKIAIOSFODNN7EXAMPLE-super-secret")
	blob, _ := Seal(key, secret)
	if bytes.Contains(blob, secret) {
		t.Fatal("plaintext secret found verbatim in ciphertext")
	}
}

// A blob sealed with bound bytes opens only when the same bytes are given
// again: not with others, and not with none.
func TestBoundBytesMustMatchToOpen(t *testing.T) {
	key := NewKey()
	msg := []byte("sealed for one name")
	blob, err := SealBound(key, msg, []byte("NAME_A"))
	if err != nil {
		t.Fatalf("SealBound: %v", err)
	}
	if got, err := OpenBound(key, blob, []byte("NAME_A")); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("OpenBound with the same bound bytes = %q, %v", got, err)
	}
	for name, open := range map[string]func() ([]byte, error){
		"other bound bytes": func() ([]byte, error) { return OpenBound(key, blob, []byte("NAME_B")) },
		"no bound bytes":    func() ([]byte, error) { return OpenBound(key, blob, nil) },
		"plain Open":        func() ([]byte, error) { return Open(key, blob) },
		"truncated":         func() ([]byte, error) { return OpenBound(key, blob[:nonceSize-1], []byte("NAME_A")) },
	} {
		if _, err := open(); err != ErrDecrypt {
			t.Errorf("%s: err = %v, want ErrDecrypt", name, err)
		}
	}
}

// store.enc and key.enc are written with Seal. Adding the bound variant must
// not change what Seal writes: its output is exactly a seal with no bound
// bytes, in both directions.
func TestSealFormatUnchangedByBoundVariant(t *testing.T) {
	key := NewKey()
	msg := []byte("a store written before captures were bound")
	plain, _ := Seal(key, msg)
	if got, err := OpenBound(key, plain, nil); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("a Seal blob is not a seal with no bound bytes: %v", err)
	}
	unbound, _ := SealBound(key, msg, nil)
	if got, err := Open(key, unbound); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open cannot read a seal with no bound bytes: %v", err)
	}
	if len(plain) != len(unbound) {
		t.Fatalf("blob length changed: %d vs %d", len(plain), len(unbound))
	}
}
