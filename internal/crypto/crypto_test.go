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
