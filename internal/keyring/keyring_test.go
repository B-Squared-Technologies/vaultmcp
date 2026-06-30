package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/dubb-b/vaultmcp/internal/crypto"
)

// These tests cover passphrase-mode key persistence (WrapToFile/UnwrapFromFile)
// without touching the OS keychain.

func TestWrapUnwrapRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.enc")
	master := crypto.NewKey()
	if err := WrapToFile(path, master, "correct horse battery staple"); err != nil {
		t.Fatalf("WrapToFile: %v", err)
	}
	got, err := UnwrapFromFile(path, "correct horse battery staple")
	if err != nil {
		t.Fatalf("UnwrapFromFile: %v", err)
	}
	if !bytes.Equal(got, master) {
		t.Fatal("unwrapped key does not match wrapped master key")
	}
}

func TestUnwrapWrongPassphraseFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.enc")
	_ = WrapToFile(path, crypto.NewKey(), "right-passphrase")
	if _, err := UnwrapFromFile(path, "wrong-passphrase"); err == nil {
		t.Fatal("wrong passphrase must fail")
	}
}

func TestUnwrapTamperedFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.enc")
	_ = WrapToFile(path, crypto.NewKey(), "pw")
	blob, _ := os.ReadFile(path)
	blob[len(blob)-1] ^= 0x01
	_ = os.WriteFile(path, blob, 0o600)
	if _, err := UnwrapFromFile(path, "pw"); err == nil {
		t.Fatal("tampered key file must fail authentication")
	}
}

func TestUnwrapTruncatedFileFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.enc")
	_ = os.WriteFile(path, []byte("short"), 0o600)
	if _, err := UnwrapFromFile(path, "pw"); err == nil {
		t.Fatal("truncated key file must fail, not panic")
	}
}

func TestKeyFileNeverContainsRawMasterKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key.enc")
	master := crypto.NewKey()
	_ = WrapToFile(path, master, "pw")
	blob, _ := os.ReadFile(path)
	if bytes.Contains(blob, master) {
		t.Fatal("raw master key found in key.enc — wrapping failed")
	}
}
