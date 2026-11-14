package keyring

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
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

// A key file is replaced in one piece and leaves no temp file behind.
func TestWrapToFileReplacesInOnePiece(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key.enc")
	first, second := crypto.NewKey(), crypto.NewKey()
	if err := WrapToFile(path, first, "one passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := WrapToFile(path, second, "two passphrase"); err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapFromFile(path, "two passphrase")
	if err != nil || string(got) != string(second) {
		t.Fatalf("the second write is not what is on disk: %v", err)
	}
	des, _ := os.ReadDir(dir)
	if len(des) != 1 {
		t.Fatalf("temp files left beside the key file: %d entries", len(des))
	}
	if fi, _ := os.Stat(path); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, want 0600", fi.Mode().Perm())
	}
}
