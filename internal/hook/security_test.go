package hook

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// The central security guarantee: once a secret is vaulted, its plaintext must
// never be recoverable from the on-disk store without the master key.
func TestStoreFileNeverContainsPlaintextSecret(t *testing.T) {
	d := testDeps(t)
	secret := "AKIAIOSFODNN7EXAMPLE"
	runPre(t, d, "Bash", `{"command":"aws set `+secret+`"}`)

	raw, err := os.ReadFile(d.Paths.Store)
	if err != nil {
		t.Fatalf("read store: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Fatal("plaintext secret found in encrypted store file")
	}
	if len(raw) == 0 {
		t.Fatal("store file empty — secret was not persisted")
	}
}

// The hook's stdout (what reaches Claude's transcript) must never contain a raw
// vaulted value — neither on ingress nor egress.
func TestHookOutputNeverLeaksSecret(t *testing.T) {
	d := testDeps(t)
	secret := "Xq9vR2mT7wL4pK8nZ5jB3cF6dG1hA0sE" // high-entropy, no known prefix
	out := runPre(t, d, "Bash", `{"command":"deploy --token `+secret+`"}`)
	if strings.Contains(out, secret) {
		t.Fatalf("hook output leaked the secret: %s", out)
	}
	// And on a subsequent egress reference, still no leak.
	out2 := runPre(t, d, "Bash", `{"command":"deploy --token [vault:HIGH_ENTROPY_SECRET]"}`)
	if strings.Contains(out2, secret) {
		t.Fatalf("egress leaked the secret: %s", out2)
	}
}

// Persisted files must carry owner-only permissions.
func TestFilePermissions(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX permission check")
	}
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo AKIAIOSFODNN7EXAMPLE"}`)

	di, err := os.Stat(d.Paths.Dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Fatalf("vault dir perms = %o, want 700", perm)
	}
	fi, err := os.Stat(d.Paths.Store)
	if err != nil {
		t.Fatalf("stat store: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("store perms = %o, want 600", perm)
	}
}

// Injected-key (keychain) mode must not write a passphrase-wrapped key file or
// any passphrase to disk.
func TestNoPassphraseArtifactsInKeychainMode(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo AKIAIOSFODNN7EXAMPLE"}`)
	if _, err := os.Stat(d.Paths.Key); err == nil {
		t.Fatal("key.enc written in injected-key mode — unexpected")
	}
}

// Tampering with the encrypted store must be detected (AEAD), not silently
// decrypted into garbage.
func TestTamperedStoreRejected(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo AKIAIOSFODNN7EXAMPLE"}`)
	raw, _ := os.ReadFile(d.Paths.Store)
	raw[len(raw)-1] ^= 0x01
	_ = os.WriteFile(d.Paths.Store, raw, 0o600)

	if _, err := vault.Load(d.Paths.Store, d.MasterKey); err == nil {
		t.Fatal("tampered store was accepted — AEAD authentication failed to trigger")
	}
}
