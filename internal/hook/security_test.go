package hook

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// entropySecret is high-entropy with no known prefix. It is built from short
// pieces so the hook that is live while this file is edited cannot vault the
// literal out of it.
const entropySecret = "Xq9vR2mT7wL4" + "pK8nZ5jB3cF6" + "dG1hA0sE"

// The central security guarantee: once a secret is captured, its plaintext
// must never be recoverable from anything on disk without the key.
func TestVaultFilesNeverContainPlaintextSecret(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"aws set `+awsKey+`"}`)

	files := 0
	err := filepath.WalkDir(d.Paths.Dir, func(path string, de fs.DirEntry, err error) error {
		if err != nil || de.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files++
		if bytes.Contains(raw, []byte(awsKey)) {
			t.Errorf("plaintext secret found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk vault dir: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(d.Paths.Captured, awsAlias(d)+".enc"))
	if err != nil || len(raw) == 0 {
		t.Fatalf("capture file missing or empty — secret was not persisted (err=%v)", err)
	}
	if files < 2 {
		t.Fatalf("expected the capture file and the audit log, found %d file(s)", files)
	}
}

// The hook's stdout (what reaches Claude's transcript) must never contain a raw
// vaulted value — neither on ingress nor egress.
func TestHookOutputNeverLeaksSecret(t *testing.T) {
	d := testDeps(t)
	out := runPre(t, d, "Bash", `{"command":"deploy --token `+entropySecret+`"}`)
	if out == "" || strings.Contains(out, entropySecret) {
		t.Fatalf("hook output missing or leaked the secret: %s", out)
	}
	// And on a subsequent egress reference, still no leak.
	alias := capture.Alias(d.CaptureKey(), "high_entropy_secret", entropySecret)
	out2 := runPre(t, d, "Bash", `{"command":"deploy --token [vault:`+alias+`]"}`)
	if !strings.Contains(out2, fakeExe+" get "+alias) {
		t.Fatalf("captured alias not expanded on egress: %s", out2)
	}
	if strings.Contains(out2, entropySecret) {
		t.Fatalf("egress leaked the secret: %s", out2)
	}
}

// Persisted files must carry owner-only permissions.
func TestFilePermissions(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX permission check")
	}
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo `+awsKey+`"}`)

	for path, want := range map[string]os.FileMode{
		d.Paths.Dir:      0o700,
		d.Paths.Captured: 0o700,
		filepath.Join(d.Paths.Captured, awsAlias(d)+".enc"): 0o600,
	} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if perm := fi.Mode().Perm(); perm != want {
			t.Fatalf("%s perms = %o, want %o", path, perm, want)
		}
	}
}

// Injected-key (keychain) mode must not write a passphrase-wrapped key file or
// any passphrase to disk.
func TestNoPassphraseArtifactsInKeychainMode(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo `+awsKey+`"}`)
	if _, err := os.Stat(d.Paths.Key); err == nil {
		t.Fatal("key.enc written in injected-key mode — unexpected")
	}
}

// Tampering with the encrypted store must be detected (AEAD), not silently
// decrypted into garbage.
func TestTamperedStoreRejected(t *testing.T) {
	d := testDeps(t)
	if err := vault.Save(d.Paths.Store, vault.Store{"NAMED": "a named value"}, d.MasterKey); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(d.Paths.Store)
	raw[len(raw)-1] ^= 0x01
	_ = os.WriteFile(d.Paths.Store, raw, 0o600)

	if _, err := vault.Load(d.Paths.Store, d.MasterKey); err == nil {
		t.Fatal("tampered store was accepted — AEAD authentication failed to trigger")
	}
}

// The same holds for a capture file.
func TestTamperedCaptureRejected(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo `+awsKey+`"}`)
	path := filepath.Join(d.Paths.Captured, awsAlias(d)+".enc")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 0x01
	_ = os.WriteFile(path, raw, 0o600)

	if _, err := capture.Read(d.Paths.Captured, d.CaptureKey(), awsAlias(d)); err != crypto.ErrDecrypt {
		t.Fatalf("tampered capture was accepted, err = %v", err)
	}
}
