package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// osHasEntry asks the operating system itself, not the keyring library,
// whether this user's vaultmcp keychain entry exists. It is how the test below
// knows it reached the real keychain: a stand-in never shows up here.
func osHasEntry(t *testing.T) bool {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("/usr/bin/security", "find-generic-password", "-s", "vaultmcp", "-a", "master").Run() == nil
	case "windows":
		// Credential Manager lists a "Target:" line for each entry it finds,
		// and none when there is no such entry.
		out, _ := exec.Command("cmdkey", "/list:vaultmcp:master").CombinedOutput()
		return strings.Contains(string(out), "Target:")
	default:
		out, err := exec.Command("secret-tool", "lookup", "service", "vaultmcp", "username", "master").Output()
		return err == nil && len(out) > 0
	}
}

// TestRealKeychain takes one vault through its whole life against the real OS
// keychain: the macOS Keychain, Windows Credential Manager, or a Secret
// Service on Linux. Every other test uses a stand-in.
//
// It is off unless VAULTMCP_REAL_KEYCHAIN=1, and it must run alone
// (go test -run '^TestRealKeychain$'), because the other tests swap the
// stand-in in for the rest of the process.
//
// The keychain holds ONE vaultmcp key per user account, whatever folder the
// vault is in. This test writes and deletes that entry, so it is for a
// throwaway account such as a CI runner. On an account that already has a
// key it refuses to start.
func TestRealKeychain(t *testing.T) {
	if os.Getenv("VAULTMCP_REAL_KEYCHAIN") != "1" {
		t.Skip("set VAULTMCP_REAL_KEYCHAIN=1 on a throwaway account to run this against the real OS keychain")
	}
	const refusing = "this account already has a vaultmcp key in its OS keychain. This test replaces and deletes that entry, which would destroy a real vault's key: refusing to run"
	if osHasEntry(t) {
		t.Fatal(refusing)
	}
	if _, ok := keyring.FromKeychain(); ok {
		t.Fatal(refusing)
	}
	if !keyring.Available() {
		t.Fatal("the OS keychain cannot be reached on this machine")
	}
	t.Cleanup(func() { _ = keyring.DeleteFromKeychain() })

	t.Setenv("VAULTMCP_DIR", filepath.Join(t.TempDir(), "vault"))
	t.Setenv("VAULTMCP_KEY", "")
	p, err := vault.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	v := testVault{p: p}
	terminal(t, true)

	// A first secret makes the key, puts it in the keychain, and shows a
	// recovery code.
	_, shown := output(t, func() { err = cmdSet([]string{"MINE", "value-one"}) })
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	code := codeShape.FindString(shown)
	if code == "" {
		t.Fatalf("the first set did not show a recovery code:\n%s", shown)
	}
	if !osHasEntry(t) {
		t.Fatal("after set, the operating system has no vaultmcp entry: the key did not reach the real keychain")
	}
	key := keychainKey(t)
	mustGet(t, v)

	// The hook reaches the key through the keychain and hides a secret.
	token := fakeToken(1)
	var out bytes.Buffer
	runHook(hookInput(token), &out, p, time.Now())
	if out.Len() == 0 || strings.Contains(out.String(), token) {
		t.Fatalf("the hook did not hide the secret: %q", out.String())
	}

	// lock takes the key out of the keychain, and the hook stops tool calls.
	const pass = "a passphrase for the lock"
	answers(t, pass)
	if err := cmdLock(nil); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if osHasEntry(t) {
		t.Fatal("after lock, the key is still in the real keychain")
	}
	if !fileExists(p.Locked) {
		t.Fatal("after lock, there is no lock marker")
	}
	if got := hookSays(t, p, claudeEvent, time.Now()); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Fatalf("while locked, the hook did not stop the call: %q", got)
	}

	// unlock puts the same key back, and the vault reads again.
	answers(t, pass)
	if err := cmdUnlock(nil); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !osHasEntry(t) || !bytes.Equal(keychainKey(t), key) {
		t.Fatal("after unlock, the real keychain does not hold the vault's key")
	}
	if fileExists(p.Locked) {
		t.Fatal("after unlock, the lock marker is still there")
	}
	mustGet(t, v)
	if got := hookSays(t, p, claudeEvent, time.Now()); got != "" {
		t.Fatalf("after unlock, the hook still has something to say about a plain call: %q", got)
	}

	// The keychain entry is lost. The recovery code brings the key back.
	if err := keyring.DeleteFromKeychain(); err != nil {
		t.Fatalf("deleting the entry: %v", err)
	}
	if osHasEntry(t) {
		t.Fatal("the entry is still there after it was deleted")
	}
	answers(t, code, pass, pass)
	if err := cmdRecover(nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !osHasEntry(t) || !bytes.Equal(keychainKey(t), key) {
		t.Fatal("after recover, the real keychain does not hold the vault's key")
	}
	mustGet(t, v)

	// Leave the account as it was found.
	if err := keyring.DeleteFromKeychain(); err != nil {
		t.Fatalf("cleaning up: %v", err)
	}
	if osHasEntry(t) {
		t.Fatal("the test left a vaultmcp entry in the keychain")
	}
}
