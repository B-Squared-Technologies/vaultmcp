package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/keyring"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
	zk "github.com/zalando/go-keyring"
)

// Every test here goes through commands that read and write the keychain, so
// every one calls useMockKeychain first: VAULTMCP_DIR does not keep a test
// away from the real login keychain, only the mock does.

// answers stands in for a person typing at the prompts, in order. A prompt
// nobody answered fails the test.
func answers(t *testing.T, typed ...string) {
	t.Helper()
	old := askSecret
	n := 0
	askSecret = func(prompt string, confirm bool) (string, error) {
		if n >= len(typed) {
			t.Errorf("a prompt nobody answered: %q", prompt)
			return "", errors.New("no answer")
		}
		n++
		return typed[n-1], nil
	}
	t.Cleanup(func() { askSecret = old })
}

func terminal(t *testing.T, present bool) {
	t.Helper()
	old := atTerminal
	atTerminal = func() bool { return present }
	t.Cleanup(func() { atTerminal = old })
}

// output runs fn and returns what it printed.
func output(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	dir := t.TempDir()
	fo, err := os.Create(filepath.Join(dir, "out"))
	if err != nil {
		t.Fatal(err)
	}
	fe, err := os.Create(filepath.Join(dir, "err"))
	if err != nil {
		t.Fatal(err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = fo, fe
	func() {
		defer func() { os.Stdout, os.Stderr = oldOut, oldErr }()
		fn()
	}()
	_ = fo.Close()
	_ = fe.Close()
	return string(mustRead(t, fo.Name())), string(mustRead(t, fe.Name()))
}

var codeShape = regexp.MustCompile(`[0-9A-Z]{4}(-[0-9A-Z]{4}){7}`)

// keychainVault makes a vault whose key is in the (mock) keychain, with one
// named secret and a recovery code, and returns the code.
func keychainVault(t *testing.T) (testVault, string) {
	t.Helper()
	useMockKeychain(t)
	terminal(t, true)
	v := newTestVault(t)
	var err error
	_, shown := output(t, func() { err = cmdSet([]string{"MINE", "value-one"}) })
	if err != nil {
		t.Fatal(err)
	}
	code := codeShape.FindString(shown)
	if code == "" {
		t.Fatalf("the first set did not show a recovery code:\n%s", shown)
	}
	return v, code
}

func mustGet(t *testing.T, v testVault) {
	t.Helper()
	key, err := masterKeyNonInteractive(v.p)
	if err != nil {
		t.Fatalf("the vault key cannot be reached: %v", err)
	}
	if got, err := resolve(v.p, key, "MINE", testNow); err != nil || got != "value-one" {
		t.Fatalf("the stored secret no longer opens: %v", err)
	}
}

func keychainKey(t *testing.T) []byte {
	t.Helper()
	k, ok := keyring.FromKeychain()
	if !ok {
		t.Fatal("no key in the keychain")
	}
	return k
}

// --- the recovery code ---

func TestRecoveryCodeShapeAndTyping(t *testing.T) {
	code := newRecoveryCode()
	if !codeShape.MatchString(code) || len(code) != 39 {
		t.Fatalf("code %q is not eight groups of four", code)
	}
	if newRecoveryCode() == code {
		t.Fatal("two codes came out the same")
	}
	plain, ok := normalizeRecoveryCode(code)
	if !ok || len(plain) != recoveryChars {
		t.Fatalf("a fresh code did not normalize: %q", plain)
	}
	// Case, dashes and spaces do not matter; look-alike letters are read as
	// the digits they stand for.
	sloppy := " " + strings.ToLower(strings.ReplaceAll(code, "-", " ")) + "\n"
	sloppy = strings.NewReplacer("0", "o", "1", "l").Replace(sloppy)
	if got, ok := normalizeRecoveryCode(sloppy); !ok || got != plain {
		t.Fatalf("a sloppily typed code did not normalize to the same code")
	}
	for _, bad := range []string{"", "ABCD", plain + "A", plain[:31] + "U", plain[:31] + "!"} {
		if _, ok := normalizeRecoveryCode(bad); ok {
			t.Errorf("%d characters ending %q passed as a recovery code", len(bad), bad[max(0, len(bad)-1):])
		}
	}
}

// A new vault gets its recovery code the moment its key is made, in either
// mode, when a person is there to be shown it.
func TestFirstKeyComesWithARecoveryCode(t *testing.T) {
	for _, mode := range []string{"keychain", "VAULTMCP_KEY"} {
		t.Run(mode, func(t *testing.T) {
			useMockKeychain(t)
			terminal(t, true)
			v := newTestVault(t)
			if mode == "VAULTMCP_KEY" {
				t.Setenv("VAULTMCP_KEY", "a passphrase for tests")
			}
			var err error
			stdout, stderr := output(t, func() { err = cmdSet([]string{"MINE", "value-one"}) })
			if err != nil {
				t.Fatal(err)
			}
			code := codeShape.FindString(stderr)
			if code == "" || !strings.Contains(stderr, "shown once") {
				t.Fatalf("no recovery code and notice on stderr:\n%s", stderr)
			}
			if codeShape.MatchString(stdout) {
				t.Fatal("the recovery code was printed on stdout, where `set` output gets piped and logged")
			}
			master, err := masterKeyNonInteractive(v.p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := openRecovery(v.p, code)
			if err != nil || !bytes.Equal(got, master) {
				t.Fatalf("the code shown does not open the vault's own key: %v", err)
			}
		})
	}
}

// With nobody at a terminal, a code would go into a log. None is made, the
// command says so, and status keeps saying it.
func TestNoRecoveryCodeIsPrintedIntoALog(t *testing.T) {
	useMockKeychain(t)
	terminal(t, false)
	v := newTestVault(t)
	var err error
	stdout, stderr := output(t, func() { err = cmdSet([]string{"MINE", "value-one"}) })
	if err != nil {
		t.Fatal(err)
	}
	if codeShape.MatchString(stdout + stderr) {
		t.Fatal("a recovery code was printed with nobody at a terminal")
	}
	if fileExists(v.p.Recovery) {
		t.Fatal("recovery.enc was made for a code nobody was shown")
	}
	if !strings.Contains(stderr, "no recovery code yet") {
		t.Fatalf("set did not say that no recovery code exists:\n%s", stderr)
	}
	status, _ := output(t, func() { _ = cmdStatus(nil) })
	if !strings.Contains(status, "NO RECOVERY CODE") {
		t.Fatalf("status does not show the missing recovery code:\n%s", status)
	}
}

func TestRecoveryCodeCommandReplacesTheOldCode(t *testing.T) {
	v, first := keychainVault(t)
	var err error
	stdout, stderr := output(t, func() { err = cmdRecoveryCode(nil) })
	if err != nil {
		t.Fatal(err)
	}
	second := strings.TrimSpace(stdout)
	if !codeShape.MatchString(second) || second != codeShape.FindString(stdout) || strings.Contains(stdout, " ") {
		t.Fatalf("stdout must be the code and nothing else, for piping: %q", stdout)
	}
	if codeShape.MatchString(stderr) {
		t.Fatal("the code was also printed on stderr")
	}
	if second == first {
		t.Fatal("the new code is the old code")
	}
	if _, err := openRecovery(v.p, first); err == nil {
		t.Fatal("the old code still opens recovery.enc")
	}
	if got, err := openRecovery(v.p, second); err != nil || !bytes.Equal(got, keychainKey(t)) {
		t.Fatalf("the new code does not open the key: %v", err)
	}
	status, _ := output(t, func() { _ = cmdStatus(nil) })
	if !strings.Contains(status, "a recovery code exists") {
		t.Fatalf("status does not show the recovery code:\n%s", status)
	}
	if err := cmdRecoveryCode([]string{"--print"}); err == nil {
		t.Fatal("an unknown argument was accepted")
	}
}

// --- recover ---

// The keychain entry is gone. The code brings the same key back, so the
// secrets open as before.
func TestRecoverBringsTheKeyBackToTheKeychain(t *testing.T) {
	v, code := keychainVault(t)
	before := keychainKey(t)
	if err := keyring.DeleteFromKeychain(); err != nil {
		t.Fatal(err)
	}

	answers(t, "0000-0000-0000-0000-0000-0000-0000-0000")
	if err := cmdRecover(nil); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("a wrong code: err = %v, want a refusal", err)
	}
	answers(t, "not a code")
	if err := cmdRecover(nil); err == nil || !strings.Contains(err.Error(), "not a recovery code") {
		t.Fatalf("a malformed code: err = %v, want a refusal", err)
	}
	if _, ok := keyring.FromKeychain(); ok {
		t.Fatal("a refused recover put a key in the keychain")
	}

	answers(t, strings.ToLower(strings.ReplaceAll(code, "-", " ")))
	if err := cmdRecover(nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !bytes.Equal(keychainKey(t), before) {
		t.Fatal("recover put back another key")
	}
	mustGet(t, v)
	if err := cmdRecover([]string{code}); err == nil {
		t.Fatal("the code was accepted as an argument, where it lands in shell history")
	}
}

// The passphrase is forgotten. Recover writes a new key.enc for the same key
// under a new passphrase, and keeps the old file.
func TestRecoverWithANewPassphrase(t *testing.T) {
	useMockKeychain(t)
	terminal(t, true)
	v := newTestVault(t)
	t.Setenv("VAULTMCP_KEY", "the first passphrase")
	var err error
	_, shown := output(t, func() { err = cmdSet([]string{"MINE", "value-one"}) })
	if err != nil {
		t.Fatal(err)
	}
	code := codeShape.FindString(shown)

	t.Setenv("VAULTMCP_KEY", "a second passphrase")
	if _, err := masterKeyNonInteractive(v.p); err == nil {
		t.Fatal("the vault opened with the wrong passphrase")
	}
	answers(t, code)
	if err := cmdRecover(nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	mustGet(t, v)
	kept, _ := filepath.Glob(v.p.Key + ".before-recover-*")
	if len(kept) != 1 {
		t.Fatalf("the old key.enc was not kept aside: %v", kept)
	}
	if _, err := keyring.UnwrapFromFile(kept[0], "the first passphrase"); err != nil {
		t.Fatalf("the file kept aside is not the old key.enc: %v", err)
	}
	if _, ok := keyring.FromKeychain(); ok {
		t.Fatal("recover in VAULTMCP_KEY mode wrote to the keychain")
	}
}

// The keychain entry is one per user. Recover must not write over an entry
// that holds another vault's key.
func TestRecoverLeavesAnotherKeychainKeyAlone(t *testing.T) {
	_, code := keychainVault(t)
	other := crypto.NewKey()
	if err := keyring.ToKeychain(other); err != nil {
		t.Fatal(err)
	}
	answers(t, code)
	if err := cmdRecover(nil); err == nil || !strings.Contains(err.Error(), "different key") {
		t.Fatalf("recover over another key: err = %v, want a refusal", err)
	}
	if !bytes.Equal(keychainKey(t), other) {
		t.Fatal("recover replaced the other vault's key")
	}
}

// A recovery file from another vault opens with its own code, but its key
// does not open this store. Nothing may change.
func TestRecoverChecksTheKeyAgainstTheStore(t *testing.T) {
	v, _ := keychainVault(t)
	strangerCode, err := makeRecovery(v.p, crypto.NewKey())
	if err != nil {
		t.Fatal(err)
	}
	before := keychainKey(t)
	answers(t, strangerCode)
	if err := cmdRecover(nil); err == nil || !strings.Contains(err.Error(), "does not open store.enc") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if !bytes.Equal(keychainKey(t), before) {
		t.Fatal("a refused recover changed the keychain")
	}
}

// --- lock and unlock ---

// Lock moves the key into key.enc and unlock moves it back. The key is the
// same key throughout, and it is never in neither place.
func TestLockMovesTheKeyAndUnlockMovesItBack(t *testing.T) {
	v, _ := keychainVault(t)
	master := keychainKey(t)

	answers(t, "a passphrase for the lock")
	if err := cmdLock(nil); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, ok := keyring.FromKeychain(); ok {
		t.Fatal("lock left the key in the keychain")
	}
	inFile, err := keyring.UnwrapFromFile(v.p.Key, "a passphrase for the lock")
	if err != nil || !bytes.Equal(inFile, master) {
		t.Fatalf("after lock, key.enc does not hold the vault's key: %v", err)
	}
	if !fileExists(v.p.Locked) {
		t.Fatal("lock did not leave its marker")
	}
	if _, err := masterKeyNonInteractive(v.p); err == nil {
		t.Fatal("a locked vault still opens without the passphrase")
	}
	status, _ := output(t, func() { _ = cmdStatus(nil) })
	if !strings.Contains(status, "LOCKED") {
		t.Fatalf("status does not show the lock:\n%s", status)
	}
	stdout, _ := output(t, func() { err = cmdLock(nil) })
	if err != nil || !strings.Contains(stdout, "already locked") {
		t.Fatalf("a second lock: err=%v out=%q", err, stdout)
	}

	answers(t, "not the passphrase")
	if err := cmdUnlock(nil); err == nil {
		t.Fatal("unlock took a wrong passphrase")
	}
	if _, ok := keyring.FromKeychain(); ok || !fileExists(v.p.Locked) {
		t.Fatal("a refused unlock changed something")
	}
	answers(t, "a passphrase for the lock")
	if err := cmdUnlock(nil); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !bytes.Equal(keychainKey(t), master) {
		t.Fatal("unlock put back another key")
	}
	if fileExists(v.p.Locked) {
		t.Fatal("unlock left the marker")
	}
	mustGet(t, v)

	// The second lock finds key.enc and asks for its passphrase once. A wrong
	// one changes nothing.
	answers(t, "not the passphrase")
	if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "did not open") {
		t.Fatalf("lock with a wrong passphrase: err = %v, want a refusal", err)
	}
	if !bytes.Equal(keychainKey(t), master) || fileExists(v.p.Locked) {
		t.Fatal("a refused lock changed something")
	}
	answers(t, "a passphrase for the lock")
	if err := cmdLock(nil); err != nil {
		t.Fatalf("second lock: %v", err)
	}
	if _, ok := keyring.FromKeychain(); ok {
		t.Fatal("the second lock left the key in the keychain")
	}
}

// Every way lock can refuse, and after each the key is still where it was.
func TestLockRefusesAndKeepsTheKey(t *testing.T) {
	t.Run("no recovery code", func(t *testing.T) {
		useMockKeychain(t)
		terminal(t, false) // so the first set makes no code
		newTestVault(t)
		if err := cmdSet([]string{"MINE", "value-one"}); err != nil {
			t.Fatal(err)
		}
		before := keychainKey(t)
		if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "no recovery code") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if !bytes.Equal(keychainKey(t), before) {
			t.Fatal("the key is gone")
		}
	})
	// The keychain entry is one per user. From another, empty folder there is
	// no recovery code, so lock must not take the shared key away.
	t.Run("another vault's key, from an empty folder", func(t *testing.T) {
		keychainVault(t)
		before := keychainKey(t)
		newTestVault(t) // VAULTMCP_DIR now names another, empty folder
		if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "no recovery code") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if !bytes.Equal(keychainKey(t), before) {
			t.Fatal("lock from an empty folder deleted the key of another vault")
		}
	})
	// A key.enc that holds ANOTHER key is no copy: this is the vault an
	// earlier version left behind when VAULTMCP_KEY was set on a keychain
	// vault.
	t.Run("key.enc holds a different key", func(t *testing.T) {
		v, _ := keychainVault(t)
		before := keychainKey(t)
		if err := keyring.WrapToFile(v.p.Key, crypto.NewKey(), "a passphrase"); err != nil {
			t.Fatal(err)
		}
		answers(t, "a passphrase")
		if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "different key") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if !bytes.Equal(keychainKey(t), before) || fileExists(v.p.Locked) {
			t.Fatal("a refused lock changed something")
		}
	})
	t.Run("VAULTMCP_KEY is set", func(t *testing.T) {
		v, _ := keychainVault(t)
		before := keychainKey(t)
		t.Setenv("VAULTMCP_KEY", "a passphrase")
		if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "VAULTMCP_KEY is set") {
			t.Fatalf("err = %v, want a refusal", err)
		}
		if !bytes.Equal(keychainKey(t), before) || fileExists(v.p.Key) {
			t.Fatal("a refused lock changed something")
		}
	})
	t.Run("key.enc cannot be written", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a folder that refuses new files")
		}
		v, _ := keychainVault(t)
		before := keychainKey(t)
		if err := os.Chmod(v.p.Dir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(v.p.Dir, 0o700) })
		answers(t, "a passphrase for the lock")
		if err := cmdLock(nil); err == nil {
			t.Fatal("lock reported success without a key file")
		}
		if !bytes.Equal(keychainKey(t), before) {
			t.Fatal("the key left the keychain though key.enc was never written")
		}
	})
}

// With VAULTMCP_KEY the vault is never locked, and unlock says so instead of
// claiming to have unlocked something. Without a keychain it says that.
func TestUnlockSaysWhatItDid(t *testing.T) {
	t.Run("VAULTMCP_KEY", func(t *testing.T) {
		useMockKeychain(t)
		terminal(t, false)
		newTestVault(t)
		t.Setenv("VAULTMCP_KEY", "a passphrase for tests")
		if err := cmdSet([]string{"MINE", "value-one"}); err != nil {
			t.Fatal(err)
		}
		var err error
		stdout, _ := output(t, func() { err = cmdUnlock(nil) })
		if err != nil || !strings.Contains(stdout, "nothing to unlock") {
			t.Fatalf("err=%v out=%q", err, stdout)
		}
		t.Setenv("VAULTMCP_KEY", "another passphrase")
		if err := cmdUnlock(nil); err == nil || !strings.Contains(err.Error(), "does not open key.enc") {
			t.Fatalf("a wrong VAULTMCP_KEY: err = %v", err)
		}
	})
	t.Run("already unlocked", func(t *testing.T) {
		keychainVault(t)
		var err error
		stdout, _ := output(t, func() { err = cmdUnlock(nil) })
		if err != nil || !strings.Contains(stdout, "already unlocked") {
			t.Fatalf("err=%v out=%q", err, stdout)
		}
	})
	t.Run("no keychain on this machine", func(t *testing.T) {
		v, _ := keychainVault(t)
		answers(t, "a passphrase for the lock")
		if err := cmdLock(nil); err != nil {
			t.Fatal(err)
		}
		zk.MockInitWithError(errors.New("no keychain here"))
		t.Cleanup(zk.MockInit)
		answers(t, "a passphrase for the lock")
		var err error
		stdout, _ := output(t, func() { err = cmdUnlock(nil) })
		if err != nil || !strings.Contains(stdout, "no OS keychain") || strings.Contains(stdout, "vault unlocked:") {
			t.Fatalf("err=%v out=%q", err, stdout)
		}
		if fileExists(v.p.Locked) {
			t.Fatal("the lock marker outlived a correct passphrase")
		}
	})
	t.Run("nothing to unlock", func(t *testing.T) {
		useMockKeychain(t)
		newTestVault(t)
		if err := cmdUnlock(nil); err == nil || !strings.Contains(err.Error(), "nothing to unlock") {
			t.Fatalf("err = %v", err)
		}
	})
}

// --- what the hook does when it cannot reach the key ---

const (
	claudeEvent = `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Read","tool_input":{"file_path":"/x"}}`
	claudePost  = `{"hook_event_name":"PostToolUse","session_id":"s","tool_name":"Read","tool_input":{"file_path":"/x"},"tool_response":"text"}`
	grokEvent   = `{"hookEventName":"pre_tool_use","hook_event_name":"PreToolUse","toolName":"Read","toolInput":{"file_path":"/x"}}`
	cursorEvent = `{"hook_event_name":"beforeShellExecution","command":"ls"}`
)

func hookSays(t *testing.T, p vault.Paths, event string, now time.Time) string {
	t.Helper()
	var out bytes.Buffer
	runHook([]byte(event), &out, p, now)
	return out.String()
}

// Locked on purpose: the tool call is stopped, in the form each agent tool
// documents. A call that already ran cannot be stopped, so nothing is said.
func TestHookStopsToolCallsWhileLockedOnPurpose(t *testing.T) {
	v, _ := keychainVault(t)
	answers(t, "a passphrase for the lock")
	if err := cmdLock(nil); err != nil {
		t.Fatal(err)
	}
	for name, event := range map[string]string{"claude": claudeEvent, "grok": grokEvent} {
		got := hookSays(t, v.p, event, testNow)
		if !strings.Contains(got, `"permissionDecision":"deny"`) || !strings.Contains(got, "vaultmcp unlock") || strings.Contains(got, "systemMessage") {
			t.Errorf("%s: want a bare deny that names the fix, got %s", name, got)
		}
	}
	if got := hookSays(t, v.p, cursorEvent, testNow); !strings.Contains(got, `"permission":"deny"`) || !strings.Contains(got, `"user_message"`) {
		t.Errorf("cursor: want its own deny form, got %s", got)
	}
	if got := hookSays(t, v.p, claudePost, testNow); got != "" {
		t.Errorf("a finished call was answered: %s", got)
	}

	// Unlocked again, the hook is back to its normal work.
	answers(t, "a passphrase for the lock")
	if err := cmdUnlock(nil); err != nil {
		t.Fatal(err)
	}
	if got := hookSays(t, v.p, claudeEvent, testNow); got != "" {
		t.Errorf("after unlock, a call with nothing to redact was answered: %s", got)
	}
}

// A marker left behind must never stop a vault whose key can be reached. This
// is the unattended setup: VAULTMCP_KEY plus key.enc.
func TestStaleLockMarkerDoesNotStopAnOpenVault(t *testing.T) {
	useMockKeychain(t)
	terminal(t, false)
	v := newTestVault(t)
	t.Setenv("VAULTMCP_KEY", "a passphrase for tests")
	if err := cmdSet([]string{"MINE", "value-one"}); err != nil {
		t.Fatal(err)
	}
	redact := string(hookInput(fakeToken(1)))
	without := hookSays(t, v.p, redact, testNow)
	if !strings.Contains(without, "vault:") {
		t.Fatalf("the hook did not redact: %s", without)
	}
	if err := os.WriteFile(v.p.Locked, []byte("stale\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if with := hookSays(t, v.p, redact, testNow); with != without {
		t.Fatalf("a stale marker changed the hook's answer:\n%s\n%s", without, with)
	}
	if got := hookSays(t, v.p, claudeEvent, testNow); got != "" {
		t.Fatalf("a stale marker made the hook answer a plain call: %s", got)
	}
}

// The key is out of reach but nobody locked the vault: the call goes ahead
// and the person is told, not on every call, and only where the agent tool
// documents a way to tell them.
func TestHookWarnsWhenTheKeyIsOutOfReach(t *testing.T) {
	useMockKeychain(t)
	terminal(t, false)
	v := newTestVault(t)
	t.Setenv("VAULTMCP_KEY", "a passphrase for tests")
	if err := cmdSet([]string{"MINE", "value-one"}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULTMCP_KEY", "") // an app that never loaded the shell profile

	for name, event := range map[string]string{"grok": grokEvent, "cursor": cursorEvent, "a finished call": claudePost} {
		if got := hookSays(t, v.p, event, testNow); got != "" {
			t.Errorf("%s has no documented way to show a warning, but got %s", name, got)
		}
	}
	first := hookSays(t, v.p, claudeEvent, testNow)
	if !strings.Contains(first, `"systemMessage"`) || !strings.Contains(first, "NOT being hidden") || strings.Contains(first, "deny") {
		t.Fatalf("want a warning that lets the call through, got %s", first)
	}
	if got := hookSays(t, v.p, claudeEvent, testNow.Add(warnEvery-time.Second)); got != "" {
		t.Fatalf("the warning was repeated inside %s: %s", warnEvery, got)
	}
	if got := hookSays(t, v.p, claudeEvent, testNow.Add(warnEvery+time.Second)); !strings.Contains(got, `"systemMessage"`) {
		t.Fatalf("the warning was not repeated after %s: %s", warnEvery, got)
	}
}

// A key that is found but opens nothing here (another folder's key in the
// keychain) is the same danger: redaction is off, and the person is told.
func TestHookWarnsWhenTheKeyDoesNotOpenTheStore(t *testing.T) {
	v, _ := keychainVault(t)
	if err := keyring.ToKeychain(crypto.NewKey()); err != nil {
		t.Fatal(err)
	}
	got := hookSays(t, v.p, claudeEvent, testNow)
	if !strings.Contains(got, `"systemMessage"`) || !strings.Contains(got, "does not open this vault") {
		t.Fatalf("want a warning, got %s", got)
	}
}

// A machine where the vault was never used: the hook stays out of the way.
func TestHookIsSilentWhenTheVaultWasNeverSetUp(t *testing.T) {
	useMockKeychain(t)
	v := newTestVault(t)
	for _, event := range []string{claudeEvent, grokEvent, cursorEvent, claudePost} {
		if got := hookSays(t, v.p, event, testNow); got != "" {
			t.Errorf("an unused vault made the hook answer: %s", got)
		}
	}
}

// A key that is not this vault's must not be sealed, moved or called "open":
// the keychain holds one key per user, and it may be another folder's.
func TestCommandsRefuseAKeyThatDoesNotOpenTheStore(t *testing.T) {
	v, code := keychainVault(t)
	other := crypto.NewKey()
	if err := keyring.ToKeychain(other); err != nil {
		t.Fatal(err)
	}
	if err := cmdRecoveryCode(nil); err == nil || !strings.Contains(err.Error(), "does not open this vault's store.enc") {
		t.Fatalf("recovery-code: err = %v, want a refusal", err)
	}
	if _, err := openRecovery(v.p, code); err != nil {
		t.Fatal("a refused recovery-code replaced the recovery file of the real key")
	}
	if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "does not open store.enc") {
		t.Fatalf("lock: err = %v, want a refusal", err)
	}
	if err := os.WriteFile(v.p.Locked, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdUnlock(nil); err == nil || !strings.Contains(err.Error(), "does not open store.enc") {
		t.Fatalf("unlock: err = %v, want a refusal", err)
	}
	if !bytes.Equal(keychainKey(t), other) || fileExists(v.p.Key) || !fileExists(v.p.Locked) {
		t.Fatal("a refused command changed something")
	}
}

// If the new key.enc cannot be written, the old one is still there.
func TestRecoverKeepsTheOldKeyFileWhenTheNewOneFails(t *testing.T) {
	useMockKeychain(t)
	terminal(t, true)
	v := newTestVault(t)
	t.Setenv("VAULTMCP_KEY", "the first passphrase")
	var err error
	_, shown := output(t, func() { err = cmdSet([]string{"MINE", "value-one"}) })
	if err != nil {
		t.Fatal(err)
	}
	code := codeShape.FindString(shown)
	// A folder where the new file has to go makes the write fail.
	if err := os.Mkdir(v.p.Key+".new-"+strconv.Itoa(os.Getpid()), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VAULTMCP_KEY", "a second passphrase")
	answers(t, code)
	if err := cmdRecover(nil); err == nil {
		t.Fatal("recover reported success though key.enc could not be written")
	}
	if _, err := keyring.UnwrapFromFile(v.p.Key, "the first passphrase"); err != nil {
		t.Fatalf("the old key.enc is gone or changed after a failed recover: %v", err)
	}
	if kept, _ := filepath.Glob(v.p.Key + ".before-recover-*"); len(kept) != 0 {
		t.Fatalf("a failed recover left a copy behind: %v", kept)
	}
}

// The key is already out of the keychain, but no lock was ever declared (a
// passphrase vault whose VAULTMCP_KEY was taken away). `lock` declares it, and
// from then on the hook stops tool calls.
func TestLockDeclaresALockWhenTheKeyIsAlreadyOut(t *testing.T) {
	v, _ := keychainVault(t)
	answers(t, "a passphrase for the lock")
	if err := cmdLock(nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(v.p.Locked); err != nil {
		t.Fatal(err)
	}
	if got := hookSays(t, v.p, claudeEvent, testNow); strings.Contains(got, "deny") {
		t.Fatalf("with no marker the hook must not stop the call: %s", got)
	}
	var err error
	stdout, _ := output(t, func() { err = cmdLock(nil) })
	if err != nil || !strings.Contains(stdout, "already locked") || !fileExists(v.p.Locked) {
		t.Fatalf("err=%v marker=%v out=%q", err, fileExists(v.p.Locked), stdout)
	}
	if got := hookSays(t, v.p, claudeEvent, testNow); !strings.Contains(got, `"permissionDecision":"deny"`) {
		t.Fatalf("after lock the hook must stop the call: %s", got)
	}
}

// If the marker cannot be written, nothing is locked: the key stays in the
// keychain, so there is never a vault that is "locked" yet lets calls through.
func TestLockWithoutAMarkerLeavesTheKeyInTheKeychain(t *testing.T) {
	v, _ := keychainVault(t)
	before := keychainKey(t)
	if err := os.Mkdir(v.p.Locked, 0o700); err != nil { // a folder in the marker's place
		t.Fatal(err)
	}
	answers(t, "a passphrase for the lock")
	if err := cmdLock(nil); err == nil || !strings.Contains(err.Error(), "nothing was locked") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if !bytes.Equal(keychainKey(t), before) {
		t.Fatal("the key left the keychain though the lock was not recorded")
	}
}

// Recover ends a lock. If the passphrase typed already opens key.enc there is
// nothing to write, but the key must still go back into the keychain, or the
// vault would be "not locked" with a key the hook cannot reach.
func TestRecoverUnlocksEvenWhenTheKeyFileNeedsNoChange(t *testing.T) {
	v, code := keychainVault(t)
	master := keychainKey(t)
	answers(t, "a passphrase for the lock")
	if err := cmdLock(nil); err != nil {
		t.Fatal(err)
	}
	answers(t, code, "a passphrase for the lock")
	if err := cmdRecover(nil); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !bytes.Equal(keychainKey(t), master) {
		t.Fatal("recover ended the lock but left the key out of the keychain")
	}
	if kept, _ := filepath.Glob(v.p.Key + ".before-recover-*"); len(kept) != 0 || fileExists(v.p.Locked) {
		t.Fatalf("kept=%v marker=%v", kept, fileExists(v.p.Locked))
	}
	if got := hookSays(t, v.p, claudeEvent, testNow); got != "" {
		t.Fatalf("after recover the hook answered a plain call: %s", got)
	}
}
