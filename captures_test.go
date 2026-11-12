package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/hook"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

const testMachine = "test-machine"

// testNow is a whole second, like every Created the hook writes.
var testNow = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

type testVault struct {
	p      vault.Paths
	master []byte
	capKey []byte
}

// newTestVault points the whole CLI at a temp vault. VAULTMCP_DIR isolates the
// vault folder; HOME is moved too, so a path that ignored VAULTMCP_DIR would
// land in a temp dir (and fail the test) rather than in the real vault. The
// machine id is injected, never read from the hardware.
func newTestVault(t *testing.T) testVault {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "vault")
	t.Setenv("VAULTMCP_DIR", dir)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	setMachineID(t, testMachine, nil)

	p, err := vault.DefaultPaths()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	master := crypto.NewKey()
	return testVault{p: p, master: master, capKey: capture.Key(master, testMachine)}
}

// newPassphraseVault is newTestVault for tests that go through the cmd*
// entry points. Those resolve the master key themselves, so it is put in
// passphrase mode: with VAULTMCP_KEY set and key.enc present the resolvers
// never reach for the OS keychain.
func newPassphraseVault(t *testing.T) testVault {
	t.Helper()
	v := newTestVault(t)
	const pass = "passphrase for the test vault"
	t.Setenv("VAULTMCP_KEY", pass)
	master, err := masterKeyFromPassphrase(v.p, pass, true)
	if err != nil {
		t.Fatal(err)
	}
	v.master, v.capKey = master, capture.Key(master, testMachine)
	return v
}

func setMachineID(t *testing.T, id string, err error) {
	t.Helper()
	prev := machineID
	machineID = func() (string, error) { return id, err }
	t.Cleanup(func() { machineID = prev })
}

// fakeToken builds a distinct GitHub-token-shaped value at runtime, so no
// secret-shaped literal sits in this file for the live hook to vault.
func fakeToken(i int) string {
	return "ghp_" + strings.Repeat("a1B2", 6) + fmt.Sprintf("%04d", i)
}

// hookInput is a PreToolUse event for a non-shell tool carrying value. A shell
// tool would get the test binary's own path spliced into the rewritten JSON,
// and on Windows that path has backslashes the hook cannot emit.
func hookInput(value string) []byte {
	return []byte(`{"hook_event_name":"PreToolUse","session_id":"s","cwd":"/w","tool_name":"Write","tool_input":{"file_path":"/x","content":"k=` + value + `"}}`)
}

func (v testVault) saveStore(t *testing.T, s vault.Store) {
	t.Helper()
	if err := vault.Save(v.p.Store, s, v.master); err != nil {
		t.Fatal(err)
	}
}

func (v testVault) loadStore(t *testing.T) vault.Store {
	t.Helper()
	s, err := vault.Load(v.p.Store, v.master)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// capture writes a capture file the way the hook does and returns its alias.
func (v testVault) capture(t *testing.T, value string, created time.Time) string {
	t.Helper()
	alias := capture.Alias(v.capKey, "github_token", value)
	e := capture.Entry{Value: value, Kind: "github_token", Created: created.UTC().Format(time.RFC3339), Tool: "Bash"}
	if _, err := capture.Write(v.p.Captured, v.capKey, alias, e); err != nil {
		t.Fatal(err)
	}
	return alias
}

func (v testVault) isUsed(t *testing.T, alias string) bool {
	t.Helper()
	items, err := capture.List(v.p.Captured, v.capKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Alias == alias {
			return it.Used
		}
	}
	t.Fatalf("capture %s not listed", alias)
	return false
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- lookup order ---

func TestResolveNamedWinsOverCapture(t *testing.T) {
	v := newTestVault(t)
	v.saveStore(t, vault.Store{"BOTH": "the named value"})
	e := capture.Entry{Value: "the captured value", Kind: "github_token", Created: testNow.Format(time.RFC3339)}
	if _, err := capture.Write(v.p.Captured, v.capKey, "BOTH", e); err != nil {
		t.Fatal(err)
	}
	got, err := resolve(v.p, v.master, "BOTH", testNow.Add(time.Hour))
	if err != nil || got != "the named value" {
		t.Fatalf("resolve = %q, %v; the named secret must win", got, err)
	}
	if v.isUsed(t, "BOTH") {
		t.Fatal("resolving a named secret touched the capture of the same alias")
	}
}

// `get NAME` for a named secret works whatever state captured/ is in.
func TestResolveNamedWithBrokenCaptures(t *testing.T) {
	cases := map[string]func(t *testing.T, v testVault){
		"missing folder": func(t *testing.T, v testVault) {},
		"a file where the folder should be": func(t *testing.T, v testVault) {
			if err := os.WriteFile(v.p.Captured, []byte("not a folder"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"corrupt capture files": func(t *testing.T, v testVault) {
			if err := os.MkdirAll(v.p.Captured, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"NAMED.enc", "OTHER.enc", "junk"} {
				if err := os.WriteFile(filepath.Join(v.p.Captured, name), []byte("garbage"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			v := newTestVault(t)
			v.saveStore(t, vault.Store{"NAMED": "the named value"})
			breakIt(t, v)
			got, err := resolve(v.p, v.master, "NAMED", testNow)
			if err != nil || got != "the named value" {
				t.Fatalf("resolve = %q, %v", got, err)
			}
			// An alias that is nowhere is a plain error, not a crash.
			if _, err := resolve(v.p, v.master, "NOWHERE", testNow); err == nil {
				t.Fatal("resolving an unknown alias must fail")
			}
		})
	}
}

// A machine with no id must still be able to read what it captured.
func TestResolveNamedWithoutMachineID(t *testing.T) {
	v := newTestVault(t)
	setMachineID(t, "", errors.New("no id on this machine"))
	v.saveStore(t, vault.Store{"NAMED": "the named value"})
	if got, err := resolve(v.p, v.master, "NAMED", testNow); err != nil || got != "the named value" {
		t.Fatalf("resolve = %q, %v", got, err)
	}
	key, locked := captureKey(v.master)
	if locked || !bytes.Equal(key, capture.Key(v.master, "")) {
		t.Fatal("with no machine id the capture key must be the unlocked one, reported as not locked")
	}
}

func TestResolveCaptureMarksItUsed(t *testing.T) {
	v := newTestVault(t)
	v.saveStore(t, vault.Store{"NAMED": "x"})
	alias := v.capture(t, fakeToken(1), testNow)
	if v.isUsed(t, alias) {
		t.Fatal("a fresh capture must be never-used")
	}
	// Read in the same second it was captured: the usual shell substitution.
	got, err := resolve(v.p, v.master, alias, testNow.Add(300*time.Millisecond))
	if err != nil || got != fakeToken(1) {
		t.Fatalf("resolve capture failed: %v", err)
	}
	if !v.isUsed(t, alias) {
		t.Fatal("reading a capture must mark it used")
	}
}

func TestResolveCaptureFromAnotherMachine(t *testing.T) {
	v := newTestVault(t)
	alias := v.capture(t, fakeToken(1), testNow)
	setMachineID(t, "a-different-machine", nil)
	_, err := resolve(v.p, v.master, alias, testNow)
	if err == nil || !strings.Contains(err.Error(), "does not open on this machine") {
		t.Fatalf("expected a machine-lock error, got %v", err)
	}
}

func TestResolveRejectsPathLikeAlias(t *testing.T) {
	v := newTestVault(t)
	v.capture(t, fakeToken(1), testNow)
	for _, alias := range []string{"../STORE", "..", "A/B", ""} {
		if _, err := resolve(v.p, v.master, alias, testNow); err == nil || !strings.Contains(err.Error(), "no secret for alias") {
			t.Errorf("resolve(%q) err = %v, want a plain not-found", alias, err)
		}
	}
}

// --- set / delete / list / status ---

func TestSetRefusesNameOfExistingCapture(t *testing.T) {
	v := newPassphraseVault(t)
	e := capture.Entry{Value: fakeToken(1), Kind: "github_token", Created: testNow.Format(time.RFC3339)}
	if _, err := capture.Write(v.p.Captured, v.capKey, "TAKEN_NAME", e); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"TAKEN_NAME", "taken-name"} { // the second normalizes to the first
		err := cmdSet([]string{name, "a new value"})
		if err == nil || !strings.Contains(err.Error(), "captured secret") {
			t.Fatalf("set %s err = %v, want a refusal", name, err)
		}
	}
	if _, err := os.Stat(v.p.Store); !os.IsNotExist(err) {
		t.Fatal("a refused set wrote the store")
	}
	// The capture is untouched, and a free name still works.
	if got, err := resolve(v.p, v.master, "TAKEN_NAME", testNow); err != nil || got != fakeToken(1) {
		t.Fatalf("capture changed by a refused set: %v", err)
	}
	if err := cmdSet([]string{"FREE_NAME", "a new value"}); err != nil {
		t.Fatalf("set of a free name failed: %v", err)
	}
	if got := v.loadStore(t)["FREE_NAME"]; got != "a new value" {
		t.Fatalf("store holds %q for FREE_NAME", got)
	}
}

func TestDeleteNamedOrCapture(t *testing.T) {
	v := newPassphraseVault(t)
	v.saveStore(t, vault.Store{"NAMED": "x", "KEEP": "y"})
	alias := v.capture(t, fakeToken(1), testNow)
	other := v.capture(t, fakeToken(2), testNow)

	if err := cmdDelete([]string{alias, "--yes"}); err != nil {
		t.Fatalf("delete capture: %v", err)
	}
	if capture.Exists(v.p.Captured, alias) || !capture.Exists(v.p.Captured, other) {
		t.Fatal("delete removed the wrong capture file")
	}
	if err := cmdDelete([]string{"NAMED", "--yes"}); err != nil {
		t.Fatalf("delete named: %v", err)
	}
	store := v.loadStore(t)
	if _, ok := store["NAMED"]; ok || store["KEEP"] != "y" {
		t.Fatalf("store after delete = %v", sortedKeys(store))
	}
	if err := cmdDelete([]string{"NOWHERE", "--yes"}); err == nil {
		t.Fatal("deleting an unknown alias must fail")
	}
	if err := cmdDelete([]string{"../store", "--yes"}); err == nil {
		t.Fatal("deleting a path-like alias must fail")
	}
	if _, err := os.Stat(v.p.Store); err != nil {
		t.Fatal("store.enc is gone")
	}
}

func TestListNamedThenCaptureCount(t *testing.T) {
	v := newTestVault(t)
	v.saveStore(t, vault.Store{"NAMED_ONE": "x", "NAMED_TWO": "y"})
	captured := v.capture(t, fakeToken(1), testNow)
	v.capture(t, fakeToken(2), testNow)

	var out bytes.Buffer
	if err := listNamed(&out, v.p, v.master); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	for _, want := range []string{"2 secret(s)", "NAMED_ONE", "NAMED_TWO", "2 captured by the hook", "vaultmcp list --captured"} {
		if !strings.Contains(text, want) {
			t.Errorf("list output lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, captured) {
		t.Errorf("plain list must not show captures:\n%s", text)
	}
}

func TestListCaptured(t *testing.T) {
	v := newTestVault(t)
	v.saveStore(t, vault.Store{"NAMED_ONE": "x"})
	fresh := v.capture(t, fakeToken(1), testNow.Add(-3*24*time.Hour))
	read := v.capture(t, fakeToken(2), testNow.Add(-5*time.Hour))
	if _, err := resolve(v.p, v.master, read, testNow.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	foreign := capture.Alias(capture.Key(v.master, "elsewhere"), "github_token", fakeToken(3))
	e := capture.Entry{Value: fakeToken(3), Kind: "github_token", Created: testNow.Format(time.RFC3339)}
	if _, err := capture.Write(v.p.Captured, capture.Key(v.master, "elsewhere"), foreign, e); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := listCaptured(&out, v.p, v.master, testNow); err != nil {
		t.Fatal(err)
	}
	lines := map[string]string{}
	for _, line := range strings.Split(out.String(), "\n") {
		if f := strings.Fields(line); len(f) > 0 {
			lines[f[0]] = line
		}
	}
	for alias, wants := range map[string][]string{
		fresh:   {"github_token", " 3d ", "never used"},
		read:    {"github_token", " 5h ", " used "},
		foreign: {"does not open on this machine"},
	} {
		for _, want := range wants {
			if !strings.Contains(lines[alias], want) {
				t.Errorf("line for %s lacks %q: %q", alias, want, lines[alias])
			}
		}
	}
	if strings.Contains(lines[read], "never used") {
		t.Errorf("a read capture listed as never used: %q", lines[read])
	}
	text := out.String()
	for i := 1; i <= 3; i++ {
		if strings.Contains(text, fakeToken(i)) {
			t.Fatal("list --captured printed a full value")
		}
	}
	if strings.Contains(text, "NAMED_ONE") {
		t.Fatal("list --captured must not show named secrets")
	}
}

func TestStatusCounts(t *testing.T) {
	v := newTestVault(t)
	v.saveStore(t, vault.Store{"MY_KEY": "x", "GITHUB_TOKEN": "y", "JWT_TOKEN_12": "z"})
	v.capture(t, fakeToken(1), testNow)

	var out bytes.Buffer
	writeVaultCounts(&out, v.p, v.master)
	text := out.String()
	for _, want := range []string{"named:   3 secret(s)", "2 have hook-generated names", "vaultmcp migrate-captures", "captures: 1", "new captures are sealed for this machine only"} {
		if !strings.Contains(text, want) {
			t.Errorf("status lacks %q:\n%s", want, text)
		}
	}

	// No machine id: status must say so plainly.
	setMachineID(t, "", errors.New("no id"))
	out.Reset()
	writeVaultCounts(&out, v.p, v.master)
	if !strings.Contains(out.String(), "captures are NOT locked to this machine") {
		t.Errorf("status hides the missing machine lock:\n%s", out.String())
	}

	// Locked vault: no named count, but captures are still counted.
	out.Reset()
	writeVaultCounts(&out, v.p, nil)
	if strings.Contains(out.String(), "named:") || !strings.Contains(out.String(), "captures: 1") {
		t.Errorf("locked status wrong:\n%s", out.String())
	}

	// Nothing hook-named left: no migration hint.
	v.saveStore(t, vault.Store{"MY_KEY": "x"})
	out.Reset()
	writeVaultCounts(&out, v.p, v.master)
	if strings.Contains(out.String(), "migrate-captures") {
		t.Errorf("migration hint shown with nothing to migrate:\n%s", out.String())
	}
}

// --- migration ---

func TestAutoKind(t *testing.T) {
	cases := map[string]string{
		"GITHUB_TOKEN":             "github_token",
		"GITHUB_TOKEN_2":           "github_token",
		"HIGH_ENTROPY_SECRET_4821": "high_entropy_secret",
		"DB_CONNECTION_STRING_10":  "db_connection_string",
		"PRIVATE_KEY":              "private_key",
		"GITHUB_TOKEN_PROD":        "",
		"GITHUB_TOKEN_":            "",
		"GITHUB_TOKEN_2_3":         "",
		"GITHUB_TOKENS":            "",
		"github_token":             "",
		"STRIPE":                   "",
	}
	for alias, want := range cases {
		got, ok := autoKind(alias)
		if got != want || ok != (want != "") {
			t.Errorf("autoKind(%q) = %q, %v; want %q", alias, got, ok, want)
		}
	}
}

// migrationVault is a store as the old design left it, with its audit log.
//
//	GITHUB_TOKEN     a person ran `set GITHUB_TOKEN`          -> stays, reported
//	GITHUB_TOKEN_2   the hook captured it, and it was read    -> moves, used
//	JWT_TOKEN        the hook captured it, never read         -> moves, never used
//	STRIPE_KEY_3     generated-looking name, no audit record  -> stays, reported
//	OPENAI_KEY       captured by the hook, later set by hand  -> stays, reported
//	MY_API_KEY       an ordinary named secret                 -> stays
func migrationVault(t *testing.T) (testVault, vault.Store) {
	t.Helper()
	v := newTestVault(t)
	store := vault.Store{
		"GITHUB_TOKEN":   "set by a person",
		"GITHUB_TOKEN_2": fakeToken(2),
		"JWT_TOKEN":      fakeToken(3),
		"STRIPE_KEY_3":   "no audit record for this one",
		"OPENAI_KEY":     "captured then set by hand",
		"MY_API_KEY":     "ordinary named secret",
	}
	v.saveStore(t, store)
	for _, e := range [][2]string{
		{"set", "GITHUB_TOKEN"},
		{"vault", "GITHUB_TOKEN_2"},
		{"get", "GITHUB_TOKEN_2"},
		{"vault", "JWT_TOKEN"},
		{"vault", "OPENAI_KEY"},
		{"set", "OPENAI_KEY"},
		{"set", "MY_API_KEY"},
		{"get", "MY_API_KEY"},
	} {
		if err := audit.Log(v.p.Audit, e[0], e[1], "test", testNow.Add(-24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	// A damaged line in the log must be skipped, not stop the migration.
	f, err := os.OpenFile(v.p.Audit, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{not json\n")
	_ = f.Close()
	return v, store
}

func backups(t *testing.T, v testVault) []string {
	t.Helper()
	m, err := filepath.Glob(v.p.Store + ".pre-captures-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMigrateDryRunChangesNothing(t *testing.T) {
	v, _ := migrationVault(t)
	before := mustRead(t, v.p.Store)
	auditBefore := mustRead(t, v.p.Audit)

	var out bytes.Buffer
	if err := migrateCaptures(&out, v.p, v.master, v.capKey, false, testNow); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, mustRead(t, v.p.Store)) || !bytes.Equal(auditBefore, mustRead(t, v.p.Audit)) {
		t.Fatal("dry run changed store.enc or the audit log")
	}
	if _, err := os.Stat(v.p.Captured); !os.IsNotExist(err) {
		t.Fatal("dry run created the captures folder")
	}
	if len(backups(t, v)) != 0 {
		t.Fatal("dry run wrote a backup")
	}
	text := out.String()
	for _, want := range []string{"dry run", "to move:    2 hook-captured", "stay named: 4", "--apply"} {
		if !strings.Contains(text, want) {
			t.Errorf("dry-run report lacks %q:\n%s", want, text)
		}
	}
	// Names that look generated but stay are listed one per line, and only those.
	listed := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		listed[strings.TrimSpace(line)] = true
	}
	for alias, want := range map[string]bool{
		"GITHUB_TOKEN": true, "STRIPE_KEY_3": true, "OPENAI_KEY": true,
		"GITHUB_TOKEN_2": false, "JWT_TOKEN": false, "MY_API_KEY": false,
	} {
		if listed[alias] != want {
			t.Errorf("%s listed as left in place = %v, want %v:\n%s", alias, listed[alias], want, text)
		}
	}
}

func TestMigrateApply(t *testing.T) {
	v, original := migrationVault(t)
	before := mustRead(t, v.p.Store)

	var out bytes.Buffer
	if err := migrateCaptures(&out, v.p, v.master, v.capKey, true, testNow); err != nil {
		t.Fatalf("apply: %v\n%s", err, out.String())
	}

	// The backup is the old store, byte for byte, owner-only, and reported.
	bk := backups(t, v)
	if len(bk) != 1 || !bytes.Equal(before, mustRead(t, bk[0])) {
		t.Fatalf("backup missing or not the original store: %v", bk)
	}
	if !strings.Contains(out.String(), bk[0]) || !strings.Contains(out.String(), "Delete it once") {
		t.Errorf("report does not name the backup or say to delete it:\n%s", out.String())
	}
	if os.PathSeparator == '/' {
		if fi, _ := os.Stat(bk[0]); fi.Mode().Perm() != 0o600 {
			t.Errorf("backup perms = %o, want 600", fi.Mode().Perm())
		}
	}

	// The store keeps everything that did not provably come from the hook.
	store := v.loadStore(t)
	if got, want := strings.Join(sortedKeys(store), " "), "GITHUB_TOKEN MY_API_KEY OPENAI_KEY STRIPE_KEY_3"; got != want {
		t.Fatalf("store aliases after migration = %q, want %q", got, want)
	}
	for alias, value := range store {
		if value != original[alias] {
			t.Errorf("named value for %s changed", alias)
		}
	}

	// Moved entries keep their old alias as the file name.
	for alias, wantUsed := range map[string]bool{"GITHUB_TOKEN_2": true, "JWT_TOKEN": false} {
		e, err := capture.Read(v.p.Captured, v.capKey, alias)
		if err != nil {
			t.Fatalf("moved capture %s does not open: %v", alias, err)
		}
		wantKind := strings.ToLower(strings.TrimSuffix(alias, "_2"))
		if e.Value != original[alias] || e.Kind != wantKind || e.Used != wantUsed || e.Created != testNow.Format(time.RFC3339) {
			t.Errorf("capture %s = kind %q used %v created %q", alias, e.Kind, e.Used, e.Created)
		}
		fi, err := os.Stat(filepath.Join(v.p.Captured, alias+".enc"))
		if err != nil || !fi.ModTime().Equal(testNow) {
			t.Errorf("capture %s mtime is not the migration time (err=%v)", alias, err)
		}
		if v.isUsed(t, alias) != wantUsed {
			t.Errorf("capture %s used = %v, want %v", alias, !wantUsed, wantUsed)
		}
	}
	if n, _ := capture.Count(v.p.Captured); n != 2 {
		t.Fatalf("%d capture files, want 2", n)
	}

	// Old placeholders still resolve: through the hook's egress and `get`.
	d := hook.Deps{Paths: v.p, MasterKey: v.master, CaptureKey: func() []byte { return v.capKey }, ExePath: "/bin/vaultmcp", Now: testNow}
	for _, alias := range []string{"GITHUB_TOKEN_2", "JWT_TOKEN", "GITHUB_TOKEN"} {
		in := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo [vault:` + alias + `]"}}`
		if got := string(hook.Process([]byte(in), d)); !strings.Contains(got, "/bin/vaultmcp get "+alias+")") {
			t.Errorf("old placeholder for %s no longer expands: %s", alias, got)
		}
		got, err := resolve(v.p, v.master, alias, testNow.Add(time.Hour))
		if err != nil || got != original[alias] {
			t.Errorf("get %s after migration failed: %v", alias, err)
		}
	}
}

func TestMigrateSecondApplyIsNoOp(t *testing.T) {
	v, _ := migrationVault(t)
	var out bytes.Buffer
	if err := migrateCaptures(&out, v.p, v.master, v.capKey, true, testNow); err != nil {
		t.Fatal(err)
	}
	store := mustRead(t, v.p.Store)
	captured := mustRead(t, filepath.Join(v.p.Captured, "JWT_TOKEN.enc"))

	out.Reset()
	if err := migrateCaptures(&out, v.p, v.master, v.capKey, true, testNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(store, mustRead(t, v.p.Store)) {
		t.Fatal("a second --apply rewrote store.enc")
	}
	if !bytes.Equal(captured, mustRead(t, filepath.Join(v.p.Captured, "JWT_TOKEN.enc"))) {
		t.Fatal("a second --apply rewrote a capture file")
	}
	if n := len(backups(t, v)); n != 1 {
		t.Fatalf("%d backups after a no-op second run, want 1", n)
	}
	if !strings.Contains(out.String(), "Nothing to move") {
		t.Errorf("second run did not say it was a no-op:\n%s", out.String())
	}
}

// A run that died after writing some capture files but before saving the
// store is finished by the next run.
func TestMigrateFinishesAPartialRun(t *testing.T) {
	v, original := migrationVault(t)
	e := capture.Entry{Value: original["JWT_TOKEN"], Kind: "jwt_token", Created: testNow.Add(-time.Hour).Format(time.RFC3339)}
	if _, err := capture.Write(v.p.Captured, v.capKey, "JWT_TOKEN", e); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := migrateCaptures(&out, v.p, v.master, v.capKey, true, testNow); err != nil {
		t.Fatalf("apply after a partial run: %v", err)
	}
	store := v.loadStore(t)
	if _, ok := store["JWT_TOKEN"]; ok {
		t.Fatal("the partial run was not finished")
	}
	for _, alias := range []string{"JWT_TOKEN", "GITHUB_TOKEN_2"} {
		if got, err := resolve(v.p, v.master, alias, testNow); err != nil || got != original[alias] {
			t.Fatalf("%s does not resolve after finishing the partial run: %v", alias, err)
		}
	}
}

// Anything going wrong before the single store save leaves the store as it was.
func TestMigrateFailureLeavesStoreUntouched(t *testing.T) {
	cases := map[string]func(t *testing.T, v testVault){
		"captures folder cannot be written": func(t *testing.T, v testVault) {
			if err := os.WriteFile(v.p.Captured, []byte("in the way"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"a capture file already holds another value": func(t *testing.T, v testVault) {
			e := capture.Entry{Value: "something else", Kind: "jwt_token", Created: testNow.Format(time.RFC3339)}
			if _, err := capture.Write(v.p.Captured, v.capKey, "JWT_TOKEN", e); err != nil {
				t.Fatal(err)
			}
		},
		"a capture file sealed on another machine": func(t *testing.T, v testVault) {
			e := capture.Entry{Value: fakeToken(3), Kind: "jwt_token", Created: testNow.Format(time.RFC3339)}
			if _, err := capture.Write(v.p.Captured, capture.Key(v.master, "elsewhere"), "JWT_TOKEN", e); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			v, _ := migrationVault(t)
			before := mustRead(t, v.p.Store)
			breakIt(t, v)
			var out bytes.Buffer
			err := migrateCaptures(&out, v.p, v.master, v.capKey, true, testNow)
			if err == nil || !strings.Contains(err.Error(), "store.enc was not changed") {
				t.Fatalf("expected a failure that says the store is untouched, got %v", err)
			}
			if !bytes.Equal(before, mustRead(t, v.p.Store)) {
				t.Fatal("a failed migration changed store.enc")
			}
		})
	}
}

// --- everything stays inside VAULTMCP_DIR ---

// Drives every command that got a new path through its real entry point and
// then checks where files ended up: all inside VAULTMCP_DIR, nothing in HOME.
func TestNewPathsHonourVaultDir(t *testing.T) {
	v := newPassphraseVault(t)
	home := os.Getenv("HOME")

	// An old-style capture in the store, for migrate-captures to move.
	v.saveStore(t, vault.Store{"MY_KEY": "x", "GITHUB_TOKEN_2": fakeToken(9)})
	if err := audit.Log(v.p.Audit, "vault", "GITHUB_TOKEN_2", "Bash", testNow); err != nil {
		t.Fatal(err)
	}
	// An expired capture, for the hook's once-a-day prune to delete.
	expired := v.capture(t, fakeToken(8), time.Now().Add(-10*24*time.Hour))

	var out bytes.Buffer
	runHook(hookInput(fakeToken(1)), &out, paths(), time.Now())
	alias := capture.Alias(v.capKey, "github_token", fakeToken(1))
	if !strings.Contains(out.String(), "k=[vault:"+alias+"]") || strings.Contains(out.String(), fakeToken(1)) {
		t.Fatalf("hook did not redact to the capture alias: %s", out.String())
	}
	if !capture.Exists(filepath.Join(os.Getenv("VAULTMCP_DIR"), "captured"), alias) {
		t.Fatal("the capture file is not under VAULTMCP_DIR/captured")
	}
	if capture.Exists(v.p.Captured, expired) {
		t.Fatal("the hook's daily prune did not run")
	}
	if _, err := os.Stat(filepath.Join(v.p.Captured, ".pruned")); err != nil {
		t.Fatalf("prune marker not under VAULTMCP_DIR/captured: %v", err)
	}

	steps := map[string]func() error{
		"get capture":            func() error { return cmdGet([]string{alias}) },
		"list":                   func() error { return cmdList(nil) },
		"list --captured":        func() error { return cmdList([]string{"--captured"}) },
		"prune --dry-run":        func() error { return cmdPrune([]string{"--dry-run"}) },
		"prune":                  func() error { return cmdPrune(nil) },
		"migrate-captures":       func() error { return cmdMigrateCaptures(nil) },
		"migrate-captures apply": func() error { return cmdMigrateCaptures([]string{"--apply"}) },
		"get migrated":           func() error { return cmdGet([]string{"GITHUB_TOKEN_2"}) },
		"delete capture":         func() error { return cmdDelete([]string{alias, "--yes"}) },
	}
	for _, name := range []string{"get capture", "list", "list --captured", "prune --dry-run", "prune", "migrate-captures", "migrate-captures apply", "get migrated", "delete capture"} {
		if err := steps[name](); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, ok := v.loadStore(t)["GITHUB_TOKEN_2"]; ok || !capture.Exists(v.p.Captured, "GITHUB_TOKEN_2") {
		t.Fatal("migrate-captures --apply did not move the entry inside VAULTMCP_DIR")
	}

	// HOME was never written to, and the vault folder holds only known files.
	if des, err := os.ReadDir(home); err != nil || len(des) != 0 {
		t.Fatalf("something was written under HOME: %v (err=%v)", des, err)
	}
	des, err := os.ReadDir(v.p.Dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range des {
		name := de.Name()
		switch {
		case name == "store.enc", name == "key.enc", name == "audit.log", name == "captured":
		case strings.HasPrefix(name, "store.enc.pre-captures-"):
		default:
			t.Errorf("unexpected file in the vault folder: %s", name)
		}
	}
}

// With no machine id the hook still captures and redacts.
func TestHookRedactsWithoutMachineID(t *testing.T) {
	v := newPassphraseVault(t)
	setMachineID(t, "", errors.New("no id on this machine"))
	var out bytes.Buffer
	runHook(hookInput(fakeToken(1)), &out, v.p, testNow)

	alias := capture.Alias(capture.Key(v.master, ""), "github_token", fakeToken(1))
	if !strings.Contains(out.String(), "k=[vault:"+alias+"]") || strings.Contains(out.String(), fakeToken(1)) {
		t.Fatalf("hook did not redact without a machine id: %s", out.String())
	}
	if got, err := resolve(v.p, v.master, alias, testNow); err != nil || got != fakeToken(1) {
		t.Fatalf("capture made without a machine id does not resolve: %v", err)
	}
}

// The prune after the hook's answer never changes that answer.
func TestHookOutputUnchangedByPrune(t *testing.T) {
	v := newPassphraseVault(t)
	in := hookInput(fakeToken(1))
	var first, second bytes.Buffer
	runHook(in, &first, v.p, testNow) // prunes: no marker yet
	if _, err := os.Stat(filepath.Join(v.p.Captured, ".pruned")); err != nil {
		t.Fatal("first hook run did not leave the prune marker")
	}
	runHook(in, &second, v.p, testNow.Add(time.Minute)) // does not prune
	if first.Len() == 0 || first.String() != second.String() {
		t.Fatalf("hook output differs between a pruning and a non-pruning run:\n%s\n%s", first.String(), second.String())
	}
}

// A hook run that could not read the machine id seals its capture with the
// key that is not tied to a machine. That capture must still open later, when
// the id is readable again.
func TestResolveCaptureMadeWithoutMachineID(t *testing.T) {
	v := newTestVault(t)
	unlocked := capture.Key(v.master, "")
	alias := capture.Alias(unlocked, "github_token", fakeToken(1))
	e := capture.Entry{Value: fakeToken(1), Kind: "github_token", Created: testNow.Format(time.RFC3339)}
	if _, err := capture.Write(v.p.Captured, unlocked, alias, e); err != nil {
		t.Fatal(err)
	}
	got, err := resolve(v.p, v.master, alias, testNow)
	if err != nil || got != fakeToken(1) {
		t.Fatalf("capture made without a machine id did not open: %v", err)
	}
}

func TestMigrateLeavesOneAuditLine(t *testing.T) {
	v, _ := migrationVault(t)
	count := func() int {
		t.Helper()
		log, err := audit.Read(v.p.Audit)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range log {
			if e.Action == "migrate" {
				n++
			}
		}
		return n
	}
	for run, want := range []int{1, 1} { // the second apply moves nothing and logs nothing
		var out bytes.Buffer
		if err := migrateCaptures(&out, v.p, v.master, v.capKey, true, testNow.Add(time.Duration(run)*time.Minute)); err != nil {
			t.Fatal(err)
		}
		if got := count(); got != want {
			t.Fatalf("after apply %d: %d migrate lines, want %d", run+1, got, want)
		}
	}
}

// The store can change while the capture files are being written. The final
// save must keep a secret that was added meanwhile, and must not take out an
// entry whose value changed after it was read.
func TestMigrateKeepsChangesMadeMeanwhile(t *testing.T) {
	v := newTestVault(t)
	asRead := vault.Store{"GITHUB_TOKEN_2": fakeToken(2), "JWT_TOKEN": fakeToken(3), "MY_API_KEY": "named"}
	// Since then: a person added one secret and replaced one of the captures.
	v.saveStore(t, vault.Store{"GITHUB_TOKEN_2": fakeToken(2), "JWT_TOKEN": "set by hand meanwhile", "MY_API_KEY": "named", "ADDED_MEANWHILE": "new"})

	moved, left, err := dropMoved(v.p, v.master, asRead, []string{"GITHUB_TOKEN_2", "JWT_TOKEN"})
	if err != nil {
		t.Fatal(err)
	}
	got := v.loadStore(t)
	want := vault.Store{"JWT_TOKEN": "set by hand meanwhile", "MY_API_KEY": "named", "ADDED_MEANWHILE": "new"}
	if moved != 1 || left != len(want) || len(got) != len(want) {
		t.Fatalf("moved=%d left=%d store=%d entries, want 1, %d, %d", moved, left, len(got), len(want), len(want))
	}
	for alias, val := range want {
		if got[alias] != val {
			t.Fatalf("[%s] was lost or changed by the final save", alias)
		}
	}
}
