package hook

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/B-Squared-Technologies/vaultmcp/internal/audit"
	"github.com/B-Squared-Technologies/vaultmcp/internal/capture"
	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/detect"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

// fakeAWS builds a distinct AWS-key-shaped value at runtime. No literal secret
// is written in this file: the live hook would vault it out of the source.
func fakeAWS(i int) string {
	return "AKIA" + fmt.Sprintf("%016d", i)
}

func fakeAlias(d Deps, i int) string {
	return capture.Alias(d.CaptureKey, "aws_access_key", fakeAWS(i))
}

func runPost(d Deps, tool, response string) string {
	in := `{"hook_event_name":"PostToolUse","tool_name":"` + tool + `","tool_response":` + response + `}`
	return string(Process([]byte(in), d))
}

func placeholder(alias string) string {
	return "[vault:" + alias + "]"
}

// saveNamed writes the named store the way `vaultmcp set` does.
func saveNamed(t *testing.T, d Deps, s vault.Store) {
	t.Helper()
	if err := d.Paths.EnsureDir(); err != nil {
		t.Fatal(err)
	}
	if err := vault.Save(d.Paths.Store, s, d.MasterKey); err != nil {
		t.Fatal(err)
	}
}

func captureCount(t *testing.T, d Deps) int {
	t.Helper()
	n, err := capture.Count(d.Paths.Captured)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A vault folder copied to machine B: A's capture does not open there, and
// the hook on B still captures and redacts the same secret under B's own key.
func TestHookOnAnotherMachineStillCapturesAndRedacts(t *testing.T) {
	a := testDeps(t)
	if out := runPre(t, a, "Bash", `{"command":"echo `+awsKey+`"}`); out == "" {
		t.Fatal("machine A did not redact")
	}
	b := a
	b.CaptureKey = capture.Key(a.MasterKey, "another-machine")

	if _, err := capture.Read(a.Paths.Captured, b.CaptureKey, awsAlias(a)); err != crypto.ErrDecrypt {
		t.Fatalf("machine B opened machine A's capture, err = %v", err)
	}
	out := runPre(t, b, "Bash", `{"command":"echo `+awsKey+`"}`)
	if out == "" || strings.Contains(out, awsKey) {
		t.Fatalf("machine B did not redact: %s", out)
	}
	if awsAlias(b) == awsAlias(a) {
		t.Fatal("alias must depend on the machine, or B would reuse a file it cannot open")
	}
	if !strings.Contains(out, fakeExe+" get "+awsAlias(b)) {
		t.Fatalf("machine B output lacks its own alias: %s", out)
	}
	got, err := capture.Read(b.Paths.Captured, b.CaptureKey, awsAlias(b))
	if err != nil || got.Value != awsKey {
		t.Fatalf("machine B cannot read its own capture: %v", err)
	}
	if n := captureCount(t, a); n != 2 {
		t.Fatalf("%d capture files, want one per machine", n)
	}
}

// Parallel hook runs, each seeing a different secret, must all leave a capture
// that resolves. This fails on the old design: every hook process loaded the
// whole store.enc, added its secret and saved the whole file back with no
// lock, so concurrent runs overwrote each other and captures were lost.
func TestParallelHooksLoseNoCapture(t *testing.T) {
	d := testDeps(t)
	const n = 48
	outs := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				outs[i] = runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(i)+`"}`)
			} else {
				outs[i] = runPost(d, "Bash", `"KEY=`+fakeAWS(i)+`\n"`)
			}
		}(i)
	}
	wg.Wait()

	for i, out := range outs {
		alias := fakeAlias(d, i)
		if !strings.Contains(out, alias) || strings.Contains(out, fakeAWS(i)) {
			t.Fatalf("run %d did not redact to its alias: %s", i, out)
		}
		got, err := capture.Read(d.Paths.Captured, d.CaptureKey, alias)
		if err != nil || got.Value != fakeAWS(i) {
			t.Fatalf("capture %d does not resolve after the parallel runs: %v", i, err)
		}
		// And the hook itself still knows the alias on egress.
		if egress := runPre(t, d, "Bash", `{"command":"echo `+placeholder(alias)+`"}`); !strings.Contains(egress, fakeExe+" get "+alias) {
			t.Fatalf("alias %d not known on egress: %s", i, egress)
		}
	}
	if got := captureCount(t, d); got != n {
		t.Fatalf("%d capture files, want %d", got, n)
	}
}

// The same secret seen by two hook processes at once, and again later, is one
// alias and one file.
func TestSameSecretFromTwoHooksIsOneCapture(t *testing.T) {
	d := testDeps(t)
	outs := make([]string, 8)
	var wg sync.WaitGroup
	for i := range outs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outs[i] = runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`)
		}(i)
	}
	wg.Wait()
	outs = append(outs, runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+` again"}`))
	for i, out := range outs {
		if !strings.Contains(out, fakeExe+" get "+fakeAlias(d, 1)) {
			t.Fatalf("run %d used a different alias: %s", i, out)
		}
	}
	if got := captureCount(t, d); got != 1 {
		t.Fatalf("%d capture files for one secret, want 1", got)
	}
	des, err := os.ReadDir(d.Paths.Captured)
	if err != nil || len(des) != 1 {
		t.Fatalf("captures folder holds %d entries, want exactly the one file (err=%v)", len(des), err)
	}
}

// The hook reads store.enc and never writes it: its bytes are identical after
// runs that capture, on ingress and on results, and after egress.
func TestHookNeverWritesStore(t *testing.T) {
	d := testDeps(t)
	saveNamed(t, d, vault.Store{"NAMED_KEY": "a named value"})
	before, err := os.ReadFile(d.Paths.Store)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(d.Paths.Store)

	if out := runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`); out == "" {
		t.Fatal("ingress did not capture")
	}
	if out := runPost(d, "Bash", `"KEY=`+fakeAWS(2)+`\n"`); out == "" {
		t.Fatal("result redaction did not capture")
	}
	if out := runPre(t, d, "Write", `{"file_path":"/x","content":"k=`+fakeAWS(3)+`"}`); out == "" {
		t.Fatal("non-shell ingress did not capture")
	}
	if out := runPre(t, d, "Bash", `{"command":"echo `+placeholder("NAMED_KEY")+` `+placeholder(fakeAlias(d, 1))+`"}`); out == "" {
		t.Fatal("egress did not expand")
	}
	if got := captureCount(t, d); got != 3 {
		t.Fatalf("%d captures, want 3", got)
	}

	after, err := os.ReadFile(d.Paths.Store)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a hook run changed the bytes of store.enc")
	}
	if now, _ := os.Stat(d.Paths.Store); !now.ModTime().Equal(info.ModTime()) {
		t.Fatal("a hook run rewrote store.enc")
	}
}

// With no store.enc at all, capturing must not create one.
func TestHookDoesNotCreateStore(t *testing.T) {
	d := testDeps(t)
	if out := runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`); out == "" {
		t.Fatal("ingress did not capture")
	}
	if _, err := os.Stat(d.Paths.Store); !os.IsNotExist(err) {
		t.Fatalf("hook created store.enc (err=%v)", err)
	}
}

// A secret a person stored keeps its name. When several names hold the value,
// the smallest one is used every time, and nothing is captured.
func TestNamedSecretKeepsItsName(t *testing.T) {
	d := testDeps(t)
	saveNamed(t, d, vault.Store{"ZED_KEY": fakeAWS(1), "MY_AWS": fakeAWS(1), "MY_AWS_OLD": fakeAWS(1), "OTHER": "x"})
	for i := 0; i < 20; i++ { // map order is random; the choice must not be
		out := runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`)
		if !strings.Contains(out, fakeExe+" get MY_AWS)") {
			t.Fatalf("run %d did not use the smallest named alias: %s", i, out)
		}
		post := runPost(d, "Bash", `"KEY=`+fakeAWS(1)+`\n"`)
		if !strings.Contains(post, "KEY="+placeholder("MY_AWS")) {
			t.Fatalf("run %d result did not use the smallest named alias: %s", i, post)
		}
	}
	if got := captureCount(t, d); got != 0 {
		t.Fatalf("a named secret was captured again (%d files)", got)
	}
	if entries, _ := audit.Read(d.Paths.Audit); len(entries) != 0 {
		t.Fatalf("reusing a named alias must not be audited as a capture: %+v", entries)
	}
}

// Egress knows a capture by one stat of its file: the alias expands even if
// the file cannot be decrypted, and an alias with no file is left alone.
func TestEgressKnowsCapturesByStatOnly(t *testing.T) {
	d := testDeps(t)
	if err := os.MkdirAll(d.Paths.Captured, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d.Paths.Captured, "SOME_CAPTURE.enc"), []byte("not a sealed file"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		alias string
		known bool
	}{
		{"SOME_CAPTURE", true},
		{"NO_SUCH_CAPTURE", false},
		{"some_capture", false}, // must not match the file on a case-insensitive disk
	}
	for _, c := range cases {
		out := runPre(t, d, "Bash", `{"command":"echo `+placeholder(c.alias)+`"}`)
		if got := strings.Contains(out, " get "+c.alias+")"); got != c.known {
			t.Errorf("alias %q expanded = %v, want %v (out: %s)", c.alias, got, c.known, out)
		}
	}
}

// A capture that cannot be written must not produce a redaction: the hook
// emits nothing and the tool call goes ahead untouched.
func TestCaptureWriteFailureFailsOpen(t *testing.T) {
	d := testDeps(t)
	// A regular file where the captures folder should be: every write fails.
	if err := os.WriteFile(d.Paths.Captured, []byte("in the way"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`); out != "" {
		t.Fatalf("PreToolUse emitted a redaction it could not persist: %s", out)
	}
	if out := runPost(d, "Bash", `{"stdout":"KEY=`+fakeAWS(2)+`\n","stderr":""}`); out != "" {
		t.Fatalf("PostToolUse emitted a redaction it could not persist: %s", out)
	}
	if entries, _ := audit.Read(d.Paths.Audit); len(entries) != 0 {
		t.Fatalf("a failed capture was audited: %+v", entries)
	}
}

// Named secrets resolve first, so the hook must not hand out a capture alias
// that a named entry already uses for a different value.
func TestCaptureAliasTakenByNamedEntryFailsOpen(t *testing.T) {
	d := testDeps(t)
	saveNamed(t, d, vault.Store{fakeAlias(d, 1): "some other value"})
	if out := runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`); out != "" {
		t.Fatalf("emitted an alias that resolves to a different secret: %s", out)
	}
	if got := captureCount(t, d); got != 0 {
		t.Fatalf("%d captures written, want 0", got)
	}
}

// A capture records where it came from, and is audited once: when its file is
// created, not each time the same secret is seen again.
func TestCaptureRecordsOriginAndAuditsOnce(t *testing.T) {
	d := testDeps(t)
	in := `{"hook_event_name":"PreToolUse","session_id":"sess-1","cwd":"/work/repo","tool_name":"Bash","tool_input":{"command":"echo ` + fakeAWS(1) + `"}}`
	for i := 0; i < 3; i++ {
		if out := Process([]byte(in), d); out == nil {
			t.Fatal("expected a redaction")
		}
	}
	got, err := capture.Read(d.Paths.Captured, d.CaptureKey, fakeAlias(d, 1))
	if err != nil {
		t.Fatal(err)
	}
	want := capture.Entry{Value: fakeAWS(1), Kind: "aws_access_key", Created: "1970-01-01T00:00:00Z", Tool: "Bash", Session: "sess-1", Cwd: "/work/repo"}
	if got != want {
		t.Fatalf("capture entry = %+v, want %+v", got, want)
	}
	entries, err := audit.Read(d.Paths.Audit)
	if err != nil || len(entries) != 1 {
		t.Fatalf("audit has %d entries, want 1 (err=%v)", len(entries), err)
	}
	if e := entries[0]; e.Action != "vault" || e.Alias != fakeAlias(d, 1) || e.Context != "Bash" {
		t.Fatalf("audit entry = %+v", e)
	}
}

// Session and cwd are optional in the hook JSON.
func TestCaptureWithoutSessionOrCwd(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`)
	got, err := capture.Read(d.Paths.Captured, d.CaptureKey, fakeAlias(d, 1))
	if err != nil || got.Session != "" || got.Cwd != "" || got.Value != fakeAWS(1) {
		t.Fatalf("capture without session/cwd = %+v, %v", got, err)
	}
}

// The detector must never take an alias for a secret, or the hook would
// capture its own placeholders. Checked for every kind an alias can be named
// after, in each form an alias appears in: bare, as a placeholder, and as the
// exact substitution the hook writes into shell commands.
func TestDetectorDoesNotMatchAliases(t *testing.T) {
	d := testDeps(t)
	for _, kind := range detect.Kinds() {
		for i := 0; i < 200; i++ {
			key := capture.Key(crypto.NewKey(), hex.EncodeToString(crypto.Random(8)))
			alias := capture.Alias(key, kind, hex.EncodeToString(crypto.Random(24)))
			for _, text := range []string{alias, placeholder(alias), d.sub(alias)} {
				if got := detect.Find(text); len(got) != 0 {
					t.Fatalf("detector matched alias text %q: %+v", text, got)
				}
			}
		}
	}
}

// End to end: what the hook emits for a capture is clean input for the next
// hook run, so nothing is captured twice or re-redacted.
func TestHookOutputIsStableUnderTheHook(t *testing.T) {
	d := testDeps(t)
	alias := fakeAlias(d, 1)
	runPre(t, d, "Bash", `{"command":"echo `+fakeAWS(1)+`"}`)
	if out := runPre(t, d, "Bash", `{"command":"echo `+d.sub(alias)+`"}`); out != "" {
		t.Fatalf("the hook rewrote its own substitution: %s", out)
	}
	if out := runPost(d, "Bash", `"KEY=`+placeholder(alias)+`\n"`); out != "" {
		t.Fatalf("the hook rewrote its own placeholder: %s", out)
	}
	if got := captureCount(t, d); got != 1 {
		t.Fatalf("%d captures, want 1", got)
	}
}
