package hook

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
	"github.com/B-Squared-Technologies/vaultmcp/internal/vault"
)

const fakeExe = "/usr/local/bin/vaultmcp"
const awsKey = "AKIAIOSFODNN7EXAMPLE"

func testDeps(t *testing.T) Deps {
	t.Helper()
	dir := t.TempDir()
	p := vault.Paths{
		Dir:   dir,
		Store: dir + "/store.enc",
		Key:   dir + "/key.enc",
		Meta:  dir + "/meta.json",
		Audit: dir + "/audit.log",
	}
	return Deps{Paths: p, MasterKey: crypto.NewKey(), ExePath: fakeExe, Now: time.Unix(0, 0)}
}

func runPre(t *testing.T, d Deps, tool, input string) string {
	t.Helper()
	in := `{"hook_event_name":"PreToolUse","tool_name":"` + tool + `","tool_input":` + input + `}`
	return string(Process([]byte(in), d))
}

func TestPreBashIngressVaultsAndSubstitutes(t *testing.T) {
	d := testDeps(t)
	out := runPre(t, d, "Bash", `{"command":"aws configure set key `+awsKey+`"}`)
	if out == "" {
		t.Fatal("expected output, got none")
	}
	if strings.Contains(out, awsKey) {
		t.Fatalf("raw secret leaked into hook output: %s", out)
	}
	if !strings.Contains(out, fakeExe+" get AWS_ACCESS_KEY") {
		t.Fatalf("expected command substitution, got: %s", out)
	}
	// Output must be valid hook JSON with updatedInput.
	var parsed preOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output not valid hook JSON: %v", err)
	}
	if parsed.HookSpecificOutput.HookEventName != "PreToolUse" {
		t.Fatalf("wrong hookEventName: %q", parsed.HookSpecificOutput.HookEventName)
	}
	if parsed.HookSpecificOutput.PermissionDecision != "allow" {
		t.Fatalf("expected allow, got %q", parsed.HookSpecificOutput.PermissionDecision)
	}
	// The secret is now retrievable from the store.
	store, err := vault.Load(d.Paths.Store, d.MasterKey)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if store["AWS_ACCESS_KEY"] != awsKey {
		t.Fatalf("store did not capture the secret: %+v", store)
	}
}

func TestPreBashEgressExpandsExistingAlias(t *testing.T) {
	d := testDeps(t)
	_ = d.Paths.EnsureDir()
	_ = vault.Save(d.Paths.Store, vault.Store{"STRIPE_KEY": "sk_live_secretvalue"}, d.MasterKey)

	out := runPre(t, d, "Bash", `{"command":"curl -H 'Authorization: [vault:STRIPE_KEY]' x"}`)
	if !strings.Contains(out, fakeExe+" get STRIPE_KEY") {
		t.Fatalf("alias not expanded to substitution: %s", out)
	}
	if strings.Contains(out, "sk_live_secretvalue") {
		t.Fatalf("raw value leaked: %s", out)
	}
}

func TestPreNonBashUsesPlaceholder(t *testing.T) {
	d := testDeps(t)
	out := runPre(t, d, "Write", `{"file_path":"/x","content":"key=`+awsKey+`"}`)
	if strings.Contains(out, awsKey) {
		t.Fatalf("secret leaked in non-Bash output: %s", out)
	}
	if !strings.Contains(out, "[vault:AWS_ACCESS_KEY]") {
		t.Fatalf("expected [vault:ALIAS] placeholder, got: %s", out)
	}
	if strings.Contains(out, "get AWS_ACCESS_KEY") {
		t.Fatalf("non-Bash tool must NOT get a command substitution: %s", out)
	}
}

func TestPostToolUseRedactsResult(t *testing.T) {
	d := testDeps(t)
	in := `{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_response":"AWS_KEY=` + awsKey + `\n"}`
	out := string(Process([]byte(in), d))
	if out == "" {
		t.Fatal("expected redacted output")
	}
	if strings.Contains(out, awsKey) {
		t.Fatalf("secret leaked in tool result: %s", out)
	}
	var parsed postOutput
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("not valid hook JSON: %v", err)
	}
	got := parsed.HookSpecificOutput.UpdatedToolOutput
	// Must be the cleanly-decoded redacted string — NOT double-encoded with
	// literal surrounding JSON quotes (the regression the reviewer caught).
	want := "AWS_KEY=[vault:AWS_ACCESS_KEY]\n"
	if got != want {
		t.Fatalf("updatedToolOutput = %q, want %q", got, want)
	}
}

func TestNoSecretNoOutput(t *testing.T) {
	d := testDeps(t)
	if out := runPre(t, d, "Bash", `{"command":"ls -la /tmp"}`); out != "" {
		t.Fatalf("expected no output for clean input, got: %s", out)
	}
}

func TestFailOpenOnGarbage(t *testing.T) {
	d := testDeps(t)
	if out := string(Process([]byte("not json at all"), d)); out != "" {
		t.Fatalf("expected fail-open (no output) on garbage, got: %s", out)
	}
	if out := string(Process([]byte(""), d)); out != "" {
		t.Fatalf("expected no output on empty input, got: %s", out)
	}
}

func TestIdempotentAliasOnRepeatedSecret(t *testing.T) {
	d := testDeps(t)
	runPre(t, d, "Bash", `{"command":"echo `+awsKey+`"}`)
	runPre(t, d, "Bash", `{"command":"echo `+awsKey+` again"}`)
	store, _ := vault.Load(d.Paths.Store, d.MasterKey)
	count := 0
	for _, v := range store {
		if v == awsKey {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected the secret vaulted once, found %d aliases: %+v", count, store)
	}
}

func TestUnknownAliasNotExpanded(t *testing.T) {
	d := testDeps(t)
	// [vault:NOPE] has no stored value — must be left untouched, not turned
	// into a substitution that would resolve to nothing.
	out := runPre(t, d, "Bash", `{"command":"echo [vault:NOPE]"}`)
	if strings.Contains(out, "get NOPE") {
		t.Fatalf("unknown alias should not be expanded: %s", out)
	}
}
