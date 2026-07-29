package detect

import "testing"

func hasType(ms []Match, kind string) bool {
	for _, m := range ms {
		if m.Type == kind {
			return true
		}
	}
	return false
}

func hasValue(ms []Match, val string) bool {
	for _, m := range ms {
		if m.Value == val {
			return true
		}
	}
	return false
}

func TestKnownPatterns(t *testing.T) {
	cases := []struct {
		text string
		kind string
	}{
		{"key is AKIAIOSFODNN7EXAMPLE here", "aws_access_key"},
		{"token ghp_aBcD1234567890aBcD1234567890", "github_token"},
		{"sk-ant-abcdefghijklmnopqrstuvwxyz0123456789ABCD", "anthropic_key"},
		{"sk-abcdefghijklmnopqrstuvwxyz0123456789", "openai_key"},
		{"xoxb-12345-67890-aBcDeFgHiJkLmN", "slack_bot_token"},
		{"stripe_sk_live_abcdefghijklmnopqrstuvwx", "stripe_key"},
		{"-----BEGIN RSA PRIVATE KEY-----", "private_key"},
		{"postgres://user:supersecretpw@db:5432/app", "db_connection_string"},
		{"redis://:supersecretpw@cache:6379", "redis_url"},
		{"eyJhbGciOiJIUzI1NiwidHlwIjoiSldUI.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "jwt_token"},
	}
	for _, c := range cases {
		if got := Find(c.text); !hasType(got, c.kind) {
			t.Errorf("text %q: expected a %s match, got %+v", c.text, c.kind, got)
		}
	}
}

func TestEntropyCatchesUnknownSecret(t *testing.T) {
	// A custom key with no known prefix but high randomness.
	text := "export MY_KEY=Xq9vR2mT7wL4pK8nZ5jB3cF6dG1hA0sE"
	if got := Find(text); !hasType(got, "high_entropy_secret") {
		t.Errorf("expected high_entropy_secret, got %+v", got)
	}
}

func TestAllowlistNotFlagged(t *testing.T) {
	clean := []string{
		"https://example.com/some/long/path/that/is/here",
		"${MY_ENVIRONMENT_VARIABLE_NAME}",
		"$(some-command --with-args here)",
		"[vault:AWS_ACCESS_KEY]",
		"550e8400-e29b-41d4-a716-446655440000", // UUID
		"the quick brown fox jumps over the lazy dog repeatedly",
	}
	for _, c := range clean {
		if got := Find(c); len(got) != 0 {
			t.Errorf("expected no matches for %q, got %+v", c, got)
		}
	}
}

func TestLongPathNotFlaggedAsSecret(t *testing.T) {
	// The known entropy false-positive the architect asked us to suppress.
	path := "/private/tmp/claude-501/some-very-long-nested/build/artifacts/output/final/result.tmp"
	if got := Find(path); hasType(got, "high_entropy_secret") {
		t.Errorf("long path wrongly flagged as secret: %+v", got)
	}
}

func TestCodeIdentifiersNotFlagged(t *testing.T) {
	// Real corruption cases from autonomous-agent sessions (2026-07-12): the
	// entropy scan vaulted ordinary code identifiers and rewrote source files
	// mid-edit. Identifiers are digit-free; random key material almost never is.
	clean := []string{
		"BSquaredWorkClientConfig",
		"process.env.GRIPHQ_API_URL",
		"process.env.BSQUARED_WORK_TENANT_ID",
		"listPendingApprovalsForTenant",
		"createBSquaredWorkClient(config)",
		"const bsquaredWorkRequestHandler = makeHandler",
	}
	for _, c := range clean {
		if got := Find(c); len(got) != 0 {
			t.Errorf("identifier %q wrongly flagged: %+v", c, got)
		}
	}
}

func TestDigitBearingSecretStillCaught(t *testing.T) {
	// The digit gate must not blind the entropy layer to real key material.
	text := "export TOKEN=dEadBeefCafe1234x90abQdef1p34zz7"
	if got := Find(text); !hasType(got, "high_entropy_secret") {
		t.Errorf("expected high_entropy_secret, got %+v", got)
	}
}

func TestShortStringsIgnored(t *testing.T) {
	if got := Find("abc123 short tokens xyz"); len(got) != 0 {
		t.Errorf("expected no matches for short tokens, got %+v", got)
	}
}

func TestNoRedundantSuperstringOfKnownSecret(t *testing.T) {
	// A known AKIA key inside an assignment line must vault ONLY the key, not
	// the whole "AWS_ACCESS_KEY_ID=AKIA…" line as a second high-entropy secret.
	got := Find("AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 match (the key), got %d: %+v", len(got), got)
	}
	if got[0].Value != "AKIAIOSFODNN7EXAMPLE" {
		t.Fatalf("expected the bare key, got %q", got[0].Value)
	}
}

func TestDeduplicatesByValue(t *testing.T) {
	text := "AKIAIOSFODNN7EXAMPLE and again AKIAIOSFODNN7EXAMPLE"
	got := Find(text)
	count := 0
	for _, m := range got {
		if m.Value == "AKIAIOSFODNN7EXAMPLE" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected value deduped to 1, got %d (%+v)", count, got)
	}
	if !hasValue(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Error("expected the AWS key value present")
	}
}

// Regression tests for the 2026-07 false-positive classes that corrupted real
// artifacts (task UUIDs in prose, ISO timestamps, date-prefixed doc filenames,
// file:line refs, shallow repo paths). The strings are built by concatenation
// so the currently-installed hook can't vault them out of this very file.
func TestProseUUIDWithTrailingPeriodNotFlagged(t *testing.T) {
	uuid := "44cb0f45-33fc-" + "4cab-811d-" + "2f98e59630ef"
	text := "Priority list on task " + uuid + ". St George first."
	if got := Find(text); len(got) != 0 {
		t.Fatalf("prose UUID flagged: %+v", got)
	}
}

func TestISOTimestampNotFlagged(t *testing.T) {
	ts := "2026-07-17T15:" + "32:22.452426+00:00"
	text := `{"created_at": "` + ts + `"}`
	if got := Find(text); len(got) != 0 {
		t.Fatalf("ISO timestamp flagged: %+v", got)
	}
}

func TestDatePrefixedFilenameNotFlagged(t *testing.T) {
	name := "2026-07-16-qc-" + "testing-fixes-" + "workstreams.md"
	for _, text := range []string{name, "docs/plans/" + name, "spec at docs/plans/" + name + " on develop"} {
		if got := Find(text); len(got) != 0 {
			t.Fatalf("date-prefixed filename flagged in %q: %+v", text, got)
		}
	}
}

func TestFileLineReferenceNotFlagged(t *testing.T) {
	ref := "src/lib/" + "invoicing.ts:53"
	if got := Find("(" + ref + ")"); len(got) != 0 {
		t.Fatalf("file:line ref flagged: %+v", got)
	}
}

func TestDottedConfigFilenameNotFlagged(t *testing.T) {
	name := "spider.config" + ".template"
	long := "tech.bsquared." + "screamingfrog." + "autostart.plist"
	for _, text := range []string{name, long} {
		if got := Find(text); len(got) != 0 {
			t.Fatalf("dotted filename flagged in %q: %+v", text, got)
		}
	}
}

// Regression tests for the 2026-07-27 corruption class: PreToolUse scans the
// raw JSON of tool_input, where newlines are the two-byte escape sequence
// backslash-n. Tokens must split at backslashes and backticks or content that
// merely straddles a line break (or sits in a markdown code span) gets vaulted
// and a Write corrupts the file on disk.
func TestJSONEscapedNewlineSplitsTokens(t *testing.T) {
	// As seen inside a Write tool_input: **Date:** [vault:HIGH_ENTROPY_SECRET_3533] …
	text := `**Date:** 2026-07-27` + `\` + `n**Status:** Approved approach`
	if got := Find(text); len(got) != 0 {
		t.Fatalf("JSON-escaped newline span flagged: %+v", got)
	}
}

func TestBacktickedRepoPathNotFlagged(t *testing.T) {
	path := "`/images/motorcycles/" + "2025-FE350.webp`"
	if got := Find("(e.g. "+path+")"); len(got) != 0 {
		t.Fatalf("backticked repo path flagged: %+v", got)
	}
}

func TestRealSecretsStillDetectedAfterAllowlists(t *testing.T) {
	// Shape-allowlists must not swallow genuine key material.
	ghp := "ghp_" + "Abc123def456ghi789jkl012mno345pqr"
	if got := Find("token=" + ghp); len(got) == 0 {
		t.Fatal("github token no longer detected")
	}
	entropic := "9fK2mQ8xL4vB7nR1" + "pT6wY3zD5cH0jS8a"
	if got := Find("value " + entropic + " end"); len(got) == 0 {
		t.Fatal("high-entropy 32-char secret no longer detected")
	}
}

// Regression tests for the 2026-07-28 false-positive classes: digit-bearing
// code identifiers (dotted member access on names like chacha20-poly1305's Go
// package), Go import paths, and module pseudo-versions were vaulted out of
// tool results and would corrupt an Edit that carried them.
func TestDottedCodeIdentifierNotFlagged(t *testing.T) {
	for _, tok := range []string{
		"chacha20poly" + "1305.NewX",
		"chacha20poly" + "1305.NonceSizeX",
	} {
		if got := Find("aead, err := " + tok + "(key)"); len(got) != 0 {
			t.Fatalf("code identifier %q flagged: %+v", tok, got)
		}
	}
}

func TestGoImportPathNotFlagged(t *testing.T) {
	path := "golang.org/x/" + "crypto/chacha" + "20poly1305"
	if got := Find(`import "` + path + `"`); len(got) != 0 {
		t.Fatalf("import path flagged: %+v", got)
	}
}

func TestModulePseudoVersionNotFlagged(t *testing.T) {
	ver := "v0.0.0-2026" + "0728192015-" + "85242b5f6c72"
	if got := Find("go: downloading example.com/mod " + ver); len(got) != 0 {
		t.Fatalf("module pseudo-version flagged: %+v", got)
	}
}

func TestTwoSegmentSecretStillCaught(t *testing.T) {
	// A dotted token whose segments are long and digit-bearing is key
	// material, not a code identifier — the dotted-identifier allowlist
	// must not swallow it.
	sec := "Xq9vR2mT7wL4pK8n" + "Z5jB.3cF6dG1hA0s" + "EbTqW9xYzK2mPd4r"
	if got := Find("key " + sec + " end"); len(got) == 0 {
		t.Fatal("two-segment entropic secret no longer detected")
	}
}
