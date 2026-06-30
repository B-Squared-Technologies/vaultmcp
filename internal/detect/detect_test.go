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
