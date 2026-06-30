package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func tempLog(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "audit.log")
}

func TestLogAppendsAndChainVerifies(t *testing.T) {
	p := tempLog(t)
	now := time.Unix(1700000000, 0)
	for _, a := range []string{"AWS_KEY", "GH_TOKEN", "AWS_KEY"} {
		if err := Log(p, "vault", a, "Bash", now); err != nil {
			t.Fatalf("Log: %v", err)
		}
	}
	ok, err := Verify(p)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("freshly written chain should verify")
	}
}

func TestTamperBreaksChain(t *testing.T) {
	p := tempLog(t)
	now := time.Unix(1700000000, 0)
	_ = Log(p, "vault", "A", "x", now)
	_ = Log(p, "vault", "B", "x", now)
	_ = Log(p, "vault", "C", "x", now)

	data, _ := os.ReadFile(p)
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines[1] = strings.Replace(lines[1], `"B"`, `"B_TAMPERED"`, 1)
	_ = os.WriteFile(p, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	ok, _ := Verify(p)
	if ok {
		t.Fatal("tampered chain must NOT verify")
	}
}

func TestVerifyEmptyLogIsValid(t *testing.T) {
	ok, err := Verify(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if err != nil || !ok {
		t.Fatalf("missing log should be valid, got ok=%v err=%v", ok, err)
	}
}

func TestContextTruncatedAndNoValueLogged(t *testing.T) {
	p := tempLog(t)
	long := strings.Repeat("x", 300)
	if err := Log(p, "vault", "ALIAS", long, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	var e Entry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &e); err != nil {
		t.Fatalf("parse entry: %v", err)
	}
	if len(e.Context) != 120 {
		t.Fatalf("context = %d chars, want 120", len(e.Context))
	}
	// Sanity: only alias/context are logged — the log format has no value field.
	if strings.Contains(string(data), `"value"`) {
		t.Fatal("audit log must never contain a value field")
	}
}
