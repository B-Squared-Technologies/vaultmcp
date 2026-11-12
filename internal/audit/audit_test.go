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

func TestReadSkipsUnparsableLines(t *testing.T) {
	p := tempLog(t)
	now := time.Unix(1700000000, 0)
	_ = Log(p, "vault", "A", "Bash", now)
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("this line is not json\n\n")
	_ = f.Close()
	_ = Log(p, "get", "A", "cli", now)

	got, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got) != 2 || got[0].Action != "vault" || got[1].Action != "get" || got[1].Alias != "A" {
		t.Fatalf("Read = %+v, want the two valid entries in order", got)
	}
}

func TestReadMissingLogIsEmpty(t *testing.T) {
	got, err := Read(filepath.Join(t.TempDir(), "does-not-exist.log"))
	if err != nil || len(got) != 0 {
		t.Fatalf("missing log should read as empty, got %+v err=%v", got, err)
	}
}

// ReadCounting reports the lines it could not parse, so a caller deciding
// from the log knows the log has holes. The blank line every log ends in is
// not one of them.
func TestReadCountingReportsSkippedLines(t *testing.T) {
	p := tempLog(t)
	now := time.Unix(1700000000, 0)
	_ = Log(p, "vault", "A", "x", now)
	_ = Log(p, "set", "B", "x", now)
	entries, skipped, err := ReadCounting(p)
	if err != nil || len(entries) != 2 || skipped != 0 {
		t.Fatalf("whole log: %d entries, %d skipped, %v; want 2, 0", len(entries), skipped, err)
	}

	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("{not json\n\n   \n" + `{"action":"set","alias":"HALF` + "\n")
	_ = f.Close()
	_ = Log(p, "get", "A", "x", now)

	entries, skipped, err = ReadCounting(p)
	if err != nil || len(entries) != 3 || skipped != 2 {
		t.Fatalf("damaged log: %d entries, %d skipped, %v; want 3, 2", len(entries), skipped, err)
	}
	if plain, err := Read(p); err != nil || len(plain) != 3 {
		t.Fatalf("Read = %d entries, %v; want the same 3", len(plain), err)
	}
	if entries, skipped, err := ReadCounting(filepath.Join(t.TempDir(), "missing.log")); err != nil || entries != nil || skipped != 0 {
		t.Fatalf("a missing log is an empty history, got %d entries, %d skipped, %v", len(entries), skipped, err)
	}
}
