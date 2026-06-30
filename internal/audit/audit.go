// Package audit writes an append-only, hash-chained log of vault operations.
// Each entry embeds the SHA-256 of the previous line, so any deletion or edit
// of history breaks the chain and is detectable.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"
)

// Entry is one audit record. Values are never logged — only alias names.
type Entry struct {
	TS      string `json:"ts"`
	Action  string `json:"action"`
	Alias   string `json:"alias"`
	Context string `json:"context"`
	Chain   string `json:"chain"` // full SHA-256 hex of the previous line
}

// Log appends an entry for action on alias. ctx is a short free-form context
// (e.g. the tool name). Failures are returned but callers in the hot path
// generally ignore them — auditing must never break the primary operation.
//
// Known limitation: the read-prev-then-append is not atomic across processes.
// Each `vaultmcp hook` invocation is a separate process, so two tool calls
// firing concurrently could chain from the same previous hash and make Verify
// report a (cosmetic) break. The audit log is a secondary integrity aid, not a
// security boundary; cross-process file locking is deferred.
func Log(path, action, alias, ctx string, now time.Time) error {
	prev := ""
	// #nosec G304 -- path is internally derived (~/.vaultmcp/audit.log).
	if data, err := os.ReadFile(path); err == nil {
		if lines := strings.Split(strings.TrimSpace(string(data)), "\n"); len(lines) > 0 {
			if last := lines[len(lines)-1]; last != "" {
				sum := sha256.Sum256([]byte(last))
				prev = hex.EncodeToString(sum[:])
			}
		}
	}

	if len(ctx) > 120 {
		ctx = ctx[:120]
	}
	e := Entry{
		TS:      now.UTC().Format(time.RFC3339),
		Action:  action,
		Alias:   alias,
		Context: ctx,
		Chain:   prev,
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}

	// #nosec G304 -- path is internally derived (~/.vaultmcp/audit.log).
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// Verify walks the log and returns true if the hash chain is intact.
func Verify(path string) (bool, error) {
	// #nosec G304 -- path is internally derived (~/.vaultmcp/audit.log).
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return true, nil // empty log is trivially valid
		}
		return false, err
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	prev := ""
	for _, line := range lines {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			return false, nil
		}
		if e.Chain != prev {
			return false, nil
		}
		sum := sha256.Sum256([]byte(line))
		prev = hex.EncodeToString(sum[:])
	}
	return true, nil
}
