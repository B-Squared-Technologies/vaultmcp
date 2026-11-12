// Package capture stores the secrets the hook captured by itself, one sealed
// file per secret under <vault>/captured. Secrets a person stored with
// `vaultmcp set` stay in store.enc and never come here.
//
// One file per capture is what makes parallel hook processes safe without a
// lock: nobody rewrites a shared file, so nobody can drop another process's
// capture. The alias is derived from the value, so the same value always lands
// on the same file and an alias can never come to mean a different value.
//
// Capture files are sealed with a key derived from the master key AND this
// machine's id, so a copied vault folder does not open them elsewhere.
package capture

import (
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/B-Squared-Technologies/vaultmcp/internal/crypto"
)

const (
	// keyInfo is the HKDF context. The version label lets a later format
	// derive a different key from the same master key and machine.
	keyInfo = "vaultmcp capture v1 machine:"
	ext     = ".enc"
	// aliasBytes is how much of the value's MAC names the file: 80 bits is
	// exactly 16 base32 characters and far past any chance of two values
	// sharing an alias.
	aliasBytes = 10
	// usedSlack absorbs coarse filesystem timestamps: a file counts as used
	// only when its mtime is clearly past its creation time.
	usedSlack = time.Second
	// seenAfter is how stale a capture's mtime must be before meeting its
	// value again moves it. A value that shows up in every tool result must
	// not cost a write each time.
	seenAfter = time.Hour
)

// ErrInvalidAlias means the name cannot be a capture file. It is checked
// before any path is built, so an alias can never reach outside the folder.
var ErrInvalidAlias = errors.New("vaultmcp: not a valid capture alias")

var validAlias = regexp.MustCompile(`^[A-Z0-9_]+$`)

// Entry is the sealed content of one capture file.
type Entry struct {
	Value   string `json:"value"`
	Kind    string `json:"kind"`
	Created string `json:"created"` // RFC3339
	Tool    string `json:"tool"`
	Session string `json:"session"`
	Cwd     string `json:"cwd"`
	// Used is set only by the migration, for a capture the audit log shows was
	// read before it moved here. Later use is tracked by the file's mtime.
	Used bool `json:"used"`
}

// Key derives the capture key from the master key and this machine's id. An
// empty machineID still gives a working key, just one that is not tied to the
// machine: redaction must keep working where no id is available.
func Key(master []byte, machineID string) []byte {
	k, err := hkdf.Key(sha256.New, master, nil, keyInfo+machineID, crypto.KeySize)
	if err != nil {
		// Only possible for an output far longer than 32 bytes.
		panic("vaultmcp: capture key derivation failed: " + err.Error())
	}
	return k
}

// Alias names the capture of value: the kind, then 80 bits of a keyed MAC of
// the value. A MAC (not a plain hash) keeps the alias from being a way to
// test guesses of the value without the key.
func Alias(key []byte, kind, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	sum := mac.Sum(nil)[:aliasBytes]
	return strings.ToUpper(kind) + "_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(sum)
}

func file(dir, alias string) (string, error) {
	if !validAlias.MatchString(alias) {
		return "", ErrInvalidAlias
	}
	return filepath.Join(dir, alias+ext), nil
}

// Exists reports whether alias has a capture file. It is a single stat: the
// hook calls it per alias and must not decrypt or list the folder.
func Exists(dir, alias string) bool {
	path, err := file(dir, alias)
	if err != nil {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// Write seals e as the capture file for alias, unless that file is already
// there, in which case nothing is written. created reports whether this call
// made the file.
func Write(dir string, key []byte, alias string, e Entry) (created bool, err error) {
	path, err := file(dir, alias)
	if err != nil {
		return false, err
	}
	if Exists(dir, alias) {
		return false, nil
	}
	when, err := time.Parse(time.RFC3339, e.Created)
	if err != nil {
		return false, err
	}
	pt, err := json.Marshal(e)
	if err != nil {
		return false, err
	}
	blob, err := crypto.Seal(key, pt)
	if err != nil {
		return false, err
	}
	if err := ensureDir(dir); err != nil {
		return false, err
	}
	// Temp file in the same directory, then rename: a reader sees either no
	// file or a complete one. The temp name has no .enc suffix, so a leftover
	// from a killed process is never taken for a capture.
	f, err := os.CreateTemp(dir, "tmp-*")
	if err != nil {
		return false, err
	}
	tmp := f.Name()
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return false, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	// mtime = created is the "never used" mark; a later read moves it.
	if err := os.Chtimes(tmp, when, when); err != nil {
		_ = os.Remove(tmp)
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if Exists(dir, alias) {
			// A parallel hook captured the same value first (Windows refuses
			// to replace a file another process is renaming into place).
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// ensureDir creates the captures folder owner-only. MkdirAll does not tighten
// a directory that already exists, hence the explicit chmod.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	// #nosec G302 -- 0700 is correct for a directory; 0600 would drop the
	// execute bit required to traverse it.
	return os.Chmod(dir, 0o700)
}

// Read opens the capture file for alias. It fails with crypto.ErrDecrypt when
// the file was sealed on another machine or is damaged.
func Read(dir string, key []byte, alias string) (Entry, error) {
	path, err := file(dir, alias)
	if err != nil {
		return Entry{}, err
	}
	// #nosec G304 -- path is the captures folder plus an alias validated above.
	blob, err := os.ReadFile(path)
	if err != nil {
		return Entry{}, err
	}
	pt, err := crypto.Open(key, blob)
	if err != nil {
		return Entry{}, err
	}
	var e Entry
	if err := json.Unmarshal(pt, &e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// Touch records that the capture was just used, by moving its mtime to now.
// A read within the slack of creation (a shell command runs its substitution
// right after the hook captured the value) would not register as a use, so
// the mtime is never set closer to creation than twice the slack.
func Touch(dir, alias string, e Entry, now time.Time) error {
	path, err := file(dir, alias)
	if err != nil {
		return err
	}
	when := now
	if created, err := time.Parse(time.RFC3339, e.Created); err == nil {
		if floor := created.Add(2 * usedSlack); when.Before(floor) {
			when = floor
		}
	}
	return os.Chtimes(path, when, when)
}

// Seen records that the hook met this capture's value again. The session
// still has the value in play and is being handed this alias, so the capture
// must not expire as "never used" underneath it: meeting it again counts as a
// use. Best effort, like Touch.
func Seen(dir, alias string, now time.Time) {
	path, err := file(dir, alias)
	if err != nil {
		return
	}
	fi, err := os.Stat(path)
	if err != nil || now.Sub(fi.ModTime()) < seenAfter {
		return
	}
	_ = os.Chtimes(path, now, now)
}

// Delete removes the capture file for alias.
func Delete(dir, alias string) error {
	path, err := file(dir, alias)
	if err != nil {
		return err
	}
	return os.Remove(path)
}

// used reports whether a capture has been read since it was made.
func used(e Entry, mtime time.Time) bool {
	if e.Used {
		return true
	}
	created, err := time.Parse(time.RFC3339, e.Created)
	if err != nil {
		return true // unknown age: the longer, 30-day rule is the safe one
	}
	return mtime.Sub(created) > usedSlack
}

// scan returns the alias of every capture file in dir, sorted. Only regular
// files named <valid alias>.enc count, which skips temp files, the prune
// marker and anything else that found its way into the folder. A missing
// folder is simply no captures.
func scan(dir string) ([]string, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, de := range des {
		alias, ok := strings.CutSuffix(de.Name(), ext)
		if ok && de.Type().IsRegular() && validAlias.MatchString(alias) {
			out = append(out, alias)
		}
	}
	return out, nil
}

// Count returns how many capture files exist, without opening any.
func Count(dir string) (int, error) {
	aliases, err := scan(dir)
	return len(aliases), err
}

// Item is one capture as shown by `vaultmcp list --captured`.
type Item struct {
	Alias    string
	Entry    Entry // zero when !Readable
	Used     bool
	Readable bool // false: sealed on another machine, or damaged
}

// List opens every capture in dir. A file that does not open is still listed,
// as not readable, so it is visible rather than silently missing.
func List(dir string, key []byte) ([]Item, error) {
	aliases, err := scan(dir)
	if err != nil {
		return nil, err
	}
	items := make([]Item, 0, len(aliases))
	for _, alias := range aliases {
		it := Item{Alias: alias}
		fi, statErr := os.Stat(filepath.Join(dir, alias+ext))
		if e, err := Read(dir, key, alias); err == nil && statErr == nil {
			it.Entry, it.Readable, it.Used = e, true, used(e, fi.ModTime())
		}
		items = append(items, it)
	}
	return items, nil
}
