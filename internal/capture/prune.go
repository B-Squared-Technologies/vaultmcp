package capture

import (
	"os"
	"path/filepath"
	"time"
)

const (
	unusedTTL = 7 * 24 * time.Hour  // never read: gone after a week
	usedTTL   = 30 * 24 * time.Hour // read at least once: gone a month after the last read

	pruneMarker    = ".pruned"
	autoPruneEvery = 24 * time.Hour
	// autoPruneLimit bounds the work one hook run may do after it has answered.
	// A migrated vault can hold over ten thousand captures that all come due
	// in the same week; at this size the backlog is gone in days.
	autoPruneLimit = 2000
	secondsPerDay  = 24 * 60 * 60
)

// PruneResult counts what one Prune pass did.
type PruneResult struct {
	Candidates int // files older than 7 days: the only ones that were opened
	Unused     int // deleted: never used
	Stale      int // deleted: used, but not for 30 days
	Kept       int // used within 30 days
	Unreadable int // did not open; left alone, they may belong to another machine
}

// Prune deletes expired captures: never used and older than 7 days, or used
// and last used more than 30 days ago. Only files whose mtime is older than 7
// days are opened. limit caps how many of those one call handles; 0 means all.
// With dryRun nothing is deleted and the counts say what would be.
func Prune(dir string, key []byte, now time.Time, limit int, dryRun bool) (PruneResult, error) {
	var r PruneResult
	aliases, err := scan(dir)
	if err != nil {
		return r, err
	}
	// A bounded pass over a fixed order would look at the same first files
	// every day: used captures stay candidates for weeks without being
	// deleted, and enough of them would hide everything sorted after them.
	// Starting one window further each day lets the passes cover the folder.
	start := 0
	if limit > 0 && len(aliases) > limit {
		start = int(now.Unix()/secondsPerDay%int64(len(aliases))) * limit % len(aliases)
	}
	for i := range aliases {
		if limit > 0 && r.Candidates == limit {
			break
		}
		alias := aliases[(start+i)%len(aliases)]
		path := filepath.Join(dir, alias+ext)
		fi, err := os.Stat(path)
		if err != nil || now.Sub(fi.ModTime()) <= unusedTTL {
			continue
		}
		r.Candidates++
		e, err := Read(dir, key, alias)
		if err != nil {
			r.Unreadable++
			continue
		}
		wasUsed := used(e, fi.ModTime())
		if wasUsed && now.Sub(fi.ModTime()) <= usedTTL {
			r.Kept++
			continue
		}
		if !dryRun {
			// Already gone means a parallel prune got there first.
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return r, err
			}
		}
		if wasUsed {
			r.Stale++
		} else {
			r.Unused++
		}
	}
	return r, nil
}

// AutoPrune runs a bounded Prune at most once a day, tracked by the mtime of a
// marker file inside dir. It is for the hook, after the hook has written its
// answer: it reports nothing and touches nothing outside dir. key is a
// function so the hook derives the capture key only on the one run a day
// that actually prunes.
func AutoPrune(dir string, key func() []byte, now time.Time) {
	marker := filepath.Join(dir, pruneMarker)
	if fi, err := os.Stat(marker); err == nil && now.Sub(fi.ModTime()) < autoPruneEvery {
		return
	}
	// Marker first, so the parallel hooks of the same moment do not all prune.
	// With no captures folder there is nothing to prune and this fails: the
	// folder is deliberately not created just to hold a marker.
	if err := touchMarker(marker, now); err != nil {
		return
	}
	_, _ = Prune(dir, key(), now, autoPruneLimit, false)
}

func touchMarker(marker string, now time.Time) error {
	// #nosec G304 -- marker is a fixed file name inside the captures folder.
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chtimes(marker, now, now)
}
