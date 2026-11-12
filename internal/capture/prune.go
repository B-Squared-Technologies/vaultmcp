package capture

import (
	"os"
	"path/filepath"
	"strings"
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
	// markerSkew is how far ahead of now the prune marker may be and still
	// count as fresh. Hooks started in the same moment read the clock a few
	// milliseconds apart, and the earlier reading must not take the marker
	// the later one just wrote for a marker from the future.
	markerSkew = time.Minute
	// tempTTL is how old a temp file must be before a prune removes it. Write
	// keeps its temp file for a moment only, so one this old belongs to a
	// process that is gone.
	tempTTL = 24 * time.Hour
)

// PruneResult counts what one Prune pass did.
type PruneResult struct {
	Candidates int // files older than 7 days: the only ones that were opened
	Unused     int // deleted: never used
	Stale      int // deleted: used, but not for 30 days
	Kept       int // used within 30 days
	Unreadable int // did not open, touched within 30 days: left alone
	Orphaned   int // deleted: did not open and untouched for 30 days
	Temps      int // deleted: temp files left by a process that was killed
}

// Deleted is how many files the pass removed, or would have on a dry run.
func (r PruneResult) Deleted() int {
	return r.Unused + r.Stale + r.Orphaned + r.Temps
}

// Prune deletes expired captures: never used and older than 7 days, or used
// and last used more than 30 days ago. Only files whose mtime is older than 7
// days are opened. limit caps how many of those one call handles; 0 means all.
// With dryRun nothing is deleted and the counts say what would be.
//
// A file that does not open (sealed on another machine, or in a moment when
// this machine's id could not be read) is deleted once it has gone untouched
// for 30 days. No rule would have kept a file that old, whichever key it was
// sealed with, so nothing is lost that a readable file would have kept.
//
// Temp files a killed process left behind go too, once they are a day old.
//
// A file that cannot be deleted does not stop the pass: the rest still
// expire, and the first such error is returned at the end with the counts.
func Prune(dir string, key []byte, now time.Time, limit int, dryRun bool) (PruneResult, error) {
	var r PruneResult
	aliases, err := scan(dir)
	if err != nil {
		return r, err
	}
	var firstErr error
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
		stale := now.Sub(fi.ModTime()) > usedTTL
		e, err := Read(dir, key, alias)
		readable := err == nil
		wasUsed := readable && used(e, fi.ModTime())
		if (!readable || wasUsed) && !stale {
			if readable {
				r.Kept++
			} else {
				r.Unreadable++
			}
			continue
		}
		gone, err := expire(path, fi.ModTime(), dryRun)
		switch {
		case err != nil:
			if firstErr == nil {
				firstErr = err
			}
		case !gone:
			r.Kept++
		case !readable:
			r.Orphaned++
		case wasUsed:
			r.Stale++
		default:
			r.Unused++
		}
	}
	r.Temps, err = sweepTemps(dir, now, dryRun)
	if firstErr == nil {
		firstErr = err
	}
	return r, firstErr
}

// sweepTemps deletes temp files older than a day and returns how many. A hook
// killed while it was writing a capture leaves its temp file behind. That
// file holds a sealed secret, no capture rule ever looks at it, and without
// this it would stay for good.
func sweepTemps(dir string, now time.Time, dryRun bool) (int, error) {
	des, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	var firstErr error
	for _, de := range des {
		if !strings.HasPrefix(de.Name(), tempPrefix) || !de.Type().IsRegular() {
			continue
		}
		fi, err := de.Info()
		if err != nil || now.Sub(fi.ModTime()) <= tempTTL {
			continue
		}
		if !dryRun {
			if err := os.Remove(filepath.Join(dir, de.Name())); err != nil && !os.IsNotExist(err) {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
		}
		n++
	}
	return n, firstErr
}

// expire deletes path unless its mtime moved since it was judged. A read, or
// a hook that met the value again, refreshes the mtime and is about to hand
// out the alias, so that capture is in use and must stay. The second look
// leaves only the instant between it and the unlink; losing that means the
// capture expired a moment early, which is what would have happened had the
// prune run a moment sooner.
func expire(path string, judged time.Time, dryRun bool) (gone bool, err error) {
	if dryRun {
		return true, nil
	}
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true, nil // a parallel prune got there first
	}
	if err != nil {
		return false, err
	}
	if !fi.ModTime().Equal(judged) {
		return false, nil
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return true, nil
}

// AutoPrune runs a bounded Prune at most once a day, tracked by the mtime of a
// marker file inside dir. It is for the hook, after the hook has written its
// answer: it touches nothing outside dir, and returns what it deleted only so
// the caller can put that in the audit log. The result is zero when no prune
// ran. key is a function so the hook derives the capture key only on the one
// run a day that actually prunes.
func AutoPrune(dir string, key func() []byte, now time.Time) PruneResult {
	marker := filepath.Join(dir, pruneMarker)
	if fi, err := os.Stat(marker); err == nil {
		// A marker dated ahead of now was written while the clock was wrong.
		// Taken at its word it would switch the daily prune off until that
		// date, so it counts as stale.
		if age := now.Sub(fi.ModTime()); age < autoPruneEvery && age > -markerSkew {
			return PruneResult{}
		}
	}
	// Marker first, so the parallel hooks of the same moment do not all prune.
	// With no captures folder there is nothing to prune and this fails: the
	// folder is deliberately not created just to hold a marker.
	if err := touchMarker(marker, now); err != nil {
		return PruneResult{}
	}
	r, _ := Prune(dir, key(), now, autoPruneLimit, false)
	return r
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
