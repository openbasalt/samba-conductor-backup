// Package retention decides which backups to keep (grandfather-father-
// son). Only complete backups (archive + manifest) take part; the caller
// never deletes anything this package does not mark for deletion.
package retention

import (
	"fmt"
	"sort"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
)

// Item is one complete backup.
type Item struct {
	ID string
	At time.Time
}

// MinAge: backups younger than this are always kept (a manual backup is
// never deleted right after it was taken).
const MinAge = 24 * time.Hour

// Keep returns the IDs to keep:
//   - the newest backup, always (the last successful one);
//   - everything younger than MinAge;
//   - the newest backup of each of the Daily most recent days that have
//     backups, of the Weekly most recent ISO weeks and of the Monthly most
//     recent months (UTC).
func Keep(items []Item, r helper.BackupRetention, now time.Time) map[string]bool {
	sorted := append([]Item(nil), items...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].At.After(sorted[j].At) })
	keep := map[string]bool{}
	if len(sorted) == 0 {
		return keep
	}
	keep[sorted[0].ID] = true
	for _, it := range sorted {
		if now.Sub(it.At) < MinAge {
			keep[it.ID] = true
		}
	}
	bucket := func(n int, key func(time.Time) string) {
		seen := map[string]bool{}
		for _, it := range sorted {
			if len(seen) >= n {
				return
			}
			k := key(it.At.UTC())
			if !seen[k] {
				seen[k] = true
				keep[it.ID] = true
			}
		}
	}
	bucket(r.Daily, func(t time.Time) string { return t.Format("2006-01-02") })
	bucket(r.Weekly, func(t time.Time) string {
		y, w := t.ISOWeek()
		return fmt.Sprintf("%d-W%02d", y, w)
	})
	bucket(r.Monthly, func(t time.Time) string { return t.Format("2006-01") })
	return keep
}
