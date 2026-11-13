package runner

import (
	"fmt"
	"time"
)

// Rollback detection. Retention always keeps the newest complete backup,
// so the newest usable backup in a destination never gets older on its
// own. If it does, someone with write access to the bucket deleted the
// newer ones (or their manifests), and "latest" would silently restore or
// drill an older domain. A host remembers the newest backup it has seen
// (a high-water mark) and refuses "latest" when the bucket now offers
// something older, unless the operator accepts it explicitly.

// Mark is the newest backup a host has seen.
type Mark struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// NewestUsable returns the newest usable backup of a list (ListBackups
// order), if any.
func NewestUsable(list []Listed) (Listed, bool) {
	for _, l := range list {
		if l.Usable() {
			return l, true
		}
	}
	return Listed{}, false
}

// RollbackError: the newest usable backup is older than one seen before.
type RollbackError struct {
	// Newest is the newest usable backup now (nil: none at all).
	Newest *Mark
	Seen   Mark
}

func (e *RollbackError) Error() string {
	now := "no usable backup"
	if e.Newest != nil {
		now = fmt.Sprintf("the newest usable backup is %s (%s)", e.Newest.ID, e.Newest.CreatedAt.UTC().Format(time.RFC3339))
	}
	return fmt.Sprintf("possible rollback: %s, but %s (%s) was seen before; newer backups or their manifests were removed from the bucket",
		now, e.Seen.ID, e.Seen.CreatedAt.UTC().Format(time.RFC3339))
}

// CheckRollback compares the newest usable backup of list with a mark.
// It returns the mark to keep (the newer of the two) and a RollbackError
// when the list went backwards.
func CheckRollback(list []Listed, seen *Mark) (*Mark, error) {
	newest, ok := NewestUsable(list)
	var cur *Mark
	if ok {
		cur = &Mark{ID: newest.ID, CreatedAt: newest.Manifest.CreatedAt}
	}
	switch {
	case seen == nil || seen.ID == "":
		return cur, nil
	case cur == nil || cur.CreatedAt.Before(seen.CreatedAt):
		return seen, &RollbackError{Newest: cur, Seen: *seen}
	case cur.CreatedAt.After(seen.CreatedAt):
		return cur, nil
	default:
		return seen, nil
	}
}
