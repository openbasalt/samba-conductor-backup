package runner

import (
	"errors"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-backup/internal/manifest"
)

func listed(id string, at time.Time) Listed {
	return Listed{ID: id, HasArchive: true, Size: 10, Manifest: &manifest.Manifest{ID: id, Size: 10, CreatedAt: at}}
}

func TestCheckRollback(t *testing.T) {
	t1 := time.Date(2026, 10, 1, 2, 30, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	old, newer := listed("20261001T023000Z-dc1", t1), listed("20261002T023000Z-dc1", t2)
	// First sight: the mark is the newest.
	m, err := CheckRollback([]Listed{newer, old}, nil)
	if err != nil || m.ID != newer.ID {
		t.Fatalf("%v %v", m, err)
	}
	// Same newest again, or a newer one: no error, the mark moves forward.
	if m2, err := CheckRollback([]Listed{newer, old}, m); err != nil || m2.ID != newer.ID {
		t.Fatalf("%v %v", m2, err)
	}
	t3 := listed("20261003T023000Z-dc1", t2.Add(24*time.Hour))
	if m3, err := CheckRollback([]Listed{t3, newer}, m); err != nil || m3.ID != t3.ID {
		t.Fatalf("%v %v", m3, err)
	}
	// The newest was deleted: rollback, and the mark stays.
	m4, err := CheckRollback([]Listed{old}, m)
	var rb *RollbackError
	if !errors.As(err, &rb) || m4.ID != newer.ID || rb.Newest.ID != old.ID {
		t.Fatalf("rollback not detected: %v %v", m4, err)
	}
	// Everything deleted.
	if _, err := CheckRollback(nil, m); !errors.As(err, &rb) || rb.Newest != nil {
		t.Fatalf("empty bucket: %v", err)
	}
	// An unusable newest (manifest removed) does not count.
	gone := newer
	gone.Manifest = nil
	if _, err := CheckRollback([]Listed{gone, old}, m); !errors.As(err, &rb) {
		t.Fatalf("manifest removal: %v", err)
	}
}
