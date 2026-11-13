package restore

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-backup/internal/manifest"
	"github.com/openbasalt/samba-conductor-backup/internal/runner"
)

func TestCheckLatest(t *testing.T) {
	at := time.Date(2026, 10, 2, 2, 30, 0, 0, time.UTC)
	b := runner.Listed{ID: "20261002T023000Z-dc1", HasArchive: true, Size: 1, Manifest: &manifest.Manifest{Size: 1, CreatedAt: at}}
	now := func() time.Time { return at.Add(3 * time.Hour) }
	var log strings.Builder
	if err := checkLatest(b, Options{Now: now}, &log); err != nil || !strings.Contains(log.String(), "3h0m0s ago") || strings.Contains(log.String(), "WARNING") {
		t.Fatalf("fresh: %v %q", err, log.String())
	}
	// Old: a warning, no refusal without a mark.
	log.Reset()
	old := func() time.Time { return at.Add(72 * time.Hour) }
	if err := checkLatest(b, Options{Now: old}, &log); err != nil || !strings.Contains(log.String(), "WARNING") {
		t.Fatalf("old: %v %q", err, log.String())
	}
	// This host saw a newer backup: refused, unless accepted.
	seen := []runner.Mark{{ID: "20261003T023000Z-dc1", CreatedAt: at.Add(24 * time.Hour)}}
	err := checkLatest(b, Options{Now: now, Seen: seen}, &log)
	var rb *runner.RollbackError
	if !errors.As(err, &rb) || !strings.Contains(err.Error(), "--accept-older") {
		t.Fatalf("rollback: %v", err)
	}
	log.Reset()
	if err := checkLatest(b, Options{Now: now, Seen: seen, AcceptOlder: true}, &log); err != nil || !strings.Contains(log.String(), "accepted") {
		t.Fatalf("accepted: %v %q", err, log.String())
	}
	// A mark at or before the backup is fine.
	if err := checkLatest(b, Options{Now: now, Seen: []runner.Mark{{ID: b.ID, CreatedAt: at}}}, &log); err != nil {
		t.Fatal(err)
	}
}
