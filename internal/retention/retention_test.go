package retention

import (
	"fmt"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
)

func TestKeep(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	var items []Item
	// Two backups a day for 120 days.
	for d := 0; d < 120; d++ {
		for _, h := range []int{2, 14} {
			at := now.Add(-time.Duration(d) * 24 * time.Hour).Truncate(24 * time.Hour).Add(time.Duration(h) * time.Hour)
			if at.After(now) {
				continue
			}
			items = append(items, Item{ID: at.Format("20060102T150405Z"), At: at})
		}
	}
	keep := Keep(items, helper.BackupRetention{Daily: 7, Weekly: 4, Monthly: 3}, now)
	// Within 24 h: today 02:00 and yesterday 14:00 (22 h ago).
	for _, id := range []string{"20261003T020000Z", "20261002T140000Z"} {
		if !keep[id] {
			t.Errorf("recent %s not kept", id)
		}
	}
	// Daily keeps the newest of each day: yesterday's 14:00, not 02:00.
	if !keep["20260930T140000Z"] || keep["20260930T020000Z"] {
		t.Error("daily choice")
	}
	// Sep 20 is the newest of ISO week 38 (weekly keeps it); Sep 19 is not.
	if !keep["20260920T140000Z"] || keep["20260919T140000Z"] {
		t.Error("weekly choice")
	}
	// Monthly: newest of September, August, … (3 months incl. October).
	if !keep["20260831T140000Z"] {
		t.Error("monthly August not kept")
	}
	if keep["20260731T140000Z"] {
		t.Error("July kept beyond 3 months")
	}
	if n := len(keep); n > 7+4+3+2 {
		t.Errorf("kept %d", n)
	}
}

func TestKeepNewestAlways(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	// Backups stopped two years ago: retention would keep none of them
	// by date, but the newest (the last successful backup) stays.
	var items []Item
	for i := 0; i < 5; i++ {
		at := now.AddDate(-2, 0, -i)
		items = append(items, Item{ID: fmt.Sprint(i), At: at})
	}
	keep := Keep(items, helper.BackupRetention{Daily: 1}, now)
	if !keep["0"] || len(keep) != 1 {
		t.Fatalf("keep %v", keep)
	}
	if len(Keep(nil, helper.BackupRetention{Daily: 1}, now)) != 0 {
		t.Fatal("empty input")
	}
}
