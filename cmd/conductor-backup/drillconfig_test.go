package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-backup/internal/config"
)

// TestDrillConfigDefault: drill reads drill.toml without --config, a host
// without that file gets an error naming it and the README section, and an
// explicit --config is left to the configuration loader.
func TestDrillConfigDefault(t *testing.T) {
	fs, path := flagsWith("drill", config.DefaultDrillPath)
	parse(fs, nil)
	if *path != "/etc/conductor-backup/drill.toml" {
		t.Fatalf("default drill configuration %q", *path)
	}
	if _, p := flags("run"); *p != config.DefaultPath {
		t.Fatalf("run default changed: %q", *p)
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "drill.toml")
	fs, _ = flagsWith("drill", missing)
	parse(fs, nil)
	err := drillConfig(fs, missing)
	if err == nil || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), "Install a drill host") ||
		!strings.Contains(err.Error(), "--config") {
		t.Fatalf("missing drill.toml: %v", err)
	}
	if err := os.WriteFile(missing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := drillConfig(fs, missing); err != nil {
		t.Fatalf("present drill.toml: %v", err)
	}
	other := filepath.Join(dir, "other.toml")
	fs, path = flagsWith("drill", config.DefaultDrillPath)
	parse(fs, []string{"--config", other})
	if *path != other {
		t.Fatalf("--config ignored: %q", *path)
	}
	if err := drillConfig(fs, *path); err != nil {
		t.Fatalf("explicit --config: %v", err)
	}
}
