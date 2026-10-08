package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-backup/internal/state"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The loop runs once at start, not again before full-every, and at once
// when a request is pending; errors do not stop it; cancel does.
func TestRunLoop(t *testing.T) {
	dir := state.Dir{Path: t.TempDir()}
	if err := os.MkdirAll(dir.Requests(), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runs atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- runLoop(ctx, quietLog(), dir, loopOptions{Interval: 20 * time.Millisecond, FullEvery: time.Hour},
			func(context.Context) error {
				runs.Add(1)
				return errors.New("destination unreachable")
			})
	}()
	waitFor(t, func() bool { return runs.Load() == 1 })
	time.Sleep(100 * time.Millisecond)
	if n := runs.Load(); n != 1 {
		t.Fatalf("runs = %d before full-every and without requests, want 1", n)
	}
	// A pending request (as the helper writes it) starts a run.
	if err := dir.AddRequest(helper.BackupRequest{ID: "r1", Kind: helper.TriggerBackup, At: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return runs.Load() >= 2 })
	if _, err := os.Stat(filepath.Join(dir.Path, heartbeatName)); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("loop did not stop")
	}
}

func TestRunLoopRejectsZeroInterval(t *testing.T) {
	if err := runLoop(context.Background(), quietLog(), state.Dir{Path: t.TempDir()}, loopOptions{}, nil); err == nil {
		t.Fatal("want an error")
	}
}

func TestCheckHealth(t *testing.T) {
	stateDir := t.TempDir()
	sock := filepath.Join(t.TempDir(), "backup.sock")
	now := time.Now()
	if err := checkHealth(stateDir, sock, time.Minute, now); err == nil || !strings.Contains(err.Error(), "heartbeat") {
		t.Fatalf("no heartbeat: %v", err)
	}
	if err := touchFile(filepath.Join(stateDir, heartbeatName)); err != nil {
		t.Fatal(err)
	}
	if err := checkHealth(stateDir, sock, time.Minute, now); err == nil || !strings.Contains(err.Error(), "helper socket") {
		t.Fatalf("no socket: %v", err)
	}
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	if err := checkHealth(stateDir, sock, time.Minute, now); err != nil {
		t.Fatalf("healthy: %v", err)
	}
	if err := checkHealth(stateDir, sock, time.Minute, now.Add(5*time.Minute)); err == nil || !strings.Contains(err.Error(), "old") {
		t.Fatalf("stale heartbeat: %v", err)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
