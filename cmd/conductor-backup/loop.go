package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"github.com/openbasalt/samba-conductor-backup/internal/state"
)

// heartbeatName is the file `run --loop` touches while it is alive; the
// `healthcheck` command reads its age. It lives in the state directory,
// which only conductor-backup (and the helper, for requests/ and spool/)
// writes.
const heartbeatName = "loop-heartbeat"

// heartbeatEvery is how often the loop touches its heartbeat file,
// independent of the work it does (a backup can take many minutes).
const heartbeatEvery = 30 * time.Second

// loopOptions drive `run --scheduled --loop`, the container replacement of
// the systemd timer (hourly) and path unit (requests).
type loopOptions struct {
	// Interval between two checks for requests (the path unit's role).
	Interval time.Duration
	// FullEvery is the period of a full scheduled run (the timer's role).
	FullEvery time.Duration
}

// runLoop runs a full scheduled run at start, then every FullEvery, and at
// once whenever a request is pending, checking every Interval. A failed run
// is logged and retried by the next one (as the hourly timer does); only a
// cancelled context ends the loop.
func runLoop(ctx context.Context, log *slog.Logger, dir state.Dir, opts loopOptions, run func(context.Context) error) error {
	if opts.Interval <= 0 {
		return errors.New("--loop needs a positive interval")
	}
	if opts.FullEvery < opts.Interval {
		opts.FullEvery = opts.Interval
	}
	hbPath := filepath.Join(dir.Path, heartbeatName)
	touch := func() {
		if err := touchFile(hbPath); err != nil {
			log.Warn("heartbeat", "err", err)
		}
	}
	touch()
	hbCtx, stopHB := context.WithCancel(ctx)
	defer stopHB()
	go func() {
		t := time.NewTicker(heartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				touch()
			}
		}
	}()
	log.Info("loop started", "interval", opts.Interval.String(), "full_every", opts.FullEvery.String())
	var lastFull time.Time
	for {
		reqs, err := dir.PendingRequests()
		if err != nil {
			log.Error("reading requests", "err", err)
		}
		if lastFull.IsZero() || time.Since(lastFull) >= opts.FullEvery || len(reqs) > 0 {
			if len(reqs) == 0 {
				lastFull = time.Now()
			}
			if err := run(ctx); err != nil {
				switch {
				case ctx.Err() != nil:
				case errors.Is(err, state.ErrLocked):
					log.Info("another run is in progress")
				default:
					log.Error("run failed", "err", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			log.Info("loop stopped")
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

// touchFile creates the file (0600) or updates its modification time.
func touchFile(p string) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	now := time.Now()
	return os.Chtimes(p, now, now)
}

// cmdHealthcheck is the container healthcheck (the image has no shell): the
// loop's heartbeat is recent and conductor-helper's backup socket exists.
func cmdHealthcheck(args []string) error {
	fs, path := flags("healthcheck")
	maxAge := fs.Duration("max-age", 3*time.Minute, "oldest acceptable heartbeat of run --loop")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	return checkHealth(cfg.StateDir, cfg.HelperSocket, *maxAge, time.Now())
}

func checkHealth(stateDir, helperSocket string, maxAge time.Duration, now time.Time) error {
	st, err := os.Stat(filepath.Join(stateDir, heartbeatName))
	if err != nil {
		return fmt.Errorf("no heartbeat (is run --loop running?): %w", err)
	}
	if age := now.Sub(st.ModTime()); age > maxAge {
		return fmt.Errorf("heartbeat is %s old (limit %s)", age.Round(time.Second), maxAge)
	}
	sst, err := os.Stat(helperSocket)
	if err != nil {
		return fmt.Errorf("helper socket: %w", err)
	}
	if sst.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("helper socket: %s is not a socket", helperSocket)
	}
	fmt.Println("ok")
	return nil
}

// loopFlags registers --loop and --full-every on the run command.
func loopFlags(fs *flag.FlagSet) (*time.Duration, *time.Duration) {
	return fs.Duration("loop", 0, "keep running: check for requests every interval and run on schedule (containers; replaces the timer and the path unit)"),
		fs.Duration("full-every", time.Hour, "with --loop: period of a full scheduled run (the timer's hourly run)")
}
