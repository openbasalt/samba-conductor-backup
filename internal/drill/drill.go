// Package drill runs restore drills on a drill host: a machine that is not
// a domain controller, holds a drill age identity (backups are encrypted
// to it as well as to the operator's offline key) and can read the
// bucket. The DC asks for drills by posting signed requests; the drill host
// restores the newest backup into a throwaway sandbox (see sandbox.go),
// checks it, removes every plaintext byte and posts a signed report that
// the DC reads back into conductor's Backups page.
//
// Why not on the DC: the drill must decrypt, and the private key must
// never be on a DC (a compromised DC could then read every old backup).
package drill

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-backup/internal/alert"
	"github.com/openbasalt/samba-conductor-backup/internal/archive"
	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"github.com/openbasalt/samba-conductor-backup/internal/dest"
	"github.com/openbasalt/samba-conductor-backup/internal/manifest"
	"github.com/openbasalt/samba-conductor-backup/internal/runner"
	"github.com/openbasalt/samba-conductor-backup/internal/sign"
	"github.com/openbasalt/samba-conductor-backup/internal/state"
)

// Drill holds what a drill needs.
type Drill struct {
	Cfg   *config.Config
	Store dest.Store
	// Trusted verifies manifests and requests (the DCs' public keys).
	Trusted []sign.PublicKey
	// Key signs reports.
	Key           sign.PrivateKey
	Identities    []age.Identity
	ProbePassword string
	Alerts        runner.AlertSender
	Log           *slog.Logger
	Now           func() time.Time
	Version       string
	// Exe is this program (re-executed as the sandbox).
	Exe string
	// sandbox is replaced in tests.
	sandbox func(ctx context.Context, exe, spec, pw string, logw io.Writer) (SandboxResult, error)
}

// Options of a drill run.
type Options struct {
	// Force a drill of the newest backup now.
	Force bool
	// BackupID drills a specific backup (with Force).
	BackupID string
}

// hostState is the drill host's bookkeeping (<work_dir>/drill-state.json).
type hostState struct {
	Handled          []string              `json:"handled"`
	LastReport       *manifest.DrillReport `json:"last_report,omitempty"`
	WatchdogSentAt   time.Time             `json:"watchdog_sent_at"`
	FailureAlertSent time.Time             `json:"failure_alert_sent"`
}

func (d *Drill) now() time.Time {
	if d.Now != nil {
		return d.Now().UTC()
	}
	return time.Now().UTC()
}

// ErrNothingToDo: a scheduled run found no request.
var ErrNothingToDo = errors.New("no drill requested")

// Run performs a scheduled check (requests, watchdog) or a forced drill.
func (d *Drill) Run(ctx context.Context, opts Options) (*manifest.DrillReport, error) {
	if err := os.MkdirAll(d.Cfg.Drill.WorkDir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := state.Dir{Path: d.Cfg.Drill.WorkDir}.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	statePath := filepath.Join(d.Cfg.Drill.WorkDir, "drill-state.json")
	var hs hostState
	if err := state.ReadJSON(statePath, &hs); err != nil {
		return nil, err
	}
	defer func() { _ = state.WriteJSON(statePath, hs) }()

	list, err := runner.ListBackups(ctx, d.Store, d.Cfg.Realm, d.Trusted)
	if err != nil {
		return nil, fmt.Errorf("listing backups: %w", err)
	}
	d.watchdog(ctx, list, &hs)

	var req *manifest.DrillRequest
	if !opts.Force {
		req, err = d.nextRequest(ctx, hs.Handled)
		if err != nil {
			return nil, err
		}
		if req == nil {
			return nil, ErrNothingToDo
		}
	}
	backupID := opts.BackupID
	if req != nil {
		backupID = req.BackupID
	}
	rep := d.drill(ctx, list, backupID, req)
	if req != nil {
		hs.Handled = append(hs.Handled, req.ID)
		if len(hs.Handled) > 200 {
			hs.Handled = hs.Handled[len(hs.Handled)-200:]
		}
	}
	hs.LastReport = rep
	if err := d.publish(ctx, rep); err != nil {
		d.Log.Error("publishing the drill report", "err", err)
	}
	if !rep.Drill.Passed && d.Alerts != nil && d.Alerts.Enabled() {
		m := alert.Message{Kind: helper.AlertDrillFailed, Realm: strings.ToUpper(d.Cfg.Realm), Host: hostName(), At: d.now(),
			Subject: fmt.Sprintf("[conductor-backup] %s: restore drill failed (%s)", strings.ToUpper(d.Cfg.Realm), rep.Drill.BackupID),
			Text:    fmt.Sprintf("Restore drill %s of backup %s failed on %s.\n\n%s\n", rep.Drill.ID, rep.Drill.BackupID, hostName(), describe(rep))}
		if err := d.Alerts.Send(ctx, m); err != nil {
			d.Log.Error("sending the alert", "err", err)
		}
	}
	if !rep.Drill.Passed {
		return rep, fmt.Errorf("restore drill failed: %s", firstFailure(rep.Drill))
	}
	return rep, nil
}

// nextRequest returns the oldest signed, unhandled drill request.
func (d *Drill) nextRequest(ctx context.Context, handled []string) (*manifest.DrillRequest, error) {
	objs, err := d.Store.List(ctx, dest.RequestPrefix(d.Cfg.Realm))
	if err != nil {
		return nil, fmt.Errorf("listing drill requests: %w", err)
	}
	var reqs []manifest.DrillRequest
	for _, o := range objs {
		b, err := dest.ReadAll(ctx, d.Store, o.Key, 1<<20)
		if err != nil {
			continue
		}
		var q manifest.DrillRequest
		if _, err := sign.Open(b, d.Trusted, &q); err != nil || q.Format != manifest.RequestFormat || !strings.EqualFold(q.Realm, d.Cfg.Realm) {
			d.Log.Warn("ignoring an unverifiable drill request", "key", o.Key, "err", err)
			continue
		}
		if !contains(handled, q.ID) && d.now().Sub(q.At) < 72*time.Hour {
			reqs = append(reqs, q)
		}
	}
	if len(reqs) == 0 {
		return nil, nil
	}
	sort.Slice(reqs, func(i, j int) bool { return reqs[i].At.Before(reqs[j].At) })
	return &reqs[0], nil
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// watchdog alerts when the newest backup in the bucket is too old: an
// off-DC check that still works when the DC's own scheduler is dead.
func (d *Drill) watchdog(ctx context.Context, list []runner.Listed, hs *hostState) {
	max := d.Cfg.Drill.MaxBackupAgeHours
	if max <= 0 || d.Alerts == nil || !d.Alerts.Enabled() {
		return
	}
	var newest time.Time
	for _, l := range list {
		if l.Usable() {
			newest = l.Manifest.CreatedAt
			break
		}
	}
	age := d.now().Sub(newest)
	if !newest.IsZero() && age <= time.Duration(max)*time.Hour {
		hs.WatchdogSentAt = time.Time{}
		return
	}
	if d.now().Sub(hs.WatchdogSentAt) < 24*time.Hour {
		return
	}
	text := "No backup found in the bucket."
	if !newest.IsZero() {
		text = fmt.Sprintf("The newest backup in the bucket is from %s (%s ago).", newest.Format(time.RFC3339), age.Round(time.Minute))
	}
	m := alert.Message{Kind: helper.AlertStale, Realm: strings.ToUpper(d.Cfg.Realm), Host: hostName(), At: d.now(),
		Subject: fmt.Sprintf("[conductor-backup] %s: no recent backup (seen from the drill host)", strings.ToUpper(d.Cfg.Realm)),
		Text:    text + "\nCheck conductor-backup.timer and the Backups page on the domain controller.\n"}
	if err := d.Alerts.Send(ctx, m); err == nil {
		hs.WatchdogSentAt = d.now()
	} else {
		d.Log.Error("sending the watchdog alert", "err", err)
	}
}

var hostRE = regexp.MustCompile(`[^a-z0-9-]+`)

func hostName() string {
	h, _ := os.Hostname()
	h = hostRE.ReplaceAllString(strings.ToLower(strings.SplitN(h, ".", 2)[0]), "-")
	h = strings.Trim(h, "-")
	if h == "" {
		h = "drill"
	}
	if len(h) > 40 {
		h = h[:40]
	}
	return h
}

// drill restores one backup and checks it. It never returns without a
// report; the plaintext is shredded whatever happens.
func (d *Drill) drill(ctx context.Context, list []runner.Listed, backupID string, req *manifest.DrillRequest) *manifest.DrillReport {
	start := d.now()
	rep := &manifest.DrillReport{Format: manifest.ReportFormat, Realm: strings.ToUpper(d.Cfg.Realm), Version: d.Version, Phases: map[string]int64{},
		Drill: helper.DrillRecord{ID: start.Format("20060102T150405Z") + "-" + hostName(), Host: hostName(), StartedAt: start}}
	if req != nil {
		rep.Drill.RequestID = req.ID
	}
	finish := func(err error) *manifest.DrillReport {
		rep.Drill.FinishedAt = d.now()
		if err != nil {
			rep.Drill.Error = err.Error()
			if len(rep.Drill.Error) > 200 {
				rep.Drill.Error = rep.Drill.Error[:197] + "..."
			}
		}
		rep.Drill.Passed = err == nil && len(rep.Drill.Checks) > 0
		for _, c := range rep.Drill.Checks {
			if !c.OK {
				rep.Drill.Passed = false
			}
		}
		d.Log.Info("drill finished", "id", rep.Drill.ID, "backup", rep.Drill.BackupID, "passed", rep.Drill.Passed, "rto_ms", rep.Drill.RTOMS)
		return rep
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.Cfg.Drill.TimeoutMinutes)*time.Minute)
	defer cancel()

	b, err := runner.Latest(list, backupID)
	if err != nil {
		return finish(err)
	}
	rep.Drill.BackupID = b.ID
	work := filepath.Join(d.Cfg.Drill.WorkDir, rep.Drill.ID)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return finish(err)
	}
	defer func() {
		if err := archive.ShredTree(work); err != nil {
			d.Log.Error("removing the drill's plaintext", "dir", work, "err", err)
		}
	}()

	// Download and verify against the signed manifest.
	t := time.Now()
	cipher := filepath.Join(work, "archive.tar.age")
	if err := download(ctx, d.Store, dest.ArchiveKey(d.Cfg.Realm, b.ID), cipher); err != nil {
		return finish(fmt.Errorf("download: %w", err))
	}
	rep.Phases["download"] = time.Since(t).Milliseconds()
	t = time.Now()
	size, sum, _, err := dest.FileDigests(cipher)
	if err != nil {
		return finish(err)
	}
	if size != b.Manifest.Size || sum != b.Manifest.SHA256 {
		return finish(errors.New("the downloaded archive does not match its signed manifest (SHA-256)"))
	}
	rep.Drill.Checks = append(rep.Drill.Checks, helper.DrillCheck{Name: "integrity", OK: true, Detail: "sha256 " + sum[:16] + "…"})
	rep.Phases["verify"] = time.Since(t).Milliseconds()

	// Decrypt and extract.
	t = time.Now()
	f, err := os.Open(cipher)
	if err != nil {
		return finish(err)
	}
	plain := filepath.Join(work, "x")
	meta, err := archive.Extract(f, d.Identities, plain)
	_ = f.Close()
	_ = os.Remove(cipher)
	if err != nil {
		return finish(err)
	}
	if meta.ID != b.ID || !strings.EqualFold(meta.Realm, d.Cfg.Realm) {
		return finish(fmt.Errorf("archive metadata (%s, %s) does not match the manifest", meta.ID, meta.Realm))
	}
	rep.Phases["decrypt"] = time.Since(t).Milliseconds()
	if d.Cfg.Drill.ProbeUser == "" {
		return finish(errors.New("drill.probe_user is not configured"))
	}

	// Restore, start and check in the sandbox.
	spec := SandboxSpec{BackupFile: filepath.Join(plain, filepath.FromSlash(meta.SambaFile)), TargetDir: filepath.Join(work, "restore"),
		WorkDir: work, ServerName: d.Cfg.Drill.ServerName, Realm: strings.ToUpper(d.Cfg.Realm), ProbeUser: d.Cfg.Drill.ProbeUser,
		Samples: meta.Samples, Users: meta.Users, SambaBinary: d.Cfg.Drill.SambaBinary, SambaTool: d.Cfg.Drill.SambaTool,
		TimeoutSeconds: d.Cfg.Drill.TimeoutMinutes * 60}
	specPath := filepath.Join(work, "sandbox.json")
	if err := state.WriteJSON(specPath, spec); err != nil {
		return finish(err)
	}
	logw, err := os.OpenFile(filepath.Join(d.Cfg.Drill.WorkDir, "sandbox.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return finish(err)
	}
	defer func() { _ = logw.Close() }()
	sandboxStart := d.now()
	run := d.sandbox
	if run == nil {
		run = startSandbox
	}
	res, err := run(ctx, d.Exe, specPath, d.ProbePassword, logw)
	rep.Drill.Checks = append(rep.Drill.Checks, res.Checks...)
	rep.Phases["restore"], rep.Phases["start"], rep.Phases["checks"] = res.RestoreMS, res.StartMS, res.ChecksMS
	if err == nil && res.Error != "" {
		err = errors.New(res.Error)
	}
	if err != nil {
		return finish(err)
	}
	// RTO: from the start of the drill until the restored DC passed its
	// checks (download, verify, decrypt, restore, start, checks).
	rep.Drill.RTOMS = sandboxStart.Sub(start).Milliseconds() + res.ReadyMS
	return finish(nil)
}

func download(ctx context.Context, s dest.Store, key, path string) error {
	rc, _, err := s.Get(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, rc); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// publish signs the report and stores it where the DC reads it.
func (d *Drill) publish(ctx context.Context, rep *manifest.DrillReport) error {
	env, err := sign.Seal(d.Key, rep)
	if err != nil {
		return err
	}
	key, err := dest.DocKey(dest.ReportPrefix(d.Cfg.Realm), rep.Drill.ID)
	if err != nil {
		return err
	}
	return d.Store.PutBytes(ctx, key, env)
}

func firstFailure(dr helper.DrillRecord) string {
	if dr.Error != "" {
		return dr.Error
	}
	for _, c := range dr.Checks {
		if !c.OK {
			return c.Name + ": " + c.Detail
		}
	}
	return "unknown"
}

func describe(rep *manifest.DrillReport) string {
	var b strings.Builder
	if rep.Drill.Error != "" {
		fmt.Fprintf(&b, "Error: %s\n", rep.Drill.Error)
	}
	for _, c := range rep.Drill.Checks {
		mark := "ok  "
		if !c.OK {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "%s %s %s\n", mark, c.Name, c.Detail)
	}
	return b.String()
}
