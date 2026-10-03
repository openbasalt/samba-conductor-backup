// Package runner is what `conductor-backup run` does on a domain
// controller, under the conductor-backup user (no root, no AD
// credentials):
//
//  1. take the run lock; read the policy, the requests left by
//     conductor-helper and the bookkeeping;
//  2. retry uploads that did not reach every destination;
//  3. when a backup is due (schedule slot passed without a good backup, a
//     "back up now" request, or --now): ask conductor-helper for an
//     encrypted archive, check it, sign its manifest, upload it to every
//     destination and read it back to verify the SHA-256;
//  4. apply the retention policy (never the newest good backup);
//  5. read signed drill reports, and post a signed drill request when one
//     was asked for or the policy's interval has passed;
//  6. evaluate alert conditions, send alerts, write state.json.
package runner

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor-backup/internal/alert"
	"github.com/samba-conductor/conductor-backup/internal/config"
	"github.com/samba-conductor/conductor-backup/internal/dest"
	"github.com/samba-conductor/conductor-backup/internal/manifest"
	"github.com/samba-conductor/conductor-backup/internal/retention"
	"github.com/samba-conductor/conductor-backup/internal/sign"
	"github.com/samba-conductor/conductor-backup/internal/state"
)

// HelperClient calls conductor-helper.
type HelperClient interface {
	Call(ctx context.Context, req helper.Request) (helper.Response, error)
}

// SocketHelper calls the helper on its Unix socket.
type SocketHelper struct{ Socket string }

// Call implements HelperClient.
func (h SocketHelper) Call(ctx context.Context, req helper.Request) (helper.Response, error) {
	return helper.Call(ctx, h.Socket, req)
}

// AlertSender delivers alerts.
type AlertSender interface {
	Enabled() bool
	Send(ctx context.Context, m alert.Message) error
}

// Runner holds what a run needs.
type Runner struct {
	Cfg     *config.Config
	Dir     state.Dir
	Helper  HelperClient
	Stores  []dest.Store
	Key     sign.PrivateKey
	Alerts  AlertSender
	Now     func() time.Time
	Log     *slog.Logger
	Version string
}

// Options of a run.
type Options struct {
	// Scheduled: a timer run, backing up when the schedule says so.
	Scheduled bool
	// Force a backup now (CLI).
	Force bool
}

// BackupTimeout bounds the helper's part of a backup.
const BackupTimeout = 45 * time.Minute

func (r *Runner) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

// Run performs one run. A run that is already in progress makes this one
// return state.ErrLocked. Requests that arrive while it runs (the path
// unit's start then merges into this run) are processed before it ends.
func (r *Runner) Run(ctx context.Context, opts Options) error {
	unlock, err := r.Dir.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	var errs []error
	for pass := 0; pass < 3; pass++ {
		if err := r.runOnce(ctx, opts); err != nil {
			errs = append(errs, err)
		}
		opts.Force = false
		if reqs, err := r.Dir.PendingRequests(); err != nil || len(reqs) == 0 || ctx.Err() != nil {
			break
		}
	}
	return errors.Join(errs...)
}

func (r *Runner) runOnce(ctx context.Context, opts Options) error {
	st, err := r.Dir.LoadStatus()
	if err != nil {
		return err
	}
	priv, err := r.Dir.LoadPrivate()
	if err != nil {
		return err
	}
	policy, custom, perr := r.Dir.Policy()
	if perr != nil {
		r.Log.Warn("policy unreadable, using the default", "err", perr)
	}
	now := r.now()
	r.describe(&st)
	st.Policy, st.PolicyCustom = policy, custom
	st.LastRunAt = now

	reqs, err := r.Dir.PendingRequests()
	if err != nil {
		r.Log.Error("reading requests", "err", err)
	}
	var backupReqs, drillReqs []helper.BackupRequest
	for _, q := range reqs {
		if q.Kind == helper.TriggerBackup {
			backupReqs = append(backupReqs, q)
		} else {
			drillReqs = append(drillReqs, q)
		}
	}

	r.retryLeftovers(ctx, &st, &priv)

	slot := policy.Schedule.Slot(now)
	last, hasLast := st.LastGood()
	due := opts.Force || len(backupReqs) > 0 || (opts.Scheduled && (!hasLast || last.CreatedAt.Before(slot)))
	var runErr error
	if due {
		trigger := "scheduled"
		var req *helper.BackupRequest
		if len(backupReqs) > 0 {
			trigger, req = "manual", &backupReqs[0]
		} else if opts.Force {
			trigger = "manual"
		}
		rec := r.backup(ctx, trigger, req, &priv)
		st.Backups = append([]helper.BackupRecord{rec}, st.Backups...)
		priv.Attempted = slot
		for _, q := range backupReqs {
			_ = r.Dir.DoneRequest(q.ID)
		}
		if rec.Status == helper.StatusFailed {
			runErr = fmt.Errorf("backup %s failed: %s", rec.ID, rec.Error)
		}
		if rec.Status != helper.StatusFailed || now.Sub(priv.LastPrune) > 24*time.Hour {
			r.prune(ctx, &st, &priv, policy, false)
		}
	} else if now.Sub(priv.LastPrune) > 24*time.Hour {
		r.prune(ctx, &st, &priv, policy, false)
	}

	r.syncDrills(ctx, &st, &priv, policy, drillReqs)
	st.NextDueAt = policy.Schedule.Next(now)
	if last, ok := st.LastGood(); !ok || last.CreatedAt.Before(policy.Schedule.Slot(now)) {
		st.NextDueAt = now.Add(time.Hour).Truncate(time.Hour) // retried by the next hourly run
	}
	r.evaluateAlerts(ctx, &st, &priv, policy, now)
	st.UpdatedAt = r.now()
	if err := r.Dir.SaveStatus(st); err != nil {
		return err
	}
	if err := r.Dir.SavePrivate(priv); err != nil {
		return err
	}
	return runErr
}

// describe fills the configuration part of the status (no secrets).
func (r *Runner) describe(st *helper.BackupStatus) {
	st.Configured = true
	st.Realm, st.DC, st.Version = strings.ToUpper(r.Cfg.Realm), r.Cfg.DC, r.Version
	st.Destinations = st.Destinations[:0]
	for _, s := range r.Stores {
		st.Destinations = append(st.Destinations, s.Describe())
	}
	st.Recipients, _ = RecipientFingerprints(r.Cfg.RecipientsFile)
	st.SigningKeyID = r.Key.Public().ID()
}

// RecipientFingerprints reads the recipients file (one age recipient per
// line, # comments) and returns their fingerprints.
func RecipientFingerprints(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, helper.RecipientFingerprint(line))
	}
	return out, sc.Err()
}

func newID(prefix string) string {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

// short trims an error for the status document (no secrets are in these
// errors: helper codes, S3 codes, file names).
func short(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}

// backup asks the helper for an archive and distributes it.
func (r *Runner) backup(ctx context.Context, trigger string, req *helper.BackupRequest, priv *state.Private) helper.BackupRecord {
	start := r.now()
	rec := helper.BackupRecord{ID: helper.NewBackupID(start, r.Cfg.DC), CreatedAt: start, Trigger: trigger, Status: helper.StatusFailed}
	caller := helper.Caller{User: "conductor-backup", SID: "S-1-5-18", SessionID: newID("run-")}
	if req != nil {
		rec.RequestedBy = req.RequestedBy
		caller = helper.Caller{User: req.RequestedBy, SID: req.SID, SessionID: "request-" + req.ID}
	}
	fail := func(err error) helper.BackupRecord {
		rec.Error = short(err)
		rec.DurationMS = r.now().Sub(start).Milliseconds()
		r.Log.Error("backup failed", "id", rec.ID, "err", err)
		return rec
	}
	hreq, err := helper.NewRequest(newID("cb-"), helper.OpDomainBackupOnline, caller, helper.BackupOnlineParams{Label: trigger})
	if err != nil {
		return fail(err)
	}
	cctx, cancel := context.WithTimeout(ctx, BackupTimeout)
	defer cancel()
	resp, err := r.Helper.Call(cctx, hreq)
	if err != nil {
		return fail(fmt.Errorf("conductor-helper: %w", err))
	}
	var res helper.BackupOnlineResult
	if err := helper.DecodeResult(resp, &res); err != nil {
		return fail(fmt.Errorf("conductor-helper result: %w", err))
	}
	if !helper.BackupIDRE.MatchString(res.ID) || res.File != res.ID+".tar.age" {
		return fail(fmt.Errorf("conductor-helper returned an invalid archive name %q", res.File))
	}
	if !strings.EqualFold(res.Realm, r.Cfg.Realm) {
		return fail(fmt.Errorf("the helper backed up realm %q, configured %q", res.Realm, r.Cfg.Realm))
	}
	rec.ID, rec.CreatedAt, rec.Users = res.ID, res.CreatedAt.UTC(), res.Users
	path := filepath.Join(r.Dir.Spool(), res.File)
	size, sum, _, err := dest.FileDigests(path)
	if err != nil {
		return fail(err)
	}
	if size != res.Size || sum != res.SHA256 {
		return fail(errors.New("the archive in the spool does not match what the helper reported"))
	}
	rec.Size, rec.SHA256 = size, sum
	m := manifest.Manifest{Format: manifest.ManifestFormat, ID: res.ID, Realm: strings.ToUpper(res.Realm), DC: res.DC,
		CreatedAt: res.CreatedAt.UTC(), Trigger: trigger, Object: dest.ArchiveKey(r.Cfg.Realm, res.ID), Size: size, SHA256: sum,
		Recipients: res.Recipients, Versions: res.Versions, Contents: res.Contents}
	if m.Versions == nil {
		m.Versions = map[string]string{}
	}
	m.Versions["conductor-backup"] = r.Version
	env, err := sign.Seal(r.Key, m)
	if err != nil {
		return fail(err)
	}
	if err := os.WriteFile(filepath.Join(r.Dir.Spool(), res.ID+".json"), env, 0o600); err != nil {
		return fail(err)
	}
	var names []string
	for _, s := range r.Stores {
		names = append(names, s.Name())
	}
	rec.Uploads = r.distribute(ctx, res.ID, names)
	r.settle(&rec, priv)
	rec.DurationMS = r.now().Sub(start).Milliseconds()
	r.Log.Info("backup done", "id", rec.ID, "status", rec.Status, "size", rec.Size, "users", rec.Users)
	return rec
}

// distribute uploads a spooled archive and its manifest to the named
// destinations and verifies each copy.
func (r *Runner) distribute(ctx context.Context, id string, names []string) []helper.UploadRecord {
	path := filepath.Join(r.Dir.Spool(), id+".tar.age")
	env, err := os.ReadFile(filepath.Join(r.Dir.Spool(), id+".json"))
	var out []helper.UploadRecord
	if err != nil {
		for _, n := range names {
			out = append(out, helper.UploadRecord{Destination: n, Status: helper.StatusFailed, Error: "manifest missing from the spool"})
		}
		return out
	}
	size, sum, md, err := dest.FileDigests(path)
	for _, s := range r.Stores {
		if !slices.Contains(names, s.Name()) {
			continue
		}
		u := helper.UploadRecord{Destination: s.Name(), Status: helper.StatusFailed}
		if err != nil {
			u.Error = short(err)
			out = append(out, u)
			continue
		}
		if perr := r.uploadOne(ctx, s, id, path, size, sum, md, env); perr != nil {
			u.Error = short(perr)
			r.Log.Warn("upload failed", "id", id, "destination", s.Name(), "err", perr)
		} else {
			u.Status = helper.StatusOK
			u.VerifiedAt = r.now()
		}
		out = append(out, u)
	}
	return out
}

func (r *Runner) uploadOne(ctx context.Context, s dest.Store, id, path string, size int64, sum, md string, env []byte) error {
	key := dest.ArchiveKey(r.Cfg.Realm, id)
	if err := s.PutFile(ctx, key, path, size, sum, md); err != nil {
		return err
	}
	if err := s.PutBytes(ctx, dest.ManifestKey(r.Cfg.Realm, id), env); err != nil {
		return err
	}
	if *r.Cfg.VerifyAfterUpload {
		return VerifyObject(ctx, s, key, size, sum)
	}
	return nil
}

// ErrMismatch: a stored archive does not match its manifest.
var ErrMismatch = errors.New("stored archive does not match the manifest (size or SHA-256)")

// VerifyObject downloads an object and checks its size and SHA-256.
func VerifyObject(ctx context.Context, s dest.Store, key string, size int64, sum string) error {
	rc, _, err := s.Get(ctx, key)
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()
	n, got, _, err := dest.ReaderDigests(io.LimitReader(rc, size+1))
	if err != nil {
		return err
	}
	if n != size || got != sum {
		return ErrMismatch
	}
	return nil
}

// settle derives the record status from its uploads and keeps the spool
// copy while a destination is missing.
func (r *Runner) settle(rec *helper.BackupRecord, priv *state.Private) {
	var ok, missing []string
	for _, u := range rec.Uploads {
		if u.Status == helper.StatusOK || u.Status == helper.StatusPruned {
			ok = append(ok, u.Destination)
		} else {
			missing = append(missing, u.Destination)
		}
	}
	switch {
	case len(missing) == 0 && len(ok) > 0:
		rec.Status, rec.Error = helper.StatusOK, ""
		delete(priv.Missing, rec.ID)
		_ = os.Remove(filepath.Join(r.Dir.Spool(), rec.ID+".tar.age"))
		_ = os.Remove(filepath.Join(r.Dir.Spool(), rec.ID+".json"))
	case len(ok) > 0:
		rec.Status = helper.StatusPartial
		rec.Error = "not stored in: " + strings.Join(missing, ", ")
		priv.Missing[rec.ID] = missing
	default:
		rec.Status = helper.StatusFailed
		if rec.Error == "" {
			for _, u := range rec.Uploads {
				if u.Error != "" {
					rec.Error = u.Destination + ": " + u.Error
					break
				}
			}
		}
		priv.Missing[rec.ID] = missing
	}
}

// retryLeftovers uploads spooled archives to the destinations they missed,
// and removes stale spool files.
func (r *Runner) retryLeftovers(ctx context.Context, st *helper.BackupStatus, priv *state.Private) {
	for id, missing := range priv.Missing {
		if _, err := os.Stat(filepath.Join(r.Dir.Spool(), id+".tar.age")); err != nil {
			delete(priv.Missing, id)
			continue
		}
		ups := r.distribute(ctx, id, missing)
		for i := range st.Backups {
			b := &st.Backups[i]
			if b.ID != id {
				continue
			}
			for _, u := range ups {
				replaced := false
				for j := range b.Uploads {
					if b.Uploads[j].Destination == u.Destination {
						b.Uploads[j], replaced = u, true
					}
				}
				if !replaced {
					b.Uploads = append(b.Uploads, u)
				}
			}
			r.settle(b, priv)
		}
	}
	// Anything else in the spool is a leftover of an interrupted run.
	entries, _ := os.ReadDir(r.Dir.Spool())
	for _, e := range entries {
		id := strings.TrimSuffix(strings.TrimSuffix(e.Name(), ".tar.age"), ".json")
		if _, inFlight := priv.Missing[id]; inFlight {
			continue
		}
		if info, err := e.Info(); err == nil && r.now().Sub(info.ModTime()) > 6*time.Hour {
			_ = os.Remove(filepath.Join(r.Dir.Spool(), e.Name()))
		}
	}
}

// ---- retention ----

// PruneReport is what pruning did (or would do) at one destination.
type PruneReport struct {
	Destination string
	Kept        []string
	Deleted     []string
	Incomplete  []string
	Errors      []string
}

// trustedBackupKeys are the keys whose manifests count as this DC's.
func (r *Runner) trustedBackupKeys() []sign.PublicKey {
	keys, _ := config.PublicKeys(r.Cfg.BackupPublicKeys)
	return append(keys, r.Key.Public())
}

// complete lists, at one destination, this DC's backups that have an
// archive and a signed manifest of the same size.
func (r *Runner) complete(ctx context.Context, s dest.Store) (map[string]time.Time, []string, error) {
	objs, err := s.List(ctx, dest.DomainPrefix(r.Cfg.Realm))
	if err != nil {
		return nil, nil, err
	}
	sizes := map[string]int64{}
	manifests := map[string]bool{}
	for _, o := range objs {
		name := strings.TrimPrefix(o.Key, dest.DomainPrefix(r.Cfg.Realm))
		switch {
		case strings.HasSuffix(name, ".tar.age"):
			sizes[strings.TrimSuffix(name, ".tar.age")] = o.Size
		case strings.HasSuffix(name, ".json"):
			manifests[strings.TrimSuffix(name, ".json")] = true
		}
	}
	ids := map[string]bool{}
	for id := range sizes {
		ids[id] = true
	}
	for id := range manifests {
		ids[id] = true
	}
	good := map[string]time.Time{}
	var incomplete []string
	for id := range ids {
		at, err := helper.BackupIDTime(id)
		if err != nil || !strings.HasSuffix(id, "-"+r.Cfg.DC) {
			continue // not ours (another DC, or foreign objects)
		}
		ok := false
		if size, has := sizes[id]; has && manifests[id] {
			if b, err := dest.ReadAll(ctx, s, dest.ManifestKey(r.Cfg.Realm, id), 1<<20); err == nil {
				var m manifest.Manifest
				if _, err := sign.Open(b, r.trustedBackupKeys(), &m); err == nil && m.Validate(r.Cfg.Realm) == nil && m.Size == size && m.ID == id {
					ok = true
				}
			}
		}
		if ok {
			good[id] = at
		} else {
			incomplete = append(incomplete, id)
		}
	}
	sort.Strings(incomplete)
	return good, incomplete, nil
}

// Prune applies the retention policy at every destination.
func (r *Runner) Prune(ctx context.Context, dryRun bool) ([]PruneReport, error) {
	unlock, err := r.Dir.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := r.Dir.LoadStatus()
	if err != nil {
		return nil, err
	}
	priv, err := r.Dir.LoadPrivate()
	if err != nil {
		return nil, err
	}
	policy, _, _ := r.Dir.Policy()
	reports := r.prune(ctx, &st, &priv, policy, dryRun)
	if !dryRun {
		if err := r.Dir.SaveStatus(st); err != nil {
			return reports, err
		}
		if err := r.Dir.SavePrivate(priv); err != nil {
			return reports, err
		}
	}
	return reports, nil
}

func (r *Runner) prune(ctx context.Context, st *helper.BackupStatus, priv *state.Private, policy helper.BackupPolicy, dryRun bool) []PruneReport {
	now := r.now()
	var reports []PruneReport
	for _, s := range r.Stores {
		rep := PruneReport{Destination: s.Name()}
		good, incomplete, err := r.complete(ctx, s)
		if err != nil {
			rep.Errors = append(rep.Errors, short(err))
			reports = append(reports, rep)
			continue
		}
		var items []retention.Item
		for id, at := range good {
			items = append(items, retention.Item{ID: id, At: at})
		}
		keep := retention.Keep(items, policy.Retention, now)
		for id := range good {
			if keep[id] {
				rep.Kept = append(rep.Kept, id)
				continue
			}
			rep.Deleted = append(rep.Deleted, id)
		}
		sort.Strings(rep.Kept)
		sort.Strings(rep.Deleted)
		for _, id := range incomplete {
			at, _ := helper.BackupIDTime(id)
			if _, inFlight := priv.Missing[id]; inFlight || now.Sub(at) < 48*time.Hour {
				continue
			}
			rep.Incomplete = append(rep.Incomplete, id)
		}
		if !dryRun {
			for _, id := range append(append([]string(nil), rep.Deleted...), rep.Incomplete...) {
				// Archive first: a manifest without its archive is
				// incomplete and cleaned later; the reverse would leave an
				// archive nobody can verify.
				if err := s.Delete(ctx, dest.ArchiveKey(r.Cfg.Realm, id)); err != nil {
					rep.Errors = append(rep.Errors, id+": "+short(err))
					continue
				}
				if err := s.Delete(ctx, dest.ManifestKey(r.Cfg.Realm, id)); err != nil {
					rep.Errors = append(rep.Errors, id+": "+short(err))
				}
				markPruned(st, id, s.Name())
			}
		}
		reports = append(reports, rep)
		r.Log.Info("retention", "destination", s.Name(), "kept", len(rep.Kept), "deleted", len(rep.Deleted),
			"incomplete", len(rep.Incomplete), "errors", len(rep.Errors), "dry_run", dryRun)
	}
	if !dryRun {
		priv.LastPrune = now
	}
	return reports
}

func markPruned(st *helper.BackupStatus, id, destination string) {
	for i := range st.Backups {
		b := &st.Backups[i]
		if b.ID != id {
			continue
		}
		all := true
		for j := range b.Uploads {
			if b.Uploads[j].Destination == destination {
				b.Uploads[j].Status = helper.StatusPruned
			}
			if b.Uploads[j].Status != helper.StatusPruned {
				all = false
			}
		}
		if all && len(b.Uploads) > 0 {
			b.Status = helper.StatusPruned
		}
	}
}
