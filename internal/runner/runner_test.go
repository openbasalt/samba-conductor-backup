package runner

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor-backup/internal/alert"
	"github.com/samba-conductor/conductor-backup/internal/config"
	"github.com/samba-conductor/conductor-backup/internal/dest"
	"github.com/samba-conductor/conductor-backup/internal/manifest"
	"github.com/samba-conductor/conductor-backup/internal/sign"
	"github.com/samba-conductor/conductor-backup/internal/state"
)

// fakeHelper writes a ciphertext-like file in the spool, like the helper.
type fakeHelper struct {
	spool string
	now   func() time.Time
	fail  bool
	calls []helper.Request
}

func (f *fakeHelper) Call(_ context.Context, req helper.Request) (helper.Response, error) {
	f.calls = append(f.calls, req)
	if _, err := req.Decode(); err != nil {
		return helper.Response{}, err
	}
	if f.fail {
		return helper.Response{}, &helper.Error{Code: helper.CodeFailed, Message: "operation failed; see the helper log"}
	}
	at := f.now()
	id := helper.NewBackupID(at, "dc1")
	data := []byte("age-encryption.org/v1 fake ciphertext " + id)
	_ = os.MkdirAll(f.spool, 0o700)
	if err := os.WriteFile(filepath.Join(f.spool, id+".tar.age"), data, 0o600); err != nil {
		return helper.Response{}, err
	}
	size, sum, md, _ := dest.FileDigests(filepath.Join(f.spool, id+".tar.age"))
	return helper.OKResponse(req.ID, helper.BackupOnlineResult{ID: id, File: id + ".tar.age", Size: size, SHA256: sum, MD5: md,
		CreatedAt: at, Realm: "LAB.TEST", DC: "dc1", Recipients: []string{"SHA256:0011223344556677"}, Users: 42,
		Versions: map[string]string{"samba": "4.22"}, Contents: []string{"conductor-backup.json", "samba/x.tar.bz2"}})
}

// failingStore wraps a store and fails PutFile while fail is set.
type failingStore struct {
	dest.Store
	mu   sync.Mutex
	fail bool
}

func (f *failingStore) PutFile(ctx context.Context, key, path string, size int64, sum, md string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("s3: dial tcp: connection refused")
	}
	return f.Store.PutFile(ctx, key, path, size, sum, md)
}

type fakeAlerts struct{ sent []alert.Message }

func (f *fakeAlerts) Enabled() bool { return true }
func (f *fakeAlerts) Send(_ context.Context, m alert.Message) error {
	f.sent = append(f.sent, m)
	return nil
}

type env struct {
	r      *Runner
	now    time.Time
	fh     *fakeHelper
	remote *failingStore
	local  dest.Store
	alerts *fakeAlerts
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	for _, d := range []string{stateDir, filepath.Join(stateDir, "spool"), filepath.Join(stateDir, "requests")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	rec := filepath.Join(root, "recipients.txt")
	_ = os.WriteFile(rec, []byte("# operator\nage1qqqq\n"), 0o644)
	verify := true
	cfg := &config.Config{Realm: "LAB.TEST", DC: "dc1", StateDir: stateDir, RecipientsFile: rec, VerifyAfterUpload: &verify,
		Destinations: []config.Destination{{Name: "local", Type: "local", Path: filepath.Join(root, "local")},
			{Name: "remote", Type: "local", Path: filepath.Join(root, "remote")}}}
	key, _ := sign.Generate()
	e := &env{now: time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC), alerts: &fakeAlerts{}}
	local, _ := dest.Open(cfg, cfg.Destinations[0])
	remote, _ := dest.Open(cfg, cfg.Destinations[1])
	e.local, e.remote = local, &failingStore{Store: remote}
	e.fh = &fakeHelper{spool: filepath.Join(stateDir, "spool"), now: func() time.Time { return e.now }}
	e.r = &Runner{Cfg: cfg, Dir: state.Dir{Path: stateDir}, Helper: e.fh, Stores: []dest.Store{e.local, e.remote}, Key: key,
		Alerts: e.alerts, Now: func() time.Time { return e.now }, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"}
	return e
}

func TestRunBackupUploadVerify(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.r.Run(ctx, Options{Scheduled: true}); err != nil {
		t.Fatal(err)
	}
	st, _ := e.r.Dir.LoadStatus()
	if len(st.Backups) != 1 || st.Backups[0].Status != helper.StatusOK || len(st.Backups[0].Uploads) != 2 {
		t.Fatalf("backups %+v", st.Backups)
	}
	b := st.Backups[0]
	if b.Users != 42 || b.Trigger != "scheduled" || st.Recipients[0] != helper.RecipientFingerprint("age1qqqq") {
		t.Fatalf("record %+v recipients %v", b, st.Recipients)
	}
	if req := e.fh.calls[0]; req.Op != helper.OpDomainBackupOnline || req.Caller.User != "conductor-backup" {
		t.Fatalf("helper request %+v", req)
	}
	// Spool emptied once every destination has it.
	if entries, _ := os.ReadDir(e.r.Dir.Spool()); len(entries) != 0 {
		t.Fatalf("spool not emptied: %v", entries)
	}
	// The stored copy verifies against its signed manifest.
	trusted := []sign.PublicKey{e.r.Key.Public()}
	if _, err := Verify(ctx, e.local, "LAB.TEST", b.ID, trusted); err != nil {
		t.Fatal(err)
	}
	// Not due again within the same slot.
	e.now = e.now.Add(time.Hour)
	_ = e.r.Run(ctx, Options{Scheduled: true})
	if st, _ := e.r.Dir.LoadStatus(); len(st.Backups) != 1 {
		t.Fatalf("backed up twice in one slot: %d", len(st.Backups))
	}
	// Tampering in a destination is detected by verify.
	key := filepath.Join(e.r.Cfg.Destinations[0].Path, "domain", "lab.test", b.ID+".tar.age")
	raw, _ := os.ReadFile(key)
	raw[3] ^= 1
	_ = os.WriteFile(key, raw, 0o600)
	if _, err := Verify(ctx, e.local, "LAB.TEST", b.ID, trusted); !errors.Is(err, ErrMismatch) {
		t.Fatalf("tampered archive: %v", err)
	}
	// A manifest signed by another key is not trusted.
	other, _ := sign.Generate()
	if _, err := Verify(ctx, e.remote, "LAB.TEST", b.ID, []sign.PublicKey{other.Public()}); err == nil {
		t.Fatal("untrusted manifest accepted")
	}
}

func TestPartialUploadIsRetried(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.remote.fail = true
	err := e.r.Run(ctx, Options{Scheduled: true})
	if err != nil {
		t.Fatalf("a partial backup is not a failed run: %v", err)
	}
	st, _ := e.r.Dir.LoadStatus()
	if st.Backups[0].Status != helper.StatusPartial || !strings.Contains(st.Backups[0].Error, "remote") {
		t.Fatalf("status %+v", st.Backups[0])
	}
	if entries, _ := os.ReadDir(e.r.Dir.Spool()); len(entries) != 2 {
		t.Fatalf("spool should keep the archive and manifest: %v", entries)
	}
	e.remote.fail = false
	e.now = e.now.Add(time.Hour)
	if err := e.r.Run(ctx, Options{Scheduled: true}); err != nil {
		t.Fatal(err)
	}
	st, _ = e.r.Dir.LoadStatus()
	if st.Backups[0].Status != helper.StatusOK || len(st.Backups) != 1 {
		t.Fatalf("after retry %+v", st.Backups)
	}
}

func TestFailureAlertsAndRequests(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.fh.fail = true
	if err := e.r.Run(ctx, Options{Scheduled: true}); err == nil {
		t.Fatal("failed backup not reported")
	}
	st, _ := e.r.Dir.LoadStatus()
	if st.Backups[0].Status != helper.StatusFailed || len(st.Alerts) != 1 || st.Alerts[0].Kind != helper.AlertFailed {
		t.Fatalf("status %+v alerts %+v", st.Backups[0], st.Alerts)
	}
	if len(e.alerts.sent) != 1 || !strings.Contains(e.alerts.sent[0].Subject, "backup failed") {
		t.Fatalf("alerts %+v", e.alerts.sent)
	}
	// Not re-sent within a day; re-sent after.
	e.now = e.now.Add(time.Hour)
	_ = e.r.Run(ctx, Options{Scheduled: true})
	if len(e.alerts.sent) != 1 {
		t.Fatalf("alert repeated: %d", len(e.alerts.sent))
	}
	// A manual request carries the administrator's identity to the helper.
	e.fh.fail = false
	req := helper.BackupRequest{ID: "req-abc12345", Kind: helper.TriggerBackup, RequestedBy: "lab.admin", SID: "S-1-5-21-1-2-3-1104", At: e.now}
	_ = state.WriteJSON(filepath.Join(e.r.Dir.Requests(), req.ID+".json"), req)
	if err := e.r.Run(ctx, Options{Scheduled: true}); err != nil {
		t.Fatal(err)
	}
	last := e.fh.calls[len(e.fh.calls)-1]
	if last.Caller.User != "lab.admin" || last.Caller.SID != req.SID {
		t.Fatalf("caller %+v", last.Caller)
	}
	st, _ = e.r.Dir.LoadStatus()
	if st.Backups[0].Trigger != "manual" || st.Backups[0].RequestedBy != "lab.admin" || len(st.Alerts) != 0 {
		t.Fatalf("manual backup %+v alerts %+v", st.Backups[0], st.Alerts)
	}
	if reqs, _ := e.r.Dir.PendingRequests(); len(reqs) != 0 {
		t.Fatalf("request not consumed: %v", reqs)
	}
}

func TestStaleAlert(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_ = e.r.Run(ctx, Options{Scheduled: true})
	// The scheduler stops; 27 hours later a check finds the backup stale.
	e.now = e.now.Add(27 * time.Hour)
	alerts, err := e.r.Check(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(alerts) != 1 || alerts[0].Kind != helper.AlertStale {
		t.Fatalf("alerts %+v", alerts)
	}
	if len(e.alerts.sent) != 1 || !strings.Contains(e.alerts.sent[0].Subject, "no recent backup") {
		t.Fatalf("sent %+v", e.alerts.sent)
	}
}

func TestPruneKeepsLastGood(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Ten daily backups.
	for i := 0; i < 10; i++ {
		if err := e.r.Run(ctx, Options{Force: true}); err != nil {
			t.Fatal(err)
		}
		e.now = e.now.Add(24 * time.Hour)
	}
	pol := helper.DefaultBackupPolicy()
	pol.Retention = helper.BackupRetention{Daily: 3}
	_ = state.WriteJSON(filepath.Join(e.r.Dir.Path, "policy.json"), pol)
	// The daily runs already applied the default policy (7 daily, 4
	// weekly, 12 monthly) along the way.
	before, _ := ListBackups(ctx, e.local, "LAB.TEST", []sign.PublicKey{e.r.Key.Public()})
	reports, err := e.r.Prune(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports[0].Kept) != 3 || len(reports[0].Deleted) != len(before)-3 || len(before) < 7 {
		t.Fatalf("dry run %+v (stored %d)", reports[0], len(before))
	}
	if list, _ := ListBackups(ctx, e.local, "LAB.TEST", []sign.PublicKey{e.r.Key.Public()}); len(list) != len(before) {
		t.Fatal("dry run deleted something")
	}
	if _, err := e.r.Prune(ctx, false); err != nil {
		t.Fatal(err)
	}
	list, _ := ListBackups(ctx, e.local, "LAB.TEST", []sign.PublicKey{e.r.Key.Public()})
	if len(list) != 3 {
		t.Fatalf("after prune %d", len(list))
	}
	// Two years later with backups failing and a policy of one daily
	// backup: the last good one survives, the rest goes.
	newest := list[0].ID
	pol.Retention = helper.BackupRetention{Daily: 1}
	_ = state.WriteJSON(filepath.Join(e.r.Dir.Path, "policy.json"), pol)
	e.now = e.now.AddDate(2, 0, 0)
	e.fh.fail = true
	_ = e.r.Run(ctx, Options{Scheduled: true})
	if _, err := e.r.Prune(ctx, false); err != nil {
		t.Fatal(err)
	}
	list, _ = ListBackups(ctx, e.local, "LAB.TEST", []sign.PublicKey{e.r.Key.Public()})
	if len(list) != 1 || !list[0].Usable() || list[0].ID != newest {
		t.Fatalf("last good backup not kept: %+v", list)
	}
	st, _ := e.r.Dir.LoadStatus()
	if _, ok := st.LastGood(); !ok {
		t.Fatal("status lost the last good backup")
	}
}

func TestDrillRequestAndReport(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	drillKey, _ := sign.Generate()
	e.r.Cfg.DrillPublicKeys = []string{drillKey.Public().String()}
	_ = e.r.Run(ctx, Options{Scheduled: true})
	// The default policy wants a drill every 7 days: the first run asks.
	objs, _ := e.local.List(ctx, dest.RequestPrefix("LAB.TEST"))
	if len(objs) != 1 {
		t.Fatalf("requests %v", objs)
	}
	b, _ := dest.ReadAll(ctx, e.local, objs[0].Key, 1<<20)
	var q manifest.DrillRequest
	if _, err := sign.Open(b, []sign.PublicKey{e.r.Key.Public()}, &q); err != nil || q.RequestedBy != "schedule" {
		t.Fatalf("request %+v %v", q, err)
	}
	// The drill host answers.
	rep := manifest.DrillReport{Format: manifest.ReportFormat, Realm: "LAB.TEST", Drill: helper.DrillRecord{ID: "20261003T040000Z-drill",
		BackupID: "x", RequestID: q.ID, StartedAt: e.now, FinishedAt: e.now.Add(2 * time.Minute), Passed: false, RTOMS: 120000,
		Checks: []helper.DrillCheck{{Name: "kerberos", OK: false, Detail: "KDC unreachable"}}}}
	env, _ := sign.Seal(drillKey, rep)
	key, _ := dest.DocKey(dest.ReportPrefix("LAB.TEST"), rep.Drill.ID)
	_ = e.remote.PutBytes(ctx, key, env)
	// A forged report (wrong key) is ignored.
	forger, _ := sign.Generate()
	forged := rep
	forged.Drill.ID, forged.Drill.Passed = "20261003T050000Z-drill", true
	fenv, _ := sign.Seal(forger, forged)
	fkey, _ := dest.DocKey(dest.ReportPrefix("LAB.TEST"), forged.Drill.ID)
	_ = e.remote.PutBytes(ctx, fkey, fenv)

	e.now = e.now.Add(time.Hour)
	_ = e.r.Run(ctx, Options{Scheduled: true})
	st, _ := e.r.Dir.LoadStatus()
	if len(st.Drills) != 1 || st.Drills[0].Passed {
		t.Fatalf("drills %+v", st.Drills)
	}
	kinds := map[string]bool{}
	for _, a := range st.Alerts {
		kinds[a.Kind] = true
	}
	if !kinds[helper.AlertDrillFailed] {
		t.Fatalf("alerts %+v", st.Alerts)
	}
	// The answered request was removed from the bucket.
	if objs, _ := e.local.List(ctx, dest.RequestPrefix("LAB.TEST")); len(objs) != 0 {
		t.Fatalf("answered request still there: %v", objs)
	}
}
