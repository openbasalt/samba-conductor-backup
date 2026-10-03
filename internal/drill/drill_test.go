package drill

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor-backup/internal/config"
	"github.com/samba-conductor/conductor-backup/internal/dest"
	"github.com/samba-conductor/conductor-backup/internal/manifest"
	"github.com/samba-conductor/conductor-backup/internal/sign"
)

type fixture struct {
	d       *Drill
	store   dest.Store
	dcKey   sign.PrivateKey
	drillID *age.X25519Identity
	now     time.Time
	spec    SandboxSpec
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	cfg := &config.Config{Realm: "LAB.TEST", Destinations: []config.Destination{{Name: "local", Type: "local", Path: filepath.Join(root, "bucket")}},
		Drill: config.Drill{WorkDir: filepath.Join(root, "work"), ServerName: "DRILL", ProbeUser: "svc-drill-probe", TimeoutMinutes: 5,
			SambaBinary: "/usr/sbin/samba", SambaTool: "/usr/bin/samba-tool"}}
	store, _ := dest.Open(cfg, cfg.Destinations[0])
	dcKey, _ := sign.Generate()
	drillKey, _ := sign.Generate()
	id, _ := age.GenerateX25519Identity()
	f := &fixture{store: store, dcKey: dcKey, drillID: id, now: time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)}
	f.d = &Drill{Cfg: cfg, Store: store, Trusted: []sign.PublicKey{dcKey.Public()}, Key: drillKey, Identities: []age.Identity{id},
		ProbePassword: "pw", Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Now: func() time.Time { return f.now }, Version: "test"}
	f.d.sandbox = func(_ context.Context, _, specPath, pw string, _ io.Writer) (SandboxResult, error) {
		b, _ := os.ReadFile(specPath)
		_ = json.Unmarshal(b, &f.spec)
		if pw != "pw" {
			return SandboxResult{}, errors.New("password not passed")
		}
		if _, err := os.Stat(f.spec.BackupFile); err != nil {
			return SandboxResult{}, err
		}
		return SandboxResult{Checks: []helper.DrillCheck{{Name: "ldap", OK: true}, {Name: "users", OK: true, Detail: "3 users"}},
			RestoreMS: 1000, StartMS: 500, ChecksMS: 700, ReadyMS: 2300}, nil
	}
	return f
}

// putBackup stores an encrypted archive and its signed manifest.
func (f *fixture) putBackup(t *testing.T, id string, to age.Recipient) {
	t.Helper()
	var buf bytes.Buffer
	w, _ := age.Encrypt(&buf, to)
	tw := tar.NewWriter(w)
	meta, _ := json.Marshal(helper.ArchiveMeta{Format: helper.ArchiveFormat, ID: id, Realm: "LAB.TEST", DC: "dc1",
		SambaFile: "samba/samba-backup.tar.bz2", Users: helper.CountRange{Min: 3, Max: 3},
		Samples: []helper.ArchiveSample{{Kind: "user", Name: "Administrator", SID: "S-1-5-21-1-2-3-500"}}})
	for _, m := range []struct {
		n string
		b []byte
	}{{helper.ArchiveMetaName, meta}, {"samba/samba-backup.tar.bz2", []byte("BZh9")}} {
		_ = tw.WriteHeader(&tar.Header{Name: m.n, Mode: 0o600, Size: int64(len(m.b)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(m.b)
	}
	_ = tw.Close()
	_ = w.Close()
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "a")
	_ = os.WriteFile(p, buf.Bytes(), 0o600)
	size, sum, md, _ := dest.FileDigests(p)
	if err := f.store.PutFile(ctx, dest.ArchiveKey("LAB.TEST", id), p, size, sum, md); err != nil {
		t.Fatal(err)
	}
	env, _ := sign.Seal(f.dcKey, manifest.Manifest{Format: manifest.ManifestFormat, ID: id, Realm: "LAB.TEST", DC: "dc1", Size: size, SHA256: sum,
		Object: dest.ArchiveKey("LAB.TEST", id)})
	_ = f.store.PutBytes(ctx, dest.ManifestKey("LAB.TEST", id), env)
}

func (f *fixture) request(t *testing.T, id string, key sign.PrivateKey) {
	env, _ := sign.Seal(key, manifest.DrillRequest{Format: manifest.RequestFormat, ID: id, Realm: "LAB.TEST", RequestedBy: "lab.admin", At: f.now})
	k, _ := dest.DocKey(dest.RequestPrefix("LAB.TEST"), id)
	if err := f.store.PutBytes(context.Background(), k, env); err != nil {
		t.Fatal(err)
	}
}

func TestDrillOnRequest(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	f.putBackup(t, "20261002T023000Z-dc1", f.drillID.Recipient())
	f.putBackup(t, "20261003T023000Z-dc1", f.drillID.Recipient())
	if _, err := f.d.Run(ctx, Options{}); !errors.Is(err, ErrNothingToDo) {
		t.Fatalf("no request: %v", err)
	}
	// A request signed by an unknown key is ignored.
	forger, _ := sign.Generate()
	f.request(t, "forged-1", forger)
	if _, err := f.d.Run(ctx, Options{}); !errors.Is(err, ErrNothingToDo) {
		t.Fatalf("forged request honoured: %v", err)
	}
	f.request(t, "req-1", f.dcKey)
	rep, err := f.d.Run(ctx, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Drill.BackupID != "20261003T023000Z-dc1" || !rep.Drill.Passed || rep.Drill.RequestID != "req-1" || rep.Drill.RTOMS < 2300 {
		t.Fatalf("report %+v", rep.Drill)
	}
	if f.spec.ProbeUser != "svc-drill-probe" || f.spec.Users.Max != 3 || len(f.spec.Samples) != 1 || f.spec.ServerName != "DRILL" {
		t.Fatalf("spec %+v", f.spec)
	}
	// Plaintext removed.
	if entries, _ := os.ReadDir(f.d.Cfg.Drill.WorkDir); len(entries) > 3 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("work dir left: %v", names)
	}
	if _, err := os.Stat(filepath.Join(f.d.Cfg.Drill.WorkDir, rep.Drill.ID)); !os.IsNotExist(err) {
		t.Fatal("drill directory not removed")
	}
	// The signed report is in the bucket.
	objs, _ := f.store.List(ctx, dest.ReportPrefix("LAB.TEST"))
	if len(objs) != 1 {
		t.Fatalf("reports %v", objs)
	}
	b, _ := dest.ReadAll(ctx, f.store, objs[0].Key, 1<<20)
	var got manifest.DrillReport
	if _, err := sign.Open(b, []sign.PublicKey{f.d.Key.Public()}, &got); err != nil || !got.Drill.Passed {
		t.Fatalf("report %v", err)
	}
	// The same request is not handled twice.
	if _, err := f.d.Run(ctx, Options{}); !errors.Is(err, ErrNothingToDo) {
		t.Fatalf("request repeated: %v", err)
	}
}

func TestDrillFailures(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	other, _ := age.GenerateX25519Identity()
	// Encrypted to someone else: the drill identity cannot decrypt it.
	f.putBackup(t, "20261003T023000Z-dc1", other.Recipient())
	rep, err := f.d.Run(ctx, Options{Force: true})
	if err == nil || rep.Drill.Passed || !strings.Contains(rep.Drill.Error, "identity does not match") {
		t.Fatalf("wrong key: %v %+v", err, rep.Drill)
	}
	// A tampered archive (same size) fails the integrity check.
	f.putBackup(t, "20261003T033000Z-dc1", f.drillID.Recipient())
	p := filepath.Join(f.d.Cfg.Destinations[0].Path, "domain", "lab.test", "20261003T033000Z-dc1.tar.age")
	raw, _ := os.ReadFile(p)
	raw[len(raw)-5] ^= 0xff
	_ = os.WriteFile(p, raw, 0o600)
	rep, err = f.d.Run(ctx, Options{Force: true, BackupID: "20261003T033000Z-dc1"})
	if err == nil || !strings.Contains(rep.Drill.Error, "SHA-256") {
		t.Fatalf("tampered: %v %+v", err, rep.Drill)
	}
	// A failing check fails the drill.
	f.putBackup(t, "20261003T043000Z-dc1", f.drillID.Recipient())
	f.d.sandbox = func(context.Context, string, string, string, io.Writer) (SandboxResult, error) {
		return SandboxResult{Checks: []helper.DrillCheck{{Name: "kerberos", OK: false, Detail: "refused"}}}, nil
	}
	rep, err = f.d.Run(ctx, Options{Force: true})
	if err == nil || rep.Drill.Passed || rep.Drill.RTOMS != 0 {
		t.Fatalf("failed check: %v %+v", err, rep.Drill)
	}
}
