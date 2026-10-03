// Command conductor-backup takes encrypted Samba AD backups through
// conductor-helper, stores them in local directories and S3-compatible
// buckets, restores them, and runs restore drills. See README.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"filippo.io/age"
	"github.com/openbasalt/samba-conductor-ad/helper"
	"github.com/openbasalt/samba-conductor-backup/internal/alert"
	"github.com/openbasalt/samba-conductor-backup/internal/archive"
	"github.com/openbasalt/samba-conductor-backup/internal/config"
	"github.com/openbasalt/samba-conductor-backup/internal/dest"
	"github.com/openbasalt/samba-conductor-backup/internal/drill"
	"github.com/openbasalt/samba-conductor-backup/internal/restore"
	"github.com/openbasalt/samba-conductor-backup/internal/runner"
	"github.com/openbasalt/samba-conductor-backup/internal/sign"
	"github.com/openbasalt/samba-conductor-backup/internal/state"
)

var version = "dev"

const usage = `conductor-backup: encrypted Samba AD backups, restore and restore drills

On a domain controller (user conductor-backup; conductor-helper does the
privileged part):
  run [--scheduled|--now]     back up when due (timer) or now, upload, verify,
                              prune, exchange drill requests/reports, alert
                              (run by conductor-backup.service, which holds
                              the credentials)
  request backup|drill [--wait]
                              ask the service for a backup or a drill now
                              (root or conductor-backup; starts through
                              conductor-backup.path)
  check                       evaluate and send alerts only (exit 1 if any)
  status [--json]             what the Backups page shows
  list [--destination N]      backups in a destination (signatures verified)
  verify ID|latest            download and check SHA-256 (no decryption)
  prune [--dry-run]           apply the retention policy

Anywhere you can read the bucket (as root, with the offline key):
  restore ID|latest --identity FILE --target DIR --newservername NAME
          [--with-conductor-state] [--host-ip IP] [--destination N]

On a drill host (root; never on a DC):
  drill [--now] [--backup ID]  run a requested (or forced) restore drill

Keys:
  keygen signing --out FILE   signing key (prints the public key)
  keygen age --out FILE       age identity (prints the recipient)
  pubkey FILE                 public key of a signing key

Global: --config FILE (default /etc/conductor-backup/conductor-backup.toml)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "drill-sandbox" {
		// Internal: the restore drill's sandbox (see internal/drill).
		if len(args) != 1 {
			os.Exit(2)
		}
		os.Exit(drill.RunSandbox(args[0]))
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var err error
	code := 0
	switch cmd {
	case "run":
		err = cmdRun(ctx, log, args)
	case "check":
		code, err = cmdCheck(ctx, log, args)
	case "request":
		err = cmdRequest(ctx, args)
	case "status":
		err = cmdStatus(args)
	case "list":
		err = cmdList(ctx, args)
	case "verify":
		err = cmdVerify(ctx, args)
	case "prune":
		err = cmdPrune(ctx, log, args)
	case "restore":
		err = cmdRestore(ctx, args)
	case "drill":
		err = cmdDrill(ctx, log, args)
	case "keygen":
		err = cmdKeygen(args)
	case "pubkey":
		err = cmdPubkey(args)
	case "version", "--version":
		fmt.Println("conductor-backup", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		if errors.Is(err, state.ErrLocked) {
			fmt.Fprintln(os.Stderr, "conductor-backup:", err)
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "conductor-backup:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func flags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	return fs, fs.String("config", config.DefaultPath, "configuration file")
}

// parse accepts flags before and after positional arguments.
func parse(fs *flag.FlagSet, args []string) []string {
	var pos []string
	for {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) == 0 {
			return pos
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func stores(cfg *config.Config, only string) ([]dest.Store, error) {
	var out []dest.Store
	for _, d := range cfg.Destinations {
		if only != "" && d.Name != only {
			continue
		}
		s, err := dest.Open(cfg, d)
		if err != nil {
			return nil, fmt.Errorf("destination %s: %w", d.Name, err)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("no destination configured (or --destination unknown)")
	}
	return out, nil
}

func newRunner(cfg *config.Config, log *slog.Logger) (*runner.Runner, error) {
	ss, err := stores(cfg, "")
	if err != nil {
		return nil, err
	}
	key, err := cfg.LoadSigningKey(cfg.SigningKey)
	if err != nil {
		return nil, err
	}
	return &runner.Runner{Cfg: cfg, Dir: state.Dir{Path: cfg.StateDir}, Helper: runner.SocketHelper{Socket: cfg.HelperSocket},
		Stores: ss, Key: key, Alerts: alert.New(cfg), Log: log, Version: version}, nil
}

func cmdRun(ctx context.Context, log *slog.Logger, args []string) error {
	fs, path := flags("run")
	scheduled := fs.Bool("scheduled", false, "back up only when the schedule says so (timer)")
	now := fs.Bool("now", false, "back up now")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	r, err := newRunner(cfg, log)
	if err != nil {
		return err
	}
	return r.Run(ctx, runner.Options{Scheduled: *scheduled || !*now, Force: *now})
}

func cmdRequest(ctx context.Context, args []string) error {
	fs, path := flags("request")
	wait := fs.Bool("wait", false, "wait until the service processed it, then print the status")
	pos := parse(fs, args)
	if len(pos) != 1 || (pos[0] != helper.TriggerBackup && pos[0] != helper.TriggerDrill) {
		return errors.New("usage: request backup|drill [--wait]")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	who := os.Getenv("SUDO_USER")
	if who == "" {
		who = "root"
	}
	now := time.Now().UTC()
	r := helper.BackupRequest{ID: pos[0] + "-" + now.Format("20060102T150405Z") + "-cli", Kind: pos[0], RequestedBy: who + " (shell)",
		SID: "S-1-5-18", At: now}
	dir := state.Dir{Path: cfg.StateDir}
	if err := dir.AddRequest(r); err != nil {
		return err
	}
	fmt.Println("requested", r.ID)
	if !*wait {
		return nil
	}
	for {
		reqs, err := dir.PendingRequests()
		if err != nil {
			return err
		}
		pending := false
		for _, q := range reqs {
			pending = pending || q.ID == r.ID
		}
		if !pending {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	// The request file goes when the run takes it; wait for the run to end.
	for {
		unlock, err := dir.Lock()
		if err == nil {
			unlock()
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return cmdStatus([]string{"--config", *path})
}

func cmdCheck(ctx context.Context, log *slog.Logger, args []string) (int, error) {
	fs, path := flags("check")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return 0, err
	}
	r, err := newRunner(cfg, log)
	if err != nil {
		return 0, err
	}
	alerts, err := r.Check(ctx)
	if err != nil {
		return 0, err
	}
	for _, a := range alerts {
		fmt.Printf("ALERT %s since %s: %s\n", a.Kind, a.Since.Format(time.RFC3339), a.Detail)
	}
	if len(alerts) > 0 {
		return 1, nil
	}
	fmt.Println("no alert")
	return 0, nil
}

func cmdStatus(args []string) error {
	fs, path := flags("status")
	asJSON := fs.Bool("json", false, "print state.json")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	st, err := state.Dir{Path: cfg.StateDir}.LoadStatus()
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	fmt.Printf("realm %s, dc %s, last run %s, next due %s\n", st.Realm, st.DC, ts(st.LastRunAt), ts(st.NextDueAt))
	p := st.Policy
	fmt.Printf("policy: %s UTC every %dh; keep %d daily, %d weekly, %d monthly; stale after %dh; drill every %d days\n",
		p.Schedule.Time, p.Schedule.EveryHours, p.Retention.Daily, p.Retention.Weekly, p.Retention.Monthly, p.MaxAgeHours, p.DrillIntervalDays)
	if last, ok := st.LastGood(); ok {
		fmt.Printf("RPO: last good backup %s, %s ago\n", last.ID, time.Since(last.CreatedAt).Round(time.Minute))
	} else {
		fmt.Println("RPO: no good backup")
	}
	if d, ok := st.LastPassedDrill(); ok {
		fmt.Printf("RTO: last passing drill %s measured %s\n", d.ID, (time.Duration(d.RTOMS) * time.Millisecond).Round(time.Second))
	}
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "BACKUP\tSTATUS\tTRIGGER\tSIZE\tUSERS\tDESTINATIONS")
	for _, b := range st.Backups {
		var ds []string
		for _, u := range b.Uploads {
			ds = append(ds, u.Destination+":"+u.Status)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\n", b.ID, b.Status, b.Trigger, b.Size, b.Users, strings.Join(ds, " "))
	}
	_ = tw.Flush()
	for _, d := range st.Drills {
		res := "FAILED"
		if d.Passed {
			res = "passed"
		}
		fmt.Printf("drill %s of %s: %s, RTO %s\n", d.ID, d.BackupID, res, (time.Duration(d.RTOMS) * time.Millisecond).Round(time.Second))
	}
	for _, a := range st.Alerts {
		fmt.Printf("ALERT %s: %s\n", a.Kind, a.Detail)
	}
	return nil
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

func cmdList(ctx context.Context, args []string) error {
	fs, path := flags("list")
	only := fs.String("destination", "", "only this destination")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ss, err := stores(cfg, *only)
	if err != nil {
		return err
	}
	trusted := runner.TrustedBackupKeys(cfg)
	tw := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DESTINATION\tBACKUP\tSIZE\tUSABLE\tNOTE")
	for _, s := range ss {
		list, err := runner.ListBackups(ctx, s, cfg.Realm, trusted)
		if err != nil {
			fmt.Fprintf(tw, "%s\t-\t-\tno\t%v\n", s.Name(), err)
			continue
		}
		for _, l := range list {
			fmt.Fprintf(tw, "%s\t%s\t%d\t%v\t%s\n", s.Name(), l.ID, l.Size, l.Usable(), l.ManifestErr)
		}
	}
	return tw.Flush()
}

func cmdVerify(ctx context.Context, args []string) error {
	fs, path := flags("verify")
	only := fs.String("destination", "", "only this destination")
	pos := parse(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: verify ID|latest")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ss, err := stores(cfg, *only)
	if err != nil {
		return err
	}
	id := pos[0]
	if id == "latest" {
		id = ""
	}
	failed := false
	for _, s := range ss {
		l, err := runner.Verify(ctx, s, cfg.Realm, id, runner.TrustedBackupKeys(cfg))
		if err != nil {
			failed = true
			fmt.Printf("%s: %s: FAILED: %v\n", s.Name(), firstNonEmpty(l.ID, pos[0]), err)
			continue
		}
		fmt.Printf("%s: %s: ok (%d bytes, sha256 %s, signed manifest)\n", s.Name(), l.ID, l.Size, l.Manifest.SHA256)
	}
	if failed {
		return errors.New("verification failed")
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func cmdPrune(ctx context.Context, log *slog.Logger, args []string) error {
	fs, path := flags("prune")
	dry := fs.Bool("dry-run", false, "only show what would be deleted")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	r, err := newRunner(cfg, log)
	if err != nil {
		return err
	}
	reports, err := r.Prune(ctx, *dry)
	for _, rep := range reports {
		verb := "deleted"
		if *dry {
			verb = "would delete"
		}
		fmt.Printf("%s: keep %d (%s); %s %d %v; incomplete %v; unverified (kept) %v; errors %v\n", rep.Destination, len(rep.Kept),
			strings.Join(rep.Kept, " "), verb, len(rep.Deleted), rep.Deleted, rep.Incomplete, rep.Unverified, rep.Errors)
	}
	return err
}

func cmdRestore(ctx context.Context, args []string) error {
	fs, path := flags("restore")
	identity := fs.String("identity", "", "age identity file (the operator's offline key)")
	target := fs.String("target", "", "target directory")
	withState := fs.Bool("with-conductor-state", false, "install conductor's database (/var/lib/conductor/conductor.db)")
	name := fs.String("newservername", "", "NetBIOS name of the restored DC (required; not the name of an old DC)")
	hostIP := fs.String("host-ip", "", "IPv4 address of the restored DC (optional)")
	only := fs.String("destination", "", "destination to restore from (default: the first)")
	pos := parse(fs, args)
	if len(pos) != 1 || *identity == "" || *target == "" || *name == "" {
		return errors.New("usage: restore ID|latest --identity FILE --target DIR --newservername NAME")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ss, err := stores(cfg, *only)
	if err != nil {
		return err
	}
	ids, err := archive.LoadIdentities(*identity)
	if err != nil {
		return err
	}
	res, err := restore.Run(ctx, ss[0], runner.TrustedBackupKeys(cfg), restore.Options{Realm: cfg.Realm, BackupID: pos[0], Identities: ids,
		Target: *target, NewServerName: *name, HostIP: *hostIP, WithConductorState: *withState}, os.Stdout)
	if err != nil {
		return err
	}
	fmt.Print("\n" + restore.NextSteps(res))
	return nil
}

func cmdDrill(ctx context.Context, log *slog.Logger, args []string) error {
	fs, path := flags("drill")
	now := fs.Bool("now", false, "drill the newest backup now (without a request)")
	backup := fs.String("backup", "", "with --now: this backup")
	parse(fs, args)
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("drill must run as root (namespaces and samba-tool restore)")
	}
	name := cfg.Drill.Destination
	ss, err := stores(cfg, name)
	if err != nil {
		return err
	}
	key, err := cfg.LoadSigningKey(cfg.Drill.SigningKey)
	if err != nil {
		return err
	}
	idPath, err := cfg.Credential(cfg.Drill.Identity)
	if err != nil {
		return err
	}
	ids, err := archive.LoadIdentities(idPath)
	if err != nil {
		return err
	}
	pw, err := cfg.ReadCredential(cfg.Drill.ProbePassword)
	if err != nil {
		return err
	}
	trusted, err := config.PublicKeys(cfg.BackupPublicKeys)
	if err != nil {
		return err
	}
	if len(trusted) == 0 {
		return errors.New("backup_public_keys must list the DC's public key (verifies manifests and requests)")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	d := &drill.Drill{Cfg: cfg, Store: ss[0], Trusted: trusted, Key: key, Identities: ids, ProbePassword: strings.TrimRight(string(pw), "\r\n"),
		Alerts: alert.New(cfg), Log: log, Version: version, Exe: exe}
	rep, err := d.Run(ctx, drill.Options{Force: *now, BackupID: *backup})
	if errors.Is(err, drill.ErrNothingToDo) {
		log.Info("no drill requested")
		return nil
	}
	if rep != nil {
		res := "FAILED"
		if rep.Drill.Passed {
			res = "passed"
		}
		fmt.Printf("drill %s of %s: %s, RTO %s\n", rep.Drill.ID, rep.Drill.BackupID, res, (time.Duration(rep.Drill.RTOMS) * time.Millisecond).Round(time.Second))
		for _, c := range rep.Drill.Checks {
			mark := "ok  "
			if !c.OK {
				mark = "FAIL"
			}
			fmt.Printf("  %s %s %s\n", mark, c.Name, c.Detail)
		}
		fmt.Printf("  phases (ms): %v\n", rep.Phases)
	}
	return err
}

// writeNew creates a 0600 file that must not exist yet.
func writeNew(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(f, content); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to create (0600, must not exist)")
	pos := parse(fs, args)
	if len(pos) != 1 || *out == "" {
		return errors.New("usage: keygen signing|age --out FILE")
	}
	switch pos[0] {
	case "signing":
		k, err := sign.Generate()
		if err != nil {
			return err
		}
		if err := writeNew(*out, k.String()+"\n"); err != nil {
			return err
		}
		fmt.Println(k.Public().String())
	case "age":
		id, err := age.GenerateX25519Identity()
		if err != nil {
			return err
		}
		content := fmt.Sprintf("# created: %s\n# public key: %s\n%s\n", time.Now().UTC().Format(time.RFC3339), id.Recipient(), id)
		if err := writeNew(*out, content); err != nil {
			return err
		}
		fmt.Println(id.Recipient().String())
		fmt.Fprintln(os.Stderr, "fingerprint:", helper.RecipientFingerprint(id.Recipient().String()))
	default:
		return errors.New("usage: keygen signing|age --out FILE")
	}
	return nil
}

func cmdPubkey(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: pubkey FILE")
	}
	k, err := sign.LoadPrivate(args[0])
	if err != nil {
		return err
	}
	fmt.Println(k.Public().String())
	return nil
}
