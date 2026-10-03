// Package restore is `conductor-backup restore`: a real Samba AD restore
// (original SIDs and GUIDs; `samba-tool domain backup restore`) from an
// encrypted backup, run by an operator as root on the host that becomes
// the domain controller, with the age identity the operator kept offline.
package restore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"
	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/ad/sambatool"
	"github.com/samba-conductor/conductor-backup/internal/archive"
	"github.com/samba-conductor/conductor-backup/internal/dest"
	"github.com/samba-conductor/conductor-backup/internal/runner"
	"github.com/samba-conductor/conductor-backup/internal/sign"
)

// Options of a restore.
type Options struct {
	Realm    string
	BackupID string // "" or "latest": the newest usable backup
	// Identities decrypt the archive (from --identity).
	Identities []age.Identity
	// Target directory (created; its "samba" subdirectory must not exist
	// or be empty).
	Target string
	// NewServerName: NetBIOS name of the restored DC. Required, and it must
	// not be the name of a DC in the backup: samba-tool adds the new DC's
	// account first and then removes every old DC from the restored
	// database (so the old names are gone afterwards).
	NewServerName string
	HostIP        string
	// WithConductorState installs conductor's database at ConductorDB.
	WithConductorState bool
	ConductorDB        string
	SambaTool          string
}

// Result describes what was restored.
type Result struct {
	Meta       helper.ArchiveMeta
	BackupID   string
	ServerName string
	SambaDir   string
	FilesDir   string
	TLSPlaced  []string
	Conductor  string // where conductor's database is
	// ConductorInstalled: the database was put in place for conductor.
	ConductorInstalled bool
	Duration           time.Duration
}

// Run downloads, verifies, decrypts and restores a backup.
func Run(ctx context.Context, s dest.Store, trusted []sign.PublicKey, o Options, log io.Writer) (*Result, error) {
	start := time.Now()
	if os.Geteuid() != 0 {
		return nil, errors.New("restore must run as root (samba-tool domain backup restore needs it)")
	}
	if !filepath.IsAbs(o.Target) || filepath.Clean(o.Target) != o.Target {
		return nil, errors.New("--target must be a clean absolute path")
	}
	sambaDir := filepath.Join(o.Target, "samba")
	if entries, err := os.ReadDir(sambaDir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s is not empty", sambaDir)
	}
	id := o.BackupID
	if id == "latest" {
		id = ""
	}
	list, err := runner.ListBackups(ctx, s, o.Realm, trusted)
	if err != nil {
		return nil, err
	}
	b, err := runner.Latest(list, id)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(log, "backup %s from %s (%d bytes, sha256 %s)\n", b.ID, s.Name(), b.Manifest.Size, b.Manifest.SHA256)
	if err := os.MkdirAll(o.Target, 0o700); err != nil {
		return nil, err
	}
	work, err := os.MkdirTemp(o.Target, ".restore-")
	if err != nil {
		return nil, err
	}
	defer func() { _ = archive.ShredTree(work) }()

	cipher := filepath.Join(work, "archive.tar.age")
	rc, _, err := s.Get(ctx, dest.ArchiveKey(o.Realm, b.ID))
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(cipher, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	_, err = io.Copy(f, rc)
	_ = rc.Close()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	size, sum, _, err := dest.FileDigests(cipher)
	if err != nil {
		return nil, err
	}
	if size != b.Manifest.Size || sum != b.Manifest.SHA256 {
		return nil, errors.New("the downloaded archive does not match its signed manifest (SHA-256): refusing to restore it")
	}
	fmt.Fprintln(log, "integrity: SHA-256 matches the signed manifest")

	in, err := os.Open(cipher)
	if err != nil {
		return nil, err
	}
	plain := filepath.Join(work, "x")
	meta, err := archive.Extract(in, o.Identities, plain)
	_ = in.Close()
	_ = os.Remove(cipher)
	if err != nil {
		return nil, err
	}
	if meta.ID != b.ID || !strings.EqualFold(meta.Realm, o.Realm) {
		return nil, errors.New("the archive's metadata does not match its manifest")
	}
	fmt.Fprintf(log, "decrypted: %s, taken on %s at %s, %d-%d users\n", meta.Realm, meta.DC, meta.CreatedAt.Format(time.RFC3339), meta.Users.Min, meta.Users.Max)

	name := strings.ToUpper(o.NewServerName)
	if name == "" || strings.EqualFold(name, meta.DC) {
		return nil, fmt.Errorf("--newservername is required and must differ from %s: samba-tool gives the restored DC a new name "+
			"and removes the old DCs (%s included) from the restored database", strings.ToUpper(meta.DC), strings.ToUpper(meta.DC))
	}
	tool := o.SambaTool
	if tool == "" {
		tool = "/usr/bin/samba-tool"
	}
	r := &sambatool.Runner{Binary: tool, Credentials: sambatool.LocalSystem{}, Timeout: 2 * time.Hour}
	op := sambatool.DomainBackupRestore{BackupFile: filepath.Join(plain, filepath.FromSlash(meta.SambaFile)), TargetDir: sambaDir,
		NewServerName: name, HostIP: o.HostIP}
	cmdline, err := sambatool.Preview(r, op)
	if err != nil {
		return nil, err
	}
	fmt.Fprintln(log, "running:", cmdline)
	if _, err := sambatool.Run(ctx, r, op); err != nil {
		return nil, err
	}
	_ = archive.Shred(op.BackupFile)
	res := &Result{Meta: meta, BackupID: b.ID, ServerName: name, SambaDir: sambaDir, FilesDir: filepath.Join(o.Target, "files")}

	// Host files (configs, TLS) next to the restored domain.
	if src := filepath.Join(plain, "files"); exists(src) {
		_ = os.RemoveAll(res.FilesDir)
		if err := os.Rename(src, res.FilesDir); err != nil {
			return nil, err
		}
	}
	// TLS files named relative to the private directory go where the
	// restored smb.conf expects them.
	for _, t := range meta.TLS {
		if filepath.IsAbs(t.Value) || !helper.SafeMember(t.Value) || !strings.HasPrefix(t.Member, helper.ArchiveFilesDir) {
			continue
		}
		srcFile := filepath.Join(res.FilesDir, filepath.FromSlash(strings.TrimPrefix(t.Member, helper.ArchiveFilesDir)))
		dst := filepath.Join(sambaDir, "private", filepath.FromSlash(t.Value))
		if err := copyFile(srcFile, dst, tlsMode(t.Param)); err != nil {
			fmt.Fprintf(log, "warning: TLS %s not placed: %v\n", t.Param, err)
			continue
		}
		res.TLSPlaced = append(res.TLSPlaced, dst)
	}
	if meta.ConductorDB {
		dbSrc := filepath.Join(plain, filepath.FromSlash(helper.ArchiveConductorDB))
		dbDst := filepath.Join(o.Target, "conductor", "conductor.db")
		if err := copyFile(dbSrc, dbDst, 0o600); err != nil {
			return nil, err
		}
		res.Conductor = dbDst
		if o.WithConductorState {
			installed, err := installConductorDB(dbSrc, o.ConductorDB)
			if err != nil {
				return nil, fmt.Errorf("conductor state: %w", err)
			}
			res.Conductor, res.ConductorInstalled = installed, true
		}
	}
	res.Duration = time.Since(start)
	return res, nil
}

func tlsMode(param string) os.FileMode {
	if param == "keyfile" {
		return 0o600
	}
	return 0o644
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

// installConductorDB puts the database in place for the conductor user,
// keeping any database already there.
func installConductorDB(src, dst string) (string, error) {
	if dst == "" {
		dst = "/var/lib/conductor/conductor.db"
	}
	u, err := user.Lookup("conductor")
	if err != nil {
		return "", errors.New("the conductor user does not exist: install conductor first (docs/install.md), then rerun with --with-conductor-state")
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return "", err
	}
	if exists(dst) {
		keep := dst + ".pre-restore-" + time.Now().UTC().Format("20060102T150405Z")
		if err := os.Rename(dst, keep); err != nil {
			return "", err
		}
		for _, sfx := range []string{"-wal", "-shm"} {
			if exists(dst + sfx) {
				_ = os.Rename(dst+sfx, keep+sfx)
			}
		}
	}
	if err := copyFile(src, dst, 0o600); err != nil {
		return "", err
	}
	if err := os.Chown(dst, uid, gid); err != nil {
		return "", err
	}
	_ = os.Chown(filepath.Dir(dst), uid, gid)
	return dst, nil
}

// NextSteps renders what the operator does after a restore.
func NextSteps(r *Result) string {
	var b strings.Builder
	domain := strings.ToLower(r.Meta.Realm)
	fmt.Fprintf(&b, "Restored backup %s (domain %s, taken on %s at %s) into %s as DC %s, in %s.\n",
		r.BackupID, r.Meta.Realm, r.Meta.DC, r.Meta.CreatedAt.Format(time.RFC3339), r.SambaDir, r.ServerName, r.Duration.Round(time.Second))
	b.WriteString("SIDs and GUIDs are those of the backup. Every FSMO role is now held by this DC and the old DCs were removed\n")
	b.WriteString("from the restored database; the krbtgt keys were renewed (tickets of the old domain are invalid).\n")
	fmt.Fprintf(&b, "The host must be named %s.%s (this DC's new name).\n\n", strings.ToLower(r.ServerName), domain)
	b.WriteString("Next steps (full-forest recovery, conductor/docs/restore.md):\n")
	fmt.Fprintf(&b, "  1. Make sure no old DC of %s is running on the network.\n", r.Meta.Realm)
	fmt.Fprintf(&b, "  2. Use the restored configuration:\n       systemctl stop samba-ad-dc\n       mv /etc/samba/smb.conf /etc/samba/smb.conf.pre-restore\n       ln -s %s/etc/smb.conf /etc/samba/smb.conf\n       cp %s/private/krb5.conf /etc/krb5.conf\n", r.SambaDir, r.SambaDir)
	if len(r.TLSPlaced) > 0 {
		fmt.Fprintf(&b, "  3. TLS: the old DC's certificate files were put back (%s); issue one for %s.%s from your CA and replace them\n",
			strings.Join(r.TLSPlaced, ", "), strings.ToLower(r.ServerName), domain)
		b.WriteString("     (LDAPS clients verify the host name).\n")
	} else {
		fmt.Fprintf(&b, "  3. TLS: install the DC certificate where smb.conf names it (copies of the original files are under %s), or let Samba generate one.\n", r.FilesDir)
	}
	b.WriteString("  4. Point the host's resolver at itself (/etc/resolv.conf: nameserver 127.0.0.1) and start Samba:\n       systemctl unmask samba-ad-dc && systemctl enable --now samba-ad-dc\n")
	fmt.Fprintf(&b, "  5. Check: samba-tool dbcheck --cross-ncs; samba-tool fsmo show; host -t SRV _ldap._tcp.%s 127.0.0.1\n", domain)
	b.WriteString("     (samba_dnsupdate registers this DC's records at start; `samba_dnsupdate --verbose` to see it).\n")
	b.WriteString("  6. Time: chrony serving signed time through Samba's ntp_signd socket, as on any DC.\n")
	switch {
	case r.ConductorInstalled:
		fmt.Fprintf(&b, "  7. conductor: its database is in place (%s). Restore /etc/conductor/conductor.toml from %s/etc/conductor/ and change\n", r.Conductor, r.FilesDir)
		fmt.Fprintf(&b, "     its [domain] preferred/dcs to %s.%s, put the TOTP key (/etc/conductor/credentials/totp-key) back from where you keep it,\n", strings.ToLower(r.ServerName), domain)
		b.WriteString("     then: systemctl restart conductor-helper conductor; conductor audit verify\n")
	case r.Conductor != "":
		fmt.Fprintf(&b, "  7. conductor: its database is at %s (install conductor, then copy it to /var/lib/conductor/conductor.db owned by\n", r.Conductor)
		fmt.Fprintf(&b, "     conductor, and point [domain] preferred/dcs at %s.%s). Without the TOTP key, users enroll 2FA again.\n", strings.ToLower(r.ServerName), domain)
	}
	fmt.Fprintf(&b, "  8. Rebuild every other DC with a fresh host and `samba-tool domain join %s DC` (never restore a second copy);\n", domain)
	b.WriteString("     the old DC names are free again. Update whatever names a DC explicitly (clients normally find DCs through DNS).\n")
	return b.String()
}
