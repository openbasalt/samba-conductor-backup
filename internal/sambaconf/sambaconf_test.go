package sambaconf

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

var lab = Expect{NetbiosName: "DRILL", Workgroup: "LAB", Realm: "LAB.TEST", TargetDir: "/var/lib/conductor-backup-drill/d1/restore"}

// restored is what samba-tool's make_smbconf writes after a restore.
const restored = `[globals]
	netbios name = DRILL
	workgroup = LAB
	realm = LAB.TEST
	server role = active directory domain controller
	private dir = /var/lib/conductor-backup-drill/d1/restore/private
	lock dir = /var/lib/conductor-backup-drill/d1/restore
	state directory = /var/lib/conductor-backup-drill/d1/restore/state
	cache directory = /var/lib/conductor-backup-drill/d1/restore/cache
	binddns dir = /var/lib/conductor-backup-drill/d1/restore/bind-dns

[sysvol]
	path = /var/lib/conductor-backup-drill/d1/restore/state/sysvol
	read only = no

[netlogon]
	path = /var/lib/conductor-backup-drill/d1/restore/state/sysvol/lab.test/scripts
	read only = no
`

func refused(t *testing.T, err error) {
	t.Helper()
	var r *RefusedError
	if !errors.As(err, &r) {
		t.Fatalf("want a refusal, got %v", err)
	}
}

func TestSanitizeRestored(t *testing.T) {
	out, rep, err := Sanitize([]byte(restored), lab)
	if err != nil || len(rep.Dropped) != 0 {
		t.Fatalf("make_smbconf output: %v %v", err, rep.Dropped)
	}
	gen, _ := Generate(lab)
	if !bytes.Equal(out, gen) {
		t.Fatalf("not canonical:\n%s", out)
	}
	// The canonical form passes again unchanged.
	if again, _, err := Sanitize(out, lab); err != nil || !bytes.Equal(again, out) {
		t.Fatalf("canonical form: %v", err)
	}
}

// TestSanitizeDropsHostile: every parameter outside the allowlist goes,
// whatever it does; the output is the allowlist only.
func TestSanitizeDropsHostile(t *testing.T) {
	hostile := strings.Replace(restored, "\tbinddns dir", `	dns update command = /bin/sh -c 'id > /tmp/pwned'
	samba kcc command = /bin/sh
	spn update command = /bin/sh
	nsupdate command = /bin/sh
	check password script = /bin/sh
	add user script = /bin/sh
	panic action = /bin/sh
	log file = /etc/cron.d/x
	vfs objects = /tmp/evil.so
	server services = +smb
	idmap_ldb:use rfc2307 = yes
	binddns dir`, 1) + `
[evil]
	path = /
	read only = no
	root preexec = /bin/sh
	writeable = yes

[homes]
	magic script = x
`
	hostile = strings.Replace(hostile, "[netlogon]", "[sysvol]\n\troot preexec = x\n\n[netlogon]\n\tpreexec = /bin/sh", 1)
	// The second [sysvol] above is a duplicate: refused.
	if _, _, err := Sanitize([]byte(hostile), lab); err == nil {
		t.Fatal("duplicate [sysvol] accepted")
	}
	hostile = strings.Replace(hostile, "[sysvol]\n\troot preexec = x\n\n", "", 1)
	out, rep, err := Sanitize([]byte(hostile), lab)
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := Generate(lab)
	if !bytes.Equal(out, gen) {
		t.Fatalf("hostile parameters survived:\n%s", out)
	}
	for _, want := range []string{"global: dns update command", "global: vfs objects", "global: panic action", "[evil]", "[homes]", "netlogon: preexec"} {
		found := false
		for _, d := range rep.Dropped {
			found = found || d == want
		}
		if !found {
			t.Errorf("%q not reported as dropped: %v", want, rep.Dropped)
		}
	}
}

// TestRefusedClasses: constructs that pull configuration from elsewhere
// refuse the file, in any section and any spelling.
func TestRefusedClasses(t *testing.T) {
	for _, extra := range []string{
		"include = /etc/samba/evil.conf",
		"include = registry",
		"In Clude = /x",
		"config backend = registry",
		"CONFIG  BACKEND = registry",
		"config file = /tmp/other.conf",
		"registry shares = yes",
		// A continuation line cannot hide one.
		"inc\\\nlude = /x",
	} {
		for _, where := range []string{"[globals]", "[sysvol]"} {
			conf := strings.Replace(restored, where, where+"\n\t"+extra, 1)
			_, _, err := Sanitize([]byte(conf), lab)
			refused(t, err)
			if _, err := FromBackup([]byte(conf), "LAB.TEST"); err == nil {
				t.Errorf("FromBackup accepted %q in %s", extra, where)
			}
		}
	}
	// Binary content.
	_, _, err := Sanitize([]byte("[global]\n\x00"), lab)
	refused(t, err)
}

// TestRefusedValues: allowlisted parameters must carry the expected value;
// paths are confined to the target directory.
func TestRefusedValues(t *testing.T) {
	for _, c := range []struct{ old, new string }{
		{"\tpath = /var/lib/conductor-backup-drill/d1/restore/state/sysvol\n", "\tpath = /etc\n"},
		{"\tpath = /var/lib/conductor-backup-drill/d1/restore/state/sysvol\n", "\tpath = /var/lib/conductor-backup-drill/d1/restore/state/sysvol/../../../..\n"},
		{"\tpath = /var/lib/conductor-backup-drill/d1/restore/state/sysvol\n", "\tpath = /var/lib/conductor-backup-drill/d1/restore/state/%U\n"},
		{"private dir = /var/lib/conductor-backup-drill/d1/restore/private", "private dir = /etc/conductor-backup/credentials"},
		{"lock dir = /var/lib/conductor-backup-drill/d1/restore\n", "lock dir = /var/lib/conductor-backup-drill/d1/restore\n\tlock directory = /tmp\n"},
		{"netbios name = DRILL", "netbios name = DC1"},
		{"realm = LAB.TEST", "realm = EVIL.TEST"},
		{"server role = active directory domain controller", "server role = standalone server"},
		{"[sysvol]\n\tpath = /var/lib/conductor-backup-drill/d1/restore/state/sysvol\n\tread only = no", "[sysvol]\n\tpath = /var/lib/conductor-backup-drill/d1/restore/state/sysvol\n\tread only = no\n\twriteable = no"},
		{"\tread only = no\n\n[netlogon]", "\tread only = yes\n\n[netlogon]"},
		// Missing parameters and sections.
		{"\tcache directory = /var/lib/conductor-backup-drill/d1/restore/cache\n", ""},
		{"[netlogon]", "[other]"},
	} {
		conf := strings.Replace(restored, c.old, c.new, 1)
		if conf == restored {
			t.Fatalf("case %q does not apply", c.old)
		}
		_, _, err := Sanitize([]byte(conf), lab)
		refused(t, err)
	}
}

func TestFromBackup(t *testing.T) {
	dc := "# Global parameters\n[global]\n\tnetbios name = DC1\n\trealm = lab.test\n\tworkgroup = lab\n\tdns update command = /bin/sh\n"
	wg, err := FromBackup([]byte(dc), "LAB.TEST")
	if err != nil || wg != "LAB" {
		t.Fatalf("workgroup %q %v", wg, err)
	}
	for _, bad := range []string{
		strings.Replace(dc, "lab.test", "other.test", 1),
		strings.Replace(dc, "workgroup = lab", "workgroup = %D", 1),
		strings.Replace(dc, "workgroup = lab", "workgroup = A B", 1),
		strings.Replace(dc, "\tworkgroup = lab\n", "", 1),
	} {
		if _, err := FromBackup([]byte(bad), "LAB.TEST"); err == nil {
			t.Errorf("accepted:\n%s", bad)
		}
	}
}

func TestExpectValidate(t *testing.T) {
	for _, e := range []Expect{
		{NetbiosName: "-X", Workgroup: "LAB", Realm: "LAB.TEST", TargetDir: "/t"},
		{NetbiosName: "DRILL", Workgroup: "LAB", Realm: "LAB", TargetDir: "/t"},
		{NetbiosName: "DRILL", Workgroup: "LAB", Realm: "LAB.TEST", TargetDir: "t"},
		{NetbiosName: "DRILL", Workgroup: "LAB", Realm: "LAB.TEST", TargetDir: "/t/../x"},
		{NetbiosName: "DRILL", Workgroup: "LAB", Realm: "LAB.TEST", TargetDir: "/t x"},
	} {
		if _, err := Generate(e); err == nil {
			t.Errorf("%+v accepted", e)
		}
	}
}

func TestRestoreOp(t *testing.T) {
	op := RestoreOp{DomainBackupRestore: sambatool.DomainBackupRestore{BackupFile: "/w/x/samba.tar.bz2", TargetDir: "/w/restore", NewServerName: "DRILL"},
		ConfigFile: "/w/restore-smb.conf"}
	got, err := sambatool.Preview(&sambatool.Runner{}, op)
	if err != nil || got != "samba-tool domain backup restore --backup-file=/w/x/samba.tar.bz2 --targetdir=/w/restore --newservername=DRILL --configfile=/w/restore-smb.conf" {
		t.Fatalf("%q %v", got, err)
	}
	for _, p := range []string{"", "rel", "/a/../b", "/a b", "/a\n"} {
		op.ConfigFile = p
		if _, err := op.Command(); err == nil {
			t.Errorf("config path %q accepted", p)
		}
	}
}

// ---- backup file scan ----

type member struct {
	name     string
	typ      byte
	body     string
	link     string
	mode     int64
	children []member // a nested sysvol.tar.gz
}

func tarBytes(t *testing.T, ms []member, gz bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	var w *gzip.Writer
	tw := tar.NewWriter(&buf)
	if gz {
		w = gzip.NewWriter(&buf)
		tw = tar.NewWriter(w)
	}
	for _, m := range ms {
		body := []byte(m.body)
		if m.children != nil {
			body = tarBytes(t, m.children, true)
		}
		mode := m.mode
		if mode == 0 {
			mode = 0o644
		}
		h := &tar.Header{Name: m.name, Typeflag: m.typ, Mode: mode, Linkname: m.link}
		if m.typ == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if m.typ == tar.TypeReg {
			_, _ = tw.Write(body)
		}
	}
	_ = tw.Close()
	if w != nil {
		_ = w.Close()
	}
	return buf.Bytes()
}

const backupConf = "[global]\n\tnetbios name = DC1\n\trealm = LAB.TEST\n\tworkgroup = LAB\n"

func goodMembers() []member {
	return []member{
		{name: "./", typ: tar.TypeDir},
		{name: "./etc", typ: tar.TypeDir},
		{name: "./etc/smb.conf", typ: tar.TypeReg, body: backupConf},
		{name: "./private", typ: tar.TypeDir},
		{name: "./private/sam.ldb", typ: tar.TypeReg, body: "ldb"},
		{name: "./sysvol.tar.gz", typ: tar.TypeReg, children: []member{
			{name: "lab.test", typ: tar.TypeDir}, {name: "lab.test/Policies", typ: tar.TypeDir},
			{name: "lab.test/Policies.NTACL", typ: tar.TypeReg, body: "O:BA"}}},
		{name: "./backup.txt", typ: tar.TypeReg, body: "backup"},
	}
}

func writeBackup(t *testing.T, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "samba-backup.tar")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestScanBackup(t *testing.T) {
	for _, gz := range []bool{false, true} {
		conf, err := ScanBackup(writeBackup(t, tarBytes(t, goodMembers(), gz)))
		if err != nil || string(conf) != backupConf {
			t.Fatalf("gzip=%v: %q %v", gz, conf, err)
		}
	}
	// bzip2, as samba-tool writes it (when the bzip2 tool is there).
	if bz, err := exec.LookPath("bzip2"); err == nil {
		p := writeBackup(t, tarBytes(t, goodMembers(), false))
		if out, err := exec.Command(bz, "-k", p).CombinedOutput(); err != nil {
			t.Fatalf("bzip2: %v %s", err, out)
		}
		if conf, err := ScanBackup(p + ".bz2"); err != nil || string(conf) != backupConf {
			t.Fatalf("bzip2: %v", err)
		}
	}
}

func TestScanBackupRefuses(t *testing.T) {
	cases := map[string]member{
		"symlink":          {name: "./private/tls", typ: tar.TypeSymlink, link: "/etc"},
		"relative symlink": {name: "./private/x", typ: tar.TypeSymlink, link: "../../../etc/cron.d"},
		"hard link":        {name: "./private/y", typ: tar.TypeLink, link: "etc/smb.conf"},
		"char device":      {name: "./dev-null", typ: tar.TypeChar},
		"block device":     {name: "./sda", typ: tar.TypeBlock},
		"fifo":             {name: "./fifo", typ: tar.TypeFifo},
		"absolute":         {name: "/etc/cron.d/x", typ: tar.TypeReg, body: "x"},
		"dot dot":          {name: "./private/../../x", typ: tar.TypeReg, body: "x"},
		"setuid":           {name: "./suid", typ: tar.TypeReg, body: "x", mode: 0o4755},
		"duplicate":        {name: "etc/smb.conf", typ: tar.TypeReg, body: "[global]\ninclude = /x\n"},
		"nested symlink":   {name: "./sysvol2", typ: tar.TypeReg}, // replaced below
	}
	for name, m := range cases {
		ms := goodMembers()
		if name == "nested symlink" {
			ms[5].children = append(ms[5].children, member{name: "lab.test/scripts", typ: tar.TypeSymlink, link: "/root"})
		} else {
			ms = append(ms, m)
		}
		if _, err := ScanBackup(writeBackup(t, tarBytes(t, ms, false))); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// No smb.conf.
	ms := goodMembers()
	ms = append(ms[:2], ms[3:]...)
	if _, err := ScanBackup(writeBackup(t, tarBytes(t, ms, false))); !errors.Is(err, ErrNoConf) {
		t.Errorf("missing smb.conf: %v", err)
	}
	// Not a tar at all.
	if _, err := ScanBackup(writeBackup(t, []byte("BZh9"))); err == nil {
		t.Error("garbage accepted")
	}
}

func TestPrepareAndFinalize(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "restore")
	backup := writeBackup(t, tarBytes(t, goodMembers(), true))
	cfg := filepath.Join(dir, "restore-smb.conf")
	e, err := Prepare(backup, cfg, "drill", "lab.test", target)
	if err != nil {
		t.Fatal(err)
	}
	if e.Workgroup != "LAB" || e.NetbiosName != "DRILL" || e.Realm != "LAB.TEST" {
		t.Fatalf("expect %+v", e)
	}
	gen, _ := os.ReadFile(cfg)
	if !strings.Contains(string(gen), "private dir = "+target+"/private") || strings.Contains(string(gen), "DC1") {
		t.Fatalf("generated:\n%s", gen)
	}
	// A second Prepare does not overwrite (O_EXCL).
	if _, err := Prepare(backup, cfg, "drill", "lab.test", target); err == nil {
		t.Fatal("configuration overwritten")
	}
	// Finalize: samba-tool's output becomes the canonical file.
	if err := os.MkdirAll(filepath.Join(target, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	conf := filepath.Join(target, "etc", "smb.conf")
	_ = os.WriteFile(conf, []byte(strings.ReplaceAll(restored, lab.TargetDir, target)+"[evil]\n\tpath = /\n"), 0o644)
	rep, err := Finalize(e)
	if err != nil || len(rep.Dropped) != 1 {
		t.Fatalf("finalize %v %v", rep, err)
	}
	if b, _ := os.ReadFile(conf); !bytes.Equal(b, gen) {
		t.Fatalf("finalized:\n%s", b)
	}
	// A symbolic link in place of smb.conf is refused, not followed.
	_ = os.Remove(conf)
	_ = os.Symlink(cfg, conf)
	if _, err := Finalize(e); err == nil {
		t.Fatal("symlinked smb.conf accepted")
	}
	// A hostile backup is refused before anything is written.
	bad := goodMembers()
	bad[2].body = backupConf + "\tinclude = /etc/shadow\n"
	if _, err := Prepare(writeBackup(t, tarBytes(t, bad, false)), filepath.Join(dir, "c2"), "DRILL", "LAB.TEST", target); err == nil {
		t.Fatal("include accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "c2")); !os.IsNotExist(err) {
		t.Fatal("configuration written for a refused backup")
	}
}
