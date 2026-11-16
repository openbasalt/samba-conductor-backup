package sambaconf

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

// TestScanBackupSysvolNTACLs: a sysvol archive with `.NTACL` members
// carries the NT ACLs; one without (an online backup by the
// least-privilege account) does not, and Prepare passes that on.
func TestScanBackupSysvolNTACLs(t *testing.T) {
	info, err := ScanBackupInfo(writeBackup(t, tarBytes(t, goodMembers(), true)))
	if err != nil || !info.SysvolNTACLs {
		t.Fatalf("with NT ACLs: %+v %v", info, err)
	}
	ms := goodMembers()
	for i := range ms {
		if ms[i].children != nil {
			ms[i].children = []member{{name: "lab.test", typ: tar.TypeDir}, {name: "lab.test/Policies", typ: tar.TypeDir},
				{name: "lab.test/scripts/logon.cmd", typ: tar.TypeReg, body: "echo"}}
		}
	}
	p := writeBackup(t, tarBytes(t, ms, true))
	if info, err = ScanBackupInfo(p); err != nil || info.SysvolNTACLs {
		t.Fatalf("without NT ACLs: %+v %v", info, err)
	}
	e, err := Prepare(p, filepath.Join(t.TempDir(), "c"), "drill", "lab.test", "/var/lib/x/restore")
	if err != nil || e.SysvolNTACLs {
		t.Fatalf("prepare: %+v %v", e, err)
	}
}

func TestNtaclOp(t *testing.T) {
	c, err := NtaclOp{Action: "sysvolreset", ConfigFile: "/var/lib/x/restore/etc/smb.conf"}.Command()
	if err != nil || strings.Join(c.Subcommand, " ") != "ntacl sysvolreset" || len(c.Options) != 1 ||
		c.Options[0] != "--configfile=/var/lib/x/restore/etc/smb.conf" || len(c.Args) != 0 {
		t.Fatalf("%+v %v", c, err)
	}
	for _, o := range []NtaclOp{
		{Action: "set", ConfigFile: "/x/smb.conf"},
		{Action: "sysvolcheck", ConfigFile: "smb.conf"},
		{Action: "sysvolcheck", ConfigFile: "/x/../etc/smb.conf"},
		{Action: "sysvolcheck", ConfigFile: "/x/smb.conf --use-ntvfs"},
	} {
		if _, err := o.Command(); err == nil {
			t.Errorf("%+v accepted", o)
		}
	}
}

// fakeSambaTool writes a samba-tool stand-in that records its arguments
// in calls and fails the subcommand named in fail (if any).
func fakeSambaTool(t *testing.T, fail string) (bin, calls string) {
	t.Helper()
	dir := t.TempDir()
	calls = filepath.Join(dir, "calls")
	bin = filepath.Join(dir, "samba-tool")
	script := "#!/bin/sh\necho \"$*\" >> " + calls + "\n"
	if fail != "" {
		script += "[ \"$2\" = " + fail + " ] && { echo 'ERROR: ACL mismatch on lab.test/Policies' >&2; exit 255; }\n"
	}
	script += "exit 0\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, calls
}

func TestSysvolACLs(t *testing.T) {
	const conf = "/var/lib/x/restore/etc/smb.conf"
	for _, c := range []struct {
		name       string
		hadNTACLs  bool
		fail       string
		wantCalls  []string
		wantErr    string
		wantDetail string
	}{
		{"rebuilt", false, "", []string{"ntacl sysvolreset", "ntacl sysvolcheck"}, "", "rebuilt from the directory"},
		{"restored", true, "", []string{"ntacl sysvolcheck"}, "", "restored from the backup"},
		{"reset fails", false, "sysvolreset", []string{"ntacl sysvolreset"}, "sysvolreset failed", ""},
		{"check fails", false, "sysvolcheck", []string{"ntacl sysvolreset", "ntacl sysvolcheck"}, "sysvolcheck failed", ""},
		{"check fails on restored", true, "sysvolcheck", []string{"ntacl sysvolcheck"}, "sysvolcheck failed", ""},
	} {
		bin, calls := fakeSambaTool(t, c.fail)
		r := &sambatool.Runner{Binary: bin, Credentials: sambatool.LocalSystem{}}
		detail, err := SysvolACLs(context.Background(), r, conf, c.hadNTACLs)
		b, _ := os.ReadFile(calls)
		var got []string
		for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if !strings.HasSuffix(l, " --configfile="+conf) {
				t.Errorf("%s: call %q", c.name, l)
			}
			got = append(got, strings.TrimSuffix(l, " --configfile="+conf))
		}
		if strings.Join(got, ";") != strings.Join(c.wantCalls, ";") {
			t.Errorf("%s: calls %q", c.name, got)
		}
		if c.wantErr != "" {
			if err == nil || !errors.Is(err, ErrSysvolACL) || !strings.Contains(err.Error(), c.wantErr) ||
				!strings.Contains(err.Error(), "ACL mismatch") {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err != nil || !strings.HasPrefix(detail, c.wantDetail) || !strings.HasSuffix(detail, "sysvolcheck passed") {
			t.Errorf("%s: %q %v", c.name, detail, err)
		}
	}
}
