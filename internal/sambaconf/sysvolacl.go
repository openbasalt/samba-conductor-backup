package sambaconf

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openbasalt/samba-conductor-ad/sambatool"
)

// The sysvol NT ACLs after a restore.
//
// `samba-tool domain backup online` stores each sysvol entry's NT ACL as
// a `<path>.NTACL` member of the nested sysvol archive, read over SMB with
// the backup's credentials. The backup account holds only the replication
// rights, which do not let it read them, so conductor-backup's backups
// carry none, and `backup restore` leaves sysvol with default permissions
// (it logs a warning per entry and goes on). The ACLs that matter are
// derived from the directory: `samba-tool ntacl sysvolreset` rebuilds
// every sysvol ACL (NT ACL and the POSIX ACL Samba maps it to) from the
// group policy objects, and `samba-tool ntacl sysvolcheck` verifies them.
// ACLs set by hand on sysvol outside group policy management are not
// preserved by such a rebuild.

// ntaclSuffix ends the members of the nested sysvol archive that hold an
// entry's NT ACL (Samba's ntacls.backup_online).
const ntaclSuffix = ".NTACL"

// NtaclOp is `samba-tool ntacl sysvolreset|sysvolcheck --configfile=F`,
// against the restored domain's local database (no network).
type NtaclOp struct {
	// Action is "sysvolreset" or "sysvolcheck".
	Action string
	// ConfigFile is the restored, allowlisted smb.conf (absolute path).
	ConfigFile string
}

// Command implements sambatool.Operation.
func (o NtaclOp) Command() (sambatool.Command, error) {
	if o.Action != "sysvolreset" && o.Action != "sysvolcheck" {
		return sambatool.Command{}, fmt.Errorf("sambaconf: invalid ntacl action %q", o.Action)
	}
	if !pathRE.MatchString(o.ConfigFile) || filepath.Clean(o.ConfigFile) != o.ConfigFile || strings.Contains(o.ConfigFile, "..") {
		return sambatool.Command{}, fmt.Errorf("sambaconf: invalid configuration path %q", o.ConfigFile)
	}
	return sambatool.Command{Subcommand: []string{"ntacl", o.Action}, Options: []string{"--configfile=" + o.ConfigFile}}, nil
}

// Parse implements sambatool.Operation: both print nothing on success
// and exit non-zero on failure.
func (NtaclOp) Parse([]byte) (struct{}, error) { return struct{}{}, nil }

// ErrSysvolACL: the restored sysvol ACLs could not be rebuilt or do not
// match what the directory says.
var ErrSysvolACL = errors.New("sysvol ACLs")

// maxACLDetail bounds samba-tool's message in an error.
const maxACLDetail = 300

// SysvolACLs makes the restored sysvol ACLs right and checks them: when
// the backup carries no NT ACLs (hadNTACLs false) it rebuilds them with
// sysvolreset first; either way sysvolcheck must pass. configFile is the
// restored smb.conf (TargetDir/etc/smb.conf, after Finalize). It returns
// what was done, for the drill's report and the restore's output.
func SysvolACLs(ctx context.Context, r *sambatool.Runner, configFile string, hadNTACLs bool) (string, error) {
	detail := "restored from the backup"
	if !hadNTACLs {
		detail = "rebuilt from the directory (the backup carries no NT ACLs)"
		if _, err := sambatool.Run(ctx, r, NtaclOp{Action: "sysvolreset", ConfigFile: configFile}); err != nil {
			return detail, fmt.Errorf("%w: sysvolreset failed: %s", ErrSysvolACL, short(err))
		}
	}
	if _, err := sambatool.Run(ctx, r, NtaclOp{Action: "sysvolcheck", ConfigFile: configFile}); err != nil {
		return detail, fmt.Errorf("%w %s, but sysvolcheck failed: %s", ErrSysvolACL, detail, short(err))
	}
	return detail + "; sysvolcheck passed", nil
}

// short is an error's message, bounded.
func short(err error) string {
	m := strings.Join(strings.Fields(err.Error()), " ")
	if len(m) > maxACLDetail {
		m = m[:maxACLDetail] + "..."
	}
	return m
}
