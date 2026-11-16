package restore

import (
	"strings"
	"testing"
	"time"

	"github.com/openbasalt/samba-conductor-ad/helper"
)

// TestNextStepsConductor: after a restore with conductor installed, the
// steps name both keys that are not in the archive and verify the audit
// log as root (the command requires it).
func TestNextStepsConductor(t *testing.T) {
	out := NextSteps(&Result{BackupID: "20261003T023000Z-dc1", Meta: helper.ArchiveMeta{Realm: "LAB.TEST", DC: "dc1", CreatedAt: time.Now()},
		SambaDir: "/var/lib/samba", ServerName: "DC9", ConductorInstalled: true, Conductor: "/var/lib/conductor/conductor.db", FilesDir: "/root/files"})
	for _, want := range []string{"/etc/conductor/credentials/totp-key", "/etc/conductor/credentials/audit-key", "; sudo conductor audit verify\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("next steps lack %q:\n%s", want, out)
		}
	}
}
