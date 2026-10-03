// Package manifest defines the signed documents stored next to backups:
// the manifest of each archive (written by the DC), drill requests
// (written by the DC) and drill reports (written by the drill host).
// All of them travel in a sign.Envelope.
package manifest

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/samba-conductor/ad/helper"
)

// Formats.
const (
	ManifestFormat = "conductor-backup-manifest/1"
	RequestFormat  = "conductor-backup-drill-request/1"
	ReportFormat   = "conductor-backup-drill-report/1"
)

// Manifest describes one encrypted archive. Nothing in it is secret: no
// user names or SIDs (those are inside the encrypted archive).
type Manifest struct {
	Format    string    `json:"format"`
	ID        string    `json:"id"`
	Realm     string    `json:"realm"`
	DC        string    `json:"dc"`
	CreatedAt time.Time `json:"created_at"`
	Trigger   string    `json:"trigger"`
	// Object is the archive's key in the destination.
	Object string `json:"object"`
	Size   int64  `json:"size"`
	// SHA256 of the ciphertext, verified on upload and before a restore.
	SHA256 string `json:"sha256"`
	// Recipients are the fingerprints of the age recipients.
	Recipients []string          `json:"recipients"`
	Versions   map[string]string `json:"versions"`
	Contents   []string          `json:"contents"`
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Validate checks a manifest read back from a destination.
func (m Manifest) Validate(realm string) error {
	if m.Format != ManifestFormat {
		return fmt.Errorf("manifest format %q", m.Format)
	}
	if !helper.BackupIDRE.MatchString(m.ID) {
		return fmt.Errorf("manifest id %q", m.ID)
	}
	if realm != "" && !equalFold(m.Realm, realm) {
		return fmt.Errorf("manifest for realm %q, not %q", m.Realm, realm)
	}
	if !sha256RE.MatchString(m.SHA256) || m.Size <= 0 {
		return errors.New("manifest without a valid size and SHA-256")
	}
	return nil
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'a' <= x && x <= 'z' {
			x -= 32
		}
		if 'a' <= y && y <= 'z' {
			y -= 32
		}
		if x != y {
			return false
		}
	}
	return true
}

// DrillRequest asks the drill host to restore a backup.
type DrillRequest struct {
	Format string `json:"format"`
	ID     string `json:"id"`
	Realm  string `json:"realm"`
	// BackupID: a specific backup, or "" for the newest one.
	BackupID    string    `json:"backup_id"`
	RequestedBy string    `json:"requested_by"`
	At          time.Time `json:"at"`
}

// DrillReport is the signed result of a drill.
type DrillReport struct {
	Format  string             `json:"format"`
	Realm   string             `json:"realm"`
	Version string             `json:"version"`
	Drill   helper.DrillRecord `json:"drill"`
	// Phases: download, verify, decrypt, restore, start, checks (ms).
	Phases map[string]int64 `json:"phases"`
}
