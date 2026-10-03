// Package state is conductor-backup's state directory
// (/var/lib/conductor-backup, owned by the conductor-backup user):
//
//	state.json     helper.BackupStatus, what conductor shows (read by
//	               conductor-helper on conductor's behalf)
//	private.json   bookkeeping conductor never sees (alerts sent, uploads
//	               still missing, drill requests in flight)
//	policy.json    the policy administrators edit (written by the helper)
//	requests/      "back up now" / "run drill now" (written by the helper)
//	spool/         encrypted archives and manifests waiting for upload
//	               (archives written by the helper, already encrypted)
//	.lock          one run at a time (flock)
package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/samba-conductor/ad/helper"
)

// Dir is a state directory.
type Dir struct{ Path string }

// ErrLocked: another run holds the lock.
var ErrLocked = errors.New("state: another conductor-backup run is in progress")

// Lock takes the run lock without waiting.
func (d Dir) Lock() (func(), error) {
	f, err := os.OpenFile(filepath.Join(d.Path, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	keepOwner(d.Path, f.Name())
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}

// Spool is where the helper leaves encrypted archives.
func (d Dir) Spool() string { return filepath.Join(d.Path, "spool") }

// Requests is where the helper leaves requests.
func (d Dir) Requests() string { return filepath.Join(d.Path, "requests") }

// Private is the bookkeeping conductor does not see.
type Private struct {
	// AlertsSent: alert kind → last time it was sent.
	AlertsSent map[string]time.Time `json:"alerts_sent"`
	// Missing: backup ID → destinations it still has to reach (the
	// archive stays in the spool until it has reached all of them).
	Missing map[string][]string `json:"missing"`
	// DrillRequests sent to the bucket and not answered yet.
	DrillRequests []helper.BackupRequest `json:"drill_requests"`
	// LastPrune is the last time the retention policy ran.
	LastPrune time.Time `json:"last_prune"`
	// Attempted is the last scheduled slot a backup was attempted for.
	Attempted time.Time `json:"attempted"`
}

// LoadStatus reads state.json (zero value when absent).
func (d Dir) LoadStatus() (helper.BackupStatus, error) {
	var s helper.BackupStatus
	err := readJSON(filepath.Join(d.Path, "state.json"), &s)
	return s, err
}

// SaveStatus writes state.json atomically, keeping the lists bounded.
func (d Dir) SaveStatus(s helper.BackupStatus) error {
	if len(s.Backups) > 30 {
		s.Backups = s.Backups[:30]
	}
	if len(s.Drills) > 10 {
		s.Drills = s.Drills[:10]
	}
	return writeJSON(filepath.Join(d.Path, "state.json"), s)
}

// LoadPrivate reads private.json.
func (d Dir) LoadPrivate() (Private, error) {
	p := Private{AlertsSent: map[string]time.Time{}, Missing: map[string][]string{}}
	if err := readJSON(filepath.Join(d.Path, "private.json"), &p); err != nil {
		return p, err
	}
	if p.AlertsSent == nil {
		p.AlertsSent = map[string]time.Time{}
	}
	if p.Missing == nil {
		p.Missing = map[string][]string{}
	}
	return p, nil
}

// SavePrivate writes private.json.
func (d Dir) SavePrivate(p Private) error { return writeJSON(filepath.Join(d.Path, "private.json"), p) }

// Policy returns the saved policy, or the default (custom=false).
func (d Dir) Policy() (helper.BackupPolicy, bool, error) {
	p := helper.DefaultBackupPolicy()
	b, err := os.ReadFile(filepath.Join(d.Path, "policy.json"))
	if errors.Is(err, fs.ErrNotExist) {
		return p, false, nil
	}
	if err != nil {
		return p, false, err
	}
	var saved helper.BackupPolicy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&saved); err != nil {
		return p, false, fmt.Errorf("state: policy.json: %w", err)
	}
	if err := saved.Validate(); err != nil {
		return p, false, fmt.Errorf("state: policy.json: %w", err)
	}
	return saved, true, nil
}

// PendingRequests lists the request files, oldest first.
func (d Dir) PendingRequests() ([]helper.BackupRequest, error) {
	entries, err := os.ReadDir(d.Requests())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []helper.BackupRequest
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var r helper.BackupRequest
		if err := readJSON(filepath.Join(d.Requests(), e.Name()), &r); err != nil || r.ID+".json" != e.Name() ||
			(r.Kind != helper.TriggerBackup && r.Kind != helper.TriggerDrill) {
			// A malformed request is dropped (it came from the helper; a
			// broken file must not block every later run).
			_ = os.Remove(filepath.Join(d.Requests(), e.Name()))
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

// DoneRequest removes a processed request.
func (d Dir) DoneRequest(id string) error {
	if strings.ContainsAny(id, "/\\") || id == "" {
		return errors.New("state: invalid request id")
	}
	err := os.Remove(filepath.Join(d.Requests(), id+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("state: %s: %w", filepath.Base(path), err)
	}
	return nil
}

// writeJSON replaces a file atomically (0600).
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	keepOwner(filepath.Dir(path), tmp.Name())
	return os.Rename(tmp.Name(), path)
}

// keepOwner gives a file the owner of its directory when root writes it
// (an operator running `sudo conductor-backup prune`), so the service user
// can still read and replace it.
func keepOwner(dir, file string) {
	if os.Geteuid() != 0 {
		return
	}
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err == nil && st.Uid != 0 {
		_ = os.Chown(file, int(st.Uid), int(st.Gid))
	}
}

// AddRequest writes a request file (the shell's "back up now"; conductor
// goes through conductor-helper instead). conductor-backup.path starts the
// service when it appears.
func (d Dir) AddRequest(r helper.BackupRequest) error {
	if err := os.MkdirAll(d.Requests(), 0o700); err != nil {
		return err
	}
	keepOwner(d.Path, d.Requests())
	return writeJSON(filepath.Join(d.Requests(), r.ID+".json"), r)
}

// WriteJSON is writeJSON for other packages (drill state).
func WriteJSON(path string, v any) error { return writeJSON(path, v) }

// ReadJSON is readJSON for other packages.
func ReadJSON(path string, v any) error { return readJSON(path, v) }
