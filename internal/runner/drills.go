package runner

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/samba-conductor/ad/helper"
	"github.com/samba-conductor/conductor-backup/internal/alert"
	"github.com/samba-conductor/conductor-backup/internal/config"
	"github.com/samba-conductor/conductor-backup/internal/dest"
	"github.com/samba-conductor/conductor-backup/internal/manifest"
	"github.com/samba-conductor/conductor-backup/internal/sign"
	"github.com/samba-conductor/conductor-backup/internal/state"
)

// requestTTL: a drill request not answered within this time is dropped
// (and reported as an overdue drill).
const requestTTL = 48 * time.Hour

// syncDrills reads new drill reports and posts drill requests.
func (r *Runner) syncDrills(ctx context.Context, st *helper.BackupStatus, priv *state.Private, policy helper.BackupPolicy, local []helper.BackupRequest) {
	trusted, err := config.PublicKeys(r.Cfg.DrillPublicKeys)
	if err != nil {
		r.Log.Error("drill public keys", "err", err)
	}
	known := map[string]bool{}
	for _, d := range st.Drills {
		known[d.ID] = true
	}
	if len(trusted) > 0 {
		for _, s := range r.Stores {
			objs, err := s.List(ctx, dest.ReportPrefix(r.Cfg.Realm))
			if err != nil {
				r.Log.Warn("listing drill reports", "destination", s.Name(), "err", err)
				continue
			}
			for _, o := range objs {
				id := strings.TrimSuffix(strings.TrimPrefix(o.Key, dest.ReportPrefix(r.Cfg.Realm)), ".json")
				if known[id] {
					continue
				}
				b, err := dest.ReadAll(ctx, s, o.Key, 1<<20)
				if err != nil {
					continue
				}
				var rep manifest.DrillReport
				if _, err := sign.Open(b, trusted, &rep); err != nil || rep.Format != manifest.ReportFormat ||
					!strings.EqualFold(rep.Realm, r.Cfg.Realm) || rep.Drill.ID != id {
					r.Log.Warn("ignoring an unverifiable drill report", "key", o.Key, "err", err)
					known[id] = true
					continue
				}
				known[id] = true
				st.Drills = append(st.Drills, rep.Drill)
				r.Log.Info("drill report", "id", id, "backup", rep.Drill.BackupID, "passed", rep.Drill.Passed, "rto_ms", rep.Drill.RTOMS)
				// The request it answers is done.
				kept := priv.DrillRequests[:0]
				for _, q := range priv.DrillRequests {
					if q.ID != rep.Drill.RequestID {
						kept = append(kept, q)
					}
				}
				priv.DrillRequests = kept
				for _, s := range r.Stores {
					if k, err := dest.DocKey(dest.RequestPrefix(r.Cfg.Realm), rep.Drill.RequestID); err == nil && rep.Drill.RequestID != "" {
						_ = s.Delete(ctx, k)
					}
				}
			}
		}
	}
	sort.Slice(st.Drills, func(i, j int) bool { return st.Drills[i].StartedAt.After(st.Drills[j].StartedAt) })
	if len(st.Drills) > 10 {
		st.Drills = st.Drills[:10]
	}

	now := r.now()
	kept := priv.DrillRequests[:0]
	for _, q := range priv.DrillRequests {
		if now.Sub(q.At) < requestTTL {
			kept = append(kept, q)
		}
	}
	priv.DrillRequests = kept

	// A request from an administrator, or one the policy calls for.
	var want *helper.BackupRequest
	if len(local) > 0 {
		q := local[0]
		want = &q
	} else if policy.DrillIntervalDays > 0 && len(priv.DrillRequests) == 0 {
		var lastAt time.Time
		if len(st.Drills) > 0 {
			lastAt = st.Drills[0].StartedAt
		}
		if _, ok := st.LastGood(); ok && now.Sub(lastAt) >= time.Duration(policy.DrillIntervalDays)*24*time.Hour {
			want = &helper.BackupRequest{ID: newID("sched-"), Kind: helper.TriggerDrill, RequestedBy: "schedule", SID: "S-1-5-18", At: now}
		}
	}
	if want != nil {
		if err := r.postDrillRequest(ctx, *want); err != nil {
			r.Log.Error("posting the drill request", "err", err)
		} else {
			priv.DrillRequests = append(priv.DrillRequests, *want)
			for _, q := range local {
				_ = r.Dir.DoneRequest(q.ID)
			}
		}
	}
	st.Pending = st.Pending[:0]
	if reqs, err := r.Dir.PendingRequests(); err == nil {
		st.Pending = append(st.Pending, reqs...)
	}
	st.Pending = append(st.Pending, priv.DrillRequests...)
}

func (r *Runner) postDrillRequest(ctx context.Context, q helper.BackupRequest) error {
	doc := manifest.DrillRequest{Format: manifest.RequestFormat, ID: q.ID, Realm: strings.ToUpper(r.Cfg.Realm), RequestedBy: q.RequestedBy, At: q.At}
	env, err := sign.Seal(r.Key, doc)
	if err != nil {
		return err
	}
	key, err := dest.DocKey(dest.RequestPrefix(r.Cfg.Realm), q.ID)
	if err != nil {
		return err
	}
	posted := 0
	var last error
	for _, s := range r.Stores {
		if err := s.PutBytes(ctx, key, env); err != nil {
			last = err
			continue
		}
		posted++
	}
	if posted == 0 {
		return fmt.Errorf("no destination accepted the request: %w", last)
	}
	r.Log.Info("drill requested", "request", q.ID, "by", q.RequestedBy)
	return nil
}

// ---- alerts ----

// Alerts computes the active alert conditions.
func Alerts(st helper.BackupStatus, policy helper.BackupPolicy, firstSeen, now time.Time) []helper.BackupAlert {
	var out []helper.BackupAlert
	maxAge := time.Duration(policy.MaxAgeHours) * time.Hour
	if last, ok := st.LastGood(); ok {
		if now.Sub(last.CreatedAt) > maxAge {
			out = append(out, helper.BackupAlert{Kind: helper.AlertStale, Since: last.CreatedAt.Add(maxAge),
				Detail: fmt.Sprintf("last good backup %s is %s old", last.ID, now.Sub(last.CreatedAt).Round(time.Minute))})
		}
	} else if !firstSeen.IsZero() && now.Sub(firstSeen) > maxAge {
		out = append(out, helper.BackupAlert{Kind: helper.AlertStale, Since: firstSeen.Add(maxAge), Detail: "no good backup yet"})
	}
	if len(st.Backups) > 0 && (st.Backups[0].Status == helper.StatusFailed || st.Backups[0].Status == helper.StatusPartial) {
		// A destination that missed a backup is a failure worth an alert
		// too (the archive waits in the spool for the next run).
		out = append(out, helper.BackupAlert{Kind: helper.AlertFailed, Since: st.Backups[0].CreatedAt, Detail: st.Backups[0].Error})
	}
	if len(st.Drills) > 0 && !st.Drills[0].Passed {
		out = append(out, helper.BackupAlert{Kind: helper.AlertDrillFailed, Since: st.Drills[0].FinishedAt, Detail: drillFailure(st.Drills[0])})
	}
	if policy.DrillIntervalDays > 0 {
		window := time.Duration(policy.DrillIntervalDays)*24*time.Hour + requestTTL
		var lastPass time.Time
		if d, ok := st.LastPassedDrill(); ok {
			lastPass = d.FinishedAt
		}
		ref := lastPass
		if ref.IsZero() {
			ref = firstSeen
		}
		if !ref.IsZero() && now.Sub(ref) > window {
			out = append(out, helper.BackupAlert{Kind: helper.AlertDrillOverdue, Since: ref.Add(window), Detail: "no passing restore drill within the interval"})
		}
	}
	return out
}

func drillFailure(d helper.DrillRecord) string {
	if d.Error != "" {
		return d.Error
	}
	var failed []string
	for _, c := range d.Checks {
		if !c.OK {
			failed = append(failed, c.Name)
		}
	}
	return "failed checks: " + strings.Join(failed, ", ")
}

// firstSeen is when conductor-backup first ran here (oldest record).
func firstSeen(st helper.BackupStatus) time.Time {
	var t time.Time
	for _, b := range st.Backups {
		if t.IsZero() || b.CreatedAt.Before(t) {
			t = b.CreatedAt
		}
	}
	return t
}

var alertTitles = map[string]string{
	helper.AlertStale:        "no recent backup",
	helper.AlertFailed:       "backup failed",
	helper.AlertDrillFailed:  "restore drill failed",
	helper.AlertDrillOverdue: "restore drill overdue",
}

func (r *Runner) evaluateAlerts(ctx context.Context, st *helper.BackupStatus, priv *state.Private, policy helper.BackupPolicy, now time.Time) {
	st.Alerts = Alerts(*st, policy, firstSeen(*st), now)
	active := map[string]bool{}
	for _, a := range st.Alerts {
		active[a.Kind] = true
		if sent, ok := priv.AlertsSent[a.Kind]; ok && now.Sub(sent) < 24*time.Hour {
			continue
		}
		if r.Alerts == nil || !r.Alerts.Enabled() {
			continue
		}
		m := alert.Message{Kind: a.Kind, Realm: st.Realm, Host: r.Cfg.DC, At: now,
			Subject: fmt.Sprintf("[conductor-backup] %s: %s (%s)", st.Realm, alertTitles[a.Kind], r.Cfg.DC),
			Text: fmt.Sprintf("%s on %s, domain %s.\n\n%s\n\nSince: %s\nLast run: %s\n\nOpen the Backups page in Samba Conductor, or run `conductor-backup status` on %s.\n",
				alertTitles[a.Kind], r.Cfg.DC, st.Realm, a.Detail, a.Since.Format(time.RFC3339), st.LastRunAt.Format(time.RFC3339), r.Cfg.DC)}
		if err := r.Alerts.Send(ctx, m); err != nil {
			r.Log.Error("sending the alert", "kind", a.Kind, "err", err)
			continue
		}
		priv.AlertsSent[a.Kind] = now
		r.Log.Info("alert sent", "kind", a.Kind)
	}
	// A condition that cleared may alert again the next time it happens.
	for k := range priv.AlertsSent {
		if !active[k] {
			delete(priv.AlertsSent, k)
		}
	}
}

// Check re-evaluates and sends alerts without backing up (monitoring).
func (r *Runner) Check(ctx context.Context) ([]helper.BackupAlert, error) {
	unlock, err := r.Dir.Lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	st, err := r.Dir.LoadStatus()
	if err != nil {
		return nil, err
	}
	priv, err := r.Dir.LoadPrivate()
	if err != nil {
		return nil, err
	}
	policy, custom, _ := r.Dir.Policy()
	st.Policy, st.PolicyCustom = policy, custom
	r.evaluateAlerts(ctx, &st, &priv, policy, r.now())
	if err := r.Dir.SaveStatus(st); err != nil {
		return nil, err
	}
	return st.Alerts, r.Dir.SavePrivate(priv)
}
