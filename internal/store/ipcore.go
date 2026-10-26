// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Where an address shows up, and each org's SSH source policy (see
// internal/ipinfo and docs/ip-awareness.md).

// SignIn is a Heimdall UI sign-in: a session still open, or a past one
// from the audit log.
type SignIn struct {
	UserID        int64
	Email, Name   string
	IP            string
	At            time.Time // signed in
	Until         time.Time // last activity, for an open session (else At)
	Open          bool      // a current session
	TailscaleUser string    // the tailnet login `tailscale serve` passed, if any
}

// Who is the user's display name, or their email.
func (si SignIn) Who() string {
	if si.Name != "" {
		return si.Name
	}
	return si.Email
}

// signInActions are the audit actions that record a sign-in.
const signInActions = `'login.success', 'login.dev'`

// SignInsNear returns the sign-ins from ip active within d of at: open
// sessions overlapping [at-d, at+d] and audited sign-ins in that span.
// orgID, if not 0, keeps only users who can see that org (members and
// admins). Newest first, one per user.
func (s *Store) SignInsNear(ctx context.Context, ip string, at time.Time, d time.Duration, orgID int64) ([]SignIn, error) {
	from, to := at.Add(-d).UTC().Format(timeLayout), at.Add(d).UTC().Format(timeLayout)
	all, err := s.signIns(ctx, ip, `AND x.until >= ? AND x.at <= ?`, []any{from, to}, orgID, 200)
	if err != nil {
		return nil, err
	}
	var out []SignIn
	seen := map[int64]bool{}
	for _, si := range all {
		if !seen[si.UserID] {
			seen[si.UserID] = true
			out = append(out, si)
		}
	}
	return out, nil
}

// SignInsFrom returns the newest sign-ins from ip, open sessions and
// audited ones, for the IP page.
func (s *Store) SignInsFrom(ctx context.Context, ip string, limit int) ([]SignIn, error) {
	return s.signIns(ctx, ip, "", nil, 0, limit)
}

func (s *Store) signIns(ctx context.Context, ip, where string, args []any, orgID int64, limit int) ([]SignIn, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, nil
	}
	ip = a.Unmap().String()
	q := `
		SELECT x.user_id, u.email, u.display_name, x.ip, x.at, x.until, x.open, x.ts FROM (
		  SELECT user_id, ip, created_at AS at, last_seen_at AS until, 1 AS open,
		         CASE WHEN ts_name <> '' THEN ts_name || ' (' || ts_login || ')' ELSE ts_login END AS ts
		  FROM sessions WHERE ip = ?
		  UNION ALL
		  SELECT CAST(substr(actor, 6) AS INTEGER), ip, at, at, 0, ''
		  FROM audit_log WHERE ip = ? AND action IN (` + signInActions + `) AND actor LIKE 'user:%'
		) x JOIN users u ON u.id = x.user_id
		WHERE 1 = 1 ` + where
	qargs := append([]any{ip, ip}, args...)
	if orgID != 0 {
		q += ` AND (u.is_admin = 1 OR EXISTS (SELECT 1 FROM memberships m WHERE m.user_id = u.id AND m.org_id = ?))`
		qargs = append(qargs, orgID)
	}
	q += ` ORDER BY x.at DESC, x.open DESC LIMIT ?`
	qargs = append(qargs, limit*2)
	rows, err := s.db.QueryContext(ctx, q, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SignIn
	for rows.Next() {
		var si SignIn
		var at, until string
		if err := rows.Scan(&si.UserID, &si.Email, &si.Name, &si.IP, &at, &until, &si.Open, &si.TailscaleUser); err != nil {
			return nil, err
		}
		si.At, si.Until = parseTime(at), parseTime(until)
		out = append(out, si)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// An open session was also audited when it began: keep the session.
	var kept []SignIn
	for _, si := range out {
		if len(kept) < limit && (si.Open || !slices.ContainsFunc(out, func(o SignIn) bool {
			return o.Open && o.UserID == si.UserID && o.At.Sub(si.At).Abs() < time.Minute
		})) {
			kept = append(kept, si)
		}
	}
	return kept, nil
}

// SetSessionTailscale records the tailnet identity a session signed in
// with (the Tailscale-User-Login and -Name headers of `tailscale serve`).
func (s *Store) SetSessionTailscale(ctx context.Context, hash [32]byte, login, name string) error {
	login, name = clip(login, 200), clip(name, 200)
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET ts_login = ?, ts_name = ? WHERE id_hash = ?`, login, name, hash[:])
	return err
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

// IPPolicy is an org's rule for where privileged SSH sessions may come
// from.
type IPPolicy struct {
	OrgID int64
	// TailnetOnly: a privileged session from anywhere but the tailnet, a
	// private network or loopback raises privilege_off_tailnet.
	TailnetOnly bool
	// AllowServices exempts addresses a synced source labels automation
	// (a deploy service's published ranges). On unless turned off.
	AllowServices bool
	// CountServices counts sessions from those ranges toward
	// privileged_access. Off unless turned on: deploys aren't news.
	CountServices bool
	UpdatedBy     string
	UpdatedAt     time.Time
}

// IPPolicy returns an org's policy (off, services allowed and not
// counted, if never set).
func (s *Store) IPPolicy(ctx context.Context, orgID int64) (IPPolicy, error) {
	p := IPPolicy{OrgID: orgID, AllowServices: true}
	var at string
	err := s.db.QueryRowContext(ctx, `
		SELECT tailnet_only, allow_services, count_services, updated_by, updated_at FROM ip_policies WHERE org_id = ?`, orgID).
		Scan(&p.TailnetOnly, &p.AllowServices, &p.CountServices, &p.UpdatedBy, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	p.UpdatedAt = parseTime(at)
	return p, err
}

// SetIPPolicy stores an org's policy, audited.
func (s *Store) SetIPPolicy(ctx context.Context, actor string, p IPPolicy, now time.Time) error {
	if p.OrgID == 0 {
		return &ValidationError{"org", "is required"}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO ip_policies (org_id, tailnet_only, allow_services, count_services, updated_by, updated_at)
			VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (org_id) DO UPDATE SET tailnet_only = excluded.tailnet_only,
			  allow_services = excluded.allow_services, count_services = excluded.count_services, updated_by = excluded.updated_by, updated_at = excluded.updated_at`,
			p.OrgID, p.TailnetOnly, p.AllowServices, p.CountServices, actor, now.UTC().Format(timeLayout)); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "ip_policy.set", OrgID: p.OrgID,
			Detail: map[string]any{"tailnet_only": p.TailnetOnly, "allow_services": p.AllowServices,
				"count_services": p.CountServices}})
	})
}

// AllIPLabels returns every label, for the CLI.
func (s *Store) AllIPLabels(ctx context.Context) ([]IPLabel, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, COALESCE(org_id, 0), prefix, kind, name, person, source, note, created_by, updated_at
		FROM ip_labels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPLabel
	for rows.Next() {
		var l IPLabel
		var prefix, updated string
		if err := rows.Scan(&l.ID, &l.OrgID, &prefix, &l.Kind, &l.Name, &l.Person, &l.Source, &l.Note, &l.CreatedBy, &updated); err != nil {
			return nil, err
		}
		if l.Prefix, err = netip.ParsePrefix(prefix); err != nil {
			continue
		}
		l.UpdatedAt = parseTime(updated)
		out = append(out, l)
	}
	return out, rows.Err()
}

// HostPrivilegeEvent is a privilege event with its host.
type HostPrivilegeEvent struct {
	PrivilegeEvent
	Host IngestHost
}

// PrivilegeFrom returns the newest privilege events whose source is ip, in
// orgs the scope can view.
func (s *Store) PrivilegeFrom(ctx context.Context, sc Scope, ip string, limit int) ([]HostPrivilegeEvent, error) {
	srcs := []any{ip}
	if a, err := netip.ParseAddr(ip); err == nil && a.Unmap().String() != ip {
		srcs = append(srcs, a.Unmap().String())
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT p.at, p.kind, p.user, p.source, h.id, h.org_id, o.slug, h.name
		FROM privilege_events p JOIN hosts h ON h.id = p.host_id JOIN organizations o ON o.id = h.org_id
		WHERE p.source IN (?`+strings.Repeat(", ?", len(srcs)-1)+`) AND p.source NOT IN ('', '?')
		ORDER BY p.at DESC LIMIT 2000`, srcs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostPrivilegeEvent
	for rows.Next() {
		var ev HostPrivilegeEvent
		var at int64
		if err := rows.Scan(&at, &ev.Kind, &ev.User, &ev.Source, &ev.Host.ID, &ev.Host.OrgID, &ev.Host.OrgSlug, &ev.Host.Name); err != nil {
			return nil, err
		}
		if !sc.CanView(ev.Host.OrgID) || len(out) == limit {
			continue
		}
		ev.At = time.Unix(at, 0).UTC()
		out = append(out, ev)
	}
	return out, rows.Err()
}

// PrivilegeSource is one source a host's privileged sessions came from.
type PrivilegeSource struct {
	Host   IngestHost
	Source string
	Users  []string
	Kinds  map[string]int
	Last   time.Time
	Count  int
}

// PrivilegeSourcesSince groups privilege events since a time by host and
// source (an address or host name; local and "?" left out). hostID 0 is
// every host the scope can view.
func (s *Store) PrivilegeSourcesSince(ctx context.Context, sc Scope, hostID int64, since time.Time) ([]PrivilegeSource, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, p.source, p.user, p.kind, count(*), max(p.at)
		FROM privilege_events p JOIN hosts h ON h.id = p.host_id JOIN organizations o ON o.id = h.org_id
		WHERE p.at >= ? AND p.source NOT IN ('', '?') AND (? = 0 OR h.id = ?)
		GROUP BY h.id, p.source, p.user, p.kind ORDER BY o.slug, h.name, p.source`, since.Unix(), hostID, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PrivilegeSource
	for rows.Next() {
		var h IngestHost
		var src, user, kind string
		var n int
		var last int64
		if err := rows.Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.Name, &src, &user, &kind, &n, &last); err != nil {
			return nil, err
		}
		if !sc.CanView(h.OrgID) {
			continue
		}
		if k := len(out) - 1; k < 0 || out[k].Host.ID != h.ID || out[k].Source != src {
			out = append(out, PrivilegeSource{Host: h, Source: src, Kinds: map[string]int{}})
		}
		ps := &out[len(out)-1]
		ps.Count += n
		ps.Kinds[kind] += n
		if user != "" && !slices.Contains(ps.Users, user) {
			ps.Users = append(ps.Users, user)
		}
		if t := time.Unix(last, 0).UTC(); t.After(ps.Last) {
			ps.Last = t
		}
	}
	return out, rows.Err()
}

// AuditRow is an audit log entry, for the IP page.
type AuditRow struct {
	At     time.Time
	Actor  string
	Action string
	OrgID  int64
	Target string
	IP     string
}

// AuditFrom returns the newest audit entries recorded from ip. all
// includes every entry; otherwise only those of orgs (never unscoped ones).
func (s *Store) AuditFrom(ctx context.Context, ip string, all bool, orgs []int64, limit int) ([]AuditRow, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT at, actor, action, COALESCE(org_id, 0), target, ip FROM audit_log WHERE ip = ? ORDER BY id DESC LIMIT 2000`,
		a.Unmap().String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditRow
	for rows.Next() {
		var r AuditRow
		var at string
		if err := rows.Scan(&at, &r.Actor, &r.Action, &r.OrgID, &r.Target, &r.IP); err != nil {
			return nil, err
		}
		if (!all && (r.OrgID == 0 || !slices.Contains(orgs, r.OrgID))) || len(out) == limit {
			continue
		}
		r.At = parseTime(at)
		out = append(out, r)
	}
	return out, rows.Err()
}
