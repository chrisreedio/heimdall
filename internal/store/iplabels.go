// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// IPLabel is something Heimdall knows about an address or range (see
// internal/ipinfo for how labels are matched and ranked).
type IPLabel struct {
	ID        int64
	OrgID     int64 // 0: every org
	Prefix    netip.Prefix
	Kind      string // IPKind*
	Name      string
	Person    string
	Source    string // IPSourceManual, or a synced source's name
	Note      string
	CreatedBy string
	UpdatedAt time.Time
}

// IP label kinds, from most to least telling.
const (
	IPKindStaff      = "staff"      // a person on the team
	IPKindOffice     = "office"     // a trusted network: an office, a VPN exit, a home network, not one person
	IPKindAutomation = "automation" // a deploy service or CI (Forge, Ploi, GitHub Actions)
	IPKindInfra      = "infra"      // your own servers, the hub, a VPN or proxy
	IPKindTailnet    = "tailnet"    // on the tailnet, device or person not known
	IPKindPrivate    = "private"    // a private, loopback or link-local address
	IPKindUnknown    = "unknown"
)

// IPSourceManual marks labels people added.
const IPSourceManual = "manual"

// IPSourceCloudflareList prefixes the source of labels synced from a
// Cloudflare IP list: "cloudflare:list:<list id>".
const IPSourceCloudflareList = "cloudflare:list:"

// IPListSource is a Cloudflare IP list's label source.
func IPListSource(listID string) string { return IPSourceCloudflareList + listID }

// IsIPListSource reports whether a label came from a Cloudflare IP list.
func IsIPListSource(source string) bool { return strings.HasPrefix(source, IPSourceCloudflareList) }

var ipKinds = map[string]bool{IPKindStaff: true, IPKindOffice: true, IPKindAutomation: true, IPKindInfra: true,
	IPKindTailnet: true, IPKindPrivate: true, IPKindUnknown: true}

// ParseIPPrefix accepts an address or a CIDR and returns it canonical (an
// address becomes a /32 or /128).
func ParseIPPrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, &ValidationError{"prefix", fmt.Sprintf("%q isn't an IP address or CIDR range", s)}
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ValidationError{"prefix", fmt.Sprintf("%q isn't an IP address or CIDR range", s)}
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func checkIPLabel(l *IPLabel) error {
	l.Name, l.Person, l.Note = strings.TrimSpace(l.Name), strings.TrimSpace(l.Person), strings.TrimSpace(l.Note)
	switch {
	case !l.Prefix.IsValid():
		return &ValidationError{"prefix", "is required"}
	case !ipKinds[l.Kind]:
		return &ValidationError{"kind", fmt.Sprintf("%q isn't a kind of IP label", l.Kind)}
	case l.Name == "" || len(l.Name) > 100:
		return &ValidationError{"name", "must be 1 to 100 characters"}
	case len(l.Person) > 200 || len(l.Note) > 500:
		return &ValidationError{"person", "is too long"}
	case l.Source == "":
		return &ValidationError{"source", "is required"}
	}
	return nil
}

func nullOrg(id int64) sql.NullInt64 { return sql.NullInt64{Int64: id, Valid: id != 0} }

// AddIPLabel stores a label added by hand.
func (s *Store) AddIPLabel(ctx context.Context, actor string, l IPLabel) (int64, error) {
	l.Source, l.CreatedBy = IPSourceManual, actor
	if err := checkIPLabel(&l); err != nil {
		return 0, err
	}
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO ip_labels (org_id, prefix, kind, name, person, source, note, created_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			nullOrg(l.OrgID), l.Prefix.String(), l.Kind, l.Name, l.Person, l.Source, l.Note, actor).Scan(&id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "ip_label.add", OrgID: l.OrgID, Target: l.Prefix.String(),
			Detail: map[string]any{"id": id, "kind": l.Kind, "name": l.Name, "person": l.Person}})
	})
	return id, err
}

// RemoveIPLabel deletes a label added by hand. Synced labels come back on
// their source's next sync, so they can't be removed this way.
func (s *Store) RemoveIPLabel(ctx context.Context, actor string, orgID, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var prefix string
		err := tx.QueryRowContext(ctx, `
			DELETE FROM ip_labels WHERE id = ? AND source = ? AND org_id IS ? RETURNING prefix`,
			id, IPSourceManual, nullOrg(orgID)).Scan(&prefix)
		if err == sql.ErrNoRows {
			return fmt.Errorf("IP label %d: %w", id, ErrNotFound)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "ip_label.remove", OrgID: orgID, Target: prefix,
			Detail: map[string]any{"id": id}})
	})
}

// ReplaceIPLabels makes a synced source's labels for an org (0: every org)
// exactly labels, in one transaction. Each label's Source is set to source.
func (s *Store) ReplaceIPLabels(ctx context.Context, orgID int64, source string, labels []IPLabel, now time.Time) error {
	if source == "" || source == IPSourceManual {
		return fmt.Errorf("ReplaceIPLabels: bad source %q", source)
	}
	for i := range labels {
		labels[i].Source = source
		if err := checkIPLabel(&labels[i]); err != nil {
			return err
		}
	}
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM ip_labels WHERE source = ? AND org_id IS ?`, source, nullOrg(orgID)); err != nil {
			return err
		}
		for _, l := range labels {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO ip_labels (org_id, prefix, kind, name, person, source, note, created_by, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, 'sync', ?, ?)`,
				nullOrg(orgID), l.Prefix.String(), l.Kind, l.Name, l.Person, source, l.Note, ts, ts); err != nil {
				return err
			}
		}
		return nil
	})
}

// IPLabels returns the labels that apply to an org: its own and every
// org's (orgID 0: only the latter). Small enough to match in memory.
func (s *Store) IPLabels(ctx context.Context, orgID int64) ([]IPLabel, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT id, COALESCE(org_id, 0), prefix, kind, name, person, source, note, created_by, updated_at
		FROM ip_labels WHERE org_id IS NULL OR org_id = ? ORDER BY id`, orgID)
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
		p, err := netip.ParsePrefix(prefix)
		if err != nil {
			continue // written by ParseIPPrefix; never expected
		}
		l.Prefix, l.UpdatedAt = p, parseTime(updated)
		out = append(out, l)
	}
	return out, rows.Err()
}

// RecordReportIP stores the address a host's report came from. A no-op
// when unchanged.
func (s *Store) RecordReportIP(ctx context.Context, hostID int64, ip string) error {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsUnspecified() {
		return nil
	}
	ip = a.Unmap().String()
	_, err = s.db.ExecContext(ctx, `UPDATE hosts SET report_ip = ? WHERE id = ? AND report_ip <> ?`, ip, hostID, ip)
	return err
}

// HostsByReportIP names an org's hosts whose last report came from ip.
func (s *Store) HostsByReportIP(ctx context.Context, orgID int64, ip string) ([]string, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT name FROM hosts WHERE org_id = ? AND report_ip = ? ORDER BY name`, orgID, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
