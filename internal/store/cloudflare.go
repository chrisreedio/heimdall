// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"
	"time"
)

// CloudflareZone is a zone the Cloudflare token can read (internal/cloudflare).
type CloudflareZone struct {
	ID, Name, Plan, Status string
	SyncedAt               time.Time
	// Security is how the zone's security events were last fetched: ""
	// (never), CloudflareSecurity* (see the migration).
	Security     string
	SecurityNote string
	SecurityAt   time.Time
	Last24       json.RawMessage // cloudflare.Summary
}

// Cloudflare security event states.
const (
	CloudflareSecurityOK         = "ok"
	CloudflareSecuritySampled    = "sampled"
	CloudflareSecurityPlan       = "plan"
	CloudflareSecurityPermission = "permission"
	CloudflareSecurityError      = "error"
)

// CloudflareRecord is an A, AAAA or CNAME record in a zone.
type CloudflareRecord struct {
	ZoneID, Name, Type, Content string
	Proxied                     bool
	TTL                         int
	SyncedAt                    time.Time
}

// CloudflareDaily is one day's count for a zone's security events.
type CloudflareDaily struct {
	Day   string // 2026-10-24 (UTC)
	Dim   string // total, requests, action, country, asn, path
	Key   string
	Count int64
}

// CloudflareRadar is Radar's answer for an address (ASN 0: none).
type CloudflareRadar struct {
	IP        string
	ASN       int64
	Name      string
	Country   string
	FetchedAt time.Time
}

// CloudflareKeepDays is how long daily security counts are kept.
const CloudflareKeepDays = 30

// ReplaceCloudflareZones makes the stored zones exactly zones (others are
// deleted with their records and counts). records holds the records of the
// zones whose DNS was read; a zone missing from it keeps its old records,
// so one failing zone doesn't empty the overview.
func (s *Store) ReplaceCloudflareZones(ctx context.Context, zones []CloudflareZone, records map[string][]CloudflareRecord, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		keep := make([]any, 0, len(zones))
		for _, z := range zones {
			keep = append(keep, z.ID)
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO cloudflare_zones (id, name, plan, status, synced_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET name = excluded.name, plan = excluded.plan,
					status = excluded.status, synced_at = excluded.synced_at`,
				z.ID, strings.ToLower(z.Name), z.Plan, z.Status, ts); err != nil {
				return err
			}
		}
		q := `DELETE FROM cloudflare_zones`
		if len(keep) > 0 {
			q += ` WHERE id NOT IN (?` + strings.Repeat(", ?", len(keep)-1) + `)`
		}
		if _, err := tx.ExecContext(ctx, q, keep...); err != nil {
			return err
		}
		for zone, rs := range records {
			if _, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_dns_records WHERE zone_id = ?`, zone); err != nil {
				return err
			}
			for _, r := range rs {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO cloudflare_dns_records (zone_id, name, type, content, proxied, ttl, synced_at)
					SELECT ?, ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM cloudflare_zones WHERE id = ?)`,
					zone, strings.TrimSuffix(strings.ToLower(r.Name), "."), r.Type, r.Content, r.Proxied, r.TTL, ts, zone); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// CloudflareZones returns the stored zones by name.
func (s *Store) CloudflareZones(ctx context.Context) ([]CloudflareZone, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT id, name, plan, status, synced_at, security, security_note, security_at, last24
		FROM cloudflare_zones ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudflareZone
	for rows.Next() {
		var z CloudflareZone
		var synced, secAt, last24 string
		if err := rows.Scan(&z.ID, &z.Name, &z.Plan, &z.Status, &synced, &z.Security, &z.SecurityNote, &secAt, &last24); err != nil {
			return nil, err
		}
		z.SyncedAt, z.SecurityAt, z.Last24 = parseTime(synced), parseTime(secAt), json.RawMessage(last24)
		out = append(out, z)
	}
	return out, rows.Err()
}

// CloudflareRecords returns every stored record.
func (s *Store) CloudflareRecords(ctx context.Context) ([]CloudflareRecord, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT zone_id, name, type, content, proxied, ttl, synced_at
		FROM cloudflare_dns_records ORDER BY name, type, content`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudflareRecord
	for rows.Next() {
		var r CloudflareRecord
		var synced string
		if err := rows.Scan(&r.ZoneID, &r.Name, &r.Type, &r.Content, &r.Proxied, &r.TTL, &synced); err != nil {
			return nil, err
		}
		r.SyncedAt = parseTime(synced)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SetCloudflareSecurity records how a zone's security events were fetched.
// For a fetch that worked (ok or sampled), last24 replaces the zone's
// summary and days replace those days' counts; otherwise the old counts
// stay. Counts older than CloudflareKeepDays are deleted.
func (s *Store) SetCloudflareSecurity(ctx context.Context, zoneID, state, note string, last24 []byte, days []CloudflareDaily, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	ok := state == CloudflareSecurityOK || state == CloudflareSecuritySampled
	return s.tx(ctx, func(tx *sql.Tx) error {
		if ok {
			if _, err := tx.ExecContext(ctx, `
				UPDATE cloudflare_zones SET security = ?, security_note = ?, security_at = ?, last24 = ? WHERE id = ?`,
				state, note, ts, string(last24), zoneID); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `
				UPDATE cloudflare_zones SET security = ?, security_note = ?, security_at = ? WHERE id = ?`,
			state, note, ts, zoneID); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, d := range days {
			if !seen[d.Day] {
				seen[d.Day] = true
				if _, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_security_daily WHERE zone_id = ? AND day = ?`, zoneID, d.Day); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO cloudflare_security_daily (zone_id, day, dim, key, count) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT DO UPDATE SET count = excluded.count`, zoneID, d.Day, d.Dim, d.Key, d.Count); err != nil {
				return err
			}
		}
		cutoff := now.UTC().AddDate(0, 0, -CloudflareKeepDays).Format(time.DateOnly)
		_, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_security_daily WHERE day < ?`, cutoff)
		return err
	})
}

// CloudflareDailyCounts returns a zone's daily counts since day (inclusive).
func (s *Store) CloudflareDailyCounts(ctx context.Context, zoneID, since string) ([]CloudflareDaily, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT day, dim, key, count FROM cloudflare_security_daily
		WHERE zone_id = ? AND day >= ? ORDER BY day, dim, count DESC, key`, zoneID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudflareDaily
	for rows.Next() {
		var d CloudflareDaily
		if err := rows.Scan(&d.Day, &d.Dim, &d.Key, &d.Count); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// PutCloudflareRadar caches Radar's answer for an address.
func (s *Store) PutCloudflareRadar(ctx context.Context, r CloudflareRadar) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cloudflare_radar_asn (ip, asn, name, country, fetched_at) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (ip) DO UPDATE SET asn = excluded.asn, name = excluded.name, country = excluded.country,
			fetched_at = excluded.fetched_at`,
		r.IP, r.ASN, r.Name, r.Country, r.FetchedAt.UTC().Format(timeLayout))
	return err
}

// CloudflareRadarSince returns the cached answers fetched since t, after
// deleting older ones.
func (s *Store) CloudflareRadarSince(ctx context.Context, t time.Time) ([]CloudflareRadar, error) {
	ts := t.UTC().Format(timeLayout)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM cloudflare_radar_asn WHERE fetched_at < ?`, ts); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ip, asn, name, country, fetched_at FROM cloudflare_radar_asn`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudflareRadar
	for rows.Next() {
		var r CloudflareRadar
		var at string
		if err := rows.Scan(&r.IP, &r.ASN, &r.Name, &r.Country, &at); err != nil {
			return nil, err
		}
		r.FetchedAt = parseTime(at)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RecordCloudflareSync notes a sync's run ("edge", "zones", "radar").
func (s *Store) RecordCloudflareSync(ctx context.Context, what string, syncErr error, now time.Time) error {
	msg := ""
	if syncErr != nil {
		msg = syncErr.Error()
		if len(msg) > 500 {
			msg = msg[:500]
		}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cloudflare_syncs (what, at, error) VALUES (?, ?, ?)
		ON CONFLICT (what) DO UPDATE SET at = excluded.at, error = excluded.error`,
		what, now.UTC().Format(timeLayout), msg)
	return err
}

// CloudflareSync is a sync's last run.
type CloudflareSync struct {
	At    time.Time
	Error string
}

// CloudflareSyncs returns each sync's last run, by name.
func (s *Store) CloudflareSyncs(ctx context.Context) (map[string]CloudflareSync, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT what, at, error FROM cloudflare_syncs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]CloudflareSync{}
	for rows.Next() {
		var what, at string
		var c CloudflareSync
		if err := rows.Scan(&what, &at, &c.Error); err != nil {
			return nil, err
		}
		c.At = parseTime(at)
		out[what] = c
	}
	return out, rows.Err()
}

// ReportAddr is a host and the address its last report came from.
type ReportAddr struct {
	OrgID     int64
	Org, Host string
	Addr      netip.Addr
}

// ReportAddrs lists every host with a known report address.
func (s *Store) ReportAddrs(ctx context.Context) ([]ReportAddr, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.org_id, o.slug, h.name, h.report_ip FROM hosts h JOIN organizations o ON o.id = h.org_id
		WHERE h.report_ip <> '' ORDER BY o.slug, h.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReportAddr
	for rows.Next() {
		var a ReportAddr
		var ip string
		if err := rows.Scan(&a.OrgID, &a.Org, &a.Host, &ip); err != nil {
			return nil, err
		}
		if addr, err := netip.ParseAddr(ip); err == nil {
			a.Addr = addr.Unmap()
			out = append(out, a)
		}
	}
	return out, rows.Err()
}

// SiteNames is a site in a host's latest snapshot and its server names.
type SiteNames struct {
	OrgID     int64
	Org, Host string
	Root      string
	Names     []string
}

// AllSiteNames lists every site in every host's latest snapshot.
func (s *Store) AllSiteNames(ctx context.Context) ([]SiteNames, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.org_id, o.slug, h.name, si.root, si.server_names
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN sites si ON si.snapshot_id = h.last_snapshot_id
		ORDER BY o.slug, h.name, si.root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SiteNames
	for rows.Next() {
		var n SiteNames
		var names string
		if err := rows.Scan(&n.OrgID, &n.Org, &n.Host, &n.Root, &names); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(names), &n.Names)
		out = append(out, n)
	}
	return out, rows.Err()
}

// KnownIPPrefixes returns the ranges of every label in every org whose
// kind says something (not unknown), e.g. to tell a leftover DNS record
// from an address someone recognizes.
func (s *Store) KnownIPPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT DISTINCT prefix FROM ip_labels WHERE kind <> ?`, IPKindUnknown)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netip.Prefix
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if pr, err := netip.ParsePrefix(p); err == nil {
			out = append(out, pr)
		}
	}
	return out, rows.Err()
}
