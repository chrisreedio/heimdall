// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// Web offenders: client addresses Cloudflare blocked or challenged, per
// zone and UTC day (internal/cloudflare, docs/cloudflare.md). Friendly
// addresses are filtered out before they get here.

// WebOffenderRetention is how long web offender rows are kept: as long as
// failed logins, so the two halves of the threat list cover the same time.
const WebOffenderRetention = LoginRetention

// WebOffenderDay is one zone's acted-on events from one address on one day.
type WebOffenderDay struct {
	IP          string
	Events      int
	Actions     map[string]int
	First, Last time.Time
	ASN         int64
	ASName      string
	Country     string
}

// WebDay is a zone's offenders for one UTC day, as fetched. Final: the
// day had ended (and settled) when fetched, so it isn't asked for again.
// Sampled: from capped raw events, so counts are a floor.
type WebDay struct {
	Day            string // 2026-10-24
	Final, Sampled bool
	Rows           []WebOffenderDay
}

// RecordWebOffenders replaces each fetched day's rows for a zone (a day is
// always fetched whole, so a refetch never counts twice) and marks the
// days fetched. Rows and days older than WebOffenderRetention are deleted,
// for every zone.
func (s *Store) RecordWebOffenders(ctx context.Context, zoneID string, days []WebDay, now time.Time) error {
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		for _, d := range days {
			if _, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_web_offenders WHERE zone_id = ? AND day = ?`, zoneID, d.Day); err != nil {
				return err
			}
			for _, r := range d.Rows {
				if r.Events <= 0 {
					continue
				}
				acts, _ := json.Marshal(r.Actions)
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO cloudflare_web_offenders (zone_id, day, ip, events, actions, first_at, last_at, asn, as_name, country, sampled)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT (zone_id, day, ip) DO UPDATE SET events = excluded.events, actions = excluded.actions,
						first_at = excluded.first_at, last_at = excluded.last_at, asn = excluded.asn, as_name = excluded.as_name,
						country = excluded.country, sampled = excluded.sampled`,
					zoneID, d.Day, r.IP, r.Events, string(acts), r.First.Unix(), r.Last.Unix(), r.ASN, r.ASName, r.Country, d.Sampled); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO cloudflare_web_days (zone_id, day, final, sampled, fetched_at) VALUES (?, ?, ?, ?, ?)
				ON CONFLICT (zone_id, day) DO UPDATE SET final = excluded.final, sampled = excluded.sampled,
					fetched_at = excluded.fetched_at`, zoneID, d.Day, d.Final, d.Sampled, ts); err != nil {
				return err
			}
		}
		cutoff := now.Add(-WebOffenderRetention).UTC().Format(time.DateOnly)
		if _, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_web_offenders WHERE day < ?`, cutoff); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_web_days WHERE day < ?`, cutoff)
		return err
	})
}

// WebFinalDays returns the zone's days since sinceDay that were fetched
// final.
func (s *Store) WebFinalDays(ctx context.Context, zoneID, sinceDay string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT day FROM cloudflare_web_days WHERE zone_id = ? AND day >= ? AND final = 1`, zoneID, sinceDay)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			return nil, err
		}
		out[d] = true
	}
	return out, rows.Err()
}

// WebOffenderIPs lists every stored web offender address.
func (s *Store) WebOffenderIPs(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT ip FROM cloudflare_web_offenders ORDER BY ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

// DeleteWebOffenderIPs deletes every row of these addresses, e.g. ones
// that have since become known.
func (s *Store) DeleteWebOffenderIPs(ctx context.Context, ips []string) error {
	for len(ips) > 0 {
		n := min(len(ips), 500)
		args := make([]any, n)
		for i, ip := range ips[:n] {
			args[i] = ip
		}
		ips = ips[n:]
		if _, err := s.db.ExecContext(ctx, `DELETE FROM cloudflare_web_offenders WHERE ip IN (?`+strings.Repeat(", ?", n-1)+`)`, args...); err != nil {
			return err
		}
	}
	return nil
}

// SetCloudflareZoneOrgs makes the zone-to-org mapping exactly orgs (zone
// ID → org IDs). Zones or orgs that no longer exist are skipped.
func (s *Store) SetCloudflareZoneOrgs(ctx context.Context, orgs map[string][]int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_zone_orgs`); err != nil {
			return err
		}
		for zone, ids := range orgs {
			for _, id := range ids {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO cloudflare_zone_orgs (zone_id, org_id)
					SELECT ?, ? WHERE EXISTS (SELECT 1 FROM cloudflare_zones WHERE id = ?)
						AND EXISTS (SELECT 1 FROM organizations WHERE id = ?)
					ON CONFLICT DO NOTHING`, zone, id, zone, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// WebOffender is one address's acted-on web events, summed over zones and
// days.
type WebOffender struct {
	IP          string
	Events      int            // acted-on events in the window
	Actions     map[string]int // per action
	Zones       []string       // zone names
	Days        int            // distinct UTC days seen
	First, Last time.Time
	ASN         int64
	ASName      string
	Country     string
}

// WebOffenders aggregates per IP since `since`. org "" means every zone;
// otherwise only zones mapped to that org (its slug): zones whose records
// lead to the org's hosts or sites. Most events first. The network and
// country are the latest day's.
func (s *Store) WebOffenders(ctx context.Context, org string, since time.Time) ([]WebOffender, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT w.ip, w.day, z.name, w.events, w.actions, w.first_at, w.last_at, w.asn, w.as_name, w.country
		FROM cloudflare_web_offenders w JOIN cloudflare_zones z ON z.id = w.zone_id
		WHERE w.last_at >= ? AND (? = '' OR w.zone_id IN (
			SELECT zo.zone_id FROM cloudflare_zone_orgs zo JOIN organizations o ON o.id = zo.org_id WHERE o.slug = ?))
		ORDER BY w.ip, w.day`, since.Unix(), org, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]*WebOffender{}
	days := map[string]map[string]bool{}
	var order []string
	for rows.Next() {
		var ip, day, zone, acts string
		var events int
		var first, last, asn int64
		var asName, country string
		if err := rows.Scan(&ip, &day, &zone, &events, &acts, &first, &last, &asn, &asName, &country); err != nil {
			return nil, err
		}
		o := by[ip]
		if o == nil {
			o = &WebOffender{IP: ip, Actions: map[string]int{}, First: time.Unix(first, 0).UTC()}
			by[ip], days[ip] = o, map[string]bool{}
			order = append(order, ip)
		}
		o.Events += events
		var m map[string]int
		json.Unmarshal([]byte(acts), &m)
		for a, n := range m {
			o.Actions[a] += n
		}
		if !slices.Contains(o.Zones, zone) {
			o.Zones = append(o.Zones, zone)
		}
		days[ip][day] = true
		if t := time.Unix(first, 0).UTC(); t.Before(o.First) {
			o.First = t
		}
		if t := time.Unix(last, 0).UTC(); t.After(o.Last) {
			o.Last = t
		}
		if asn != 0 || country != "" { // rows come by day: the latest wins
			o.ASN, o.ASName, o.Country = asn, asName, country
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]WebOffender, 0, len(order))
	for _, ip := range order {
		o := by[ip]
		o.Days = len(days[ip])
		slices.Sort(o.Zones)
		out = append(out, *o)
	}
	slices.SortStableFunc(out, func(a, b WebOffender) int {
		if c := cmp.Compare(b.Events, a.Events); c != 0 {
			return c
		}
		return cmp.Compare(a.IP, b.IP)
	})
	return out, nil
}
