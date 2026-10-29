// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Failed SSH logins, as each server's opt-in login watch counts them
// (docs/failed-logins.md). Counts only: never usernames or log lines.

// LoginRetention is how long failed-login counts are kept.
const LoginRetention = 30 * 24 * time.Hour

// LoginReport is what one push said about failed logins.
type LoginReport struct {
	Source    string    // where the server read them: journal, auth.log, secure, messages, none, unreadable
	CountedAt time.Time // when the server last counted (zero if unknown)
	Days      []LoginDay
}

// LoginDay is one UTC day's counts on a server.
type LoginDay struct {
	Day       string // 2026-10-24
	Failures  int    // every failure that day, including addresses not listed
	Addresses int    // how many addresses failed
	Rows      []LoginFailure
}

// LoginFailure is failed logins from one address: on one host and day as
// reported, or summed over a window by the queries below.
type LoginFailure struct {
	IP        string
	Failures  int
	Usernames int // distinct usernames tried (the most on any one day)
	First     time.Time
	Last      time.Time
	Succeeded bool // a login from it succeeded after it failed (the same day)
}

// RecordLogins stores a host's report. Servers resend today's and
// yesterday's counts on every push, and counts only grow, so each row
// keeps the larger of what it had and what came: a resend never counts
// twice. Rows older than LoginRetention are deleted, for every host.
func (s *Store) RecordLogins(ctx context.Context, hostID int64, rep LoginReport, now time.Time) error {
	counted := int64(0)
	if !rep.CountedAt.IsZero() {
		counted = rep.CountedAt.Unix()
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO login_watch (host_id, source, counted_at, reported_at) VALUES (?, ?, ?, ?)
			ON CONFLICT (host_id) DO UPDATE SET source = excluded.source, counted_at = excluded.counted_at,
				reported_at = excluded.reported_at`, hostID, rep.Source, counted, now.UTC().Format(timeLayout)); err != nil {
			return err
		}
		for _, d := range rep.Days {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO login_failure_days (host_id, day, failures, addresses) VALUES (?, ?, ?, ?)
				ON CONFLICT (host_id, day) DO UPDATE SET failures = max(failures, excluded.failures),
					addresses = max(addresses, excluded.addresses)`, hostID, d.Day, d.Failures, d.Addresses); err != nil {
				return err
			}
			for _, r := range d.Rows {
				if _, err := tx.ExecContext(ctx, `
					INSERT INTO login_failures (host_id, day, ip, failures, usernames, first_at, last_at, succeeded)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT (host_id, day, ip) DO UPDATE SET failures = max(failures, excluded.failures),
						usernames = max(usernames, excluded.usernames), first_at = min(first_at, excluded.first_at),
						last_at = max(last_at, excluded.last_at), succeeded = max(succeeded, excluded.succeeded)`,
					hostID, d.Day, r.IP, r.Failures, r.Usernames, r.First.Unix(), r.Last.Unix(), r.Succeeded); err != nil {
					return err
				}
			}
		}
		cutoff := now.Add(-LoginRetention).UTC().Format(time.DateOnly)
		if _, err := tx.ExecContext(ctx, `DELETE FROM login_failures WHERE day < ?`, cutoff); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM login_failure_days WHERE day < ?`, cutoff)
		return err
	})
}

// LoginWatch is the last report of a host's login watch.
type LoginWatch struct {
	Source     string // "" if it never reported one
	CountedAt  time.Time
	ReportedAt time.Time
}

// LoginWatchOf returns a host's login watch state (zero if none).
func (s *Store) LoginWatchOf(ctx context.Context, hostID int64) (LoginWatch, error) {
	var w LoginWatch
	var counted int64
	var reported string
	err := s.rd.QueryRowContext(ctx, `SELECT source, counted_at, reported_at FROM login_watch WHERE host_id = ?`, hostID).
		Scan(&w.Source, &counted, &reported)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginWatch{}, nil
	}
	if counted > 0 {
		w.CountedAt = time.Unix(counted, 0).UTC()
	}
	w.ReportedAt = parseTime(reported)
	return w, err
}

// HostLoginFailure is failed logins from one address on one host.
type HostLoginFailure struct {
	Host IngestHost
	LoginFailure
}

// LoginFailuresSince sums failed logins by host and address over the days
// with a failure since a time, on hosts the scope can view. hostID 0 is
// every such host; ip "" is every address. Most failures first.
func (s *Store) LoginFailuresSince(ctx context.Context, sc Scope, hostID int64, ip string, since time.Time) ([]HostLoginFailure, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, h.name, f.ip, sum(f.failures), max(f.usernames), min(f.first_at), max(f.last_at), max(f.succeeded)
		FROM login_failures f JOIN hosts h ON h.id = f.host_id JOIN organizations o ON o.id = h.org_id
		WHERE f.last_at >= ? AND (? = 0 OR f.host_id = ?) AND (? = '' OR f.ip = ?)
		GROUP BY f.host_id, f.ip ORDER BY sum(f.failures) DESC, f.ip`, since.Unix(), hostID, hostID, ip, ip)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostLoginFailure
	for rows.Next() {
		var r HostLoginFailure
		var first, last int64
		if err := rows.Scan(&r.Host.ID, &r.Host.OrgID, &r.Host.OrgSlug, &r.Host.Name, &r.IP, &r.Failures, &r.Usernames,
			&first, &last, &r.Succeeded); err != nil {
			return nil, err
		}
		if !sc.CanView(r.Host.OrgID) {
			continue
		}
		r.First, r.Last = time.Unix(first, 0).UTC(), time.Unix(last, 0).UTC()
		out = append(out, r)
	}
	return out, rows.Err()
}

// LoginDayTotals sums each day's reported totals (every failure, listed
// address or not) since a UTC day, on hosts the scope can view: one org's
// (org "" every org's), one host (hostID 0 every host).
func (s *Store) LoginDayTotals(ctx context.Context, sc Scope, org string, hostID int64, sinceDay string) (failures int, err error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT h.org_id, sum(d.failures) FROM login_failure_days d JOIN hosts h ON h.id = d.host_id
		JOIN organizations o ON o.id = h.org_id
		WHERE d.day >= ? AND (? = 0 OR d.host_id = ?) AND (? = '' OR o.slug = ?) GROUP BY d.host_id`,
		sinceDay, hostID, hostID, org, org)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var org int64
		var n int
		if err := rows.Scan(&org, &n); err != nil {
			return 0, err
		}
		if sc.CanView(org) {
			failures += n
		}
	}
	return failures, rows.Err()
}

// LoginDaysFor counts, per address, the distinct UTC days with a failure
// since a time, on hosts the scope can view: one org's (org "" every
// org's). With AllScope and every org it's LoginDays.
func (s *Store) LoginDaysFor(ctx context.Context, sc Scope, org string, since time.Time) (map[string]int, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT f.ip, h.org_id, f.day FROM login_failures f JOIN hosts h ON h.id = f.host_id
		JOIN organizations o ON o.id = h.org_id
		WHERE f.last_at >= ? AND (? = '' OR o.slug = ?) GROUP BY f.ip, h.org_id, f.day`, since.Unix(), org, org)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	days := map[string]map[string]bool{}
	for rows.Next() {
		var ip, day string
		var orgID int64
		if err := rows.Scan(&ip, &orgID, &day); err != nil {
			return nil, err
		}
		if !sc.CanView(orgID) {
			continue
		}
		if days[ip] == nil {
			days[ip] = map[string]bool{}
		}
		days[ip][day] = true
	}
	out := make(map[string]int, len(days))
	for ip, d := range days {
		out[ip] = len(d)
	}
	return out, rows.Err()
}

// RadarCached returns what's cached from Cloudflare Radar for these
// addresses, by address. It never asks Radar: only what's already known.
func (s *Store) RadarCached(ctx context.Context, ips []string) (map[string]CloudflareRadar, error) {
	out := map[string]CloudflareRadar{}
	for len(ips) > 0 {
		n := min(len(ips), 500)
		args := make([]any, n)
		for i, ip := range ips[:n] {
			args[i] = ip
		}
		ips = ips[n:]
		rows, err := s.rd.QueryContext(ctx, `SELECT ip, asn, name, country, fetched_at FROM cloudflare_radar_asn
			WHERE asn > 0 AND ip IN (?`+strings.Repeat(", ?", n-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var r CloudflareRadar
			var at string
			if err := rows.Scan(&r.IP, &r.ASN, &r.Name, &r.Country, &at); err != nil {
				rows.Close()
				return nil, err
			}
			r.FetchedAt = parseTime(at)
			out[r.IP] = r
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
