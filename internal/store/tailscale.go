// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// TailnetDevice is one device on the tailnet, as the Tailscale API listed
// it at the last sync (see internal/tailscale).
type TailnetDevice struct {
	ID                string
	Name              string // MagicDNS name, e.g. web-01.tail1234.ts.net
	Hostname          string
	Addresses         []string
	User              string // owner's login; empty for tagged devices
	Tags              []string
	OS                string
	ClientVersion     string
	UpdateAvailable   bool
	Online            bool // connected to the control server
	LastSeen          time.Time
	KeyExpiry         time.Time // zero when key expiry is disabled
	KeyExpiryDisabled bool
	SyncedAt          time.Time
}

// TailnetSync is the Tailscale sync's state.
type TailnetSync struct {
	AttemptedAt time.Time
	SyncedAt    time.Time // last good sync; zero if never
	Error       string    // the last attempt's, "" if it worked
	Devices     int
	Credential  string    // "oauth" or "api-key"
	KeyExpires  time.Time // an API access token's expiry, when known
}

func tailnetTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

func tailnetParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	return parseTime(s)
}

// ReplaceTailnetDevices makes the stored devices exactly devs and records a
// good sync, in one transaction.
func (s *Store) ReplaceTailnetDevices(ctx context.Context, devs []TailnetDevice, credential string, keyExpires, now time.Time) error {
	ts := tailnetTime(now)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM tailscale_devices`); err != nil {
			return err
		}
		for _, d := range devs {
			if _, err := tx.ExecContext(ctx, `
				INSERT OR REPLACE INTO tailscale_devices (id, name, hostname, addresses, user_login, tags, os, client_version,
					update_available, online, last_seen, key_expiry, key_expiry_disabled, synced_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				d.ID, d.Name, d.Hostname, strings.Join(d.Addresses, " "), d.User, strings.Join(d.Tags, " "), d.OS, d.ClientVersion,
				d.UpdateAvailable, d.Online, tailnetTime(d.LastSeen), tailnetTime(d.KeyExpiry), d.KeyExpiryDisabled, ts); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tailscale_sync (id, attempted_at, synced_at, error, devices, credential, key_expires)
			VALUES (1, ?, ?, '', ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET attempted_at = excluded.attempted_at, synced_at = excluded.synced_at,
				error = '', devices = excluded.devices, credential = excluded.credential, key_expires = excluded.key_expires`,
			ts, ts, len(devs), credential, tailnetTime(keyExpires))
		return err
	})
}

// RecordTailnetSyncError notes a failed sync; the last good devices stay.
func (s *Store) RecordTailnetSyncError(ctx context.Context, msg string, now time.Time) error {
	if len(msg) > 500 {
		msg = msg[:500]
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO tailscale_sync (id, attempted_at, error) VALUES (1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET attempted_at = excluded.attempted_at, error = excluded.error`, tailnetTime(now), msg)
	return err
}

// TailnetSyncState returns the sync's state (zero if it never ran).
func (s *Store) TailnetSyncState(ctx context.Context) (TailnetSync, error) {
	var st TailnetSync
	var att, synced, keyExp string
	err := s.rd.QueryRowContext(ctx, `
		SELECT attempted_at, synced_at, error, devices, credential, key_expires FROM tailscale_sync WHERE id = 1`).
		Scan(&att, &synced, &st.Error, &st.Devices, &st.Credential, &keyExp)
	if err == sql.ErrNoRows {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	st.AttemptedAt, st.SyncedAt, st.KeyExpires = tailnetParseTime(att), tailnetParseTime(synced), tailnetParseTime(keyExp)
	return st, nil
}

// TailnetDevices returns the devices from the last good sync, by name.
func (s *Store) TailnetDevices(ctx context.Context) ([]TailnetDevice, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT id, name, hostname, addresses, user_login, tags, os, client_version, update_available, online,
			last_seen, key_expiry, key_expiry_disabled, synced_at
		FROM tailscale_devices ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TailnetDevice
	for rows.Next() {
		var d TailnetDevice
		var addrs, tags, seen, exp, synced string
		if err := rows.Scan(&d.ID, &d.Name, &d.Hostname, &addrs, &d.User, &tags, &d.OS, &d.ClientVersion, &d.UpdateAvailable,
			&d.Online, &seen, &exp, &d.KeyExpiryDisabled, &synced); err != nil {
			return nil, err
		}
		d.Addresses, d.Tags = strings.Fields(addrs), strings.Fields(tags)
		d.LastSeen, d.KeyExpiry, d.SyncedAt = tailnetParseTime(seen), tailnetParseTime(exp), tailnetParseTime(synced)
		out = append(out, d)
	}
	return out, rows.Err()
}

// TailnetHost is what matching a host to a tailnet device needs.
type TailnetHost struct {
	ID, OrgID int64
	Name      string
	ReportIP  string // where its last report came from; "" if unknown
}

// TailnetHosts lists every host (all orgs) for matching to devices.
func (s *Store) TailnetHosts(ctx context.Context) ([]TailnetHost, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT id, org_id, name, report_ip FROM hosts ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TailnetHost
	for rows.Next() {
		var h TailnetHost
		if err := rows.Scan(&h.ID, &h.OrgID, &h.Name, &h.ReportIP); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// HostReportIP is the address a host's last report came from ("" if
// unknown).
func (s *Store) HostReportIP(ctx context.Context, hostID int64) (string, error) {
	var ip string
	err := s.rd.QueryRowContext(ctx, `SELECT report_ip FROM hosts WHERE id = ?`, hostID).Scan(&ip)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return ip, err
}
