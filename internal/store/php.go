// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"time"
)

// HostPHP is what a host's collector said about its PHP versions: the
// command line's (CLI, "" for none) and those whose PHP-FPM is running.
type HostPHP struct {
	CLI    string
	FPM    []string
	SeenAt time.Time
}

// phpMinor is a PHP version as the collector reports it, e.g. "8.4".
var phpMinor = regexp.MustCompile(`^[5-9]\.[0-9]{1,2}$`)

// ValidPHPVersion reports whether v looks like "8.4".
func ValidPHPVersion(v string) bool { return phpMinor.MatchString(v) }

// SetHostPHP records a host's PHP state. Versions that don't look like
// one are dropped.
func (s *Store) SetHostPHP(ctx context.Context, hostID int64, cli string, fpm []string, at time.Time) error {
	if !ValidPHPVersion(cli) {
		cli = ""
	}
	clean := []string{}
	for _, v := range fpm {
		if ValidPHPVersion(v) && !slices.Contains(clean, v) && len(clean) < 20 {
			clean = append(clean, v)
		}
	}
	slices.Sort(clean)
	b, _ := json.Marshal(clean)
	_, err := s.db.ExecContext(ctx, `INSERT INTO host_php (host_id, cli, fpm, seen_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (host_id) DO UPDATE SET cli = excluded.cli, fpm = excluded.fpm, seen_at = excluded.seen_at`,
		hostID, cli, string(b), at.UTC().Format(timeLayout))
	return err
}

// HostPHPs is every host's PHP state, by host ID; hosts whose collector
// never reported it are absent.
func (s *Store) HostPHPs(ctx context.Context) (map[int64]HostPHP, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT host_id, cli, fpm, seen_at FROM host_php`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]HostPHP{}
	for rows.Next() {
		var id int64
		var p HostPHP
		var fpm, at string
		if err := rows.Scan(&id, &p.CLI, &fpm, &at); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(fpm), &p.FPM)
		p.SeenAt = parseTime(at)
		out[id] = p
	}
	return out, rows.Err()
}
