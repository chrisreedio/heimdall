// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Window is a maintenance window: changes and reboots inside it don't
// raise anomalies. Scope is an org, one env, or one host.
type Window struct {
	ID      int64
	OrgID   int64
	OrgSlug string
	EnvSlug string // "" unless env-scoped
	Host    string // "" unless host-scoped
	Name    string
	// One-off windows:
	Starts, Ends time.Time
	// Weekly windows:
	Weekdays  int // bitmask: Sunday=1, Monday=2 … Saturday=64
	StartTime string
	Duration  time.Duration
	Timezone  string
}

func (w Window) Weekly() bool { return w.Weekdays != 0 }

// Overlaps reports whether the window is open at any moment in [from, to].
func (w Window) Overlaps(from, to time.Time) bool {
	if !w.Weekly() {
		return w.Starts.Before(to) && w.Ends.After(from)
	}
	loc, err := time.LoadLocation(w.Timezone)
	if err != nil {
		return false
	}
	hh, mm := 0, 0
	fmt.Sscanf(w.StartTime, "%d:%d", &hh, &mm)
	// Walk each local day from the day before `from` (windows can cross
	// midnight) to `to`, at most 60 days.
	day := from.In(loc).AddDate(0, 0, -1)
	day = time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, loc)
	for i := 0; i < 62 && !day.After(to); i++ {
		if w.Weekdays&(1<<int(day.Weekday())) != 0 {
			start := time.Date(day.Year(), day.Month(), day.Day(), hh, mm, 0, 0, loc)
			if start.Before(to) && start.Add(w.Duration).After(from) {
				return true
			}
		}
		day = day.AddDate(0, 0, 1)
	}
	return false
}

var weekdayNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
var hhmmRe = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// ParseWeekdays turns "sat,sun" or "mon-fri" into a bitmask.
func ParseWeekdays(s string) (int, error) {
	mask := 0
	for part := range strings.SplitSeq(strings.ToLower(s), ",") {
		part = strings.TrimSpace(part)
		a, b, isRange := strings.Cut(part, "-")
		from, ok1 := weekdayNames[a]
		to, ok2 := weekdayNames[b]
		if !isRange {
			to, ok2 = from, ok1
		}
		if !ok1 || !ok2 {
			return 0, &ValidationError{"days", fmt.Sprintf("%q: use sun,mon,…,sat or ranges like mon-fri", part)}
		}
		for d := from; ; d = (d + 1) % 7 {
			mask |= 1 << d
			if d == to {
				break
			}
		}
	}
	return mask, nil
}

// CreateWindow adds a window. Exactly one of (starts, ends) or (weekdays,
// startTime, duration, tz) must be set; envSlug/host narrow the scope.
func (s *Store) CreateWindow(ctx context.Context, actor string, w Window) (int64, error) {
	name, err := normalizeName("name", firstNonEmpty(w.Name, "maintenance"))
	if err != nil {
		return 0, err
	}
	if w.Weekly() {
		if w.Weekdays < 1 || w.Weekdays > 127 || !hhmmRe.MatchString(w.StartTime) ||
			w.Duration < time.Minute || w.Duration > 24*time.Hour {
			return 0, &ValidationError{"window", "weekly windows need days, a HH:MM start and a duration up to 24h"}
		}
		if _, err := time.LoadLocation(w.Timezone); err != nil || w.Timezone == "" {
			return 0, &ValidationError{"timezone", fmt.Sprintf("%q is not an IANA timezone", w.Timezone)}
		}
	} else if w.Starts.IsZero() || !w.Ends.After(w.Starts) || w.Ends.Sub(w.Starts) > 14*24*time.Hour {
		return 0, &ValidationError{"window", "one-off windows need a start before the end, at most 14 days long"}
	}
	var id int64
	err = s.tx(ctx, func(tx *sql.Tx) error {
		org, err := orgIDBySlug(ctx, tx, w.OrgSlug)
		if err != nil {
			return err
		}
		var envID, hostID sql.NullInt64
		if w.EnvSlug != "" {
			var eid int64
			if err := tx.QueryRowContext(ctx, `SELECT id FROM environments WHERE org_id = ? AND slug = ?`, org, w.EnvSlug).Scan(&eid); err != nil {
				return fmt.Errorf("env %q: %w", w.EnvSlug, ErrNotFound)
			}
			envID = sql.NullInt64{Int64: eid, Valid: true}
		}
		if w.Host != "" {
			name, err := normalizeHostName(w.Host)
			if err != nil {
				return err
			}
			var hid int64
			if err := tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE org_id = ? AND name = ?`, org, name).Scan(&hid); err != nil {
				return fmt.Errorf("host %q: %w", name, ErrNotFound)
			}
			hostID = sql.NullInt64{Int64: hid, Valid: true}
		}
		var starts, ends, start, tz sql.NullString
		var days, dur sql.NullInt64
		if w.Weekly() {
			days = sql.NullInt64{Int64: int64(w.Weekdays), Valid: true}
			start = sql.NullString{String: w.StartTime, Valid: true}
			dur = sql.NullInt64{Int64: int64(w.Duration / time.Minute), Valid: true}
			tz = sql.NullString{String: w.Timezone, Valid: true}
		} else {
			starts = sql.NullString{String: w.Starts.UTC().Format(timeLayout), Valid: true}
			ends = sql.NullString{String: w.Ends.UTC().Format(timeLayout), Valid: true}
		}
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO maintenance_windows (org_id, env_id, host_id, name, starts_at, ends_at, weekdays, start_time, duration_minutes, timezone)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			org, envID, hostID, name, starts, ends, days, start, dur, tz).Scan(&id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "window.create", OrgID: org, Target: name,
			Detail: map[string]any{"id": id, "env": w.EnvSlug, "host": w.Host}})
	})
	return id, err
}

// DeleteWindow removes a window.
func (s *Store) DeleteWindow(ctx context.Context, actor string, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var org int64
		if err := tx.QueryRowContext(ctx, `DELETE FROM maintenance_windows WHERE id = ? RETURNING org_id`, id).Scan(&org); err != nil {
			return fmt.Errorf("window %d: %w", id, ErrNotFound)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "window.delete", OrgID: org, Target: strconv.FormatInt(id, 10)})
	})
}

const windowCols = `SELECT w.id, w.org_id, o.slug, coalesce(e.slug, ''), coalesce(h.name, ''), w.name,
	w.starts_at, w.ends_at, coalesce(w.weekdays, 0), coalesce(w.start_time, ''), coalesce(w.duration_minutes, 0),
	coalesce(w.timezone, '')
	FROM maintenance_windows w JOIN organizations o ON o.id = w.org_id
	LEFT JOIN environments e ON e.id = w.env_id LEFT JOIN hosts h ON h.id = w.host_id `

// Windows lists all windows in the scope.
func (s *Store) Windows(ctx context.Context, sc Scope) ([]Window, error) {
	all, err := s.windows(ctx, windowCols+`ORDER BY o.slug, w.id`)
	if err != nil {
		return nil, err
	}
	var out []Window
	for _, w := range all {
		if sc.CanView(w.OrgID) {
			out = append(out, w)
		}
	}
	return out, nil
}

// WindowsFor lists the windows that apply to a host (its org, its env, or it).
func (s *Store) WindowsFor(ctx context.Context, hostID int64) ([]Window, error) {
	return s.windows(ctx, windowCols+`
		JOIN hosts target ON target.id = ? AND target.org_id = w.org_id
		WHERE (w.env_id IS NULL AND w.host_id IS NULL) OR w.env_id = target.env_id OR w.host_id = target.id`, hostID)
}

func (s *Store) windows(ctx context.Context, q string, args ...any) ([]Window, error) {
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Window
	for rows.Next() {
		var w Window
		var starts, ends sql.NullString
		var mins int64
		if err := rows.Scan(&w.ID, &w.OrgID, &w.OrgSlug, &w.EnvSlug, &w.Host, &w.Name, &starts, &ends,
			&w.Weekdays, &w.StartTime, &mins, &w.Timezone); err != nil {
			return nil, err
		}
		w.Starts, w.Ends, w.Duration = parseNullTime(starts), parseNullTime(ends), time.Duration(mins)*time.Minute
		out = append(out, w)
	}
	return out, rows.Err()
}
