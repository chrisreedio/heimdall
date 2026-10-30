// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Settings are hub-wide options an admin changes in the UI, as strings by
// key. A setting that was never changed has no row, so the caller's
// default applies.

// Setting returns a setting's value, and false when it was never set.
func (s *Store) Setting(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.rd.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetSetting stores a setting and audits the change as "setting.<key>",
// with the old value (when there was one) and the new.
func (s *Store) SetSetting(ctx context.Context, actor, key, value string, now time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		detail := map[string]any{"value": value}
		var was string
		switch err := tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&was); {
		case err == nil:
			detail["was"] = was
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
			key, value, now.UTC().Format(timeLayout)); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "setting." + key, Detail: detail})
	})
}
