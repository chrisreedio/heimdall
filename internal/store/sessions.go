// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Session is a signed-in browser session. Only the token's hash is stored.
type Session struct {
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
}

// CreateSession stores a session for a token hash and records the login.
func (s *Store) CreateSession(ctx context.Context, hash [32]byte, userID int64, now, expires time.Time, ip, userAgent string) error {
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, hash[:], userID, ts, ts, expires.UTC().Format(timeLayout), ip, userAgent); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, ts, userID)
		return err
	})
}

// SessionByHash returns a session and its user. ErrNotFound if unknown.
func (s *Store) SessionByHash(ctx context.Context, hash [32]byte) (Session, User, error) {
	var sess Session
	var created, seen, expires string
	err := s.rd.QueryRowContext(ctx,
		`SELECT user_id, created_at, last_seen_at, expires_at FROM sessions WHERE id_hash = ?`, hash[:]).
		Scan(&sess.UserID, &created, &seen, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, err
	}
	sess.CreatedAt, sess.LastSeenAt, sess.ExpiresAt = parseTime(created), parseTime(seen), parseTime(expires)
	u, err := s.UserByID(ctx, sess.UserID)
	if err != nil {
		return Session{}, User{}, err
	}
	return sess, u, nil
}

// TouchSession records activity on a session.
func (s *Store) TouchSession(ctx context.Context, hash [32]byte, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?`,
		at.UTC().Format(timeLayout), hash[:])
	return err
}

// DeleteSession removes a session; deleting an unknown one is not an error.
func (s *Store) DeleteSession(ctx context.Context, hash [32]byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, hash[:])
	return err
}

// DeleteExpiredSessions removes sessions past their absolute expiry.
func (s *Store) DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.UTC().Format(timeLayout))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
