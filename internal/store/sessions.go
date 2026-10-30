// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"time"
)

// Session is a signed-in browser session. Only the token's hash is stored.
type Session struct {
	UserID     int64
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	Kept       bool // "Keep me signed in on this device": renewed on use
}

// CreateSession stores a session for a token hash and records the login.
func (s *Store) CreateSession(ctx context.Context, hash [32]byte, userID int64, now, expires time.Time, ip, userAgent string) error {
	return s.createSession(ctx, hash, userID, now, expires, ip, userAgent, false)
}

// CreateDeviceSession is CreateSession for a kept session (one that
// TouchDeviceSession renews).
func (s *Store) CreateDeviceSession(ctx context.Context, hash [32]byte, userID int64, now, expires time.Time, ip, userAgent string) error {
	return s.createSession(ctx, hash, userID, now, expires, ip, userAgent, true)
}

func (s *Store) createSession(ctx context.Context, hash [32]byte, userID int64, now, expires time.Time, ip, userAgent string, kept bool) error {
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}
	ts := now.UTC().Format(timeLayout)
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO sessions (id_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent, kept, label)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, hash[:], userID, ts, ts, expires.UTC().Format(timeLayout), ip, userAgent,
			kept, DeviceLabel(userAgent)); err != nil {
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
		`SELECT user_id, created_at, last_seen_at, expires_at, kept FROM sessions WHERE id_hash = ?`, hash[:]).
		Scan(&sess.UserID, &created, &seen, &expires, &sess.Kept)
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

// TouchDeviceSession records activity on a kept session and moves its
// expiry out to expires.
func (s *Store) TouchDeviceSession(ctx context.Context, hash [32]byte, at, expires time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id_hash = ? AND kept = 1`,
		at.UTC().Format(timeLayout), expires.UTC().Format(timeLayout), hash[:])
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

// ── Devices ────────────────────────────────────────────────────────────────

// SessionInfo is a session as the Devices list shows it. Ref names it for
// revoking: the start of the token's hash, which reveals nothing usable.
type SessionInfo struct {
	Ref        string
	UserID     int64
	Label      string // "iPhone Safari"
	IP         string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	Kept       bool
}

// SessionRef is the Ref of the session with this token hash.
func SessionRef(hash [32]byte) string { return hex.EncodeToString(hash[:8]) }

// UserSessions lists a user's sessions that haven't reached their absolute
// expiry, most recently used first.
func (s *Store) UserSessions(ctx context.Context, userID int64, now time.Time) ([]SessionInfo, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT id_hash, user_id, label, user_agent, ip, created_at, last_seen_at, expires_at, kept
		FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY last_seen_at DESC LIMIT 200`,
		userID, now.UTC().Format(timeLayout))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionInfo
	for rows.Next() {
		var si SessionInfo
		var hash []byte
		var ua, created, seen, expires string
		if err := rows.Scan(&hash, &si.UserID, &si.Label, &ua, &si.IP, &created, &seen, &expires, &si.Kept); err != nil {
			return nil, err
		}
		if len(hash) == 32 {
			si.Ref = SessionRef([32]byte(hash))
		}
		if si.Label == "" {
			si.Label = DeviceLabel(ua)
		}
		si.CreatedAt, si.LastSeenAt, si.ExpiresAt = parseTime(created), parseTime(seen), parseTime(expires)
		out = append(out, si)
	}
	return out, rows.Err()
}

// RevokeSession ends one of a user's sessions, by Ref, and audits it.
// ErrNotFound if the user has no such session.
func (s *Store) RevokeSession(ctx context.Context, actor string, userID int64, ref, ip string) error {
	if len(ref) != 16 || strings.Trim(ref, "0123456789abcdef") != "" {
		return ErrNotFound
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var label string
		err := tx.QueryRowContext(ctx, `
			DELETE FROM sessions WHERE user_id = ? AND lower(hex(substr(id_hash, 1, 8))) = ? RETURNING label`,
			userID, ref).Scan(&label)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "session.revoke", Target: UserRef(userID), IP: ip,
			Detail: map[string]any{"session": ref, "device": label}})
	})
}

// DeviceLabel describes a browser from its User-Agent in a few words:
// "iPhone Safari", "Android Chrome", "Windows Edge". Only for showing
// people which session is which; User-Agents are easy to fake.
func DeviceLabel(ua string) string {
	has := func(s string) bool { return strings.Contains(ua, s) }
	var device string
	switch {
	case has("iPhone"):
		device = "iPhone"
	case has("iPad"):
		device = "iPad"
	case has("Android"):
		device = "Android"
	case has("Windows"):
		device = "Windows"
	case has("CrOS"):
		device = "ChromeOS"
	case has("Macintosh"), has("Mac OS X"):
		device = "Mac"
	case has("Linux"):
		device = "Linux"
	}
	var browser string
	switch {
	case has("Edg/"), has("EdgA/"), has("EdgiOS/"):
		browser = "Edge"
	case has("OPR/"), has("Opera"):
		browser = "Opera"
	case has("SamsungBrowser/"):
		browser = "Samsung Internet"
	case has("Firefox/"), has("FxiOS/"):
		browser = "Firefox"
	case has("Chrome/"), has("CriOS/"), has("Chromium/"):
		browser = "Chrome"
	case has("Safari/"), device == "iPhone" || device == "iPad":
		browser = "Safari"
	}
	switch {
	case device != "" && browser != "":
		return device + " " + browser
	case device != "":
		return device + " browser"
	case browser != "":
		return browser
	case ua == "":
		return "Unknown device"
	}
	return "Other browser"
}
