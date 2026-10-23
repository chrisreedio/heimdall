// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// User is an account. Kind is "local" (password + TOTP) or "entra" (SSO).
type User struct {
	ID           int64
	Kind         string
	Email        string
	DisplayName  string
	IsAdmin      bool
	PasswordHash string // local only
	TOTPSecret   []byte // local only
	TOTPLastStep int64
	CreatedAt    time.Time
	LastLoginAt  time.Time // zero if never
	Disabled     bool
}

var emailRe = regexp.MustCompile(`^[a-z0-9._%+'-]+@[a-z0-9.-]+\.[a-z]{2,}$`)

// NormalizeEmail trims and lowercases an email and checks its shape.
func NormalizeEmail(email string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(email))
	if len(e) > 254 || !emailRe.MatchString(e) {
		return "", &ValidationError{"email", fmt.Sprintf("%q is not a valid email address", email)}
	}
	return e, nil
}

const userColumns = `id, kind, email, display_name, is_admin, coalesce(password_hash, ''), totp_secret,
	totp_last_step, created_at, last_login_at, disabled_at IS NOT NULL`

func scanUser(row interface{ Scan(...any) error }) (User, error) {
	var u User
	var created string
	var lastLogin sql.NullString
	var admin int64
	err := row.Scan(&u.ID, &u.Kind, &u.Email, &u.DisplayName, &admin, &u.PasswordHash, &u.TOTPSecret,
		&u.TOTPLastStep, &created, &lastLogin, &u.Disabled)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.IsAdmin = admin == 1
	u.CreatedAt, u.LastLoginAt = parseTime(created), parseNullTime(lastLogin)
	return u, nil
}

// CreateLocalUser adds a password + TOTP account.
func (s *Store) CreateLocalUser(ctx context.Context, actor, email, displayName string, isAdmin bool, passwordHash string, totpSecret []byte) (int64, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return 0, err
	}
	if displayName != "" {
		if displayName, err = normalizeName("name", displayName); err != nil {
			return 0, err
		}
	}
	if passwordHash == "" || len(totpSecret) == 0 {
		return 0, errors.New("a password hash and TOTP secret are required")
	}
	var id int64
	err = s.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, `
			INSERT INTO users (kind, email, display_name, is_admin, password_hash, totp_secret)
			VALUES ('local', ?, ?, ?, ?, ?) RETURNING id`,
			email, displayName, boolInt(isAdmin), passwordHash, totpSecret).Scan(&id)
		if isUnique(err) {
			return fmt.Errorf("user %s: %w", email, ErrExists)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "user.create", Target: email,
			Detail: map[string]any{"admin": isAdmin}})
	})
	return id, err
}

// LocalUserByEmail finds a local account by (normalized) email.
func (s *Store) LocalUserByEmail(ctx context.Context, email string) (User, error) {
	email, err := NormalizeEmail(email)
	if err != nil {
		return User{}, ErrNotFound
	}
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE kind = 'local' AND email = ?`, email))
}

func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY email`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// updateLocalUser runs one UPDATE on a local user, drops their sessions
// and writes an audit entry, all in one transaction.
func (s *Store) updateLocalUser(ctx context.Context, actor, email, action, set string, detail map[string]any, args ...any) error {
	email, err := NormalizeEmail(email)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM users WHERE kind = 'local' AND email = ?`, email).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("user %s: %w", email, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET `+set+` WHERE id = ?`, append(args, id)...); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, Target: email, Detail: detail})
	})
}

// SetUserDisabled disables or re-enables a local user. Disabling ends
// their sessions.
// Works for local and Entra users; their sessions end.
func (s *Store) SetUserDisabled(ctx context.Context, actor, email string, disabled bool) error {
	set, action := `disabled_at = NULL`, "user.enable"
	if disabled {
		set, action = `disabled_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, "user.disable"
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		uid, err := userIDByEmail(ctx, tx, email)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET `+set+` WHERE id = ?`, uid); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, uid); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, Target: email})
	})
}

// SetPassword replaces a local user's password hash and ends their sessions.
func (s *Store) SetPassword(ctx context.Context, actor, email, passwordHash string) error {
	if passwordHash == "" {
		return errors.New("password hash is required")
	}
	return s.updateLocalUser(ctx, actor, email, "user.password", `password_hash = ?`, nil, passwordHash)
}

// SetTOTP replaces a local user's TOTP secret, resets replay protection
// and ends their sessions.
func (s *Store) SetTOTP(ctx context.Context, actor, email string, secret []byte) error {
	if len(secret) == 0 {
		return errors.New("TOTP secret is required")
	}
	return s.updateLocalUser(ctx, actor, email, "user.totp_reset", `totp_secret = ?, totp_last_step = 0`, nil, secret)
}

// AcceptTOTPStep atomically records step as used. It returns false if the
// step (or a later one) was already used: a replayed code.
func (s *Store) AcceptTOTPStep(ctx context.Context, userID, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx,
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Audit writes a standalone audit entry.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	return s.tx(ctx, func(tx *sql.Tx) error { return audit(ctx, tx, e) })
}
