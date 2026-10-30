// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Branding is how the hub presents itself: what an admin set on the
// settings page. Zero values are Heimdall's own.
type Branding struct {
	Name   string // display name, up to 30 characters
	Accent string // "#rrggbb", lowercase
	// AccentDark is the dark theme's accent, when an admin picked one;
	// otherwise the UI derives it from Accent.
	AccentDark string
	Logo       []byte // PNG
	// The app icon, at the sizes browsers ask for: 512 and 192 for the
	// manifest, 180 for iOS (apple-touch-icon), 32 for the favicon.
	Icon512, Icon192, Icon180, Icon32 []byte
	Version                           int64 // goes up with every change
	UpdatedAt                         time.Time
}

// Branding returns the hub's branding (the zero Branding when none is set).
func (s *Store) Branding(ctx context.Context) (Branding, error) {
	var b Branding
	var at string
	err := s.rd.QueryRowContext(ctx, `
		SELECT name, accent, accent_dark, logo, icon_512, icon_192, icon_180, icon_32, version, updated_at
		FROM branding WHERE id = 1`).
		Scan(&b.Name, &b.Accent, &b.AccentDark, &b.Logo, &b.Icon512, &b.Icon192, &b.Icon180, &b.Icon32, &b.Version, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return Branding{}, nil
	}
	if err != nil {
		return Branding{}, err
	}
	b.UpdatedAt = parseTime(at)
	return b, nil
}

// SetBranding replaces the branding, bumps its version and audits the
// change as "branding.<what>" with detail. It returns the new version.
func (s *Store) SetBranding(ctx context.Context, actor string, b Branding, what string, detail map[string]any, now time.Time) (int64, error) {
	if len([]rune(b.Name)) > 30 {
		return 0, &ValidationError{"name", "must be 30 characters or fewer"}
	}
	var version int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO branding (id, name, accent, accent_dark, logo, icon_512, icon_192, icon_180, icon_32, version, updated_at)
			VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
			ON CONFLICT (id) DO UPDATE SET name = excluded.name, accent = excluded.accent,
				accent_dark = excluded.accent_dark, logo = excluded.logo,
				icon_512 = excluded.icon_512, icon_192 = excluded.icon_192, icon_180 = excluded.icon_180,
				icon_32 = excluded.icon_32, version = branding.version + 1, updated_at = excluded.updated_at
			RETURNING version`,
			b.Name, b.Accent, b.AccentDark, nullBlob(b.Logo), nullBlob(b.Icon512), nullBlob(b.Icon192), nullBlob(b.Icon180),
			nullBlob(b.Icon32), now.UTC().Format(timeLayout)).Scan(&version); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "branding." + what, Detail: detail})
	})
	return version, err
}

// nullBlob stores an empty image as NULL.
func nullBlob(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
