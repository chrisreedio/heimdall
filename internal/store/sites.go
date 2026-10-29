// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
)

// SiteLabels are the labels an admin can give a site.
var SiteLabels = []string{"production", "staging", "development"}

// SiteLabelKey identifies a site for SiteLabelsByName.
func SiteLabelKey(org, host, root string) string { return org + "\x00" + host + "\x00" + root }

// SiteLabelsByName returns the labels set for sites, keyed by SiteLabelKey.
func (s *Store) SiteLabelsByName(ctx context.Context) (map[string]string, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT o.slug, h.name, l.root, l.label
		FROM site_labels l
		JOIN hosts h ON h.id = l.host_id
		JOIN organizations o ON o.id = h.org_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var org, host, root, label string
		if err := rows.Scan(&org, &host, &root, &label); err != nil {
			return nil, err
		}
		out[SiteLabelKey(org, host, root)] = label
	}
	return out, rows.Err()
}

// SetSiteLabel labels a site on a host. An empty label removes it, so the
// site goes back to its suggested label.
func (s *Store) SetSiteLabel(ctx context.Context, actor string, hostID int64, root, label string) error {
	if label != "" && !slices.Contains(SiteLabels, label) {
		return &ValidationError{"label", "must be production, staging or development"}
	}
	if root == "" || len(root) > 4096 {
		return &ValidationError{"site", "a site root is required"}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, hostID).Scan(&orgID, &name); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %d: %w", hostID, ErrNotFound)
		} else if err != nil {
			return err
		}
		var err error
		if label == "" {
			_, err = tx.ExecContext(ctx, `DELETE FROM site_labels WHERE host_id = ? AND root = ?`, hostID, root)
		} else {
			_, err = tx.ExecContext(ctx, `
				INSERT INTO site_labels (host_id, root, label) VALUES (?, ?, ?)
				ON CONFLICT (host_id, root) DO UPDATE SET label = excluded.label,
					updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')`, hostID, root, label)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "site.label", OrgID: orgID, Target: name,
			Detail: map[string]any{"root": root, "label": label}})
	})
}

// MoveHost moves a host to another environment in its org.
func (s *Store) MoveHost(ctx context.Context, actor string, hostID int64, envSlug string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, hostID).Scan(&orgID, &name); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %d: %w", hostID, ErrNotFound)
		} else if err != nil {
			return err
		}
		var envID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM environments WHERE org_id = ? AND slug = ?`, orgID, envSlug).Scan(&envID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("env %q: %w", envSlug, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET env_id = ? WHERE id = ?`, envID, hostID); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.move", OrgID: orgID, Target: name,
			Detail: map[string]any{"env": envSlug}})
	})
}
