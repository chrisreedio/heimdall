// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"
)

// CloudflareIPList is an account-level Cloudflare IP list the read-only
// token can see, and the kind of label its items become
// (internal/cloudflare/iplists.go).
type CloudflareIPList struct {
	ID, AccountID, Name, Description string
	Items                            int    // as Cloudflare counted them
	Kind                             string // CFListIgnore or one of CFListKinds
	UpdatedBy                        string
	UpdatedAt                        time.Time // the kind last changed (zero: never)
	SeenAt                           time.Time
}

// CFListIgnore is a list Heimdall doesn't turn into labels: every list
// starts so.
const CFListIgnore = "ignore"

// CFListKinds are what a list can map to, ignore first.
var CFListKinds = []string{CFListIgnore, IPKindStaff, IPKindOffice, IPKindAutomation, IPKindInfra}

// ReplaceCloudflareIPLists records the lists one sync found in accounts
// (the accounts it could read). A list of those accounts that's gone is
// deleted with its labels and sync state; a found one keeps its kind. It
// returns every stored list, by name.
func (s *Store) ReplaceCloudflareIPLists(ctx context.Context, accounts []string, lists []CloudflareIPList, now time.Time) ([]CloudflareIPList, error) {
	ts := now.UTC().Format(timeLayout)
	err := s.tx(ctx, func(tx *sql.Tx) error {
		for _, l := range lists {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO cloudflare_ip_lists (id, account_id, name, description, items, seen_at) VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (id) DO UPDATE SET account_id = excluded.account_id, name = excluded.name,
					description = excluded.description, items = excluded.items, seen_at = excluded.seen_at`,
				l.ID, l.AccountID, l.Name, l.Description, l.Items, ts); err != nil {
				return err
			}
		}
		rows, err := tx.QueryContext(ctx, `SELECT id, account_id FROM cloudflare_ip_lists`)
		if err != nil {
			return err
		}
		var gone []string
		for rows.Next() {
			var id, account string
			if err := rows.Scan(&id, &account); err != nil {
				rows.Close()
				return err
			}
			if slices.Contains(accounts, account) && !slices.ContainsFunc(lists, func(l CloudflareIPList) bool { return l.ID == id }) {
				gone = append(gone, id)
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range gone {
			if _, err := tx.ExecContext(ctx, `DELETE FROM cloudflare_ip_lists WHERE id = ?`, id); err != nil {
				return err
			}
			if err := dropListLabels(ctx, tx, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.CloudflareIPLists(ctx)
}

// dropListLabels removes a list's labels and its sync state.
func dropListLabels(ctx context.Context, tx *sql.Tx, listID string) error {
	src := IPListSource(listID)
	if _, err := tx.ExecContext(ctx, `DELETE FROM ip_labels WHERE source = ?`, src); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM ip_source_state WHERE source = ?`, src)
	return err
}

// CloudflareIPLists returns the stored lists by name.
func (s *Store) CloudflareIPLists(ctx context.Context) ([]CloudflareIPList, error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT id, account_id, name, description, items, kind, updated_by, updated_at, seen_at
		FROM cloudflare_ip_lists ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CloudflareIPList
	for rows.Next() {
		var l CloudflareIPList
		var updated sql.NullString
		var seen string
		if err := rows.Scan(&l.ID, &l.AccountID, &l.Name, &l.Description, &l.Items, &l.Kind, &l.UpdatedBy, &updated, &seen); err != nil {
			return nil, err
		}
		l.UpdatedAt, l.SeenAt = parseNullTime(updated), parseTime(seen)
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetCloudflareIPListKind maps a list to a kind of label (or ignore).
// Ignoring a list removes its labels at once; mapping one takes a sync.
func (s *Store) SetCloudflareIPListKind(ctx context.Context, actor, listID, kind string, now time.Time) error {
	if !slices.Contains(CFListKinds, kind) {
		return &ValidationError{"kind", fmt.Sprintf("%q isn't one of %s", kind, strings.Join(CFListKinds, ", "))}
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var name, was string
		err := tx.QueryRowContext(ctx, `SELECT name, kind FROM cloudflare_ip_lists WHERE id = ?`, listID).Scan(&name, &was)
		if err == sql.ErrNoRows {
			return fmt.Errorf("IP list %q: %w", listID, ErrNotFound)
		}
		if err != nil || was == kind {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE cloudflare_ip_lists SET kind = ?, updated_by = ?, updated_at = ? WHERE id = ?`,
			kind, actor, now.UTC().Format(timeLayout), listID); err != nil {
			return err
		}
		if kind == CFListIgnore {
			if err := dropListLabels(ctx, tx, listID); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE ip_labels SET kind = ? WHERE source = ?`, kind, IPListSource(listID)); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "cloudflare.ip_list.map", Target: name,
			Detail: map[string]any{"list": listID, "kind": kind, "was": was}})
	})
}
