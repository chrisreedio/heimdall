// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/secret"
)

type Host struct {
	ID         int64
	OrgSlug    string
	EnvSlug    string
	Name       string
	Tags       []string
	CreatedAt  time.Time
	LastSeenAt time.Time // zero if the host has never checked in
}

// AddHost registers a host and issues its first ingest token. The plaintext
// token is returned once and never stored.
func (s *Store) AddHost(ctx context.Context, actor, orgSlug, envSlug, name string, tags []string) (Host, string, error) {
	name, err := normalizeHostName(name)
	if err != nil {
		return Host{}, "", err
	}
	if tags, err = normalizeTags(tags); err != nil {
		return Host{}, "", err
	}

	h := Host{OrgSlug: orgSlug, EnvSlug: envSlug, Name: name, Tags: tags}
	token, hash := newIngestToken()
	err = s.tx(ctx, func(tx *sql.Tx) error {
		orgID, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		var envID int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM environments WHERE org_id = ? AND slug = ?`,
			orgID, envSlug).Scan(&envID)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("env %q in org %q: %w (create it with `heimdall env create`)", envSlug, orgSlug, ErrNotFound)
		}
		if err != nil {
			return err
		}

		var created string
		err = tx.QueryRowContext(ctx,
			`INSERT INTO hosts (org_id, env_id, name) VALUES (?, ?, ?) RETURNING id, created_at`,
			orgID, envID, name).Scan(&h.ID, &created)
		if isUnique(err) {
			return fmt.Errorf("host %q in org %q: %w", name, orgSlug, ErrExists)
		}
		if err != nil {
			return err
		}
		h.CreatedAt = parseTime(created)

		for _, t := range tags {
			if _, err := tx.ExecContext(ctx, `INSERT INTO host_tags (host_id, tag) VALUES (?, ?)`, h.ID, t); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO ingest_tokens (host_id, token_hash) VALUES (?, ?)`, h.ID, hash[:]); err != nil {
			return err
		}

		if err := audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.add", OrgID: orgID, Target: name,
			Detail: map[string]any{"env": envSlug, "tags": tags}}); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "token.create", OrgID: orgID, Target: name})
	})
	if err != nil {
		return Host{}, "", err
	}
	return h, token, nil
}

// ListHosts returns hosts in one org, or in all orgs if orgSlug is empty.
func (s *Store) ListHosts(ctx context.Context, orgSlug string) ([]Host, error) {
	q := `
		SELECT h.id, o.slug, e.slug, h.name, h.created_at, h.last_seen_at,
		       coalesce((SELECT group_concat(tag, ',') FROM (SELECT tag FROM host_tags WHERE host_id = h.id ORDER BY tag)), '')
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN environments e ON e.id = h.env_id`
	var args []any
	if orgSlug != "" {
		if _, err := orgIDBySlug(ctx, s.db, orgSlug); err != nil {
			return nil, err
		}
		q += ` WHERE o.slug = ?`
		args = append(args, orgSlug)
	}
	q += ` ORDER BY o.slug, e.slug, h.name`

	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var created, tags string
		var lastSeen sql.NullString
		if err := rows.Scan(&h.ID, &h.OrgSlug, &h.EnvSlug, &h.Name, &created, &lastSeen, &tags); err != nil {
			return nil, err
		}
		h.CreatedAt, h.LastSeenAt = parseTime(created), parseNullTime(lastSeen)
		if tags != "" {
			h.Tags = strings.Split(tags, ",")
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// RemoveHost deletes a host with its tokens, snapshots and findings.
func (s *Store) RemoveHost(ctx context.Context, actor, orgSlug, name string) error {
	name, err := normalizeHostName(name)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		org, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		var id int64
		var snapshots int
		err = tx.QueryRowContext(ctx, `
			SELECT h.id, (SELECT count(*) FROM snapshots WHERE host_id = h.id)
			FROM hosts h WHERE h.org_id = ? AND h.name = ?`, org, name).Scan(&id, &snapshots)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %q in org %q: %w", name, orgSlug, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM hosts WHERE id = ?`, id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.remove", OrgID: org, Target: name,
			Detail: map[string]any{"snapshots_deleted": snapshots}})
	})
}

func newIngestToken() (string, [32]byte) { return secret.NewToken(secret.IngestPrefix) }
