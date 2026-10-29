// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/secret"
)

type Host struct {
	ID         int64
	OrgSlug    string
	EnvSlug    string
	Name       string
	Tags       []string
	AutoName   bool // named by its first report (the name is a placeholder until then)
	CreatedAt  time.Time
	LastSeenAt time.Time // zero if the host has never checked in
	Awaiting   bool      // enrolled, waiting for an admin's approval
}

// AddHost registers a host and issues its first ingest token. The plaintext
// token is returned once and never stored. With an empty name the host gets
// a placeholder and takes the hostname its collector reports first.
func (s *Store) AddHost(ctx context.Context, actor, orgSlug, envSlug, name string, tags []string) (Host, string, error) {
	auto := strings.TrimSpace(name) == ""
	if auto {
		name = pendingHostName()
	}
	name, err := normalizeHostName(name)
	if err != nil {
		return Host{}, "", err
	}
	if tags, err = normalizeTags(tags); err != nil {
		return Host{}, "", err
	}

	h := Host{OrgSlug: orgSlug, EnvSlug: envSlug, Name: name, Tags: tags, AutoName: auto}
	token, hash := newIngestToken()
	err = s.tx(ctx, func(tx *sql.Tx) error {
		orgID, envID, err := orgEnvIDs(ctx, tx, orgSlug, envSlug)
		if err != nil {
			return err
		}
		if h.ID, h.CreatedAt, err = insertHost(ctx, tx, orgID, envID, name, auto, tags, hash); err != nil {
			if errors.Is(err, ErrExists) {
				return fmt.Errorf("host %q in org %q: %w", name, orgSlug, ErrExists)
			}
			return err
		}

		if err := audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.add", OrgID: orgID, Target: name,
			Detail: map[string]any{"env": envSlug, "tags": tags, "auto_name": auto}}); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "token.create", OrgID: orgID, Target: name})
	})
	if err != nil {
		return Host{}, "", err
	}
	return h, token, nil
}

// insertHost adds a host row with its tags and first ingest token.
func insertHost(ctx context.Context, tx *sql.Tx, orgID, envID int64, name string, auto bool, tags []string, tokenHash [32]byte) (int64, time.Time, error) {
	var id int64
	var created string
	err := tx.QueryRowContext(ctx,
		`INSERT INTO hosts (org_id, env_id, name, auto_name) VALUES (?, ?, ?, ?) RETURNING id, created_at`,
		orgID, envID, name, boolInt(auto)).Scan(&id, &created)
	if isUnique(err) {
		return 0, time.Time{}, ErrExists
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	for _, t := range tags {
		if _, err := tx.ExecContext(ctx, `INSERT INTO host_tags (host_id, tag) VALUES (?, ?)`, id, t); err != nil {
			return 0, time.Time{}, err
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO ingest_tokens (host_id, token_hash) VALUES (?, ?)`, id, tokenHash[:])
	return id, parseTime(created), err
}

// ListHosts returns hosts in one org, or in all orgs if orgSlug is empty.
func (s *Store) ListHosts(ctx context.Context, orgSlug string) ([]Host, error) {
	q := `
		SELECT h.id, o.slug, e.slug, h.name, h.created_at, h.last_seen_at, h.awaiting_approval,
		       coalesce((SELECT group_concat(tag, ',') FROM (SELECT tag FROM host_tags WHERE host_id = h.id ORDER BY tag)), '')
		FROM hosts h
		JOIN organizations o ON o.id = h.org_id
		JOIN environments e ON e.id = h.env_id`
	var args []any
	if orgSlug != "" {
		if _, err := orgIDBySlug(ctx, s.rd, orgSlug); err != nil {
			return nil, err
		}
		q += ` WHERE o.slug = ?`
		args = append(args, orgSlug)
	}
	q += ` ORDER BY o.slug, e.slug, h.name`

	rows, err := s.rd.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Host
	for rows.Next() {
		var h Host
		var created, tags string
		var lastSeen sql.NullString
		if err := rows.Scan(&h.ID, &h.OrgSlug, &h.EnvSlug, &h.Name, &created, &lastSeen, &h.Awaiting, &tags); err != nil {
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

// pendingHostName is the placeholder for a host that will take its
// reported hostname.
func pendingHostName() string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return "pending-" + string(b)
}

// reportedHostName turns a hostname reported by a collector into a valid,
// lower-case host name, or "" if nothing usable is left.
func reportedHostName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), "._-")
	if len(out) > 200 {
		out = strings.TrimRight(out[:200], "._-")
	}
	if !hostRe.MatchString(out) {
		return ""
	}
	return out
}

// ClaimHostName gives a host added without a name the hostname its
// collector reported, made unique in its org (web-01, web-01-2, ...). It
// does nothing for hosts that were named, or that already claimed a name.
func (s *Store) ClaimHostName(ctx context.Context, hostID int64, reported string) (string, bool, error) {
	base := reportedHostName(reported)
	if base == "" {
		return "", false, nil
	}
	var name string
	claimed := false
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var old string
		var auto int64
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name, auto_name FROM hosts WHERE id = ?`, hostID).
			Scan(&orgID, &old, &auto); err != nil {
			return err
		}
		if auto == 0 {
			return nil
		}
		n, err := freeHostName(ctx, tx, orgID, base)
		if err != nil {
			return err
		}
		name = n
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET name = ?, auto_name = 0 WHERE id = ? AND auto_name = 1`, name, hostID); err != nil {
			return err
		}
		claimed = true
		return audit(ctx, tx, AuditEntry{Actor: fmt.Sprintf("host:%d", hostID), Action: "host.rename", OrgID: orgID, Target: name,
			Detail: map[string]any{"from": old, "reported": true}})
	})
	return name, claimed, err
}

// freeHostName returns base, or base-2, base-3, ... if it's taken in the org.
func freeHostName(ctx context.Context, tx *sql.Tx, orgID int64, base string) (string, error) {
	for i := 1; i <= 100; i++ {
		name := base
		if i > 1 {
			name = fmt.Sprintf("%s-%d", base, i)
		}
		var taken int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM hosts WHERE org_id = ? AND name = ?`, orgID, name).Scan(&taken); err != nil {
			return "", err
		}
		if taken == 0 {
			return name, nil
		}
	}
	return "", fmt.Errorf("no free name for reported hostname %q", base)
}

// RenameHost renames a host. A host renamed this way no longer takes its
// reported hostname.
func (s *Store) RenameHost(ctx context.Context, actor, orgSlug, oldName, newName string) error {
	oldName, err := normalizeHostName(oldName)
	if err != nil {
		return err
	}
	if newName, err = normalizeHostName(newName); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		orgID, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `UPDATE hosts SET name = ?, auto_name = 0 WHERE org_id = ? AND name = ?`, newName, orgID, oldName)
		if isUnique(err) {
			return fmt.Errorf("host %q in org %q: %w", newName, orgSlug, ErrExists)
		}
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("host %q in org %q: %w", oldName, orgSlug, ErrNotFound)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.rename", OrgID: orgID, Target: newName,
			Detail: map[string]any{"from": oldName}})
	})
}

// TagHosts adds a tag to hosts (by ID), keeping their other tags. It
// returns how many hosts gained the tag.
func (s *Store) TagHosts(ctx context.Context, actor, tag string, hostIDs []int64) (int, error) {
	tags, err := normalizeTags([]string{tag})
	if err != nil {
		return 0, err
	}
	tag = tags[0]
	added := 0
	err = s.tx(ctx, func(tx *sql.Tx) error {
		for _, id := range hostIDs {
			var orgID int64
			var name string
			if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, id).Scan(&orgID, &name); errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("host %d: %w", id, ErrNotFound)
			} else if err != nil {
				return err
			}
			res, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO host_tags (host_id, tag) VALUES (?, ?)`, id, tag)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				continue
			}
			added++
			if err := audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.tag", OrgID: orgID, Target: name,
				Detail: map[string]any{"tag": tag}}); err != nil {
				return err
			}
		}
		return nil
	})
	return added, err
}

// SetHostTags replaces a host's tags.
func (s *Store) SetHostTags(ctx context.Context, actor string, hostID int64, tags []string) error {
	tags, err := normalizeTags(tags)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		var orgID int64
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT org_id, name FROM hosts WHERE id = ?`, hostID).Scan(&orgID, &name); errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %d: %w", hostID, ErrNotFound)
		} else if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM host_tags WHERE host_id = ?`, hostID); err != nil {
			return err
		}
		for _, t := range tags {
			if _, err := tx.ExecContext(ctx, `INSERT INTO host_tags (host_id, tag) VALUES (?, ?)`, hostID, t); err != nil {
				return err
			}
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.tags", OrgID: orgID, Target: name,
			Detail: map[string]any{"tags": tags}})
	})
}

// HostTags returns a host's tags, sorted.
func (s *Store) HostTags(ctx context.Context, hostID int64) ([]string, error) {
	rows, err := s.rd.QueryContext(ctx, `SELECT tag FROM host_tags WHERE host_id = ? ORDER BY tag`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
