// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type Org struct {
	ID        int64
	Slug      string
	Name      string
	Hosts     int // populated by ListOrgs
	CreatedAt time.Time
	// The collector options the install commands default to (ListOrgs).
	Collector CollectorDefaults
}

// CollectorDefaults are an org's default collector options for new
// servers: the install commands on the Add host and Add servers pages
// start with these flags. A new org has both on.
type CollectorDefaults struct {
	WatchPrivilegeUsers bool // --watch-privilege-users: who and from where for sudo, su, root SSH
	WatchLogins         bool // --watch-logins: failed SSH login counts
}

type Env struct {
	ID        int64
	OrgID     int64
	Slug      string
	Name      string
	Hosts     int // populated by ListEnvs
	CreatedAt time.Time
}

func (s *Store) CreateOrg(ctx context.Context, actor, slug, name string) (Org, error) {
	if err := checkSlug("org", slug); err != nil {
		return Org{}, err
	}
	if name == "" {
		name = slug
	}
	name, err := normalizeName("name", name)
	if err != nil {
		return Org{}, err
	}

	o := Org{Slug: slug, Name: name}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var created string
		err := tx.QueryRowContext(ctx,
			`INSERT INTO organizations (slug, name) VALUES (?, ?) RETURNING id, created_at`,
			slug, name).Scan(&o.ID, &created)
		if isUnique(err) {
			return fmt.Errorf("org %q: %w", slug, ErrExists)
		}
		if err != nil {
			return err
		}
		o.CreatedAt = parseTime(created)
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "org.create", OrgID: o.ID, Target: slug,
			Detail: map[string]any{"name": name}})
	})
	return o, err
}

func (s *Store) ListOrgs(ctx context.Context) ([]Org, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.id, o.slug, o.name, o.created_at, o.watch_privilege_users, o.watch_logins, count(h.id)
		FROM organizations o LEFT JOIN hosts h ON h.org_id = o.id
		GROUP BY o.id ORDER BY o.slug`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		var created string
		if err := rows.Scan(&o.ID, &o.Slug, &o.Name, &created,
			&o.Collector.WatchPrivilegeUsers, &o.Collector.WatchLogins, &o.Hosts); err != nil {
			return nil, err
		}
		o.CreatedAt = parseTime(created)
		out = append(out, o)
	}
	return out, rows.Err()
}

// SetCollectorDefaults stores an org's default collector options, audited.
func (s *Store) SetCollectorDefaults(ctx context.Context, actor, orgSlug string, d CollectorDefaults) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		id, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE organizations SET watch_privilege_users = ?, watch_logins = ? WHERE id = ?`,
			d.WatchPrivilegeUsers, d.WatchLogins, id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "org.collector_defaults", OrgID: id, Target: orgSlug,
			Detail: map[string]any{"watch_privilege_users": d.WatchPrivilegeUsers, "watch_logins": d.WatchLogins}})
	})
}

func orgIDBySlug(ctx context.Context, q querier, slug string) (int64, error) {
	var id int64
	err := q.QueryRowContext(ctx, `SELECT id FROM organizations WHERE slug = ?`, slug).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("org %q: %w", slug, ErrNotFound)
	}
	return id, err
}

func (s *Store) CreateEnv(ctx context.Context, actor, orgSlug, slug, name string) (Env, error) {
	if err := checkSlug("env", slug); err != nil {
		return Env{}, err
	}
	if name == "" {
		name = slug
	}
	name, err := normalizeName("name", name)
	if err != nil {
		return Env{}, err
	}

	e := Env{Slug: slug, Name: name}
	err = s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		if e.OrgID, err = orgIDBySlug(ctx, tx, orgSlug); err != nil {
			return err
		}
		var created string
		err = tx.QueryRowContext(ctx,
			`INSERT INTO environments (org_id, slug, name) VALUES (?, ?, ?) RETURNING id, created_at`,
			e.OrgID, slug, name).Scan(&e.ID, &created)
		if isUnique(err) {
			return fmt.Errorf("env %q in org %q: %w", slug, orgSlug, ErrExists)
		}
		if err != nil {
			return err
		}
		e.CreatedAt = parseTime(created)
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "env.create", OrgID: e.OrgID, Target: slug,
			Detail: map[string]any{"name": name}})
	})
	return e, err
}

func (s *Store) ListEnvs(ctx context.Context, orgSlug string) ([]Env, error) {
	id, err := orgIDBySlug(ctx, s.db, orgSlug)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT e.id, e.org_id, e.slug, e.name, e.created_at, count(h.id)
		FROM environments e LEFT JOIN hosts h ON h.env_id = e.id
		WHERE e.org_id = ?
		GROUP BY e.id ORDER BY e.slug`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Env
	for rows.Next() {
		var e Env
		var created string
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Slug, &e.Name, &created, &e.Hosts); err != nil {
			return nil, err
		}
		e.CreatedAt = parseTime(created)
		out = append(out, e)
	}
	return out, rows.Err()
}
