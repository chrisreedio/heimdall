// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"path"
	"slices"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "_")
		v, err := strconv.Atoi(num)
		if !ok || err != nil || v <= 0 {
			return nil, fmt.Errorf("bad migration filename %q", e.Name())
		}
		b, err := migrationFS.ReadFile(path.Join("migrations", e.Name()))
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: v, name: e.Name(), sql: string(b)})
	}
	slices.SortFunc(ms, func(a, b migration) int { return a.version - b.version })
	for i, m := range ms {
		if m.version != i+1 {
			return nil, fmt.Errorf("migrations must be numbered 1..n without gaps; found %s", m.name)
		}
	}
	return ms, nil
}

// SchemaStatus reports the applied and latest known schema versions.
func (s *Store) SchemaStatus(ctx context.Context) (applied, latest int, err error) {
	ms, err := loadMigrations()
	if err != nil {
		return 0, 0, err
	}
	applied, err = s.appliedVersion(ctx, s.db)
	return applied, len(ms), err
}

// CheckSchema returns an error unless the database is exactly at the
// schema version this binary expects.
func (s *Store) CheckSchema(ctx context.Context) error {
	applied, latest, err := s.SchemaStatus(ctx)
	switch {
	case err != nil:
		return err
	case applied < latest:
		return fmt.Errorf("database schema is at version %d, need %d (run `heimdall migrate`)", applied, latest)
	case applied > latest:
		return fmt.Errorf("database schema version %d is newer than this binary supports (%d)", applied, latest)
	}
	return nil
}

// Migrate applies pending migrations, each in its own transaction, and
// returns the names of those applied.
func (s *Store) Migrate(ctx context.Context) ([]string, error) {
	ms, err := loadMigrations()
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
	) STRICT`); err != nil {
		return nil, err
	}
	current, err := s.appliedVersion(ctx, s.db)
	if err != nil {
		return nil, err
	}
	if current > len(ms) {
		return nil, fmt.Errorf("database schema version %d is newer than this binary supports (%d)", current, len(ms))
	}

	var applied []string
	for _, m := range ms[current:] {
		err := s.tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, m.sql); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name) VALUES (?, ?)`, m.version, m.name)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.name, err)
		}
		applied = append(applied, m.name)
	}
	// 0014 changed how finding_counts tallies kernels, which takes Go, and
	// 0016 added a column the recount fills.
	if slices.ContainsFunc(applied, func(n string) bool { return strings.HasPrefix(n, "0014_") || strings.HasPrefix(n, "0016_") }) {
		if err := s.RecountFindings(ctx); err != nil {
			return applied, fmt.Errorf("recounting findings after migrating: %w", err)
		}
	}
	return applied, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) appliedVersion(ctx context.Context, q querier) (int, error) {
	var exists int
	err := q.QueryRowContext(ctx,
		`SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'schema_migrations'`).Scan(&exists)
	if err != nil || exists == 0 {
		return 0, err
	}
	var v int
	err = q.QueryRowContext(ctx, `SELECT coalesce(max(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}
