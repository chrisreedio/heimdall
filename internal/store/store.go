// SPDX-License-Identifier: AGPL-3.0-or-later

// Package store owns the SQLite database: schema, migrations and queries.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
)

type Store struct {
	db *sql.DB
}

// Create makes a new, empty database file readable only by its owner.
// It fails if the file already exists.
func Create(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	return f.Close()
}

// Open opens an existing database. It refuses files that other users can
// read or write, since the inventory is a map of the fleet's weak spots.
func Open(ctx context.Context, path string) (*Store, error) {
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("database %s does not exist (run `heimdall init`)", path)
		}
		return nil, err
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("database %s has permissions %04o; run `chmod 600 %s`", path, perm, path)
	}

	dsn := path +
		"?_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=trusted_schema(0)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// A single connection serializes writers and keeps SQLITE_BUSY out of
	// the picture; the expected load is a few hundred hosts.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// tx runs fn in a transaction, committing if it returns nil.
func (s *Store) tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isUnique(err error) bool {
	var e *sqlite.Error
	return errors.As(err, &e) &&
		(e.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE || e.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY)
}

const timeLayout = "2006-01-02T15:04:05.000Z"

func parseTime(s string) time.Time {
	t, _ := time.Parse(timeLayout, s)
	return t
}

func parseNullTime(s sql.NullString) time.Time {
	if !s.Valid {
		return time.Time{}
	}
	return parseTime(s.String)
}

// Snapshot writes a consistent copy of the database to path (which must
// not exist), using SQLite's VACUUM INTO. The copy is owner-only.
func (s *Store) Snapshot(ctx context.Context, path string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%s already exists", path)
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}
