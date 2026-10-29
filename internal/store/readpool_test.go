// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// A write in progress holds the only writer connection. Page reads go
// through the read pool, so they finish anyway and see the last commit,
// not the write's uncommitted rows.
func TestReadsDontWaitForWriter(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	if _, err := s.CreateOrg(ctx, "test", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnv(ctx, "test", "acme", "prod", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		t.Fatal(err)
	}

	// Take the writer and leave a write transaction open, as a long
	// findings recount does.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO organizations (slug, name, created_at) VALUES ('globex', 'Globex', '2026-10-29T00:00:00.000Z')`); err != nil {
		t.Fatal(err)
	}

	// The writer really is busy: a write gives up when its deadline passes.
	wctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	if _, err := s.CreateOrg(wctx, "test", "initech", "Initech"); err == nil {
		t.Fatal("write went through while the writer was held")
	}
	cancel()

	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	start := time.Now()
	orgs, err := s.ListOrgs(rctx)
	if err != nil {
		t.Fatalf("ListOrgs while a write is open: %v", err)
	}
	if len(orgs) != 1 || orgs[0].Slug != "acme" {
		t.Errorf("orgs = %+v, want only the committed acme", orgs)
	}
	hosts, err := s.ListHosts(rctx, "acme")
	if err != nil || len(hosts) != 1 {
		t.Fatalf("ListHosts: %v %v", hosts, err)
	}
	if _, err := s.OpenFindingCounts(rctx); err != nil {
		t.Fatalf("OpenFindingCounts: %v", err)
	}
	if _, err := s.HostStates(rctx); err != nil {
		t.Fatalf("HostStates: %v", err)
	}
	if _, err := s.OpenFindings(rctx, hosts[0].ID); err != nil {
		t.Fatalf("OpenFindings: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("reads took %v with a write open", d)
	}
}

// The read pool can't write, not even temp tables (which is why the
// methods that use them stay on the writer).
func TestReadPoolIsReadOnly(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	for _, q := range []string{
		`INSERT INTO organizations (slug, name, created_at) VALUES ('globex', 'Globex', '2026-10-29T00:00:00.000Z')`,
		`DELETE FROM organizations`,
		`CREATE TEMP TABLE scratch (x INTEGER)`,
		`CREATE TABLE scratch (x INTEGER)`,
	} {
		_, err := s.rd.ExecContext(ctx, q)
		var e *sqlite.Error
		if !errors.As(err, &e) || e.Code()&0xff != sqlite3.SQLITE_READONLY {
			t.Errorf("%s through the read pool: %v, want SQLITE_READONLY", q, err)
		}
	}
	// Reads see writes as soon as they commit.
	if _, err := s.CreateOrg(ctx, "test", "acme", "Acme"); err != nil {
		t.Fatal(err)
	}
	if orgs, err := s.ListOrgs(ctx); err != nil || len(orgs) != 1 {
		t.Errorf("ListOrgs after commit: %v %v", orgs, err)
	}
}
