// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/chrisreedio/heimdall/internal/secret"
)

// newStore returns a fresh, migrated store. The schema is built once per
// test run and copied, since migrating takes a few hundred milliseconds
// under the race detector (storetest does the same for other packages,
// which this package's tests can't import).
func newStore(t *testing.T) *Store {
	t.Helper()
	templateOnce.Do(func() { template, templateErr = buildTemplate() })
	if templateErr != nil {
		t.Fatal(templateErr)
	}
	path := filepath.Join(t.TempDir(), "h.db")
	if err := os.WriteFile(path, template, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

var (
	templateOnce sync.Once
	template     []byte
	templateErr  error
)

func buildTemplate() ([]byte, error) {
	dir, err := os.MkdirTemp("", "heimdall-store-test-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "h.db")
	if err := Create(path); err != nil {
		return nil, err
	}
	s, err := Open(context.Background(), path)
	if err != nil {
		return nil, err
	}
	if _, err := s.Migrate(context.Background()); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.Close(); err != nil { // checkpoints the WAL into the file
		return nil, err
	}
	return os.ReadFile(path)
}

func TestCreateIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	if err := Create(path); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("perm = %04o, want 0600", perm)
	}
	if err := Create(path); err == nil {
		t.Error("Create must refuse an existing file")
	}
}

func TestOpenRefusesLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	if err := Create(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(t.Context(), path); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("want permissions error, got %v", err)
	}
}

func TestMigrateIdempotent(t *testing.T) {
	s := newStore(t)
	applied, err := s.Migrate(t.Context())
	if err != nil || len(applied) != 0 {
		t.Fatalf("second migrate applied %v, err %v", applied, err)
	}
	if err := s.CheckSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestCheckSchemaOnFreshDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "h.db")
	if err := Create(path); err != nil {
		t.Fatal(err)
	}
	s, err := Open(t.Context(), path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.CheckSchema(t.Context()); err == nil || !strings.Contains(err.Error(), "heimdall migrate") {
		t.Fatalf("want migrate hint, got %v", err)
	}
}

func setupHost(t *testing.T, s *Store) (Host, string) {
	t.Helper()
	ctx := t.Context()
	if _, err := s.CreateOrg(ctx, "test", "acme", "Acme Corp"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateEnv(ctx, "test", "acme", "prod", ""); err != nil {
		t.Fatal(err)
	}
	h, tok, err := s.AddHost(ctx, "test", "acme", "prod", "Web-01.example.com", []string{"web", "WEB", "role:lb"})
	if err != nil {
		t.Fatal(err)
	}
	return h, tok
}

func TestOrgEnvHostLifecycle(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	h, tok := setupHost(t, s)

	if h.Name != "web-01.example.com" {
		t.Errorf("host name not normalized: %q", h.Name)
	}
	if !secret.LooksLike(tok, secret.IngestPrefix) {
		t.Errorf("bad token %q", tok)
	}

	// Only the hash is stored.
	var stored []byte
	if err := s.db.QueryRowContext(ctx, `SELECT token_hash FROM ingest_tokens WHERE host_id = ?`, h.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if want := secret.Hash(tok); string(stored) != string(want[:]) {
		t.Error("stored token hash mismatch")
	}

	hosts, err := s.ListHosts(ctx, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || strings.Join(hosts[0].Tags, ",") != "role:lb,web" || hosts[0].EnvSlug != "prod" {
		t.Fatalf("ListHosts = %+v", hosts)
	}

	orgs, err := s.ListOrgs(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].Hosts != 1 {
		t.Fatalf("ListOrgs = %+v, %v", orgs, err)
	}

	if err := s.RemoveHost(ctx, "test", "acme", "web-01.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveHost(ctx, "test", "acme", "web-01.example.com"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second remove: want ErrNotFound, got %v", err)
	}
	var tokens int
	s.db.QueryRowContext(ctx, `SELECT count(*) FROM ingest_tokens`).Scan(&tokens)
	if tokens != 0 {
		t.Error("tokens not removed with host")
	}

	var actions string
	s.db.QueryRowContext(ctx, `SELECT group_concat(action, ' ') FROM (SELECT action FROM audit_log ORDER BY id)`).Scan(&actions)
	if actions != "org.create env.create host.add token.create host.remove" {
		t.Errorf("audit log = %q", actions)
	}
}

func TestErrors(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	setupHost(t, s)

	if _, err := s.CreateOrg(ctx, "test", "acme", ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate org: %v", err)
	}
	if _, err := s.CreateEnv(ctx, "test", "acme", "prod", ""); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate env: %v", err)
	}
	if _, _, err := s.AddHost(ctx, "test", "acme", "prod", "WEB-01.example.com", nil); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate host: %v", err)
	}
	if _, _, err := s.AddHost(ctx, "test", "acme", "staging", "db-01", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing env: %v", err)
	}
	if _, _, err := s.AddHost(ctx, "test", "nope", "prod", "db-01", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing org: %v", err)
	}

	var ve *ValidationError
	for _, slug := range []string{"", "Acme", "-acme", "acme-", "a b", strings.Repeat("a", 64)} {
		if _, err := s.CreateOrg(ctx, "test", slug, ""); !errors.As(err, &ve) {
			t.Errorf("org slug %q: want ValidationError, got %v", slug, err)
		}
	}
	// An empty name is valid: the host takes its reported hostname.
	for _, name := range []string{"web 01", "web;rm", "-web", "web/01"} {
		if _, _, err := s.AddHost(ctx, "test", "acme", "prod", name, nil); !errors.As(err, &ve) {
			t.Errorf("host %q: want ValidationError, got %v", name, err)
		}
	}
	if _, err := s.CreateOrg(ctx, "test", "x", "evil\x1b[31m"); !errors.As(err, &ve) {
		t.Errorf("control chars in name: want ValidationError, got %v", err)
	}
}

// The schema itself enforces invariants the Go code relies on.
func TestSchemaConstraints(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	h, _ := setupHost(t, s)

	if _, err := s.CreateOrg(ctx, "test", "other", ""); err != nil {
		t.Fatal(err)
	}
	otherEnv, err := s.CreateEnv(ctx, "test", "other", "prod", "")
	if err != nil {
		t.Fatal(err)
	}

	mustFail := func(name, q string, args ...any) {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, q, args...); err == nil {
			t.Errorf("%s: expected constraint violation", name)
		}
	}

	mustFail("host in another org's env",
		`INSERT INTO hosts (org_id, env_id, name) SELECT id, ?, 'x' FROM organizations WHERE slug = 'acme'`, otherEnv.ID)
	mustFail("second live token",
		`INSERT INTO ingest_tokens (host_id, token_hash) VALUES (?, zeroblob(32))`, h.ID)
	mustFail("short token hash",
		`UPDATE ingest_tokens SET revoked_at = 'x'; INSERT INTO ingest_tokens (host_id, token_hash) VALUES (?, zeroblob(8))`, h.ID)

	const insertSnapshot = `INSERT INTO snapshots (host_id, source, collected_at, collector_version, collector_sha256, payload_sha256)
		VALUES (?, 'push', 'now', '0', zeroblob(32), zeroblob(32))`
	if _, err := s.db.ExecContext(ctx, insertSnapshot, h.ID); err != nil {
		t.Fatal(err)
	}
	mustFail("replayed payload", insertSnapshot, h.ID)
	mustFail("snapshot update", `UPDATE snapshots SET kernel = 'x'`)

	var acmeID, prodID int64
	s.db.QueryRowContext(ctx, `SELECT org_id, env_id FROM hosts WHERE id = ?`, h.ID).Scan(&acmeID, &prodID)
	const insertWindow = `INSERT INTO maintenance_windows
		(org_id, env_id, host_id, starts_at, ends_at, weekdays, start_time, duration_minutes, timezone)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if _, err := s.db.ExecContext(ctx, insertWindow, acmeID, nil, h.ID, "2026-01-01T02:00", "2026-01-01T04:00", nil, nil, nil, nil); err != nil {
		t.Fatalf("one-off host window: %v", err)
	}
	if _, err := s.db.ExecContext(ctx, insertWindow, acmeID, prodID, nil, nil, nil, 64, "02:00", 120, "UTC"); err != nil {
		t.Fatalf("weekly env window: %v", err)
	}
	mustFail("window scoped to env and host", insertWindow, acmeID, prodID, h.ID, nil, nil, 64, "02:00", 120, "UTC")
	mustFail("window both one-off and weekly", insertWindow, acmeID, nil, nil, "2026-01-01T02:00", "2026-01-01T04:00", 64, "02:00", 120, "UTC")
	mustFail("window ends before it starts", insertWindow, acmeID, nil, nil, "2026-01-01T04:00", "2026-01-01T02:00", nil, nil, nil, nil)
	mustFail("window on another org's host", insertWindow, otherEnv.OrgID, nil, h.ID, "2026-01-01T02:00", "2026-01-01T04:00", nil, nil, nil, nil)
	mustFail("window bad start time", insertWindow, acmeID, nil, nil, nil, nil, 64, "2am", 120, "UTC")

	mustFail("unknown anomaly rule",
		`INSERT INTO anomalies (host_id, rule, severity, summary) VALUES (?, 'vibes', 'low', 'x')`, h.ID)
	mustFail("ack without note",
		`INSERT INTO anomalies (host_id, rule, severity, summary, acknowledged_at) VALUES (?, 'replay', 'low', 'x', 'now')`, h.ID)
	mustFail("suppression without note",
		`INSERT INTO anomaly_suppressions (host_id, rule, until_at, note) VALUES (?, 'replay', '2999-01-01', '')`, h.ID)
	mustFail("suppression already expired",
		`INSERT INTO anomaly_suppressions (host_id, rule, until_at, note) VALUES (?, 'replay', '2000-01-01', 'x')`, h.ID)
	mustFail("audit update", `UPDATE audit_log SET actor = 'x'`)
	mustFail("audit delete", `DELETE FROM audit_log`)
	mustFail("entra user with password",
		`INSERT INTO users (kind, email, password_hash, entra_tid) VALUES ('entra', 'a@b', 'x', 't')`)
	mustFail("local user without password",
		`INSERT INTO users (kind, email) VALUES ('local', 'a@b')`)
	mustFail("bad role",
		`INSERT INTO users (kind, email, password_hash) VALUES ('local', 'a@b', 'x');
		 INSERT INTO memberships (user_id, org_id, role) SELECT last_insert_rowid(), id, 'root' FROM organizations LIMIT 1`)
}

func TestOrgDeleteCascades(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	setupHost(t, s)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM organizations WHERE slug = 'acme'`); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"environments", "hosts", "host_tags", "ingest_tokens"} {
		var n int
		s.db.QueryRowContext(context.Background(), `SELECT count(*) FROM `+table).Scan(&n)
		if n != 0 {
			t.Errorf("%s: %d rows left after org delete", table, n)
		}
	}
}
