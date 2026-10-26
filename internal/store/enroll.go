// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/secret"
)

// An enrollment key adds servers to one org and environment until it
// expires, is used up or is revoked. Each server it enrolls gets its own
// ingest token, so the key itself can never send reports.
type EnrollKey struct {
	ID      int64
	OrgID   int64
	OrgSlug string
	EnvSlug string
	Label   string
	Tags    []string
	MaxUses int // 0: any number until it expires
	Uses    int
	// Approval: hosts it enrolls wait for an admin to approve them;
	// until then their reports are answered but not stored.
	Approval  bool
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt time.Time
	Hosts     []string // hosts it enrolled that still exist, by current name
}

// Longest an enrollment key may live.
const MaxEnrollTTL = 30 * 24 * time.Hour

var (
	ErrEnrollExpired = errors.New("enrollment key expired")
	ErrEnrollUsedUp  = errors.New("enrollment key used up")
)

// AlreadyEnrolledError is returned for a server (by machine ID) that is
// already a host in the key's org.
type AlreadyEnrolledError struct{ Host string }

func (e *AlreadyEnrolledError) Error() string {
	return fmt.Sprintf("this server is already enrolled as %s", e.Host)
}

// Status is "active", "expired", "used up" or "revoked".
func (k EnrollKey) Status(now time.Time) string {
	switch {
	case !k.RevokedAt.IsZero():
		return "revoked"
	case !now.Before(k.ExpiresAt):
		return "expired"
	case k.MaxUses > 0 && k.Uses >= k.MaxUses:
		return "used up"
	}
	return "active"
}

// machineRe is a collector's machine ID hash: hex SHA-256.
var machineRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NormalizeMachine returns a valid machine ID hash, lower-cased, or "".
func NormalizeMachine(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !machineRe.MatchString(s) {
		return ""
	}
	return s
}

// NewEnrollKey is what an enrollment key is created with.
type NewEnrollKey struct {
	Label    string
	Tags     []string // each enrolled host gets these
	MaxUses  int      // 0: any number until it expires
	TTL      time.Duration
	Approval bool // enrolled hosts wait for an admin's approval
}

// CreateEnrollKey issues an enrollment key; the plaintext is returned once.
func (s *Store) CreateEnrollKey(ctx context.Context, actor, orgSlug, envSlug string, n NewEnrollKey, now time.Time) (EnrollKey, string, error) {
	label := strings.TrimSpace(n.Label)
	switch {
	case len(label) > 100:
		return EnrollKey{}, "", &ValidationError{"label", "must be at most 100 characters"}
	case n.TTL < time.Minute || n.TTL > MaxEnrollTTL:
		return EnrollKey{}, "", &ValidationError{"expires", "must be between a minute and 30 days"}
	case n.MaxUses < 0 || n.MaxUses > 10000:
		return EnrollKey{}, "", &ValidationError{"uses", "must be between 0 (no limit) and 10000"}
	}
	tags, err := normalizeTags(n.Tags)
	if err != nil {
		return EnrollKey{}, "", err
	}
	tagJSON, _ := json.Marshal(append([]string{}, tags...))
	k := EnrollKey{OrgSlug: orgSlug, EnvSlug: envSlug, Label: label, Tags: tags, MaxUses: n.MaxUses, Approval: n.Approval,
		CreatedBy: actor, CreatedAt: now.UTC(), ExpiresAt: now.Add(n.TTL).UTC()}
	key, hash := secret.NewToken(secret.EnrollPrefix)
	err = s.tx(ctx, func(tx *sql.Tx) error {
		orgID, envID, err := orgEnvIDs(ctx, tx, orgSlug, envSlug)
		if err != nil {
			return err
		}
		k.OrgID = orgID
		if err := tx.QueryRowContext(ctx, `
			INSERT INTO enroll_keys (org_id, env_id, label, tags, key_hash, max_uses, require_approval, created_by, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id`,
			orgID, envID, label, string(tagJSON), hash[:], n.MaxUses, boolInt(n.Approval), actor,
			k.CreatedAt.Format(timeLayout), k.ExpiresAt.Format(timeLayout)).Scan(&k.ID); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "enroll_key.create", OrgID: orgID, Target: fmt.Sprint(k.ID),
			Detail: map[string]any{"env": envSlug, "tags": tags, "label": label, "max_uses": n.MaxUses, "approval": n.Approval, "expires_at": k.ExpiresAt.Format(timeLayout)}})
	})
	if err != nil {
		return EnrollKey{}, "", err
	}
	return k, key, nil
}

// ListEnrollKeys returns an org's enrollment keys (all orgs' if orgSlug is
// empty), newest first.
func (s *Store) ListEnrollKeys(ctx context.Context, orgSlug string) ([]EnrollKey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT k.id, k.org_id, o.slug, e.slug, k.label, k.tags, k.max_uses, k.uses, k.require_approval, k.created_by,
		       k.created_at, k.expires_at, k.revoked_at
		FROM enroll_keys k JOIN organizations o ON o.id = k.org_id JOIN environments e ON e.id = k.env_id
		WHERE ? = '' OR o.slug = ?
		ORDER BY k.id DESC`, orgSlug, orgSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []EnrollKey
	byID := map[int64]int{}
	for rows.Next() {
		var k EnrollKey
		var tags, created, expires string
		var revoked sql.NullString
		if err := rows.Scan(&k.ID, &k.OrgID, &k.OrgSlug, &k.EnvSlug, &k.Label, &tags, &k.MaxUses, &k.Uses, &k.Approval, &k.CreatedBy,
			&created, &expires, &revoked); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(tags), &k.Tags)
		k.CreatedAt, k.ExpiresAt, k.RevokedAt = parseTime(created), parseTime(expires), parseNullTime(revoked)
		byID[k.ID] = len(out)
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hosts, err := s.db.QueryContext(ctx, `
		SELECT h.enroll_key_id, h.name FROM hosts h JOIN organizations o ON o.id = h.org_id
		WHERE h.enroll_key_id IS NOT NULL AND (? = '' OR o.slug = ?) ORDER BY h.name`, orgSlug, orgSlug)
	if err != nil {
		return nil, err
	}
	defer hosts.Close()
	for hosts.Next() {
		var id int64
		var name string
		if err := hosts.Scan(&id, &name); err != nil {
			return nil, err
		}
		if i, ok := byID[id]; ok {
			out[i].Hosts = append(out[i].Hosts, name)
		}
	}
	return out, hosts.Err()
}

// RevokeEnrollKey stops a key enrolling more servers. Hosts it enrolled
// keep their own tokens.
func (s *Store) RevokeEnrollKey(ctx context.Context, actor, orgSlug string, id int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		orgID, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE enroll_keys SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE id = ? AND org_id = ? AND revoked_at IS NULL`, id, orgID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("enrollment key %d: %w", id, ErrNotFound)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "enroll_key.revoke", OrgID: orgID, Target: fmt.Sprint(id)})
	})
}

// Enrolled is a host an enrollment key just added.
type Enrolled struct {
	Host     IngestHost
	Token    string // its ingest token, returned once
	KeyID    int64
	Awaiting bool // it waits for an admin's approval before its reports count
}

// EnrollHost adds a host with a live enrollment key and issues its ingest
// token. The host is named after the hostname its collector reports, made
// unique in the org (or a placeholder it replaces later; see
// ClaimHostName). machine is the server's machine ID hash, or "" if its
// collector didn't send one; a server already in the org by that hash is
// refused with *AlreadyEnrolledError. An unknown or revoked key is
// ErrNotFound.
func (s *Store) EnrollHost(ctx context.Context, hash [32]byte, hostname, machine, ip string, now time.Time) (Enrolled, error) {
	machine = NormalizeMachine(machine)
	var out Enrolled
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var envID int64
		var tags, expires string
		var maxUses, uses int
		var revoked sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT k.id, k.org_id, o.slug, k.env_id, e.slug, k.tags, k.max_uses, k.uses, k.require_approval, k.expires_at, k.revoked_at
			FROM enroll_keys k JOIN organizations o ON o.id = k.org_id JOIN environments e ON e.id = k.env_id
			WHERE k.key_hash = ?`, hash[:]).
			Scan(&out.KeyID, &out.Host.OrgID, &out.Host.OrgSlug, &envID, &out.Host.EnvSlug, &tags, &maxUses, &uses, &out.Awaiting, &expires, &revoked)
		if errors.Is(err, sql.ErrNoRows) || err == nil && revoked.Valid {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case !now.Before(parseTime(expires)):
			return ErrEnrollExpired
		case maxUses > 0 && uses >= maxUses:
			return ErrEnrollUsedUp
		}
		if machine != "" {
			var name string
			err := tx.QueryRowContext(ctx, `SELECT name FROM hosts WHERE org_id = ? AND machine = ? ORDER BY id LIMIT 1`,
				out.Host.OrgID, machine).Scan(&name)
			if err == nil {
				return &AlreadyEnrolledError{Host: name}
			}
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
		}
		var tagList []string
		_ = json.Unmarshal([]byte(tags), &tagList)
		name, auto := pendingHostName(), true
		if base := reportedHostName(hostname); base != "" {
			if name, err = freeHostName(ctx, tx, out.Host.OrgID, base); err != nil {
				return err
			}
			auto = false
		}
		token, th := newIngestToken()
		id, _, err := insertHost(ctx, tx, out.Host.OrgID, envID, name, auto, tagList, th)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE hosts SET enroll_key_id = ?, machine = ?, awaiting_approval = ? WHERE id = ?`,
			out.KeyID, machine, boolInt(out.Awaiting), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE enroll_keys SET uses = uses + 1 WHERE id = ?`, out.KeyID); err != nil {
			return err
		}
		out.Host.ID, out.Host.Name, out.Host.AutoName, out.Host.Awaiting, out.Token = id, name, auto, out.Awaiting, token
		actor := fmt.Sprintf("enroll_key:%d", out.KeyID)
		if err := audit(ctx, tx, AuditEntry{Actor: actor, Action: "host.add", OrgID: out.Host.OrgID, Target: name, IP: ip,
			Detail: map[string]any{"env": out.Host.EnvSlug, "tags": tagList, "auto_name": auto, "enroll_key": out.KeyID,
				"host_id": id, "reported": hostname, "awaiting_approval": out.Awaiting}}); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "token.create", OrgID: out.Host.OrgID, Target: name, IP: ip})
	})
	return out, err
}

// AwaitingHost is a host an enrollment key added that waits for approval.
type AwaitingHost struct {
	ID         int64
	OrgID      int64
	OrgSlug    string
	EnvSlug    string
	Name       string
	Tags       []string
	KeyID      int64
	KeyLabel   string
	EnrolledAt time.Time
	IP         string // where it enrolled from, if recorded
}

// AwaitingHosts lists hosts waiting for approval in an org (all orgs' if
// orgSlug is empty), oldest first.
func (s *Store) AwaitingHosts(ctx context.Context, orgSlug string) ([]AwaitingHost, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT h.id, h.org_id, o.slug, e.slug, h.name, coalesce(k.id, 0), coalesce(k.label, ''), h.created_at,
		       coalesce((SELECT a.ip FROM audit_log a WHERE a.action = 'host.add' AND a.org_id = h.org_id
		                 AND json_extract(a.detail, '$.host_id') = h.id ORDER BY a.id DESC LIMIT 1), ''),
		       coalesce((SELECT group_concat(tag, ',') FROM (SELECT tag FROM host_tags WHERE host_id = h.id ORDER BY tag)), '')
		FROM hosts h JOIN organizations o ON o.id = h.org_id JOIN environments e ON e.id = h.env_id
		LEFT JOIN enroll_keys k ON k.id = h.enroll_key_id
		WHERE h.awaiting_approval = 1 AND (? = '' OR o.slug = ?)
		ORDER BY h.created_at, h.id`, orgSlug, orgSlug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AwaitingHost
	for rows.Next() {
		var h AwaitingHost
		var created, tags string
		if err := rows.Scan(&h.ID, &h.OrgID, &h.OrgSlug, &h.EnvSlug, &h.Name, &h.KeyID, &h.KeyLabel, &created, &h.IP, &tags); err != nil {
			return nil, err
		}
		h.EnrolledAt = parseTime(created)
		if tags != "" {
			h.Tags = strings.Split(tags, ",")
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ApproveHost lets a host waiting for approval report. ErrNotFound if no
// such host is waiting.
func (s *Store) ApproveHost(ctx context.Context, actor, orgSlug, name string) error {
	return s.decideAwaiting(ctx, actor, orgSlug, name, "host.approve", `UPDATE hosts SET awaiting_approval = 0 WHERE id = ?`)
}

// RejectHost removes a host waiting for approval, with its token.
// ErrNotFound if no such host is waiting.
func (s *Store) RejectHost(ctx context.Context, actor, orgSlug, name string) error {
	return s.decideAwaiting(ctx, actor, orgSlug, name, "host.reject", `DELETE FROM hosts WHERE id = ?`)
}

func (s *Store) decideAwaiting(ctx context.Context, actor, orgSlug, name, action, stmt string) error {
	name, err := normalizeHostName(name)
	if err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		orgID, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		var id int64
		err = tx.QueryRowContext(ctx, `SELECT id FROM hosts WHERE org_id = ? AND name = ? AND awaiting_approval = 1`,
			orgID, name).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("host %q in org %q waiting for approval: %w", name, orgSlug, ErrNotFound)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, stmt, id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: action, OrgID: orgID, Target: name,
			Detail: map[string]any{"host_id": id}})
	})
}

// RecordMachine stores the machine ID hash a host's collector reports, so
// enrolling the same server again is refused. A no-op when unchanged.
func (s *Store) RecordMachine(ctx context.Context, hostID int64, machine string) error {
	if machine = NormalizeMachine(machine); machine == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `UPDATE hosts SET machine = ? WHERE id = ? AND machine <> ?`, machine, hostID, machine)
	return err
}

// orgEnvIDs resolves an org and one of its environments.
func orgEnvIDs(ctx context.Context, tx *sql.Tx, orgSlug, envSlug string) (int64, int64, error) {
	orgID, err := orgIDBySlug(ctx, tx, orgSlug)
	if err != nil {
		return 0, 0, err
	}
	var envID int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM environments WHERE org_id = ? AND slug = ?`, orgID, envSlug).Scan(&envID)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, fmt.Errorf("env %q in org %q: %w (create it with `heimdall env create`)", envSlug, orgSlug, ErrNotFound)
	}
	return orgID, envID, err
}
