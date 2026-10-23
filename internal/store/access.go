// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Role is a user's level of access to one organization.
type Role string

const (
	RoleViewer   Role = "viewer"   // read everything in the org
	RoleOperator Role = "operator" // also act: patch plans, anomaly triage
	RoleAdmin    Role = "admin"    // also manage the org's hosts and tokens
)

var roleRank = map[Role]int{RoleViewer: 1, RoleOperator: 2, RoleAdmin: 3}

// ParseRole validates a role name.
func ParseRole(s string) (Role, error) {
	r := Role(strings.ToLower(strings.TrimSpace(s)))
	if roleRank[r] == 0 {
		return "", &ValidationError{"role", fmt.Sprintf("%q must be viewer, operator or admin", s)}
	}
	return r, nil
}

// AtLeast reports whether r grants at least min.
func (r Role) AtLeast(min Role) bool { return roleRank[r] >= roleRank[min] && roleRank[min] > 0 }

// Scope is what a user may see and do. Every read path that serves a user
// filters by a Scope, so access is enforced in one place.
type Scope struct {
	Admin bool           // global admin: every org, plus user management
	Orgs  map[int64]Role // per-org roles
}

// AllScope is for the CLI and background jobs, which act as the operator.
var AllScope = Scope{Admin: true}

// Role returns the user's role in an org ("" if none).
func (s Scope) Role(orgID int64) Role {
	if s.Admin {
		return RoleAdmin
	}
	return s.Orgs[orgID]
}

func (s Scope) CanView(orgID int64) bool    { return s.Role(orgID).AtLeast(RoleViewer) }
func (s Scope) CanOperate(orgID int64) bool { return s.Role(orgID).AtLeast(RoleOperator) }
func (s Scope) CanAdmin(orgID int64) bool   { return s.Role(orgID).AtLeast(RoleAdmin) }

// Empty reports whether the scope grants nothing at all.
func (s Scope) Empty() bool { return !s.Admin && len(s.Orgs) == 0 }

// ScopeFor loads a user's scope.
func (s *Store) ScopeFor(ctx context.Context, userID int64) (Scope, error) {
	sc := Scope{Orgs: map[int64]Role{}}
	var admin int64
	if err := s.db.QueryRowContext(ctx, `SELECT is_admin FROM users WHERE id = ?`, userID).Scan(&admin); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sc, ErrNotFound
		}
		return sc, err
	}
	sc.Admin = admin == 1
	rows, err := s.db.QueryContext(ctx, `SELECT org_id, role FROM memberships WHERE user_id = ?`, userID)
	if err != nil {
		return sc, err
	}
	defer rows.Close()
	for rows.Next() {
		var org int64
		var role string
		if err := rows.Scan(&org, &role); err != nil {
			return sc, err
		}
		// A manual grant and an app-role grant can't coexist (one row per
		// org), so the row is the effective role.
		sc.Orgs[org] = Role(role)
	}
	return sc, rows.Err()
}

// VisibleOrgSlugs returns the slugs of orgs the scope can view.
func (s *Store) VisibleOrgSlugs(ctx context.Context, sc Scope) (map[string]bool, error) {
	orgs, err := s.ListOrgs(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(orgs))
	for _, o := range orgs {
		if sc.CanView(o.ID) {
			out[o.Slug] = true
		}
	}
	return out, nil
}

// Membership is a user's role in one org.
type Membership struct {
	OrgSlug string
	Role    Role
	Source  string // "manual" or "entra_app_role"
}

func (s *Store) Memberships(ctx context.Context, userID int64) ([]Membership, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT o.slug, m.role, m.source FROM memberships m JOIN organizations o ON o.id = m.org_id
		WHERE m.user_id = ? ORDER BY o.slug`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.OrgSlug, &m.Role, &m.Source); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Grant gives a user a role in an org (replacing any existing role there).
func (s *Store) Grant(ctx context.Context, actor, email, orgSlug string, role Role) error {
	if _, err := ParseRole(string(role)); err != nil {
		return err
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		uid, email, err := userIDByRef(ctx, tx, email)
		if err != nil {
			return err
		}
		org, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO memberships (user_id, org_id, role, source) VALUES (?, ?, ?, 'manual')
			ON CONFLICT (user_id, org_id) DO UPDATE SET role = excluded.role, source = 'manual'`,
			uid, org, string(role)); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "role.grant", OrgID: org, Target: email,
			Detail: map[string]any{"role": role}})
	})
}

// Revoke removes a user's role in an org.
func (s *Store) Revoke(ctx context.Context, actor, email, orgSlug string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		uid, email, err := userIDByRef(ctx, tx, email)
		if err != nil {
			return err
		}
		org, err := orgIDBySlug(ctx, tx, orgSlug)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM memberships WHERE user_id = ? AND org_id = ?`, uid, org)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("%s has no role in %s: %w", email, orgSlug, ErrNotFound)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "role.revoke", OrgID: org, Target: email})
	})
}

// UserRef formats a reference to one user that never matches another
// user with the same email: "#<id>".
func UserRef(id int64) string { return "#" + strconv.FormatInt(id, 10) }

// userIDByRef finds a user by "#<id>" or by email, returning the email for
// audit entries. An email shared by several users (a local and an Entra
// account, or Entra accounts in several tenants) is ambiguous.
func userIDByRef(ctx context.Context, tx *sql.Tx, ref string) (int64, string, error) {
	ref = strings.TrimSpace(ref)
	if n, ok := strings.CutPrefix(ref, "#"); ok {
		id, err := strconv.ParseInt(n, 10, 64)
		if err != nil || id <= 0 {
			return 0, "", &ValidationError{"user", "must be an email or #<id>"}
		}
		var email sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT email FROM users WHERE id = ?`, id).Scan(&email); errors.Is(err, sql.ErrNoRows) {
			return 0, "", fmt.Errorf("user %s: %w", ref, ErrNotFound)
		} else if err != nil {
			return 0, "", err
		}
		if email.String == "" {
			return id, ref, nil
		}
		return id, email.String, nil
	}
	email, err := NormalizeEmail(ref)
	if err != nil {
		return 0, "", err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM users WHERE email = ?`, email)
	if err != nil {
		return 0, "", err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return 0, "", err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, "", err
	}
	switch len(ids) {
	case 0:
		return 0, "", fmt.Errorf("user %s: %w", email, ErrNotFound)
	case 1:
		return ids[0], email, nil
	}
	return 0, "", &ValidationError{"user", fmt.Sprintf("several accounts use %s (a local and a Microsoft one); say which with --local or --entra, or by ID from `heimdall user list`, e.g. '#%d'", email, ids[0])}
}

// ── Entra users ────────────────────────────────────────────────────────────

// CreateEntraUser pre-provisions an Entra ID user. Either oid or email
// identifies them; an email is bound to the user's oid on first login.
func (s *Store) CreateEntraUser(ctx context.Context, actor, tenantID, objectID, email, displayName string, isAdmin bool) (int64, error) {
	tenantID, objectID = strings.ToLower(strings.TrimSpace(tenantID)), strings.ToLower(strings.TrimSpace(objectID))
	if !guidRe.MatchString(tenantID) {
		return 0, &ValidationError{"tenant", "must be a tenant ID (GUID)"}
	}
	if objectID != "" && !guidRe.MatchString(objectID) {
		return 0, &ValidationError{"oid", "must be an object ID (GUID)"}
	}
	if email != "" {
		var err error
		if email, err = NormalizeEmail(email); err != nil {
			return 0, err
		}
	}
	if objectID == "" && email == "" {
		return 0, &ValidationError{"user", "give an object ID or an email"}
	}
	var id int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var oid sql.NullString
		if objectID != "" {
			oid = sql.NullString{String: objectID, Valid: true}
		}
		err := tx.QueryRowContext(ctx, `
			INSERT INTO users (kind, email, display_name, is_admin, entra_tid, entra_oid)
			VALUES ('entra', ?, ?, ?, ?, ?) RETURNING id`,
			email, strings.TrimSpace(displayName), boolInt(isAdmin), tenantID, oid).Scan(&id)
		if isUnique(err) {
			return fmt.Errorf("entra user %s/%s: %w", tenantID, firstNonEmpty(objectID, email), ErrExists)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "user.create", Target: firstNonEmpty(email, objectID),
			Detail: map[string]any{"kind": "entra", "tenant": tenantID, "admin": isAdmin}})
	})
	return id, err
}

// EntraIdentity is what a validated ID token says about the user.
type EntraIdentity struct {
	TenantID, ObjectID, Email, Name string
}

// ResolveEntraUser finds the provisioned user for a validated identity:
// by (tid, oid), or else by a pending (tid, email) provisioning, which is
// then bound to the oid for good. ErrNotFound means not provisioned.
func (s *Store) ResolveEntraUser(ctx context.Context, id EntraIdentity) (User, error) {
	tid, oid := strings.ToLower(id.TenantID), strings.ToLower(id.ObjectID)
	var userID int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM users WHERE kind = 'entra' AND entra_tid = ? AND entra_oid = ?`, tid, oid).Scan(&userID)
		if err == nil {
			_, err = tx.ExecContext(ctx, `UPDATE users SET display_name = ? WHERE id = ? AND display_name = ''`,
				strings.TrimSpace(id.Name), userID)
			return err
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		email, eerr := NormalizeEmail(id.Email)
		if eerr != nil {
			return ErrNotFound
		}
		err = tx.QueryRowContext(ctx, `
			UPDATE users SET entra_oid = ?, display_name = CASE WHEN display_name = '' THEN ? ELSE display_name END
			WHERE kind = 'entra' AND entra_tid = ? AND email = ? AND entra_oid IS NULL
			RETURNING id`, oid, strings.TrimSpace(id.Name), tid, email).Scan(&userID)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: fmt.Sprintf("user:%d", userID), Action: "user.entra_bind",
			Target: email, Detail: map[string]any{"tenant": tid, "oid": oid}})
	})
	if err != nil {
		return User{}, err
	}
	return s.UserByID(ctx, userID)
}

// SyncAppRoles makes a user's app-role grants match the roles claim:
// Heimdall.Admin (global admin), Heimdall.Operator / Heimdall.Viewer (every
// org) and Heimdall.Org.<slug>.<Role> (one org). Manual grants are kept.
func (s *Store) SyncAppRoles(ctx context.Context, userID int64, roles []string) error {
	want := map[int64]Role{}
	admin := false
	return s.tx(ctx, func(tx *sql.Tx) error {
		orgs := map[string]int64{}
		rows, err := tx.QueryContext(ctx, `SELECT id, slug FROM organizations`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var slug string
			if err := rows.Scan(&id, &slug); err != nil {
				rows.Close()
				return err
			}
			orgs[slug] = id
		}
		rows.Close()
		raise := func(org int64, r Role) {
			if !want[org].AtLeast(r) {
				want[org] = r
			}
		}
		for _, claim := range roles {
			parts := strings.Split(claim, ".")
			switch {
			case claim == "Heimdall.Admin":
				admin = true
			case len(parts) == 2 && parts[0] == "Heimdall":
				if r, err := ParseRole(parts[1]); err == nil {
					for _, id := range orgs {
						raise(id, r)
					}
				}
			case len(parts) == 4 && parts[0] == "Heimdall" && parts[1] == "Org":
				if r, err := ParseRole(parts[3]); err == nil {
					if id, ok := orgs[strings.ToLower(parts[2])]; ok {
						raise(id, r)
					}
				}
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM memberships WHERE user_id = ? AND source = 'entra_app_role'`, userID); err != nil {
			return err
		}
		for org, r := range want {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO memberships (user_id, org_id, role, source) VALUES (?, ?, ?, 'entra_app_role')
				ON CONFLICT (user_id, org_id) DO NOTHING`, userID, org, string(r)); err != nil {
				return err
			}
		}
		_, err = tx.ExecContext(ctx, `UPDATE users SET is_admin = ? WHERE id = ? AND kind = 'entra'`, boolInt(admin), userID)
		return err
	})
}

// ── OIDC login state ───────────────────────────────────────────────────────

// AuthRequest is an in-flight OIDC login, keyed by the hash of its state.
type AuthRequest struct {
	Nonce, Verifier, ReturnTo string
	CreatedAt                 time.Time
}

func (s *Store) PutAuthRequest(ctx context.Context, stateHash [32]byte, r AuthRequest) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_requests (state_hash, nonce, pkce_verifier, return_to, created_at) VALUES (?, ?, ?, ?, ?)`,
		stateHash[:], r.Nonce, r.Verifier, r.ReturnTo, r.CreatedAt.UTC().Format(timeLayout))
	return err
}

// TakeAuthRequest returns and deletes a login request (single use). It is
// ErrNotFound if unknown or older than maxAge.
func (s *Store) TakeAuthRequest(ctx context.Context, stateHash [32]byte, now time.Time, maxAge time.Duration) (AuthRequest, error) {
	var r AuthRequest
	var created string
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM auth_requests WHERE state_hash = ?
		RETURNING nonce, pkce_verifier, return_to, created_at`, stateHash[:]).
		Scan(&r.Nonce, &r.Verifier, &r.ReturnTo, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.CreatedAt = parseTime(created)
	if now.Sub(r.CreatedAt) > maxAge {
		return r, ErrNotFound
	}
	// Opportunistic cleanup of abandoned logins.
	s.db.ExecContext(ctx, `DELETE FROM auth_requests WHERE created_at < ?`, now.Add(-maxAge).UTC().Format(timeLayout))
	return r, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
