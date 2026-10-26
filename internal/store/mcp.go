// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/realmwatch/heimdall/internal/secret"
)

// Token purposes: what a user's token works for (migration 0030). Each
// works only on its own endpoints.
const (
	PurposeMCP     = "mcp"     // the MCP endpoint (/mcp)
	PurposeThreats = "threats" // the threat list's REST API (/api/v1/threats*)
)

// TokenPurposes are the valid purposes.
var TokenPurposes = []string{PurposeMCP, PurposeThreats}

// tokenPrefix is each purpose's token prefix.
var tokenPrefix = map[string]string{PurposeMCP: secret.MCPPrefix, PurposeThreats: secret.ThreatsPrefix}

// TokenPrefix is the prefix a purpose's tokens start with ("" if invalid).
func TokenPrefix(purpose string) string { return tokenPrefix[purpose] }

// MCPToken is a user's token for the MCP endpoint or the threat list
// (never the secret).
type MCPToken struct {
	ID         int64
	Name       string
	Purpose    string
	CreatedAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// CreateMCPToken issues an MCP token for a user; the plaintext is
// returned once.
func (s *Store) CreateMCPToken(ctx context.Context, actor string, userID int64, name string) (string, int64, error) {
	return s.CreateToken(ctx, actor, userID, name, PurposeMCP)
}

// CreateToken issues a token with a purpose for a user; the plaintext is
// returned once.
func (s *Store) CreateToken(ctx context.Context, actor string, userID int64, name, purpose string) (string, int64, error) {
	prefix := tokenPrefix[purpose]
	if prefix == "" {
		return "", 0, &ValidationError{"purpose", "must be mcp or threats"}
	}
	name, err := normalizeName("name", firstNonEmpty(name, purpose))
	if err != nil {
		return "", 0, err
	}
	token, hash := secret.NewToken(prefix)
	var id int64
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO mcp_tokens (user_id, name, token_hash, purpose) VALUES (?, ?, ?, ?) RETURNING id`,
			userID, name, hash[:], purpose).Scan(&id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "mcp_token.create", Target: fmt.Sprint(userID),
			Detail: map[string]any{"token": id, "name": name, "purpose": purpose}})
	})
	return token, id, err
}

// MCPTokenUser resolves a live MCP token to its (enabled) user and marks
// it used. A token with another purpose is not found.
func (s *Store) MCPTokenUser(ctx context.Context, hash [32]byte, now time.Time) (User, int64, error) {
	return s.TokenUser(ctx, hash, PurposeMCP, now)
}

// TokenUser resolves a live token with this purpose to its (enabled) user
// and marks it used. A token with another purpose is not found.
func (s *Store) TokenUser(ctx context.Context, hash [32]byte, purpose string, now time.Time) (User, int64, error) {
	var userID, tokenID int64
	var lastUsed sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT t.user_id, t.id, t.last_used_at FROM mcp_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.purpose = ? AND t.revoked_at IS NULL AND u.disabled_at IS NULL`, hash[:], purpose).
		Scan(&userID, &tokenID, &lastUsed)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, 0, ErrNotFound
	}
	if err != nil {
		return User{}, 0, err
	}
	// At most one write a minute per token.
	if t := parseNullTime(lastUsed); now.Sub(t) > time.Minute {
		if _, err := s.db.ExecContext(ctx, `UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?`,
			now.UTC().Format(timeLayout), tokenID); err != nil {
			return User{}, 0, err
		}
	}
	u, err := s.UserByID(ctx, userID)
	return u, tokenID, err
}

func (s *Store) ListMCPTokens(ctx context.Context, userID int64) ([]MCPToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, purpose, created_at, last_used_at, revoked_at FROM mcp_tokens WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPToken
	for rows.Next() {
		var t MCPToken
		var created string
		var used, revoked sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Purpose, &created, &used, &revoked); err != nil {
			return nil, err
		}
		t.CreatedAt, t.LastUsedAt, t.RevokedAt = parseTime(created), parseNullTime(used), parseNullTime(revoked)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeMCPToken revokes one of a user's tokens.
func (s *Store) RevokeMCPToken(ctx context.Context, actor string, userID, tokenID int64) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE mcp_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
			WHERE id = ? AND user_id = ? AND revoked_at IS NULL`, tokenID, userID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return fmt.Errorf("token %d: %w", tokenID, ErrNotFound)
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "mcp_token.revoke", Target: fmt.Sprint(userID),
			Detail: map[string]any{"token": tokenID}})
	})
}
