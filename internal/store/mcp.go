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

// MCPToken is a user's token for the MCP endpoint (never the secret).
type MCPToken struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time
	RevokedAt  time.Time
}

// CreateMCPToken issues a token for a user; the plaintext is returned once.
func (s *Store) CreateMCPToken(ctx context.Context, actor string, userID int64, name string) (string, int64, error) {
	name, err := normalizeName("name", firstNonEmpty(name, "mcp"))
	if err != nil {
		return "", 0, err
	}
	token, hash := secret.NewToken(secret.MCPPrefix)
	var id int64
	err = s.tx(ctx, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO mcp_tokens (user_id, name, token_hash) VALUES (?, ?, ?) RETURNING id`,
			userID, name, hash[:]).Scan(&id); err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "mcp_token.create", Target: fmt.Sprint(userID),
			Detail: map[string]any{"token": id, "name": name}})
	})
	return token, id, err
}

// MCPTokenUser resolves a live token to its (enabled) user and marks it used.
func (s *Store) MCPTokenUser(ctx context.Context, hash [32]byte, now time.Time) (User, int64, error) {
	var userID, tokenID int64
	var lastUsed sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT t.user_id, t.id, t.last_used_at FROM mcp_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = ? AND t.revoked_at IS NULL AND u.disabled_at IS NULL`, hash[:]).
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
		SELECT id, name, created_at, last_used_at, revoked_at FROM mcp_tokens WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MCPToken
	for rows.Next() {
		var t MCPToken
		var created string
		var used, revoked sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &created, &used, &revoked); err != nil {
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
