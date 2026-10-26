// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strconv"

	"github.com/realmwatch/heimdall/internal/store"
)

// mcpUser finds a user of either kind by email.
func mcpUser(a *app, s *store.Store, email string) (store.User, error) {
	email, err := store.NormalizeEmail(email)
	if err != nil {
		return store.User{}, err
	}
	users, err := s.ListUsers(a.ctx)
	if err != nil {
		return store.User{}, err
	}
	for _, u := range users {
		if u.Email == email {
			return u, nil
		}
	}
	return store.User{}, fmt.Errorf("user %s: %w", email, store.ErrNotFound)
}

func cmdMCPTokenCreate(a *app, args []string) error {
	fs := a.flags("user mcp-token create", "[--name laptop] [--purpose mcp|threats] <email>")
	name := fs.String("name", "", "label for this token, e.g. the device (default: the purpose)")
	purpose := fs.String("purpose", store.PurposeMCP, "mcp (the MCP endpoint) or threats (the threat list's REST API, docs/threats.md)")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if store.TokenPrefix(*purpose) == "" {
		return fmt.Errorf("--purpose must be mcp or threats")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	u, err := mcpUser(a, s, pos[0])
	if err != nil {
		return err
	}
	token, id, err := s.CreateToken(a.ctx, actor(), u.ID, *name, *purpose)
	if err != nil {
		return err
	}
	if *purpose == store.PurposeThreats {
		fmt.Fprintf(a.stderr, "Created threat-list token %d for %s (shown once). It reads only /api/v1/threats, "+
			"over what their UI login can see; it can't use /mcp.\n"+
			"Pull with: curl --config <file holding: header = \"Authorization: Bearer <token>\"> https://<hub>/api/v1/threats?format=plain\n\n", id, u.Email)
		fmt.Fprintln(a.stdout, token)
		return nil
	}
	fmt.Fprintf(a.stderr, "Created MCP token %d for %s (shown once). It grants the same read access as their UI login.\n"+
		"Connect with: claude mcp add --transport http heimdall https://<hub>/mcp --header \"Authorization: Bearer <token>\"\n\n", id, u.Email)
	fmt.Fprintln(a.stdout, token)
	return nil
}

func cmdMCPTokenList(a *app, args []string) error {
	pos, err := parse(a.flags("user mcp-token list", "<email>"), args, 1)
	if err != nil {
		return err
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	u, err := mcpUser(a, s, pos[0])
	if err != nil {
		return err
	}
	tokens, err := s.ListMCPTokens(a.ctx, u.ID)
	if err != nil {
		return err
	}
	rows := make([][]string, len(tokens))
	for i, t := range tokens {
		status := "active"
		if !t.RevokedAt.IsZero() {
			status = "revoked"
		}
		rows[i] = []string{strconv.FormatInt(t.ID, 10), t.Name, t.Purpose, formatTime(t.CreatedAt), formatTime(t.LastUsedAt), status}
	}
	return table(a, "ID\tNAME\tPURPOSE\tCREATED\tLAST USED\tSTATUS", rows)
}

func cmdMCPTokenRevoke(a *app, args []string) error {
	pos, err := parse(a.flags("user mcp-token revoke", "<email> <token-id>"), args, 2)
	if err != nil {
		return err
	}
	id, err := strconv.ParseInt(pos[1], 10, 64)
	if err != nil {
		return fmt.Errorf("token ID must be a number")
	}
	s, err := a.openStore()
	if err != nil {
		return err
	}
	defer s.Close()
	u, err := mcpUser(a, s, pos[0])
	if err != nil {
		return err
	}
	return s.RevokeMCPToken(a.ctx, actor(), u.ID, id)
}
