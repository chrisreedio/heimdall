// SPDX-License-Identifier: AGPL-3.0-or-later

// Package secret generates and hashes bearer tokens.
//
// Only hashes are ever stored. Tokens carry 256 bits of randomness, so a fast
// hash (SHA-256) is sufficient; a slow KDF is only needed for low-entropy
// secrets like passwords.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// IngestPrefix marks host ingest tokens so secret scanners and humans can
// recognize them.
const IngestPrefix = "hmd_ingest_"

// MCPPrefix marks per-user MCP tokens.
const MCPPrefix = "hmd_mcp_"

// NewToken returns a random token with the given prefix and its hash.
func NewToken(prefix string) (token string, hash [32]byte) {
	b := make([]byte, 32)
	rand.Read(b) // never returns an error; crashes the program on failure
	token = prefix + base64.RawURLEncoding.EncodeToString(b)
	return token, Hash(token)
}

// Hash returns the value stored for a token.
func Hash(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// LooksLike reports whether s has the shape of a token with the given prefix,
// so malformed input can be rejected before touching the database.
func LooksLike(s, prefix string) bool {
	rest, ok := strings.CutPrefix(s, prefix)
	if !ok || len(rest) != base64.RawURLEncoding.EncodedLen(32) {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(rest)
	return err == nil
}
