// SPDX-License-Identifier: AGPL-3.0-or-later

// Package auth implements local accounts: argon2id passwords, TOTP,
// sessions and CSRF tokens.
package auth

import _ "golang.org/x/crypto/argon2" // keeps the dependency vendored
