// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters for new hashes (OWASP-recommended range).
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonThreads = 2
	argonSaltLen = 16
	argonKeyLen  = 32
)

// Upper bounds accepted when verifying, so a tampered hash can't make a
// login burn unbounded CPU or memory.
const (
	maxArgonMemory  = 1 << 20 // KiB = 1 GiB
	maxArgonTime    = 20
	maxArgonThreads = 16
)

var b64 = base64.RawStdEncoding

// HashPassword returns an argon2id hash in PHC string format.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	rand.Read(salt)
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

// VerifyPassword checks pw against a PHC argon2id hash in constant time.
func VerifyPassword(phc, pw string) (bool, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var v int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &v); err != nil || v != argon2.Version {
		return false, errBadHash
	}
	var m, t uint32
	var p uint8
	if n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil || n != 3 ||
		m < 8 || m > maxArgonMemory || t < 1 || t > maxArgonTime || p < 1 || p > maxArgonThreads {
		return false, errBadHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 || len(salt) > 64 {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash is verified against when an account doesn't exist, so failed
// logins take the same time either way.
var dummyHash, _ = HashPassword("heimdall-dummy-password-for-timing")

var commonPasswords = map[string]bool{
	"password1234": true, "123456789012": true, "qwertyuiopas": true, "passwordpassword": true,
	"letmein12345": true, "administrator": true, "heimdallheimdall": true, "changeme1234": true,
	"iloveyou1234": true, "welcome12345": true, "1234567890123": true, "qwerty123456": true,
}

// CheckPasswordPolicy enforces length and rejects trivially weak choices.
func CheckPasswordPolicy(pw string) error {
	switch {
	case len(pw) < 12:
		return errors.New("password must be at least 12 characters")
	case len(pw) > 256:
		return errors.New("password must be at most 256 bytes")
	case strings.Count(pw, pw[:1]) == len(pw):
		return errors.New("password must not be a single repeated character")
	case commonPasswords[strings.ToLower(pw)]:
		return errors.New("password is too common")
	}
	return nil
}
