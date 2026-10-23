// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpPeriod = 30
	totpDigits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewTOTPSecret returns a random 160-bit TOTP secret.
func NewTOTPSecret() []byte {
	s := make([]byte, 20)
	rand.Read(s)
	return s
}

// TOTPSecretBase32 formats a secret for manual entry in an authenticator.
func TOTPSecretBase32(secret []byte) string { return b32.EncodeToString(secret) }

// TOTPURI returns an otpauth:// URI for enrolling an authenticator app.
func TOTPURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", TOTPSecretBase32(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// hotp is RFC 4226 with SHA-1 and the given number of digits.
func hotp(secret []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// totpAt returns the code for a time step (exported for tests via the
// unexported name only).
func totpAt(secret []byte, step int64) string { return hotp(secret, uint64(step), totpDigits) }

// VerifyTOTP checks a 6-digit code, allowing one step of clock drift each
// way. It returns the matched time step so callers can reject replays.
func VerifyTOTP(secret []byte, code string, now time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != totpDigits || len(secret) == 0 {
		return 0, false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	cur := now.Unix() / totpPeriod
	var matched int64
	ok := 0
	// Check every candidate step so timing doesn't depend on which matched.
	for _, step := range []int64{cur - 1, cur, cur + 1} {
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 {
			matched, ok = step, 1
		}
	}
	return matched, ok == 1
}
