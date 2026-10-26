// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/netx"
)

// TokenError is a failed code exchange, described from the token
// endpoint's JSON error body, so a misconfigured app registration logs
// why ("AADSTS7000215 ...") and not just "HTTP 401". It never holds the
// client secret, the authorization code or any token: only Microsoft's
// error name, AADSTS codes and the first sentence of its description.
// Sign-in pages still show people a generic message.
type TokenError struct {
	Status      int    // HTTP status (0 for an error in a 200 response)
	Code        string // "error": invalid_client, invalid_grant, ...
	Codes       []int  // "error_codes": the AADSTS numbers
	Description string // the first sentence of "error_description"
	Hint        string // what usually fixes it, for known codes
}

func (e *TokenError) Error() string {
	var b strings.Builder
	b.WriteString("entra: token endpoint")
	if e.Status != 0 {
		fmt.Fprintf(&b, ": HTTP %d", e.Status)
	}
	if e.Code != "" {
		b.WriteString(": " + e.Code)
	}
	if s := e.AADSTS(); s != "" {
		b.WriteString(" " + s)
	}
	if e.Description != "" {
		b.WriteString(": " + e.Description)
	}
	if e.Hint != "" {
		b.WriteString(" (" + e.Hint + ")")
	}
	return b.String()
}

// AADSTS is the error codes as "AADSTS7000215, AADSTS50011".
func (e *TokenError) AADSTS() string {
	s := make([]string, len(e.Codes))
	for i, c := range e.Codes {
		s[i] = "AADSTS" + strconv.Itoa(c)
	}
	return strings.Join(s, ", ")
}

// tokenHints are fixes for the codes a new app registration usually hits.
var tokenHints = map[int]string{
	7000215: "invalid client secret: check you saved the secret's Value, not its ID",
	7000222: "the client secret has expired: create a new one and store it",
	700025:  "public client: the redirect URI is under 'Mobile and desktop applications'; register it under Web",
	9002327: "the redirect URI is registered as a single-page application; register it under Web, not Single-page application",
	50011:   "redirect URI mismatch: register Heimdall's exact callback URL under Web",
	700016:  "the application (client ID) wasn't found in the tenant: check the client ID and tenant",
}

// maxDescription bounds the description kept from an error body.
const maxDescription = 300

// tokenError builds a TokenError from a token endpoint failure. It
// returns nil when err isn't an HTTP error status.
func tokenError(err error) *TokenError {
	var se *netx.StatusError
	if !errors.As(err, &se) {
		return nil
	}
	te := parseTokenError(se.Body)
	te.Status = se.Status
	return te
}

// parseTokenError reads an OAuth error body: {"error", "error_codes",
// "error_description"}. Anything else (not JSON, too big) leaves it empty.
func parseTokenError(body []byte) *TokenError {
	var doc struct {
		Error       string `json:"error"`
		Codes       []int  `json:"error_codes"`
		Description string `json:"error_description"`
	}
	te := &TokenError{}
	if json.Unmarshal(body, &doc) != nil {
		return te
	}
	te.Code = clean(doc.Error, 64)
	if len(doc.Codes) > 5 {
		doc.Codes = doc.Codes[:5]
	}
	te.Codes = doc.Codes
	te.Description = firstSentence(doc.Description)
	for _, c := range te.Codes {
		if h, ok := tokenHints[c]; ok {
			te.Hint = h
			break
		}
	}
	return te
}

// firstSentence is the description before "Trace ID" (Microsoft appends
// trace and correlation IDs and a timestamp), cut at its first sentence.
// Its "AADSTSnnnn: " prefix is dropped: the codes are logged apart.
func firstSentence(d string) string {
	d, _, _ = strings.Cut(d, "Trace ID")
	d = strings.Join(strings.Fields(d), " ")
	if i := strings.Index(d, ": "); i > 0 && strings.HasPrefix(d, "AADSTS") {
		d = d[i+2:]
	}
	if i := strings.Index(d, ". "); i >= 0 {
		d = d[:i+1]
	}
	return clean(d, maxDescription)
}

// clean drops control characters (log lines stay one line) and bounds s.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return truncate(s, n)
}
