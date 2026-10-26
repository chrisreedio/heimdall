// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

// A failed code exchange says why (Microsoft's error, AADSTS codes, the
// first sentence of the description and a hint), never the secret, the
// code or the verifier.
func TestTokenErrorSaysWhy(t *testing.T) {
	e := newEnv(t)
	idToken := signRS256(key1, "k1", e.claims())
	trace := `\r\nTrace ID: 0b6c7e2a-0000-4000-8000-000000000000\r\nCorrelation ID: 1c2d3e4f-0000-4000-8000-000000000000\r\nTimestamp: 2026-10-26 12:00:00Z`
	for _, tc := range []struct {
		status       int
		body         string
		code, aadsts string
		desc, hint   string
		cut          string // must not be in the message
	}{
		{http.StatusUnauthorized, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided. Ensure the secret being sent in the request is the client secret value, not the client secret ID, for a secret added to app 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'.` + trace + `","error_codes":[7000215]}`,
			"invalid_client", "AADSTS7000215", "Invalid client secret provided.", "Value, not its ID", "Trace ID"},
		{http.StatusUnauthorized, `{"error":"invalid_client","error_description":"AADSTS7000222: The provided client secret keys for app 'x' are expired.` + trace + `","error_codes":[7000222]}`,
			"invalid_client", "AADSTS7000222", "The provided client secret keys for app 'x' are expired.", "expired", "Correlation"},
		{http.StatusBadRequest, `{"error":"invalid_request","error_description":"AADSTS700025: Client is public so neither 'client_assertion' nor 'client_secret' should be presented.` + trace + `","error_codes":[700025]}`,
			"invalid_request", "AADSTS700025", "Client is public so neither 'client_assertion' nor 'client_secret' should be presented.", "Mobile and desktop applications", "Timestamp"},
		{http.StatusBadRequest, `{"error":"invalid_request","error_description":"AADSTS9002327: Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests.` + trace + `","error_codes":[9002327]}`,
			"invalid_request", "AADSTS9002327", "Tokens issued for the 'Single-Page Application' client-type may only be redeemed via cross-origin requests.", "not Single-page application", "Trace ID"},
		{http.StatusBadRequest, `{"error":"invalid_grant","error_description":"AADSTS50011: The redirect URI 'https://hub.example.com/auth/entra/callback' specified in the request does not match the redirect URIs configured for the application. Make sure the redirect URI matches.` + trace + `","error_codes":[50011]}`,
			"invalid_grant", "AADSTS50011", "The redirect URI 'https://hub.example.com/auth/entra/callback' specified in the request does not match the redirect URIs configured for the application.", "redirect URI mismatch", "Make sure"},
		{http.StatusBadRequest, `{"error":"unauthorized_client","error_description":"AADSTS700016: Application with identifier 'x' was not found in the directory 'acme'. This can happen if the application has not been installed.` + trace + `","error_codes":[700016]}`,
			"unauthorized_client", "AADSTS700016", "Application with identifier 'x' was not found in the directory 'acme'.", "wasn't found in the tenant", "This can happen"},
		{http.StatusInternalServerError, `<html>oops</html>`, "", "", "", "", "oops"},
	} {
		e.idp.mu.Lock()
		e.idp.tokenErr, e.idp.tokenBody = tc.status, tc.body
		e.idp.mu.Unlock()
		_, err := e.finishWith(idToken)
		var te *TokenError
		if !errors.As(err, &te) {
			t.Fatalf("%s: not a TokenError: %v", tc.aadsts, err)
		}
		if te.Status != tc.status || te.Code != tc.code || te.AADSTS() != tc.aadsts || te.Description != tc.desc || !strings.Contains(te.Hint, tc.hint) {
			t.Errorf("%s: %+v", tc.aadsts, te)
		}
		msg := err.Error()
		for _, never := range []string{testSecret, "the-code", e.req.Verifier} {
			if strings.Contains(msg, never) {
				t.Errorf("%s: the error leaks %q: %s", tc.aadsts, never, msg)
			}
		}
		if strings.Contains(msg, tc.cut) || strings.ContainsAny(msg, "\r\n") {
			t.Errorf("%s: %q", tc.aadsts, msg)
		}
		if tc.aadsts != "" && !strings.Contains(msg, tc.aadsts) {
			t.Errorf("%s: message lacks the code: %s", tc.aadsts, msg)
		}
	}
}
