// SPDX-License-Identifier: AGPL-3.0-or-later

package entra

import (
	"regexp"
	"strconv"
	"strings"
)

// Messages for the person signing in, by AADSTS code: what went wrong and
// who can fix it. Only these fixed strings and the code's digits ever
// reach the page, never Microsoft's own text.
const (
	msgConsent       = "Your organization needs an administrator to approve Heimdall before you can sign in. Ask your Microsoft 365 admin to grant consent for the Heimdall app."
	msgNotAssigned   = "Your account hasn't been given access to Heimdall in Microsoft Entra. Ask your admin to assign you to the app."
	msgBlocked       = "Your organization's sign-in rules (Conditional Access) blocked this sign-in. Ask your Microsoft 365 admin which device or location Heimdall needs."
	msgOtherTenant   = "This account belongs to a different organization than the one Heimdall uses. Sign in with your work account for this organization."
	msgMisconfigured = "Heimdall's sign-in is misconfigured. Tell your Heimdall admin; the details are in the hub log."
)

var signInMessages = map[int]string{
	65001:   msgConsent, // consent required
	65004:   msgConsent, // consent declined
	90094:   msgConsent, // admin approval required
	90008:   msgConsent,
	50105:   msgNotAssigned, // assignment required and the user isn't assigned
	53003:   msgBlocked,
	50020:   msgOtherTenant,
	7000215: msgMisconfigured, // the ones in tokenHints
	7000222: msgMisconfigured,
	700025:  msgMisconfigured,
	9002327: msgMisconfigured,
	50011:   msgMisconfigured,
	700016:  msgMisconfigured,
}

// SignInMessage is what to tell the person signing in about the first of
// codes Heimdall knows, or "" for none. code is the one it chose (the
// first code when none is known, 0 when there are none).
func SignInMessage(codes []int) (msg string, code int) {
	for _, c := range codes {
		if m, ok := signInMessages[c]; ok {
			return m, c
		}
	}
	if len(codes) > 0 {
		return "", codes[0]
	}
	return "", 0
}

// aadstsPrefix is the code an error_description starts with
// ("AADSTS65004: User declined to consent ...").
var aadstsPrefix = regexp.MustCompile(`^AADSTS([0-9]{4,9})\b`)

// DescriptionCode is the AADSTS code an error_description starts with,
// or 0.
func DescriptionCode(desc string) int {
	m := aadstsPrefix.FindStringSubmatch(strings.TrimSpace(desc))
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(m[1]) // at most 9 digits: fits
	return n
}
