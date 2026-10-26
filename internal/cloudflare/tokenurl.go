package cloudflare

import (
	"encoding/json"
	"net/url"
	"strings"
)

// Perm is one entry of a dashboard token template: a permission group key
// and its level (read, edit, ...). Keys are from
// https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/
type Perm struct {
	Key  string `json:"key"`
	Type string `json:"type"`
}

// ReadPerms is the read-only token Heimdall needs (docs/cloudflare.md):
// zones, DNS, analytics, and the attack surface's zone settings and
// certificates. Radar has no documented template key, so it's added by hand
// (ReadManual).
var ReadPerms = []Perm{
	{"zone", "read"}, {"dns", "read"}, {"analytics", "read"},
	{"zone_settings", "read"}, {"ssl_and_certificates", "read"},
}

// ReadManual is what the template can't fill in.
const ReadManual = "Account > Radar > Read (for network names of unknown addresses; skip it with radar = false) and " +
	"Account > Account Filter Lists > Read (to label addresses from your IP lists; optional)"

// TokenURL opens the dashboard's "create token" form, pre-filled with perms
// on all accounts and zones. It's a user-owned token: VerifyToken only
// works for those. Nothing is created until the user clicks Create.
func TokenURL(name string, perms []Perm) string {
	b, _ := json.Marshal(perms)
	q := url.Values{"permissionGroupKeys": {string(b)}, "accountId": {"*"}, "zoneId": {"all"}, "name": {name}}
	// %20, not +: the dashboard shows the name as given.
	return "https://dash.cloudflare.com/profile/api-tokens?" + strings.ReplaceAll(q.Encode(), "+", "%20")
}
