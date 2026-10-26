// SPDX-License-Identifier: AGPL-3.0-or-later

package bans

import (
	"encoding/json"
	"net/url"

	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// Service is what the UI needs: the config, the engine (for live
// candidates) and the enforcer (to kick after a decision).
type Service struct {
	Cfg      config.Bans
	Engine   *Engine
	Enforcer *Enforcer // its Client is nil without a write token
	// TokenNote says why there's no write token ("" when there is one).
	TokenNote string
	// Cloudflare: [cloudflare] is on (zones come from its sync).
	Cloudflare bool
}

// Kick asks the enforcer to sync now.
func (s *Service) Kick() {
	if s != nil && s.Enforcer != nil {
		s.Enforcer.Kick()
	}
}

// TokenPermissions are the documented permission group keys the write
// token gets from the pre-filled form: Zone > Zone WAF > Edit (custom
// rules). The key for Account > Account Filter Lists > Edit isn't
// documented, so it's left out: add that permission by hand.
// https://developers.cloudflare.com/fundamentals/api/how-to/account-owned-token-template/
const TokenPermissions = `[{"key":"firewall_services","type":"edit"}]`

// TokenURL opens Cloudflare's "create token" form for the ban token,
// pre-filled (an account-owned token).
func TokenURL() string {
	return "https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=" +
		url.QueryEscape(TokenPermissions) + "&name=Heimdall%20bans"
}

// TokenManualStep is the permission the form can't pre-fill.
const TokenManualStep = "Account > Account Filter Lists > Edit"

// Decode reads a stored ban's breakdown and evidence.
func Decode(b store.Ban) ([]Factor, Evidence) {
	var fs []Factor
	var ev Evidence
	json.Unmarshal(b.Breakdown, &fs)
	json.Unmarshal(b.Evidence, &ev)
	return fs, ev
}

// FactorLabels are plain names for score parts.
var FactorLabels = map[string]string{"hosts": "hosts", "failures": "failures", "usernames": "usernames",
	"succeeded": "then succeeded", "days": "days", "asn": "same-network offenders", "network": "addresses' scores",
	"addresses": "addresses"}
