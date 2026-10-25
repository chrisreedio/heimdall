// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"context"
	"net/netip"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// SignInWindow is how close to a session a Heimdall sign-in from the same
// address must be for SignIns to guess it's the same person.
const SignInWindow = 12 * time.Hour

// SignIns guesses who's behind an address from Heimdall UI sign-ins: a
// person who signed in from it within SignInWindow of when it was seen is
// probably who it is. Only people who can see the org are matched, so
// one org's sign-ins never name people to another.
//
// Behind `tailscale serve` the UI sees every sign-in from loopback unless
// ui.behind_tailscale_serve is set; loopback is ignored either way.
type SignIns struct{ Store *store.Store }

func (SignIns) Name() string { return "signin" }

func (s SignIns) Lookup(ctx context.Context, orgID int64, ip netip.Addr, at time.Time) ([]Label, error) {
	if s.Store == nil || !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
		return nil, nil
	}
	if at.IsZero() {
		at = time.Now()
	}
	ins, err := s.Store.SignInsNear(ctx, ip.String(), at, SignInWindow, orgID)
	if err != nil {
		return nil, err
	}
	var out []Label
	for _, si := range ins {
		out = append(out, Label{Kind: store.IPKindStaff, Name: "Signed in to Heimdall", Person: si.Who(),
			Source: "signin", Prefix: netip.PrefixFrom(ip, ip.BitLen()), Guess: true})
	}
	return out, nil
}
