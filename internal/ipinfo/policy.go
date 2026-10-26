// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"net/netip"
	"slices"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Internal reports whether an address is on the tailnet, a private network
// or loopback: where an org's tailnet-only policy allows SSH from. It goes
// by the address alone, never by labels, so a label can't make a public
// address count as internal.
func Internal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && (Tailnet.Contains(a) || Tailnet6.Contains(a) || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast())
}

// InternalRanges are nobody's attacker: the tailnet, private networks,
// loopback, link-local, and the unspecified and multicast space. Bans
// never target them and the web offender list never stores them.
var InternalRanges = []netip.Prefix{
	Tailnet, Tailnet6,
	netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("::/128"), netip.MustParsePrefix("ff00::/8"),
}

// SignInLookback is how far back a Heimdall sign-in from an address makes
// it friendly, to bans and to the web offender list.
const SignInLookback = 30 * 24 * time.Hour

// SyncedAutomation reports whether the address is in a range a synced
// source labels automation (a deploy service's published ranges). Manual
// labels, guesses and user hints (which match the account, not the
// address) don't count.
func (v Verdict) SyncedAutomation() bool {
	for _, l := range v.Labels {
		if l.Kind == store.IPKindAutomation && !l.Guess && l.Prefix.IsValid() && l.Prefix.Contains(v.Addr) &&
			l.Source != store.IPSourceManual && l.Source != "builtin" {
			return true
		}
	}
	return false
}

// Unknown reports whether nothing is known about the address (or it isn't
// one, like a host name sshd resolved).
func (v Verdict) Unknown() bool { return v.Kind() == store.IPKindUnknown }

// UnknownAddress is Unknown, except that labels not about the address
// itself (a deploy service recognized only by its account name) don't
// count: the "forge" account logging in from somewhere other than Forge's
// ranges is exactly what a stolen deploy key looks like.
func (v Verdict) UnknownAddress() bool {
	_, ok := v.AddressLabel()
	return !ok
}

// AddressLabel is the most telling label about the address itself (not
// one matched by the account name), if any: what makes it known.
func (v Verdict) AddressLabel() (Label, bool) {
	i := slices.IndexFunc(v.Labels, func(l Label) bool {
		return l.Kind != store.IPKindUnknown && l.Prefix.IsValid() && l.Prefix.Contains(v.Addr)
	})
	if i < 0 {
		return Label{}, false
	}
	return v.Labels[i], true
}
