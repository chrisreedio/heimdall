// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"net/netip"

	"github.com/chrisreedio/heimdall/internal/store"
)

// Internal reports whether an address is on the tailnet, a private network
// or loopback: where an org's tailnet-only policy allows SSH from. It goes
// by the address alone, never by labels, so a label can't make a public
// address count as internal.
func Internal(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && (Tailnet.Contains(a) || Tailnet6.Contains(a) || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast())
}

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
