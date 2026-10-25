// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"time"

	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/privilege"
	"github.com/chrisreedio/heimdall/internal/store"
)

// privilegeView is the host page's "Privileged access" line. It's nil on
// Windows, which has no privilege watch.
type privilegeView struct {
	Counts   string     // "3 sudo, 1 root SSH", or "" for none
	Last     *time.Time // newest event, nil if none
	Off      bool       // the watch was on and isn't now
	EverOn   bool
	State    string
	Recent   []privilegeEvent // newest first, when the server records who
	Coverage privilegeCoverage
	// Sessions in the last 24 hours from addresses nothing is known about.
	UnknownSessions int
	Unknown         []ipLink
}

// privilegeCoverage is how fully a server's privilege watch records
// privileged access, so the ones that don't record who and from where
// can be found and fixed.
type privilegeCoverage struct {
	Full  bool   // on, recording who and from where
	Label string // what's missing: "privilege watch off", "no source IP"…
	Why   string // a sentence for the host page and tooltips
	Fix   string // the command that closes the gap, on the server
}

const watchUsersCmd = "sudo heimdall-collect upgrade --watch-privilege-users"

// coverageOf classifies a Linux server's privilege watch from its last
// reported state and detail (store.HostState). ok is false on Windows,
// which has no privilege watch.
func coverageOf(pm, state, detail string) (c privilegeCoverage, ok bool) {
	if pm == "windows" {
		return c, false
	}
	switch {
	case state == "" || state == "off":
		c = privilegeCoverage{Label: "privilege watch off", Why: "Nothing records sudo, su or root SSH logins on this server.", Fix: watchUsersCmd}
	case state == "partial":
		c = privilegeCoverage{Label: "privilege watch partly removed", Why: "Part of the privilege watch was removed, so some privileged access goes unrecorded.", Fix: watchUsersCmd}
	case detail == store.PrivilegeSources:
		c = privilegeCoverage{Full: true, Label: "who and where recorded"}
	case detail == store.PrivilegeUsers:
		c = privilegeCoverage{Label: "no source IP", Why: "It records who, but its hook predates source IPs (collector 0.4.23).", Fix: "sudo heimdall-collect upgrade"}
	case detail == store.PrivilegeKinds:
		c = privilegeCoverage{Label: "who not recorded", Why: "It records when and which kind, not who or from where.", Fix: watchUsersCmd}
	default:
		c = privilegeCoverage{Label: "privilege detail unknown", Why: "Its collector is too old to say whether it records who and from where.", Fix: "sudo heimdall-collect upgrade"}
	}
	return c, true
}

type privilegeEvent struct {
	At     time.Time
	Kind   string // "sudo", "root SSH"
	User   string
	Source string   // where from: an address or host name, "" if unknown or local
	Href   string   // the source's IP page, when it's an address
	Badge  *ipBadge // what's known about the source (ips.go)
}

// recentPrivilege is how many events the host page lists.
const recentPrivilege = 8

func (s *server) privilegeFor(ctx context.Context, host store.IngestHost, pm string) (*privilegeView, error) {
	sum, err := s.st.PrivilegeSummary(ctx, host.ID, s.now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	cov, ok := coverageOf(pm, sum.State, sum.Detail)
	if !ok {
		return nil, nil
	}
	v := &privilegeView{Counts: privilege.Counts(sum.Counts), State: sum.State, EverOn: sum.EverOn || !sum.Last.IsZero(),
		Off: sum.EverOn && sum.State != "on", Coverage: cov}
	if !sum.Last.IsZero() {
		v.Last = &sum.Last
	}
	evs, err := s.st.RecentPrivilege(ctx, host.ID, recentPrivilege)
	if err != nil {
		return nil, err
	}
	var resolve func(ip, user string, at time.Time) ipinfo.Verdict
	for _, ev := range evs {
		if ev.Source == "?" {
			ev.Source = ""
		}
		if ev.User == "" && ev.Source == "" {
			continue
		}
		pe := privilegeEvent{At: ev.At, Kind: privilege.KindLabel(ev.Kind), User: ev.User, Source: ev.Source}
		if ev.Source != "" {
			if resolve == nil {
				resolve = s.ips().Batch(ctx, host.OrgID)
			}
			b := badgeFor(resolve(ev.Source, ev.User, ev.At))
			pe.Href, pe.Badge = b.Href, &b
		}
		v.Recent = append(v.Recent, pe)
	}
	// Sessions in the last day from addresses nothing is known about.
	srcs, err := s.st.PrivilegeSourcesSince(ctx, store.AllScope, host.ID, s.now().Add(-24*time.Hour))
	if err != nil {
		return nil, err
	}
	for _, src := range srcs {
		if resolve == nil {
			resolve = s.ips().Batch(ctx, host.OrgID)
		}
		if vd, ok := unknownSource(resolve, src); ok {
			v.UnknownSessions += src.Count
			v.Unknown = append(v.Unknown, ipLink{Addr: src.Source, Href: ipURL(vd)})
		}
	}
	return v, nil
}
