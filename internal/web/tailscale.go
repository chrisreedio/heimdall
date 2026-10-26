// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"html/template"
	"time"

	"github.com/realmwatch/heimdall/internal/tailscale"
)

// The host page's Tailnet card and the "Not on tailnet" filter, from the
// devices the Tailscale sync stored (internal/tailscale). Off unless
// [tailscale] is on and a sync has worked.

// tailnetView is the Tailnet card.
type tailnetView struct {
	On              bool   // a tailnet device matches the host
	Name, DNSName   string // "web-01", "web-01.tail1234.ts.net"
	Person          string // owner's login (untagged devices)
	Addresses       []string
	Tags            []string
	OS              string
	ClientVersion   string
	UpdateAvailable bool
	Online          bool
	LastSeen        *time.Time
	SeenAgo         string // "3 days ago"
	KeyExpiry       *time.Time
	KeyExpired      bool
	KeyExpiresSoon  bool   // within keySoon
	KeyDate         string // "Oct 30, 2026"
	SyncedAt        *time.Time
}

// keySoon is when a node key's expiry becomes worth a warning.
const keySoon = 14 * 24 * time.Hour

// tailnetFor builds the Tailnet card for a host; nil when Tailscale is off
// or has never synced.
func (s *server) tailnetFor(ctx context.Context, hostID int64, name string) (*tailnetView, error) {
	if !s.cfg.Tailnet {
		return nil, nil
	}
	devs, err := s.st.TailnetDevices(ctx)
	if err != nil || len(devs) == 0 {
		return nil, err
	}
	ip, err := s.st.HostReportIP(ctx, hostID)
	if err != nil {
		return nil, err
	}
	synced := devs[0].SyncedAt
	v := &tailnetView{SyncedAt: &synced}
	d, ok := tailscale.Match(devs, name, ip)
	if !ok {
		return v, nil
	}
	v.On, v.Name, v.DNSName, v.Person = true, tailscale.DeviceName(d), d.Name, d.User
	v.Addresses, v.Tags, v.OS, v.ClientVersion, v.UpdateAvailable, v.Online = d.Addresses, d.Tags, d.OS, d.ClientVersion, d.UpdateAvailable, d.Online
	if !d.LastSeen.IsZero() {
		v.LastSeen, v.SeenAgo = &d.LastSeen, dayAgo(&d.LastSeen, s.now())
	}
	if !d.KeyExpiry.IsZero() {
		v.KeyExpiry, v.KeyDate = &d.KeyExpiry, d.KeyExpiry.Local().Format("Jan 2, 2006")
		left := d.KeyExpiry.Sub(s.now())
		v.KeyExpired, v.KeyExpiresSoon = left <= 0, left > 0 && left < keySoon
	}
	return v, nil
}

// markOffTailnet flags reported hosts no tailnet device matches (a no-op
// when Tailscale is off or has never synced, so nothing is flagged then).
func (s *server) markOffTailnet(ctx context.Context, hosts []fleetHost) error {
	if !s.cfg.Tailnet {
		return nil
	}
	devs, err := s.st.TailnetDevices(ctx)
	if err != nil || len(devs) == 0 {
		return err
	}
	all, err := s.st.TailnetHosts(ctx)
	if err != nil {
		return err
	}
	matched := tailscale.MatchHosts(all, devs)
	for i := range hosts {
		_, on := matched[hosts[i].ID]
		hosts[i].OffTailnet = hosts[i].Reported && !on
	}
	return nil
}

// parseTailnetCard adds the Tailnet card's template to the host page.
func parseTailnetCard(pages map[string]*template.Template) error {
	_, err := pages["host"].ParseFS(templatesFS, "templates/tailnet.html")
	return err
}
