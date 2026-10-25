// SPDX-License-Identifier: AGPL-3.0-or-later

package tailscale

import (
	"context"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// Source is the labels' source name (store.IPLabel.Source).
const Source = "tailscale"

// Syncer keeps the tailnet's devices and their address labels current
// (an ipinfo.Syncer). A failed sync keeps the last good ones.
type Syncer struct {
	Store  *store.Store
	Client *Client
	Period time.Duration
	Now    func() time.Time
	Log    *slog.Logger
}

func (s *Syncer) Name() string         { return Source }
func (s *Syncer) Every() time.Duration { return s.Period }

// Result is what one sync found.
type Result struct {
	Devices, Labels, Hosts int // hosts: Heimdall hosts matched to a device
	KeyExpires             time.Time
}

func (s *Syncer) Sync(ctx context.Context) error {
	_, err := s.Run(ctx)
	return err
}

// Run syncs once.
func (s *Syncer) Run(ctx context.Context) (Result, error) {
	now := s.Now()
	devs, err := s.Client.Devices(ctx)
	if err != nil {
		if rerr := s.Store.RecordTailnetSyncError(ctx, err.Error(), now); rerr != nil && s.Log != nil {
			s.Log.Warn("recording Tailscale sync error", "err", rerr)
		}
		return Result{}, err
	}
	var res Result
	res.Devices = len(devs)
	if res.KeyExpires, err = s.Client.KeyExpiry(ctx); err != nil && s.Log != nil {
		s.Log.Debug("Tailscale key expiry unknown", "err", err) // listing devices worked; this is a nicety
	}
	hosts, err := s.Store.TailnetHosts(ctx)
	if err != nil {
		return Result{}, err
	}
	matched := MatchHosts(hosts, devs)
	servers := map[string]bool{}
	for _, d := range matched {
		servers[d.ID] = true
	}
	res.Hosts = len(matched)
	labels := Labels(devs, servers, now)
	res.Labels = len(labels)
	if err := s.Store.ReplaceIPLabels(ctx, 0, Source, labels, now); err != nil {
		return Result{}, err
	}
	if err := s.Store.ReplaceTailnetDevices(ctx, devs, s.Client.Cred.Kind(), res.KeyExpires, now); err != nil {
		return Result{}, err
	}
	return res, nil
}

// short is a name's first DNS label, lowercased: "Web-01.example.com" is
// "web-01".
func short(name string) string {
	name, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(name)), ".")
	return name
}

// DeviceName is the name to show for a device: its hostname, else the
// first label of its MagicDNS name.
func DeviceName(d store.TailnetDevice) string {
	if d.Hostname != "" {
		return d.Hostname
	}
	if n := short(d.Name); n != "" {
		return n
	}
	return d.ID
}

// Match finds a host's tailnet device: the one its reports come from,
// else the one whose MagicDNS name, then hostname, matches the host's name
// (ignoring case and any domain). Among equals, the most recently seen.
func Match(devs []store.TailnetDevice, name, reportIP string) (store.TailnetDevice, bool) {
	if ip, err := netip.ParseAddr(reportIP); err == nil {
		ip = ip.Unmap()
		for _, d := range devs {
			for _, a := range d.Addresses {
				if b, err := netip.ParseAddr(a); err == nil && b == ip {
					return d, true
				}
			}
		}
	}
	want := short(name)
	if want == "" {
		return store.TailnetDevice{}, false
	}
	for _, key := range []func(store.TailnetDevice) string{
		func(d store.TailnetDevice) string { return short(d.Name) },
		func(d store.TailnetDevice) string { return short(d.Hostname) },
	} {
		var best store.TailnetDevice
		found := false
		for _, d := range devs {
			if key(d) == want && (!found || d.LastSeen.After(best.LastSeen) || d.Online && !best.Online) {
				best, found = d, true
			}
		}
		if found {
			return best, true
		}
	}
	return store.TailnetDevice{}, false
}

// MatchHosts maps host IDs to their tailnet devices; hosts not on the
// tailnet are left out.
func MatchHosts(hosts []store.TailnetHost, devs []store.TailnetDevice) map[int64]store.TailnetDevice {
	out := map[int64]store.TailnetDevice{}
	for _, h := range hosts {
		if d, ok := Match(devs, h.Name, h.ReportIP); ok {
			out[h.ID] = d
		}
	}
	return out
}

// Labels are the devices' address labels: a person's device is staff (the
// person is its owner's login), a tagged device or one of your Heimdall
// hosts (servers, by device ID) is infra.
func Labels(devs []store.TailnetDevice, servers map[string]bool, now time.Time) []store.IPLabel {
	var out []store.IPLabel
	for _, d := range devs {
		kind := store.IPKindStaff
		if len(d.Tags) > 0 || d.User == "" || servers[d.ID] {
			kind = store.IPKindInfra
		}
		name := DeviceName(d)
		if len(name) > 100 {
			name = name[:100]
		}
		person := d.User
		if len(person) > 200 {
			person = ""
		}
		note := noteFor(d, now)
		seen := map[netip.Prefix]bool{}
		for _, a := range d.Addresses {
			p, err := store.ParseIPPrefix(a)
			if err != nil || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, store.IPLabel{Prefix: p, Kind: kind, Name: name, Person: person, Source: Source, Note: note})
		}
	}
	return out
}

// noteFor is a label's note: "Tailscale · tag:server · linux · online".
func noteFor(d store.TailnetDevice, now time.Time) string {
	parts := []string{"Tailscale"}
	if len(d.Tags) > 0 {
		parts = append(parts, strings.Join(d.Tags, ", "))
	}
	if d.OS != "" {
		parts = append(parts, d.OS)
	}
	switch {
	case d.Online:
		parts = append(parts, "online")
	case !d.LastSeen.IsZero():
		parts = append(parts, "last seen "+SeenAgo(d.LastSeen, now))
	}
	note := strings.Join(parts, " · ")
	if len(note) > 500 {
		note = note[:500]
	}
	return note
}

// SeenAgo is "today", "yesterday", "3 days ago" or "Oct 23, 2026".
func SeenAgo(t, now time.Time) string {
	days := int(now.Sub(t).Hours() / 24)
	switch {
	case days <= 0:
		return "today"
	case days == 1:
		return "yesterday"
	case days < 30:
		return strconv.Itoa(days) + " days ago"
	}
	return t.Local().Format("Jan 2, 2006")
}
