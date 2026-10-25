// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/store"
)

// RadarSource is the Radar labels' source.
const RadarSource = "cloudflare:radar"

// ASN is Radar's answer for an address.
type ASN struct {
	ASN     int64  `json:"asn"`
	Name    string `json:"name"`
	OrgName string `json:"orgName"`
	Country string `json:"country"`
}

// ASNByIP asks Radar which network an address is in (Account > Radar >
// Read). An address Radar doesn't know is ASN 0 and no error.
func (c *Client) ASNByIP(ctx context.Context, ip netip.Addr) (ASN, error) {
	var out struct {
		ASN ASN `json:"asn"`
	}
	_, err := c.get(ctx, "/radar/entities/asns/ip", url.Values{"ip": {ip.String()}}, &out)
	var ae *APIError
	if errors.As(err, &ae) && (ae.Status == 404 || ae.Status == 400) {
		return ASN{}, nil
	}
	return out.ASN, err
}

const (
	radarFresh    = 7 * 24 * time.Hour // a found ASN is cached this long
	radarNegative = 24 * time.Hour     // and a miss this long
	radarPause    = 6 * time.Hour      // after a permission error
	radarMaxQueue = 1000
	radarPerRun   = 20   // lookups per run (one run a minute)
	radarPerDay   = 2000 // and per UTC day
)

// Radar labels public addresses nobody knows with their network, e.g.
// "AS64500 Example ISP (US)", as a guess of kind unknown: context for a
// person, never a verdict. Lookup only reads the in-memory cache and
// queues misses; Sync (an ipinfo.Syncer run every minute) works the queue
// slowly in the background, so a page never waits on Cloudflare.
type Radar struct {
	Client *Client
	Store  *store.Store
	Edge   *Edge // Cloudflare's own addresses are never looked up
	Now    func() time.Time
	Log    *slog.Logger
	Wait   time.Duration // between lookups; 1s if zero

	mu       sync.Mutex
	loaded   bool
	cache    map[netip.Addr]store.CloudflareRadar
	queue    map[netip.Addr]int64 // address → an org it was seen in
	paused   time.Time
	day      string
	dayCount int
}

func (r *Radar) Name() string         { return RadarSource }
func (r *Radar) Every() time.Duration { return time.Minute }

// eligible: a public IPv4 address that isn't Cloudflare's. (Radar's docs
// describe the lookup for IPv4 only.)
func (r *Radar) eligible(a netip.Addr) bool {
	a = a.Unmap()
	return a.Is4() && a.IsGlobalUnicast() && !a.IsPrivate() && !ipinfo.Tailnet.Contains(a) && !r.Edge.Contains(a)
}

// Lookup returns the cached network for ip, if any, and queues it for a
// lookup otherwise. It never makes a request or reads the database.
func (r *Radar) Lookup(_ context.Context, orgID int64, ip netip.Addr, _ time.Time) ([]ipinfo.Label, error) {
	ip = ip.Unmap()
	if !r.eligible(ip) {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.cache[ip]; ok && r.fresh(c) {
		if c.ASN == 0 {
			return nil, nil
		}
		return []ipinfo.Label{radarLabel(c, ip)}, nil
	}
	if r.queue == nil {
		r.queue = map[netip.Addr]int64{}
	}
	if _, queued := r.queue[ip]; !queued && len(r.queue) < radarMaxQueue {
		r.queue[ip] = orgID
	}
	return nil, nil
}

func (r *Radar) fresh(c store.CloudflareRadar) bool {
	ttl := radarFresh
	if c.ASN == 0 {
		ttl = radarNegative
	}
	return r.Now().Sub(c.FetchedAt) < ttl
}

func radarLabel(c store.CloudflareRadar, ip netip.Addr) ipinfo.Label {
	name := fmt.Sprintf("AS%d", c.ASN)
	if c.Name != "" {
		name += " " + c.Name
	}
	if c.Country != "" {
		name += " (" + c.Country + ")"
	}
	return ipinfo.Label{Kind: store.IPKindUnknown, Name: name, Source: RadarSource,
		Prefix: netip.PrefixFrom(ip, ip.BitLen()), Guess: true}
}

// Queued is how many addresses wait for a lookup.
func (r *Radar) Queued() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.queue)
}

// Sync loads the cache (first run) and looks up a few queued addresses,
// skipping any that became known meanwhile.
func (r *Radar) Sync(ctx context.Context) error {
	if err := r.load(ctx); err != nil {
		return err
	}
	now := r.Now()
	r.mu.Lock()
	if now.Before(r.paused) {
		r.mu.Unlock()
		return nil
	}
	if d := now.UTC().Format(time.DateOnly); d != r.day {
		r.day, r.dayCount = d, 0
	}
	batch := map[netip.Addr]int64{}
	for ip, org := range r.queue {
		if len(batch) >= radarPerRun || r.dayCount+len(batch) >= radarPerDay {
			break
		}
		delete(r.queue, ip)
		if c, ok := r.cache[ip]; ok && r.fresh(c) {
			continue // cached before the first load
		}
		batch[ip] = org
	}
	r.mu.Unlock()
	wait := r.Wait
	if wait == 0 {
		wait = time.Second
	}
	var lastErr error
	first := true
	for ip, org := range batch {
		if known, err := r.known(ctx, org, ip); err != nil || known {
			continue
		}
		if !first {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		first = false
		a, err := r.Client.ASNByIP(ctx, ip)
		r.mu.Lock()
		r.dayCount++
		r.mu.Unlock()
		if IsPermission(err) {
			r.mu.Lock()
			r.paused = r.Now().Add(radarPause)
			r.mu.Unlock()
			err = fmt.Errorf("Radar lookups paused for %s: %w (the token needs Account > Radar > Read)", radarPause, err)
			r.Store.RecordCloudflareSync(ctx, "radar", err, r.Now())
			return err
		}
		if err != nil {
			lastErr = err
			continue // not cached: asked again when next seen
		}
		name := a.OrgName
		if name == "" {
			name = a.Name
		}
		c := store.CloudflareRadar{IP: ip.String(), ASN: a.ASN, Name: clipName(name), Country: clipName(a.Country), FetchedAt: r.Now()}
		if err := r.Store.PutCloudflareRadar(ctx, c); err != nil {
			return err
		}
		r.mu.Lock()
		r.cache[ip] = c
		r.mu.Unlock()
	}
	if len(batch) > 0 {
		r.Store.RecordCloudflareSync(ctx, "radar", lastErr, r.Now())
	}
	return lastErr
}

func clipName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func (r *Radar) load(ctx context.Context) error {
	r.mu.Lock()
	loaded := r.loaded
	r.mu.Unlock()
	if loaded {
		return nil
	}
	rows, err := r.Store.CloudflareRadarSince(ctx, r.Now().Add(-radarFresh))
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cache == nil {
		r.cache = map[netip.Addr]store.CloudflareRadar{}
	}
	for _, c := range rows {
		if a, err := netip.ParseAddr(c.IP); err == nil {
			r.cache[a] = c
		}
	}
	r.loaded = true
	return nil
}

// known reports whether an address already has a label that says
// something, or is one of the org's hosts: those need no lookup.
func (r *Radar) known(ctx context.Context, orgID int64, ip netip.Addr) (bool, error) {
	ls, err := r.Store.IPLabels(ctx, orgID)
	if err != nil {
		return false, err
	}
	for _, l := range ls {
		if l.Kind != store.IPKindUnknown && l.Prefix.Contains(ip) {
			return true, nil
		}
	}
	hosts, err := r.Store.HostsByReportIP(ctx, orgID, ip.String())
	return len(hosts) > 0, err
}
