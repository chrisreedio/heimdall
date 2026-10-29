// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
)

// Prober checks whether anything answers at the addresses of dangling
// records ([cloudflare] probe_dangling, docs/cloudflare.md): a plain TCP
// connect from the hub to 443, then 80, closed as soon as it opens.
// Nothing is sent: no HTTP request, no TLS handshake. Only public
// addresses are ever dialled (re-checked here, whatever the map says).
//
// It runs every Interval and probes the addresses never checked (a record
// that appeared in the last zone sync) and those last checked more than
// Recheck ago, at most Max a run. Results for addresses that are no
// longer dangling are dropped.
type Prober struct {
	Store    *store.Store
	Edge     *Edge         // Cloudflare's edge, never probed; nil = the built-in list
	Interval time.Duration // how often to look for due addresses; 0 = 10m
	Recheck  time.Duration // how old a result may get; 0 = 6h
	Timeout  time.Duration // per connect; 0 = 3s
	Workers  int           // concurrent connects; 0 = 8
	Max      int           // addresses a run; 0 = 200
	Now      func() time.Time
	Log      *slog.Logger
	// Dial and Allow are for tests: nil dials with net.Dialer and allows
	// only public addresses outside the edge (Probeable).
	Dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	Allow func(netip.Addr) bool
	Ports []int // nil = 443, 80
}

func (p *Prober) Name() string { return "cloudflare:probe" }
func (p *Prober) Every() time.Duration {
	return orDefault(p.Interval, 10*time.Minute)
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Probeable: an address the hub may connect to: public (not private,
// loopback, link-local, the tailnet or Cloudflare's placeholders) and not
// Cloudflare's edge.
func Probeable(edge *Edge) func(netip.Addr) bool {
	if edge == nil {
		edge = NewEdge()
	}
	return func(a netip.Addr) bool {
		a = a.Unmap()
		return public(a) && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !edge.Contains(a)
	}
}

// DanglingAddrs are the distinct addresses of the map's dangling records.
func (m Map) DanglingAddrs() []netip.Addr {
	var out []netip.Addr
	for _, r := range m.Records {
		if !r.Dangling {
			continue
		}
		if a, err := netip.ParseAddr(r.Content); err == nil && !slices.Contains(out, a.Unmap()) {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// LoadMap builds the record map from the store, as /cloudflare shows it.
func LoadMap(ctx context.Context, st *store.Store, edge *Edge) ([]store.CloudflareZone, Map, error) {
	zones, err := st.CloudflareZones(ctx)
	if err != nil || len(zones) == 0 {
		return zones, Map{}, err
	}
	recs, err := st.CloudflareRecords(ctx)
	if err != nil {
		return nil, Map{}, err
	}
	hosts, err := st.ReportAddrs(ctx)
	if err != nil {
		return nil, Map{}, err
	}
	sites, err := st.AllSiteNames(ctx)
	if err != nil {
		return nil, Map{}, err
	}
	known, err := st.KnownIPPrefixes(ctx)
	if err != nil {
		return nil, Map{}, err
	}
	if edge == nil {
		edge = NewEdge()
	}
	return zones, Build(zones, recs, hosts, sites, Known(known, edge)), nil
}

func (p *Prober) Sync(ctx context.Context) error {
	_, m, err := LoadMap(ctx, p.Store, p.Edge)
	if err != nil {
		return err
	}
	addrs := m.DanglingAddrs()
	if err := p.Store.PruneDanglingProbes(ctx, addrs); err != nil {
		return err
	}
	have, err := p.Store.DanglingProbes(ctx)
	if err != nil {
		return err
	}
	now := p.Now()
	allow := p.Allow
	if allow == nil {
		allow = Probeable(p.Edge)
	}
	var due []netip.Addr
	for _, a := range addrs {
		if !allow(a) {
			continue
		}
		if r, ok := have[a]; !ok || now.Sub(r.CheckedAt) >= orDefault(p.Recheck, 6*time.Hour) {
			due = append(due, a)
		}
	}
	// Never checked first, then the oldest.
	slices.SortStableFunc(due, func(a, b netip.Addr) int { return have[a].CheckedAt.Compare(have[b].CheckedAt) })
	if limit := p.Max; len(due) > limit && limit > 0 {
		due = due[:limit]
	} else if limit <= 0 && len(due) > 200 {
		due = due[:200]
	}
	if len(due) == 0 {
		return nil
	}
	results := p.probeAll(ctx, due, allow)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if p.Log != nil {
		p.Log.Debug("Dangling records probed", "addresses", len(results), "dangling", len(addrs))
	}
	return p.Store.SetDanglingProbes(ctx, results)
}

func (p *Prober) probeAll(ctx context.Context, addrs []netip.Addr, allow func(netip.Addr) bool) []store.DanglingProbe {
	workers := p.Workers
	if workers <= 0 {
		workers = 8
	}
	jobs := make(chan netip.Addr)
	var mu sync.Mutex
	var out []store.DanglingProbe
	var wg sync.WaitGroup
	for range min(workers, len(addrs)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range jobs {
				if !allow(a) { // never dial what isn't public, whoever asked
					continue
				}
				r := p.Probe(ctx, a)
				if ctx.Err() != nil {
					continue
				}
				mu.Lock()
				out = append(out, r)
				mu.Unlock()
			}
		}()
	}
	for _, a := range addrs {
		select {
		case jobs <- a:
		case <-ctx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	return out
}

// Probe connects to a on each port in turn and closes the connection at
// once. The first that opens makes it answers; a refusal on any (and no
// open port) makes it refused; otherwise silent.
func (p *Prober) Probe(ctx context.Context, a netip.Addr) store.DanglingProbe {
	dial := p.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	ports := p.Ports
	if ports == nil {
		ports = []int{443, 80}
	}
	r := store.DanglingProbe{Addr: a, State: store.ProbeSilent}
	for _, port := range ports {
		cctx, cancel := context.WithTimeout(ctx, orDefault(p.Timeout, 3*time.Second))
		c, err := dial(cctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(port)))
		cancel()
		if err == nil {
			c.Close()
			r.State, r.Port = store.ProbeAnswers, port
			break
		}
		if errors.Is(err, syscall.ECONNREFUSED) {
			r.State = store.ProbeRefused
		}
	}
	r.CheckedAt = p.Now()
	return r
}
