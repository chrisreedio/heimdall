// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// EdgeSource is the edge ranges' label source.
const EdgeSource = "cloudflare:edge"

// DefaultEdge are Cloudflare's published edge ranges as of Oct 2026
// (https://www.cloudflare.com/ips-v4 and /ips-v6), used until the first
// sync. They change rarely, and only by growing.
var DefaultEdge = mustPrefixes(
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
	"108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
	"162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
	"2a06:98c0::/29", "2c0f:f248::/32",
)

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// Edge is the set of Cloudflare edge ranges, safe for concurrent use and
// swapped whole on each sync. A nil *Edge contains nothing.
type Edge struct {
	p atomic.Pointer[[]netip.Prefix]
}

// NewEdge starts with DefaultEdge.
func NewEdge() *Edge {
	e := &Edge{}
	e.Set(DefaultEdge)
	return e
}

// Set replaces the ranges.
func (e *Edge) Set(ps []netip.Prefix) { e.p.Store(&ps) }

// Prefixes returns the current ranges.
func (e *Edge) Prefixes() []netip.Prefix {
	if e == nil {
		return nil
	}
	if p := e.p.Load(); p != nil {
		return *p
	}
	return nil
}

// Contains reports whether a is a Cloudflare edge address.
func (e *Edge) Contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range e.Prefixes() {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// edgeURLs are where the ranges are published, one CIDR a line.
var edgeURLs = []string{"https://" + EdgeHost + "/ips-v4", "https://" + EdgeHost + "/ips-v6"}

// FetchEdge downloads the published ranges. Any bad line fails the fetch,
// and so does an implausibly short list, so a broken answer never
// replaces good ranges.
func FetchEdge(ctx context.Context, hc *http.Client, urls []string) ([]netip.Prefix, error) {
	if urls == nil {
		urls = edgeURLs
	}
	var out []netip.Prefix
	for _, u := range urls {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := hc.Do(req)
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("GET %s: HTTP %d", u, resp.StatusCode)
		}
		n := 0
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			p, err := netip.ParsePrefix(line)
			if err != nil || p.Bits() < 8 {
				return nil, fmt.Errorf("GET %s: unexpected line %.40q", u, line)
			}
			out, n = append(out, p.Masked()), n+1
		}
		if n < 3 || n > 200 {
			return nil, fmt.Errorf("GET %s: %d ranges, expected a handful", u, n)
		}
	}
	return out, nil
}

// EdgeSyncer keeps the edge ranges current: in memory (for ingest's
// CF-Connecting-IP check) and as global infra labels named "Cloudflare".
// It needs no token.
type EdgeSyncer struct {
	Store *store.Store
	Edge  *Edge
	HTTP  *http.Client
	URLs  []string // nil: the published ones
	Now   func() time.Time
}

func (s *EdgeSyncer) Name() string         { return EdgeSource }
func (s *EdgeSyncer) Every() time.Duration { return 24 * time.Hour }

// Load restores the last synced ranges from the labels (at start, before
// the first sync), or stores DefaultEdge as the labels if there are none.
func (s *EdgeSyncer) Load(ctx context.Context) error {
	ls, err := s.Store.IPLabels(ctx, 0)
	if err != nil {
		return err
	}
	var ps []netip.Prefix
	for _, l := range ls {
		if l.Source == EdgeSource {
			ps = append(ps, l.Prefix)
		}
	}
	if len(ps) == 0 {
		return s.store(ctx, DefaultEdge)
	}
	s.Edge.Set(ps)
	return nil
}

func (s *EdgeSyncer) store(ctx context.Context, ps []netip.Prefix) error {
	labels := make([]store.IPLabel, len(ps))
	for i, p := range ps {
		labels[i] = store.IPLabel{Prefix: p, Kind: store.IPKindInfra, Name: "Cloudflare",
			Note: "Cloudflare's edge network (published ranges)"}
	}
	if err := s.Store.ReplaceIPLabels(ctx, 0, EdgeSource, labels, s.Now()); err != nil {
		return err
	}
	s.Edge.Set(ps)
	return nil
}

func (s *EdgeSyncer) Sync(ctx context.Context) error {
	ps, err := FetchEdge(ctx, s.HTTP, s.URLs)
	if err == nil {
		err = s.store(ctx, ps)
	}
	if rerr := s.Store.RecordCloudflareSync(ctx, "edge", err, s.Now()); err == nil {
		err = rerr
	}
	return err
}
