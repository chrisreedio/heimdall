// SPDX-License-Identifier: AGPL-3.0-or-later

package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/netx"
	"github.com/chrisreedio/heimdall/internal/store"
)

const (
	// Every is how often each list is fetched. Vendors change them rarely
	// and announce it weeks ahead.
	Every = 24 * time.Hour
	// MaxBytes caps one list's response (GitHub's meta is about 200 KB).
	MaxBytes = 2 << 20
	// MaxPrefixes caps one service's list (GitHub Actions has about 7,000).
	MaxPrefixes = 20000
	syncTimeout = time.Minute
)

// ErrNoToken is a token-only list's sync without a stored token.
var ErrNoToken = errors.New("no API token")

// Syncer keeps one service's labels current.
type Syncer struct {
	Service Service
	Store   *store.Store
	Client  *netx.Client
	// Static are fixed ranges (a custom service's cidrs), stored with the
	// fetched ones.
	Static []string
	// Token returns the API token for a Service.Token list.
	Token func() (string, error)
	Now   func() time.Time
}

func (s *Syncer) Name() string         { return Source(s.Service.ID) }
func (s *Syncer) Every() time.Duration { return Every }

// Sync fetches the lists and replaces the service's labels. On any
// failure the old labels stay (or, before any sync has succeeded, the
// built-in fallback is stored) and the error is returned and recorded.
func (s *Syncer) Sync(ctx context.Context) error {
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	labels, err := s.fetch(ctx)
	if err == nil {
		if err = s.Store.ReplaceIPLabels(ctx, 0, s.Name(), labels, now()); err == nil {
			return s.Store.RecordIPSourceRun(ctx, s.Name(), now(), len(labels), nil)
		}
	}
	if len(s.Service.Fallback) > 0 && !s.everSynced(ctx) {
		if fb, ferr := s.labels(s.Service.Fallback, "built-in list from "+s.Service.FallbackDate+" (the live list couldn't be fetched yet)"); ferr == nil {
			_ = s.Store.ReplaceIPLabels(ctx, 0, s.Name(), fb, now())
		}
	}
	if rerr := s.Store.RecordIPSourceRun(ctx, s.Name(), now(), 0, err); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

func (s *Syncer) everSynced(ctx context.Context) bool {
	states, err := s.Store.IPSourceStates(ctx)
	if err != nil {
		return true // can't tell: don't overwrite anything
	}
	for _, st := range states {
		if st.Source == s.Name() {
			return !st.LastSuccess.IsZero()
		}
	}
	return false
}

// fetch returns the service's labels: its static ranges plus every list.
func (s *Syncer) fetch(ctx context.Context) ([]store.IPLabel, error) {
	raw := slices.Clone(s.Static)
	var hdr http.Header
	if s.Service.Token {
		if s.Token == nil {
			return nil, ErrNoToken
		}
		tok, err := s.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoToken, err)
		}
		hdr = http.Header{"Authorization": {"Bearer " + tok}}
	}
	for _, u := range s.Service.URLs {
		b, _, err := s.Client.Get(ctx, u, MaxBytes, hdr)
		if err != nil {
			return nil, err
		}
		got, err := s.Service.Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		if len(got) == 0 {
			return nil, fmt.Errorf("%s: the list is empty", u)
		}
		raw = append(raw, got...)
	}
	return s.labels(raw, "")
}

// labels validates raw (every entry must be an address or a CIDR no
// broader than /8 or IPv6 /16; one bad entry fails the whole list) and
// returns one label per distinct range.
func (s *Syncer) labels(raw []string, note string) ([]store.IPLabel, error) {
	ps, err := Prefixes(raw)
	if err != nil {
		return nil, err
	}
	out := make([]store.IPLabel, len(ps))
	for i, p := range ps {
		out[i] = store.IPLabel{Prefix: p, Kind: store.IPKindAutomation, Name: s.Service.Name, Note: note}
	}
	return out, nil
}

// Prefixes parses and checks a list's entries, dropping duplicates.
func Prefixes(raw []string) ([]netip.Prefix, error) {
	if len(raw) == 0 {
		return nil, errors.New("the list is empty")
	}
	if len(raw) > MaxPrefixes {
		return nil, fmt.Errorf("the list has %d entries, more than %d", len(raw), MaxPrefixes)
	}
	seen := map[netip.Prefix]bool{}
	var out []netip.Prefix
	for _, r := range raw {
		p, err := store.ParseIPPrefix(r)
		if err != nil {
			return nil, fmt.Errorf("%q isn't an IP address or CIDR range", trunc(r))
		}
		if TooBroad(p) {
			return nil, fmt.Errorf("%s is too broad for a deploy service", p)
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

// TooBroad reports a range no deploy service would publish: wider than an
// IPv4 /8 or an IPv6 /16.
func TooBroad(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < 8
	}
	return p.Bits() < 16
}

func trunc(s string) string {
	if len(s) > 60 {
		return s[:60] + "..."
	}
	return s
}

// UserHint recognizes a service's accounts. It's a guess: people log in
// as "forge" too, so only an address match is known.
func UserHint(id, name string, users []string) ipinfo.UserHint {
	users = slices.Clone(users)
	return func(user string) (ipinfo.Label, bool) {
		if !slices.Contains(users, user) {
			return ipinfo.Label{}, false
		}
		return ipinfo.Label{Kind: store.IPKindAutomation, Name: name, Source: Source(id), Guess: true}, true
	}
}

// Setup is what New needs besides the config.
type Setup struct {
	Store  *store.Store
	Client *netx.Client // nil: one allowlisted to the lists' hosts (UserAgent)
	// UserAgent for the default client.
	UserAgent string
	// Token returns a token-only service's API token, or an error (e.g.
	// none stored), in which case it gets a user hint but no syncer.
	Token func(id string) (string, error)
	Now   func() time.Time
}

// Built is the enabled services' syncers and user hints.
type Built struct {
	Syncers []*Syncer
	Hints   []ipinfo.UserHint
	// NoToken are enabled token-only services without a token (user hint
	// only), for a log line and status.
	NoToken []string
	// Sources are every enabled service's label source, for Prune.
	Sources []string
}

// New builds the syncers and hints for the configured services.
func New(cfg config.DeployServices, set Setup) Built {
	var b Built
	var hosts []string
	type pending struct {
		svc    Service
		static []string
		token  func() (string, error)
	}
	var ps []pending
	for _, id := range cfg.Services {
		svc, ok := Lookup(id)
		if !ok {
			continue // config validation rejects unknown IDs
		}
		b.Sources = append(b.Sources, Source(id))
		if len(svc.Users) > 0 {
			b.Hints = append(b.Hints, UserHint(svc.ID, svc.Name, svc.Users))
		}
		p := pending{svc: svc}
		if svc.Token {
			if set.Token == nil {
				b.NoToken = append(b.NoToken, id)
				continue
			}
			if _, err := set.Token(id); err != nil {
				b.NoToken = append(b.NoToken, id)
				continue
			}
			p.token = func() (string, error) { return set.Token(id) }
		}
		ps = append(ps, p)
	}
	for _, c := range cfg.Custom {
		svc := Service{ID: c.ID(), Name: strings.TrimSpace(c.Name), Parse: ParseAny, Users: c.Users}
		if c.URL != "" {
			svc.URLs = []string{c.URL}
		}
		b.Sources = append(b.Sources, Source(svc.ID))
		if len(svc.Users) > 0 {
			b.Hints = append(b.Hints, UserHint(svc.ID, svc.Name, svc.Users))
		}
		ps = append(ps, pending{svc: svc, static: c.CIDRs})
	}
	for _, p := range ps {
		for _, u := range p.svc.URLs {
			if h := config.HostOf(u); h != "" && !slices.Contains(hosts, h) {
				hosts = append(hosts, h)
			}
		}
	}
	client := set.Client
	if client == nil {
		client = netx.New(hosts, set.UserAgent)
	}
	for _, p := range ps {
		b.Syncers = append(b.Syncers, &Syncer{Service: p.svc, Store: set.Store, Client: client, Static: p.static,
			Token: p.token, Now: set.Now})
	}
	return b
}

// Pruner removes the labels of services no longer configured, so turning
// one off (or renaming a custom one) takes effect.
type Pruner struct {
	Store *store.Store
	Keep  []string // label sources still configured
	Now   func() time.Time
}

func (p *Pruner) Name() string         { return "service:(removed)" }
func (p *Pruner) Every() time.Duration { return Every }

func (p *Pruner) Sync(ctx context.Context) error {
	ls, err := p.Store.IPLabels(ctx, 0)
	if err != nil {
		return err
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	done := map[string]bool{}
	for _, l := range ls {
		if strings.HasPrefix(l.Source, "service:") && !slices.Contains(p.Keep, l.Source) && !done[l.Source] {
			done[l.Source] = true
			if err := p.Store.ReplaceIPLabels(ctx, 0, l.Source, nil, now()); err != nil {
				return err
			}
		}
	}
	return nil
}
