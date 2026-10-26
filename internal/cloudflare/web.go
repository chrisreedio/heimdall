// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// Web offenders: per client address, the security events Cloudflare acted
// on, for the threat list. Unlike Summary, this stores client addresses:
// only of requests Cloudflare blocked or challenged, never friendly ones
// (docs/cloudflare.md#web-offenders).

// actedActions are the firewall event actions that count, by how
// Cloudflare may write them (the GraphQL datasets and Logs differ in
// case), to the name stored: Cloudflare stopped the request or made the
// client prove itself. Not counted: allow, bypass, skip, log, unknown, and
// the outcomes of a challenge (solved, bypassed, skipped), which mean a
// client passed (https://developers.cloudflare.com/logs/reference/security-fields/).
var actedActions = map[string]string{
	"block":             "block",
	"challenge":         "challenge",
	"jschallenge":       "js_challenge",
	"js_challenge":      "js_challenge",
	"managed_challenge": "managed_challenge",
	"managedChallenge":  "managed_challenge",
	"connection_close":  "connection_close",
	"connectionClose":   "connection_close",
}

// ActedAction returns the stored name of an action that counts, or false.
func ActedAction(a string) (string, bool) {
	n, ok := actedActions[strings.TrimSpace(a)]
	return n, ok
}

const (
	// webGroupLimit caps the aggregated rows per day (Cloudflare's
	// maximum for a groups query); a day that hits it is a floor.
	webGroupLimit = 10000
	// webSettle is how long after a day ends it's fetched once more and
	// then left alone: late events have arrived by then.
	webSettle = time.Hour
)

// webActionFilter is the action_in list for the queries.
func webActionFilter() string {
	ks := make([]string, 0, len(actedActions))
	for k := range actedActions {
		ks = append(ks, strconv.Quote(k))
	}
	slices.Sort(ks)
	return "[" + strings.Join(ks, ", ") + "]"
}

// webDay is one UTC day's window to fetch.
type webDay struct {
	day      string
	from, to time.Time
	final    bool
}

// webDays returns the windows to fetch at now: yesterday unless it's
// already stored final, and today. Each spans at most a day, so it fits
// every plan's maximum query span; older days are never asked for.
func webDays(now time.Time, final map[string]bool) []webDay {
	today := now.UTC().Truncate(24 * time.Hour)
	var out []webDay
	for _, start := range []time.Time{today.Add(-24 * time.Hour), today} {
		day := start.Format(time.DateOnly)
		if final[day] {
			continue
		}
		end := start.Add(24*time.Hour - time.Second)
		w := webDay{day: day, from: start, to: end, final: !now.Before(end.Add(webSettle))}
		if w.to.After(now) {
			w.to = now
		}
		out = append(out, w)
	}
	return out
}

// webOffenders fetches a zone's acted-on events by client address for
// days, by aggregated groups (clientIP, clientAsn, clientASNDescription,
// clientCountryName, action, datetimeHour) or, with sampled or on a plan
// without them, the latest sampleLimit raw events of each day. The state
// is a store.CloudflareSecurity* value; friendly addresses are not yet
// filtered.
func (c *Client) webOffenders(ctx context.Context, zoneID string, days []webDay, sampled bool) (string, []store.WebDay, error) {
	if !zoneIDRe(zoneID) {
		return store.CloudflareSecurityError, nil, fmt.Errorf("bad zone ID %q", zoneID)
	}
	if len(days) == 0 {
		return store.CloudflareSecurityOK, nil, nil
	}
	if sampled {
		return c.webSampled(ctx, zoneID, days)
	}
	var q strings.Builder
	q.WriteString(`{ viewer { zones(filter: {zoneTag: "` + zoneID + `"}) {`)
	for i, d := range days {
		fmt.Fprintf(&q, ` d%d: firewallEventsAdaptiveGroups(limit: %d, filter: {datetime_geq: %s, datetime_leq: %s, action_in: %s}, orderBy: [count_DESC]) { count dimensions { clientIP clientAsn clientASNDescription clientCountryName action datetimeHour } }`,
			i, webGroupLimit, gqlTime(d.from), gqlTime(d.to), webActionFilter())
	}
	q.WriteString(` } } }`)
	var out struct {
		Viewer struct {
			Zones []map[string][]struct {
				Count      int            `json:"count"`
				Dimensions map[string]any `json:"dimensions"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	err := c.graphql(ctx, q.String(), &out)
	switch {
	case IsPlan(err):
		return c.webSampled(ctx, zoneID, days)
	case IsPermission(err):
		return store.CloudflareSecurityPermission, nil, err
	case err != nil:
		return store.CloudflareSecurityError, nil, err
	case len(out.Viewer.Zones) == 0:
		return store.CloudflareSecurityError, nil, fmt.Errorf("zone %s not returned", zoneID)
	}
	var res []store.WebDay
	for i, d := range days {
		groups := out.Viewer.Zones[0]["d"+strconv.Itoa(i)]
		b := webBuilder{}
		for _, g := range groups {
			hour, _ := time.Parse(time.RFC3339, str(g.Dimensions["datetimeHour"]))
			first, last := hour, hour.Add(time.Hour-time.Second)
			if hour.IsZero() {
				first, last = d.from, d.to
			}
			b.add(g.Dimensions, g.Count, later(first, d.from), earlier(last, d.to))
		}
		res = append(res, store.WebDay{Day: d.day, Final: d.final, Sampled: len(groups) >= webGroupLimit, Rows: b.rows()})
	}
	return store.CloudflareSecurityOK, res, nil
}

// webSampled reads the latest raw events of each day (at most
// sampleLimit each): counts are a floor.
func (c *Client) webSampled(ctx context.Context, zoneID string, days []webDay) (string, []store.WebDay, error) {
	var q strings.Builder
	q.WriteString(`{ viewer { zones(filter: {zoneTag: "` + zoneID + `"}) {`)
	for i, d := range days {
		fmt.Fprintf(&q, ` d%d: firewallEventsAdaptive(limit: %d, filter: {datetime_geq: %s, datetime_leq: %s, action_in: %s}, orderBy: [datetime_DESC]) { datetime action clientIP clientAsn clientASNDescription clientCountryName }`,
			i, sampleLimit, gqlTime(d.from), gqlTime(d.to), webActionFilter())
	}
	q.WriteString(` } } }`)
	var out struct {
		Viewer struct {
			Zones []map[string][]map[string]any `json:"zones"`
		} `json:"viewer"`
	}
	err := c.graphql(ctx, q.String(), &out)
	switch {
	case IsPlan(err):
		return store.CloudflareSecurityPlan, nil, nil
	case IsPermission(err):
		return store.CloudflareSecurityPermission, nil, err
	case err != nil:
		return store.CloudflareSecurityError, nil, err
	case len(out.Viewer.Zones) == 0:
		return store.CloudflareSecurityError, nil, fmt.Errorf("zone %s not returned", zoneID)
	}
	var res []store.WebDay
	for i, d := range days {
		b := webBuilder{}
		for _, ev := range out.Viewer.Zones[0]["d"+strconv.Itoa(i)] {
			t, err := time.Parse(time.RFC3339, str(ev["datetime"]))
			if err != nil {
				t = d.to
			}
			b.add(ev, 1, t.UTC(), t.UTC())
		}
		res = append(res, store.WebDay{Day: d.day, Final: d.final, Sampled: true, Rows: b.rows()})
	}
	return store.CloudflareSecuritySampled, res, nil
}

// webBuilder sums events by address.
type webBuilder map[netip.Addr]*store.WebOffenderDay

// add counts n events of one group or raw event (its fields by GraphQL
// name). Actions that don't count and addresses that don't parse are
// dropped here, whatever the query asked for.
func (b webBuilder) add(f map[string]any, n int, first, last time.Time) {
	act, ok := ActedAction(str(f["action"]))
	ip, err := netip.ParseAddr(str(f["clientIP"]))
	if !ok || err != nil || n <= 0 {
		return
	}
	ip = ip.Unmap()
	r := b[ip]
	if r == nil {
		r = &store.WebOffenderDay{IP: ip.String(), Actions: map[string]int{}, First: first, Last: last}
		b[ip] = r
	}
	r.Events += n
	r.Actions[act] += n
	r.First, r.Last = earlier(r.First, first), later(r.Last, last)
	if r.ASN == 0 {
		r.ASN, _ = strconv.ParseInt(strings.TrimPrefix(strings.ToUpper(str(f["clientAsn"])), "AS"), 10, 64)
		r.ASName = clip(str(f["clientASNDescription"]))
	}
	if r.Country == "" {
		r.Country = str(f["clientCountryName"])
	}
}

func (b webBuilder) rows() []store.WebOffenderDay {
	out := make([]store.WebOffenderDay, 0, len(b))
	for _, r := range b {
		out = append(out, *r)
	}
	slices.SortFunc(out, func(x, y store.WebOffenderDay) int { return strings.Compare(x.IP, y.IP) })
	return out
}

// str renders a JSON scalar as text (numbers without a fraction).
func str(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case float64:
		return strconv.FormatInt(int64(x), 10)
	case nil:
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// Friendly is the ban guard's friend check (internal/bans) for one
// address: friendly if it's in an internal range (ipinfo.InternalRanges),
// Cloudflare's edge or any org's label that says something, is one of
// your hosts' report addresses, or someone signed in to Heimdall from it
// within ipinfo.SignInLookback. Anything not a public unicast address is
// friendly too: it can't be an attacker worth listing.
type Friendly struct {
	ranges []netip.Prefix
	addrs  map[netip.Addr]bool
}

// LoadFriendly reads what Friendly checks. edge nil is the built-in list.
func LoadFriendly(ctx context.Context, st *store.Store, edge *Edge, now time.Time) (*Friendly, error) {
	if edge == nil {
		edge = NewEdge()
	}
	f := &Friendly{addrs: map[netip.Addr]bool{}}
	f.ranges = append(slices.Clone(ipinfo.InternalRanges), edge.Prefixes()...)
	labels, err := st.KnownIPPrefixes(ctx)
	if err != nil {
		return nil, err
	}
	f.ranges = append(f.ranges, labels...)
	hosts, err := st.ReportAddrs(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		f.addrs[h.Addr] = true
	}
	ins, err := st.SignInIPs(ctx, now.Add(-ipinfo.SignInLookback))
	if err != nil {
		return nil, err
	}
	for _, s := range ins {
		if a, err := netip.ParseAddr(s); err == nil {
			f.addrs[a.Unmap()] = true
		}
	}
	return f, nil
}

// Is reports whether an address is friendly.
func (f *Friendly) Is(a netip.Addr) bool {
	if f == nil {
		return true // never store blind
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || f.addrs[a] {
		return true
	}
	for _, p := range f.ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// unfriendly drops friendly addresses from days' rows.
func (f *Friendly) unfriendly(days []store.WebDay) []store.WebDay {
	for i := range days {
		days[i].Rows = slices.DeleteFunc(days[i].Rows, func(r store.WebOffenderDay) bool {
			a, err := netip.ParseAddr(r.IP)
			return err != nil || f.Is(a)
		})
	}
	return days
}

// ZoneOrgs maps each zone to the orgs its records lead to (hosts by report
// address, following CNAMEs, and sites by server name): the same join the
// /cloudflare page uses to decide who sees a zone.
func ZoneOrgs(m Map) map[string][]int64 {
	out := map[string][]int64{}
	add := func(zone string, org int64) {
		if !slices.Contains(out[zone], org) {
			out[zone] = append(out[zone], org)
		}
	}
	for _, r := range m.Records {
		for _, h := range r.Hosts {
			add(r.ZoneID, h.OrgID)
		}
		for _, s := range r.Sites {
			add(r.ZoneID, s.OrgID)
		}
	}
	return out
}

// webZone is a zone whose summary was just fetched, and how.
type webZone struct {
	zone  store.CloudflareZone
	state string
}

// syncWeb fetches and stores each zone's web offenders, after the zone
// summaries: a zone whose summary had no permission or isn't on the plan
// is skipped, and one that fell back to sampled events goes straight to
// them, so this adds one GraphQL query per zone and sync. It also rebuilds
// the zone-to-org mapping and deletes stored addresses that have since
// become friendly.
func (s *Syncer) syncWeb(ctx context.Context, zones []webZone) []error {
	now := s.Now()
	if err := s.zoneOrgs(ctx); err != nil {
		return []error{err}
	}
	f, err := LoadFriendly(ctx, s.Store, s.Edge, now)
	if err != nil {
		return []error{err}
	}
	stored, err := s.Store.WebOffenderIPs(ctx)
	if err != nil {
		return []error{err}
	}
	var drop []string
	for _, ip := range stored {
		if a, err := netip.ParseAddr(ip); err != nil || f.Is(a) {
			drop = append(drop, ip)
		}
	}
	if err := s.Store.DeleteWebOffenderIPs(ctx, drop); err != nil {
		return []error{err}
	}
	var errs []error
	for _, z := range zones {
		if z.state != store.CloudflareSecurityOK && z.state != store.CloudflareSecuritySampled {
			continue
		}
		final, err := s.Store.WebFinalDays(ctx, z.zone.ID, now.UTC().AddDate(0, 0, -2).Format(time.DateOnly))
		if err != nil {
			return append(errs, err)
		}
		state, days, err := s.Client.webOffenders(ctx, z.zone.ID, webDays(now, final), z.state == store.CloudflareSecuritySampled)
		if err != nil && state != store.CloudflareSecurityPermission {
			errs = append(errs, fmt.Errorf("%s web offenders: %w", z.zone.Name, err))
		}
		if state != store.CloudflareSecurityOK && state != store.CloudflareSecuritySampled {
			continue
		}
		if err := s.Store.RecordWebOffenders(ctx, z.zone.ID, f.unfriendly(days), now); err != nil {
			return append(errs, err)
		}
	}
	return errs
}

// zoneOrgs rebuilds the stored zone-to-org mapping from the stored zones
// and records.
func (s *Syncer) zoneOrgs(ctx context.Context) error {
	zones, err := s.Store.CloudflareZones(ctx)
	if err != nil {
		return err
	}
	recs, err := s.Store.CloudflareRecords(ctx)
	if err != nil {
		return err
	}
	hosts, err := s.Store.ReportAddrs(ctx)
	if err != nil {
		return err
	}
	sites, err := s.Store.AllSiteNames(ctx)
	if err != nil {
		return err
	}
	return s.Store.SetCloudflareZoneOrgs(ctx, ZoneOrgs(Build(zones, recs, hosts, sites, nil)))
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}
