// SPDX-License-Identifier: AGPL-3.0-or-later

package cloudflare

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// Summary is a zone's security events over a window: counts only, the top
// few of each dimension. It never holds a client address.
type Summary struct {
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	Total     int       `json:"total"`
	Requests  int       `json:"requests"` // all HTTP requests; -1 if not available
	Actions   []Count   `json:"actions,omitempty"`
	Countries []Count   `json:"countries,omitempty"`
	ASNs      []Count   `json:"asns,omitempty"`
	Paths     []Count   `json:"paths,omitempty"`
	// Sampled: built from at most sampleLimit raw events (plans without
	// the aggregated dataset), so totals are a floor.
	Sampled bool `json:"sampled,omitempty"`
}

// Count is one key's count.
type Count struct {
	Key string `json:"k"`
	N   int    `json:"n"`
}

// ParseSummary decodes a stored summary (zero if empty or invalid).
func ParseSummary(b []byte) Summary {
	var s Summary
	if json.Unmarshal(b, &s) != nil {
		return Summary{Requests: -1}
	}
	return s
}

const (
	topN        = 10
	sampleLimit = 1000
	maxPathLen  = 120
)

// dims are the dimensions summarized: the stored name and the GraphQL
// field (firewallEventsAdaptiveGroups; see
// https://developers.cloudflare.com/analytics/graphql-api/tutorials/querying-firewall-events/).
var dims = []struct{ dim, field string }{
	{"action", "action"}, {"country", "clientCountryName"}, {"asn", "clientAsn"}, {"path", "clientRequestPath"},
}

type window struct {
	alias    string
	from, to time.Time
}

func gqlTime(t time.Time) string { return strconv.Quote(t.UTC().Format(time.RFC3339)) }

// Security fetches a zone's security events: a last-24-hours summary and
// per-day counts for yesterday and today (UTC), each window at most 24h
// so it fits every plan's maximum query span. Without the aggregated
// dataset (e.g. on Free plans) it falls back to sampled raw events and
// returns no daily counts. The state is a store.CloudflareSecurity* value.
func (c *Client) Security(ctx context.Context, zoneID string, now time.Time) (state, note string, sum Summary, days []store.CloudflareDaily, err error) {
	if !zoneIDRe(zoneID) {
		return store.CloudflareSecurityError, "bad zone ID", Summary{}, nil, fmt.Errorf("bad zone ID %q", zoneID)
	}
	now = now.UTC().Truncate(time.Minute)
	today := now.Truncate(24 * time.Hour)
	wins := []window{{"l24", now.Add(-24 * time.Hour), now}, {"tdy", today, now}, {"ydy", today.Add(-24 * time.Hour), today.Add(-time.Second)}}
	var q strings.Builder
	q.WriteString(`{ viewer { zones(filter: {zoneTag: "` + zoneID + `"}) {`)
	for _, w := range wins {
		f := `filter: {datetime_geq: ` + gqlTime(w.from) + `, datetime_leq: ` + gqlTime(w.to) + `}`
		fmt.Fprintf(&q, ` %s_total: firewallEventsAdaptiveGroups(limit: 1, %s) { count }`, w.alias, f)
		for _, d := range dims {
			fmt.Fprintf(&q, ` %s_%s: firewallEventsAdaptiveGroups(limit: %d, %s, orderBy: [count_DESC]) { count dimensions { %s } }`,
				w.alias, d.dim, topN, f, d.field)
		}
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
	err = c.graphql(ctx, q.String(), &out)
	switch {
	case IsPlan(err):
		return c.sampled(ctx, zoneID, now)
	case IsPermission(err):
		return store.CloudflareSecurityPermission, "the token can't read this zone's analytics (add Zone > Analytics > Read)", Summary{}, nil, err
	case err != nil:
		return store.CloudflareSecurityError, clip(err.Error()), Summary{}, nil, err
	case len(out.Viewer.Zones) == 0:
		return store.CloudflareSecurityError, "zone not in the analytics answer", Summary{}, nil, fmt.Errorf("zone %s not returned", zoneID)
	}
	z := out.Viewer.Zones[0]
	sumOf := func(alias string) (s Summary) {
		for _, g := range z[alias+"_total"] {
			s.Total += g.Count
		}
		for _, d := range dims {
			var cs []Count
			for _, g := range z[alias+"_"+d.dim] {
				cs = append(cs, Count{Key: dimKey(d.dim, g.Dimensions[d.field]), N: g.Count})
			}
			switch d.dim {
			case "action":
				s.Actions = cs
			case "country":
				s.Countries = cs
			case "asn":
				s.ASNs = cs
			case "path":
				s.Paths = cs
			}
		}
		return s
	}
	reqs := c.requests(ctx, zoneID, today.Add(-24*time.Hour), now)
	sum = sumOf("l24")
	sum.From, sum.To, sum.Requests = wins[0].from, wins[0].to, reqs.last24(now)
	for _, w := range wins[1:] {
		s := sumOf(w.alias)
		day := w.from.Format(time.DateOnly)
		days = append(days, store.CloudflareDaily{Day: day, Dim: "total", Count: int64(s.Total)})
		if n, ok := reqs.day[day]; ok {
			days = append(days, store.CloudflareDaily{Day: day, Dim: "requests", Count: n})
		}
		for _, d := range []struct {
			dim string
			cs  []Count
		}{{"action", s.Actions}, {"country", s.Countries}, {"asn", s.ASNs}, {"path", s.Paths}} {
			for _, c := range d.cs {
				days = append(days, store.CloudflareDaily{Day: day, Dim: d.dim, Key: c.Key, Count: int64(c.N)})
			}
		}
	}
	return store.CloudflareSecurityOK, "", sum, days, nil
}

// dimKey renders a dimension's value: an ASN as "AS13335", a path
// clipped, an empty value as "?".
func dimKey(dim string, v any) string {
	var s string
	switch x := v.(type) {
	case string:
		s = x
	case float64:
		s = strconv.FormatInt(int64(x), 10)
	case nil:
	default:
		s = fmt.Sprint(x)
	}
	s = strings.TrimSpace(s)
	switch {
	case s == "" || s == "0" && dim == "asn":
		return "?"
	case dim == "asn":
		return "AS" + strings.TrimPrefix(strings.ToUpper(s), "AS")
	case dim == "path" && len(s) > maxPathLen:
		return s[:maxPathLen] + "…"
	}
	return s
}

// sampled summarizes the last 24 hours from raw events (at most
// sampleLimit), for plans without the aggregated dataset. It asks for no
// client address and keeps only counts.
func (c *Client) sampled(ctx context.Context, zoneID string, now time.Time) (string, string, Summary, []store.CloudflareDaily, error) {
	from := now.Add(-24 * time.Hour)
	q := `{ viewer { zones(filter: {zoneTag: "` + zoneID + `"}) { ev: firewallEventsAdaptive(limit: ` + strconv.Itoa(sampleLimit) +
		`, filter: {datetime_geq: ` + gqlTime(from) + `, datetime_leq: ` + gqlTime(now) + `}, orderBy: [datetime_DESC]) { action clientAsn clientCountryName clientRequestPath } } } }`
	var out struct {
		Viewer struct {
			Zones []struct {
				Events []map[string]any `json:"ev"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	err := c.graphql(ctx, q, &out)
	switch {
	case IsPlan(err):
		return store.CloudflareSecurityPlan, "this zone's plan doesn't include security analytics in the API", Summary{}, nil, nil
	case IsPermission(err):
		return store.CloudflareSecurityPermission, "the token can't read this zone's analytics (add Zone > Analytics > Read)", Summary{}, nil, err
	case err != nil:
		return store.CloudflareSecurityError, clip(err.Error()), Summary{}, nil, err
	}
	sum := Summary{From: from, To: now, Sampled: true}
	counts := map[string]map[string]int{}
	if len(out.Viewer.Zones) > 0 {
		for _, ev := range out.Viewer.Zones[0].Events {
			sum.Total++
			for _, d := range dims {
				if counts[d.dim] == nil {
					counts[d.dim] = map[string]int{}
				}
				counts[d.dim][dimKey(d.dim, ev[d.field])]++
			}
		}
	}
	sum.Actions, sum.Countries, sum.ASNs, sum.Paths = top(counts["action"]), top(counts["country"]), top(counts["asn"]), top(counts["path"])
	reqs := c.requests(ctx, zoneID, from, now)
	sum.Requests = reqs.last24(now)
	note := fmt.Sprintf("sampled: this plan's API has raw events only, so counts are from the latest %d at most", sampleLimit)
	return store.CloudflareSecuritySampled, note, sum, nil, nil
}

func top(m map[string]int) []Count {
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{k, n})
	}
	slices.SortFunc(out, func(a, b Count) int {
		if c := cmp.Compare(b.N, a.N); c != 0 {
			return c
		}
		return cmp.Compare(a.Key, b.Key)
	})
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// hourly is a zone's HTTP request counts by hour.
type hourly struct {
	ok   bool
	hour map[time.Time]int
	day  map[string]int64
}

func (h hourly) last24(now time.Time) int {
	if !h.ok {
		return -1
	}
	var n int
	for t, c := range h.hour {
		if !t.Before(now.Add(-24 * time.Hour)) {
			n += c
		}
	}
	return n
}

// requests fetches hourly request totals (httpRequests1hGroups, on every
// plan). A failure only means no request totals.
func (c *Client) requests(ctx context.Context, zoneID string, from, to time.Time) hourly {
	q := `{ viewer { zones(filter: {zoneTag: "` + zoneID + `"}) { req: httpRequests1hGroups(limit: 50, filter: {datetime_geq: ` +
		gqlTime(from) + `, datetime_lt: ` + gqlTime(to) + `}) { dimensions { datetime } sum { requests } } } } }`
	var out struct {
		Viewer struct {
			Zones []struct {
				Req []struct {
					Dimensions struct {
						Datetime time.Time `json:"datetime"`
					} `json:"dimensions"`
					Sum struct {
						Requests int64 `json:"requests"`
					} `json:"sum"`
				} `json:"req"`
			} `json:"zones"`
		} `json:"viewer"`
	}
	if err := c.graphql(ctx, q, &out); err != nil || len(out.Viewer.Zones) == 0 {
		return hourly{}
	}
	h := hourly{ok: true, hour: map[time.Time]int{}, day: map[string]int64{}}
	for _, r := range out.Viewer.Zones[0].Req {
		t := r.Dimensions.Datetime.UTC()
		h.hour[t] += int(r.Sum.Requests)
		h.day[t.Format(time.DateOnly)] += r.Sum.Requests
	}
	return h
}
