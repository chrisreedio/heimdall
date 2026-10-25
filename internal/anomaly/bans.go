// SPDX-License-Identifier: AGPL-3.0-or-later

package anomaly

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/cloudflare"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/logins"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/surface"
)

// Alerts from failed logins and the surface map (docs/bans.md#alerts):
//
//   - login_then_succeeded (high): an address nothing vouches for failed
//     to log in and then got in, on the same host and UTC day. Vouching
//     is logins.Vouched, the same as the offender list: a label, the
//     tailnet, a private network, your hosts, a sign-in or Cloudflare's
//     edge never fire.
//   - dns_unproxied (medium): a name that leads to one of our hosts went
//     from proxied to not proxied (surface_changes), so its origin is
//     public now.
//   - cname_takeover (high): a name that leads to one of our hosts or
//     sites has a CNAME whose target doesn't exist.
//
// Each event raises one anomaly per host, once: the dedupe key is
// remembered after acknowledgement too.

// loginSucceededLookback is how far back the check reads "then succeeded".
const loginSucceededLookback = 48 * time.Hour

// raiseOnce raises a for the host unless it was ever raised with its key.
func (e *Engine) raiseOnce(ctx context.Context, hostID int64, a store.Anomaly) (bool, error) {
	key, _ := a.Detail["key"].(string)
	if seen, err := e.Store.AnomalyKeySeen(ctx, hostID, a.Rule, key); err != nil || seen {
		return false, err
	}
	return e.Store.AddAnomaly(ctx, hostID, 0, a, e.Now())
}

// CheckLoginSucceeded raises login_then_succeeded. ips may be nil (only the
// built-in ranges are known); Radar is never asked.
func (e *Engine) CheckLoginSucceeded(ctx context.Context, ips *ipinfo.Resolver, edge *cloudflare.Edge) (int, error) {
	rows, err := e.Store.LoginSuccessesSince(ctx, e.Now().Add(-loginSucceededLookback))
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	res := &ipinfo.Resolver{Store: e.Store}
	if ips != nil {
		c := *ips
		c.Sources = slices.DeleteFunc(slices.Clone(c.Sources), func(s ipinfo.Source) bool { return s.Name() == cloudflare.RadarSource })
		res = &c
	}
	batches := map[int64]func(ip, user string, at time.Time) ipinfo.Verdict{}
	n := 0
	for _, r := range rows {
		resolve := batches[r.Host.OrgID]
		if resolve == nil {
			resolve = res.Batch(ctx, r.Host.OrgID)
			batches[r.Host.OrgID] = resolve
		}
		v := resolve(r.IP, "", r.Last)
		if !v.Addr.IsValid() || logins.Vouched(v, edge) {
			continue
		}
		day, _ := time.Parse(time.DateOnly, r.Day)
		ok, err := e.raiseOnce(ctx, r.Host.ID, store.Anomaly{Rule: "login_then_succeeded", Severity: "high",
			Summary: fmt.Sprintf("%s failed %d SSH %s and then logged in, on %s (UTC). Nothing vouches for the address: check who that was",
				v.Addr, r.Failures, plural(r.Failures, "login", "logins"), day.Format("Jan 2, 2006")),
			Detail: map[string]any{"key": v.Addr.String() + "|" + r.Day, "ip": v.Addr.String(), "day": r.Day, "failures": r.Failures}})
		if err != nil {
			return n, err
		}
		if ok {
			n++
		}
	}
	return n, nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// surfaceCursor is where CheckSurface got to in surface_changes.
const surfaceCursor = "alert.surface_changes"

// CheckSurface raises dns_unproxied and cname_takeover from the surface
// map. Names that lead to none of our hosts raise nothing (an anomaly is
// a host's); /surface still flags them.
func (e *Engine) CheckSurface(ctx context.Context) (int, error) {
	now := e.Now()
	m, err := surface.Load(ctx, e.Store, true, now)
	if err != nil {
		return 0, err
	}
	byName := map[string]surface.Row{}
	for _, r := range m.Rows {
		byName[r.Name] = r
	}
	ids := map[string]int64{} // "org/host" → ID, 0 when gone
	hostIDs := func(r surface.Row) []int64 {
		var out []int64
		for _, h := range r.Hosts {
			k := h.Org + "/" + h.Name
			id, ok := ids[k]
			if !ok {
				if ih, err := e.Store.HostByName(ctx, h.Org, h.Name); err == nil {
					id = ih.ID
				}
				ids[k] = id
			}
			if id != 0 && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
		return out
	}
	n := 0
	raise := func(hostID int64, a store.Anomaly) error {
		ok, err := e.raiseOnce(ctx, hostID, a)
		if ok {
			n++
		}
		return err
	}

	var since time.Time
	if _, err := e.Store.BanStateGet(ctx, surfaceCursor, &since); err != nil {
		return n, err
	}
	if since.IsZero() {
		since = now.Add(-24 * time.Hour) // first run: only recent changes
	}
	cs, err := e.Store.SurfaceChanges(ctx, since, 1000)
	if err != nil {
		return n, err
	}
	cursor := since
	for _, c := range cs {
		if c.At.After(cursor) {
			cursor = c.At
		}
		if c.Kind != store.SurfaceUnproxied {
			continue
		}
		r, ok := byName[c.Name]
		if !ok {
			continue
		}
		for _, id := range hostIDs(r) {
			if err := raise(id, store.Anomaly{Rule: "dns_unproxied", Severity: "medium",
				Summary: fmt.Sprintf("%s (zone %s) stopped going through Cloudflare on %s: visitors reach this server directly, and its address is public",
					c.Name, c.Zone, c.At.UTC().Format("Jan 2, 2006 15:04 UTC")),
				Detail: map[string]any{"key": "unproxied:" + c.Name + ":" + c.At.UTC().Format(time.RFC3339), "name": c.Name, "zone": c.Zone}}); err != nil {
				return n, err
			}
		}
	}
	if cursor.After(since) {
		if err := e.Store.BanStateSet(ctx, surfaceCursor, cursor, now); err != nil {
			return n, err
		}
	}

	for _, r := range m.Rows {
		for _, f := range r.Flags {
			if f.Kind != "takeover" {
				continue
			}
			target := strings.Join(r.Targets, ", ")
			for _, id := range hostIDs(r) {
				if err := raise(id, store.Anomaly{Rule: "cname_takeover", Severity: "high",
					Summary: "Takeover risk: " + f.Note,
					Detail:  map[string]any{"key": "takeover:" + r.Name + ":" + target, "name": r.Name, "targets": r.Targets}}); err != nil {
					return n, err
				}
			}
		}
	}
	return n, nil
}
