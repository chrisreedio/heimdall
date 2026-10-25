// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/surface"
)

// The attack-surface map (internal/surface): /surface, and a "public as"
// line on host and site pages. Rows are cut down to what the viewer may
// see the same way /cloudflare is: a name shows when it leads to a host or
// site in one of their orgs, and names that lead nowhere only to admins.

// surfaceChangeDays is how far back /surface lists changes.
const surfaceChangeDays = 30

type surfaceChip struct {
	Label, Href string
	Count       int
	Current     bool
}

type surfaceBody struct {
	Admin    bool
	CF       bool // [cloudflare] is on
	View     string
	Zone     string
	Views    []surfaceChip
	ZoneOpts []surfaceChip
	Rows     []surface.Row
	All      int // rows before the filter
	Zones    []surface.Zone
	Changes  []surfaceChangeRow
	LastSync time.Time
	BanZones map[string]store.BanZone // the "ban rule" column (bans.go)
	BanCol   bool
}

var surfaceViewLabels = map[string]string{
	surface.ViewAll: "All", surface.ViewVulnerable: "Vulnerable", surface.ViewExposed: "Exposed",
	surface.ViewFlagged: "Flagged", surface.ViewUnmatched: "Unmatched", surface.ViewOffCF: "Not on Cloudflare",
}

func surfaceHref(view, zone string) string {
	q := url.Values{}
	if view != "" {
		q.Set("view", view)
	}
	if zone != "" {
		q.Set("zone", zone)
	}
	if len(q) == 0 {
		return "/surface"
	}
	return "/surface?" + q.Encode()
}

func (s *server) surfaceMap(ctx context.Context) (surface.Map, error) {
	return surface.Load(ctx, s.st, s.cfg.Cloudflare, s.now())
}

// surfacePage is the map: every public name, worst first, filterable by
// view and zone. Operators and admins only.
func (s *server) surfacePage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	can := v.Scope.CanOperate
	if !v.Scope.Admin && !slices.ContainsFunc(mapsKeys(v.Scope.Orgs), can) {
		s.notFound(w, r, v)
		return
	}
	ctx := r.Context()
	m, err := s.surfaceMap(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	m = m.For(v.Scope.Admin, can)
	q := r.URL.Query()
	body := surfaceBody{Admin: v.Scope.Admin, CF: s.cfg.Cloudflare, Zones: m.Zones, All: len(m.Rows)}
	if view := q.Get("view"); slices.Contains(surface.Views, view) {
		body.View = view
	}
	if z := strings.ToLower(q.Get("zone")); slices.ContainsFunc(m.Zones, func(x surface.Zone) bool { return x.Name == z }) {
		body.Zone = z
	}
	for _, view := range surface.Views {
		if view == surface.ViewOffCF && !body.CF {
			continue // every name is off Cloudflare then
		}
		n := 0
		for _, row := range m.Rows {
			if row.Match(view, body.Zone) {
				n++
			}
		}
		body.Views = append(body.Views, surfaceChip{Label: surfaceViewLabels[view], Href: surfaceHref(view, body.Zone), Count: n, Current: view == body.View})
	}
	if len(m.Zones) > 0 {
		body.ZoneOpts = append(body.ZoneOpts, surfaceChip{Label: "All zones", Href: surfaceHref(body.View, ""), Current: body.Zone == ""})
		// Only zones with names in this view: a chip that shows nothing is noise.
		for _, z := range m.Zones {
			n := 0
			for _, row := range m.Rows {
				if row.Match(body.View, z.Name) {
					n++
				}
			}
			if n > 0 || z.Name == body.Zone {
				body.ZoneOpts = append(body.ZoneOpts, surfaceChip{Label: z.Name, Href: surfaceHref(body.View, z.Name), Count: n, Current: z.Name == body.Zone})
			}
		}
	}
	for _, row := range m.Rows {
		if row.Match(body.View, body.Zone) {
			body.Rows = append(body.Rows, row)
		}
	}
	if body.CF {
		cs, err := s.st.SurfaceChanges(ctx, s.now().AddDate(0, 0, -surfaceChangeDays), 200)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		for _, c := range surface.ChangesFor(cs, v.Scope.Admin, can) {
			body.Changes = append(body.Changes, surfaceChangeRow{SurfaceChange: c, When: dayAgo(&c.At, s.now()), Full: c.At.Local().Format("Jan 2, 2006 3:04 PM")})
		}
		if syncs, err := s.st.CloudflareSyncs(ctx); err == nil {
			body.LastSync = syncs["zones"].At
		}
	}
	body.BanZones = s.surfaceBanZones(ctx)
	body.BanCol = body.BanZones != nil
	s.render(w, r, http.StatusOK, "surface", v, "Attack surface", "surface", body)
}

// surfaceHTML is the rendered "public as" line the host and site pages include.
type surfaceHTML = template.HTML

// surfaceChangeRow is a change with its time as people read it.
type surfaceChangeRow struct {
	store.SurfaceChange
	When, Full string
}

// surfaceLineBody is the host or site page's "public as" line.
type surfaceLineBody struct {
	Names []surfaceName
	Link  bool // to /surface
}

type surfaceName struct {
	Name, Status string
	Exposed      bool
}

var surfaceLine struct {
	once sync.Once
	t    *template.Template
	err  error
}

func surfaceLineTemplate() (*template.Template, error) {
	parse := func() (*template.Template, error) {
		return template.New("surface_line.html").Funcs(funcs).ParseFS(templatesFS, "templates/surface_line.html")
	}
	if devMode {
		return parse()
	}
	surfaceLine.once.Do(func() { surfaceLine.t, surfaceLine.err = parse() })
	return surfaceLine.t, surfaceLine.err
}

// surfaceLineFor renders the public names that lead to a host (root "")
// or to one site on it. Empty when there are none, and on any error: the
// page never fails for it.
func (s *server) surfaceLineFor(ctx context.Context, v *auth.Viewer, orgID int64, host, root string) template.HTML {
	m, err := s.surfaceMap(ctx)
	if err != nil {
		s.log.Warn("surface line failed", "err", err)
		return ""
	}
	var body surfaceLineBody
	for _, r := range m.Rows {
		hit := false
		if root == "" {
			hit = slices.ContainsFunc(r.Hosts, func(h surface.Host) bool { return h.OrgID == orgID && h.Name == host })
		} else {
			hit = slices.ContainsFunc(r.Sites, func(x surface.Site) bool { return x.OrgID == orgID && x.Host == host && x.Root == root })
		}
		if hit {
			body.Names = append(body.Names, surfaceName{Name: r.Name, Status: r.Status, Exposed: r.Exposed})
		}
	}
	if len(body.Names) == 0 {
		return ""
	}
	slices.SortStableFunc(body.Names, func(a, b surfaceName) int { return strings.Compare(a.Name, b.Name) })
	body.Link = v.Scope.Admin || v.Scope.CanOperate(orgID)
	t, err := surfaceLineTemplate()
	if err != nil {
		s.log.Error("surface line template", "err", err)
		return ""
	}
	var b strings.Builder
	if err := t.Execute(&b, body); err != nil {
		s.log.Error("surface line render", "err", err)
		return ""
	}
	return template.HTML(b.String()) // html/template output, already escaped
}
