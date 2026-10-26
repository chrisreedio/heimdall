// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/feeds/news"
	"github.com/realmwatch/heimdall/internal/store"
)

// ── Threat news ────────────────────────────────────────────────────────────

// newsCap is how many incidents the News page lists.
const newsCap = 200

type newsBody struct {
	Items      []newsRow
	Total      int // incidents before filtering
	Affecting  int // incidents that affect a visible host
	Filter     string
	Categories []newsChip
	More       int // incidents past newsCap
	ShowOrgs   bool
}

type newsChip struct {
	Slug, Label string
	Count       int
}

// newsRow is an incident as the UI shows it. Every string in it comes from
// the feed and is rendered as escaped text only.
type newsRow struct {
	store.NewsEntry
	Via string // the source's host, for attribution
}

var categoryLabels = map[string]string{"patch": "Patches", "breach": "Breaches", "supply-chain": "Supply chain"}

// Started and Closed are pointers for the date template funcs.
func (r newsRow) Started() *time.Time { t := r.StartedAt; return &t }
func (r newsRow) Closed() *time.Time  { return r.ClosedAt }

// CategoryLabel names the incident's category for a pill.
func (r newsRow) CategoryLabel() string {
	return map[string]string{"patch": "patch", "breach": "breach", "supply-chain": "supply chain"}[r.Category]
}

// Patch returns the pill class and label for the patch status (fixed
// strings only, never feed text).
func (r newsRow) Patch() (p struct{ Class, Label string }) {
	switch r.PatchStatus {
	case "patched":
		p.Class, p.Label = "ok", "patch available"
	case "partial":
		p.Class, p.Label = "warn", "partly patched"
	case "unpatched":
		p.Class, p.Label = "bad", "no patch yet"
	case "no-fix-needed":
		p.Class, p.Label = "muted", "no fix needed"
	}
	return p
}

func newsRows(entries []store.NewsEntry) []newsRow {
	out := make([]newsRow, len(entries))
	for i, e := range entries {
		out[i] = newsRow{NewsEntry: e, Via: sourceHost(e.Source)}
	}
	return out
}

func sourceHost(src string) string {
	u, err := url.Parse(src)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
}

func (s *server) newsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if !s.cfg.News {
		s.notFound(w, r, v)
		return
	}
	entries, err := s.st.News(r.Context(), v.Scope)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	visible := 0
	for _, o := range orgs {
		if v.Scope.CanView(o.ID) {
			visible++
		}
	}
	body := newsBody{Total: len(entries), ShowOrgs: visible > 1}
	q := r.URL.Query()
	switch {
	case q.Get("affects") == "me":
		body.Filter = "me"
	case slices.Contains(news.Categories, q.Get("category")):
		body.Filter = q.Get("category")
	}
	count := map[string]int{}
	var shown []store.NewsEntry
	for _, e := range entries {
		count[e.Category]++
		if len(e.Hosts) > 0 {
			body.Affecting++
		}
		switch body.Filter {
		case "":
		case "me":
			if len(e.Hosts) == 0 {
				continue
			}
		default:
			if e.Category != body.Filter {
				continue
			}
		}
		shown = append(shown, e)
	}
	for _, c := range news.Categories {
		if count[c] > 0 || body.Filter == c {
			body.Categories = append(body.Categories, newsChip{Slug: c, Label: categoryLabels[c], Count: count[c]})
		}
	}
	if len(shown) > newsCap {
		body.More = len(shown) - newsCap
		shown = shown[:newsCap]
	}
	body.Items = newsRows(shown)
	s.render(w, r, http.StatusOK, "news", v, "News", "news", body)
}

// newsAffecting counts incidents that affect at least one host the viewer
// can see (0 when news is off).
func (s *server) newsAffecting(r *http.Request, v *auth.Viewer, org string) (int, error) {
	if !s.cfg.News {
		return 0, nil
	}
	entries, err := s.st.News(r.Context(), v.Scope)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range entries {
		for _, h := range e.Hosts {
			if org == "" || h.OrgSlug == org {
				n++
				break
			}
		}
	}
	return n, nil
}
