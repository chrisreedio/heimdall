// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/history"
	"github.com/realmwatch/heimdall/internal/store"
)

type changesBody struct {
	Org, Name string
	Snapshots []store.SnapshotInfo
	From, To  store.SnapshotInfo
	Diff      history.Diff
	HasDiff   bool
}

func (s *server) changesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	host, err := s.st.HostByName(ctx, r.PathValue("org"), r.PathValue("host"))
	var verr *store.ValidationError
	if errors.Is(err, store.ErrNotFound) || errors.As(err, &verr) || (err == nil && !v.Scope.CanView(host.OrgID)) {
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := changesBody{Org: host.OrgSlug, Name: host.Name}
	if body.Snapshots, err = s.st.Snapshots(ctx, host.ID, 50); err != nil {
		s.fail(w, r, v, err)
		return
	}
	from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
	to, _ := strconv.ParseInt(r.URL.Query().Get("to"), 10, 64)
	body.From, body.To, body.Diff, err = history.HostDiff(ctx, s.st, host, from, to)
	switch {
	case err == nil:
		body.HasDiff = true
	case !errors.Is(err, store.ErrNotFound):
		s.fail(w, r, v, err)
		return
	}
	s.render(w, r, http.StatusOK, "changes", v, "Changes on "+host.Name, "hosts", body)
}

type driftBody struct {
	Tag   string
	Tags  []string // shared by 2+ hosts: comparable
	Hosts []string
	Rows  []history.DriftRow
	// Tagging (org admins).
	AllTags  []string // every tag, for suggestions
	Taggable []store.Host
	ShowOrgs bool
	Notice   string
	Error    string
}

// adminHosts lists the visible hosts in orgs the viewer administers.
func (s *server) adminHosts(r *http.Request, v *auth.Viewer) ([]store.Host, bool, error) {
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return nil, false, err
	}
	admin := map[string]bool{}
	for _, o := range orgs {
		admin[o.Slug] = v.Scope.CanAdmin(o.ID)
	}
	all, err := s.visibleHosts(r, v, "")
	if err != nil {
		return nil, false, err
	}
	var out []store.Host
	for _, h := range all {
		if admin[h.OrgSlug] {
			out = append(out, h)
		}
	}
	return out, len(orgs) > 1, nil
}

// driftTag adds a tag to the chosen hosts (org admins only).
func (s *server) driftTag(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	hosts, _, err := s.adminHosts(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	allowed := map[int64]bool{}
	for _, h := range hosts {
		allowed[h.ID] = true
	}
	var ids []int64
	for _, raw := range r.PostForm["host"] {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || !allowed[id] {
			s.notFound(w, r, v) // a host this viewer can't tag
			return
		}
		ids = append(ids, id)
	}
	tag := strings.ToLower(strings.TrimSpace(r.PostForm.Get("tag")))
	if len(ids) == 0 {
		http.Redirect(w, r, "/drift?tag_error=nohosts", http.StatusSeeOther)
		return
	}
	n, err := s.st.TagHosts(r.Context(), actorOf(v), tag, ids)
	var verr *store.ValidationError
	if errors.As(err, &verr) {
		http.Redirect(w, r, "/drift?tag_error=invalid", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, "/drift?tag="+url.QueryEscape(tag)+"&tagged="+strconv.Itoa(n), http.StatusSeeOther)
}

var driftTagErrors = map[string]string{
	"nohosts": "Pick at least one host to tag.",
	"invalid": "Tags are up to 64 lowercase letters, digits or ':._-'.",
}

func (s *server) driftPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	tags, err := s.st.Tags(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := driftBody{Tag: strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tag")))}
	for t, n := range tags {
		if n >= 2 {
			body.Tags = append(body.Tags, t)
		}
	}
	slices.Sort(body.Tags)
	for t := range tags {
		body.AllTags = append(body.AllTags, t)
	}
	slices.Sort(body.AllTags)
	if body.Taggable, body.ShowOrgs, err = s.adminHosts(r, v); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("tagged")); err == nil {
		body.Notice = fmt.Sprintf("Tag added to %d host%s.", n, map[bool]string{true: "", false: "s"}[n == 1])
	}
	body.Error = driftTagErrors[r.URL.Query().Get("tag_error")]
	if body.Tag != "" {
		if body.Hosts, body.Rows, err = history.Drift(ctx, s.st, body.Tag, v.Scope); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "drift", v, "Drift", "drift", body)
}
