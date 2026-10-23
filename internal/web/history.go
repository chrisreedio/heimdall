// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/history"
	"github.com/chrisreedio/heimdall/internal/store"
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
	Tags  []string
	Hosts []string
	Rows  []history.DriftRow
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
	if body.Tag != "" {
		if body.Hosts, body.Rows, err = history.Drift(ctx, s.st, body.Tag, v.Scope); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	s.render(w, r, http.StatusOK, "drift", v, "Drift", "drift", body)
}
