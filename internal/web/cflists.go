// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/store"
)

// Cloudflare IP lists (internal/cloudflare/iplists.go): the card on
// /cloudflare where global admins pick which lists become IP labels and of
// what kind, and the lists' labels on /ips, read-only. Cloudflare is
// hub-wide, so the labels are for every org and only global admins map
// lists.

// cfListsView is the mapping card.
type cfListsView struct {
	Lists  []cfList
	Kinds  []string  // store.CFListKinds
	Synced time.Time // the list sync's last run (zero: never)
	Error  string    // its error, e.g. the missing permission
	Token  bool      // a token is set, so saving syncs at once
}

// cfList is a list with its last sync and dashboard page.
type cfList struct {
	store.CloudflareIPList
	State store.IPSourceState // zero: never synced
	Href  string              // the list in the Cloudflare dashboard
}

func (s *server) cfListRows(ctx context.Context) ([]cfList, map[string]store.IPSourceState, error) {
	lists, err := s.st.CloudflareIPLists(ctx)
	if err != nil {
		return nil, nil, err
	}
	states, err := s.st.IPSourceStates(ctx)
	if err != nil {
		return nil, nil, err
	}
	bySource := map[string]store.IPSourceState{}
	for _, st := range states {
		bySource[st.Source] = st
	}
	out := make([]cfList, 0, len(lists))
	for _, l := range lists {
		out = append(out, cfList{CloudflareIPList: l, State: bySource[store.IPListSource(l.ID)],
			Href: cloudflare.ListURL(l.AccountID, l.ID)})
	}
	return out, bySource, nil
}

func (s *server) cfLists(ctx context.Context) (*cfListsView, error) {
	rows, states, err := s.cfListRows(ctx)
	if err != nil {
		return nil, err
	}
	st := states[cloudflare.ListsSource]
	return &cfListsView{Lists: rows, Kinds: store.CFListKinds, Synced: st.LastAttempt, Error: st.LastError,
		Token: s.cfg.CloudflareLists != nil}, nil
}

// cloudflareListsSet saves the mapping (kind-<list id> per list) and, if
// anything changed, syncs the lists before showing the page again.
func (s *server) cloudflareListsSet(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	lists, err := s.st.CloudflareIPLists(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	changed := false
	for _, l := range lists {
		k := r.PostForm.Get("kind-" + l.ID)
		if k == "" || k == l.Kind || !slices.Contains(store.CFListKinds, k) {
			continue
		}
		if err := s.st.SetCloudflareIPListKind(ctx, actorOf(v), l.ID, k, s.now()); err != nil {
			s.fail(w, r, v, err)
			return
		}
		changed = true
	}
	if changed && s.cfg.CloudflareLists != nil {
		// The sync also closes unknown-address alerts the labels answer.
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 45*time.Second)
		if err := s.cfg.CloudflareLists(sctx); err != nil {
			s.log.Warn("Cloudflare IP list sync failed", "err", err) // and shown on the card
		}
		cancel()
		s.nav.forget(v.UserID) // its badge may count closed alerts
	}
	http.Redirect(w, r, "/cloudflare#ip-lists", http.StatusSeeOther)
}

// ipListGroup is a mapped list's labels on /ips.
type ipListGroup struct {
	cfList
	Labels []store.IPLabel
}

// ipListGroups splits the Cloudflare lists' labels out of every org's
// labels, grouped by mapped list (by name).
func (s *server) ipListGroups(ctx context.Context, global []store.IPLabel) ([]ipListGroup, []store.IPLabel, error) {
	rest := slices.DeleteFunc(slices.Clone(global), func(l store.IPLabel) bool { return store.IsIPListSource(l.Source) })
	if len(rest) == len(global) && !s.cfg.Cloudflare {
		return nil, rest, nil
	}
	rows, _, err := s.cfListRows(ctx)
	if err != nil {
		return nil, nil, err
	}
	var out []ipListGroup
	for _, l := range rows {
		if l.Kind == store.CFListIgnore {
			continue
		}
		g := ipListGroup{cfList: l}
		for _, lb := range global {
			if lb.Source == store.IPListSource(l.ID) {
				g.Labels = append(g.Labels, lb)
			}
		}
		out = append(out, g)
	}
	return out, rest, nil
}
