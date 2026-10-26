// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

func TestNavPerm(t *testing.T) {
	for _, c := range []struct {
		name string
		v    auth.Viewer
		want navPerm
	}{
		{"global admin", auth.Viewer{IsAdmin: true}, navPerm{Admin: true, OrgAdmin: true, Operator: true, AnyRole: true}},
		{"org admin", auth.Viewer{Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleViewer, 2: store.RoleAdmin}}}, navPerm{OrgAdmin: true, Operator: true, AnyRole: true}},
		{"operator", auth.Viewer{Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleOperator}}}, navPerm{Operator: true, AnyRole: true}},
		{"viewer", auth.Viewer{Scope: store.Scope{Orgs: map[int64]store.Role{1: store.RoleViewer}}}, navPerm{AnyRole: true}},
		{"no roles", auth.Viewer{}, navPerm{}},
	} {
		if got := navPermOf(&c.v); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestNavCountsCached(t *testing.T) {
	var c navCache
	c.byID = map[int64]navEntry{7: {at: time.Now(), c: navCounts{Anomalies: 3}}}
	c.forget(7)
	if _, ok := c.byID[7]; ok {
		t.Error("forget kept the entry")
	}
}
