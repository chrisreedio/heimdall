// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/updates"
)

func TestUpdateBannerForAdminsOnly(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Version = "v0.4.0"
		c.Updates = func() (updates.Release, bool) {
			return updates.Release{Version: "v0.5.0", URL: "https://github.com/realmwatch/heimdall/releases/tag/v0.5.0"}, true
		}
	})
	e.seed()
	if body := e.get("/", signedIn(e)).Body.String(); !strings.Contains(body, "v0.5.0</strong> is available") {
		t.Error("admin should see the update banner")
	}
	orgs, _ := e.st.ListOrgs(t.Context())
	e.auth.viewer = &auth.Viewer{UserID: 1, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{orgs[0].ID: store.RoleViewer}}}
	if body := e.get("/", signedIn(e)).Body.String(); strings.Contains(body, "is available") {
		t.Error("non-admins must not see the banner")
	}
}
