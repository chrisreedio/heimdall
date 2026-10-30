// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ingest"
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

// A collector is behind only when upgrading it would change it, not
// whenever the hub's release is newer than the collector's number.
func TestCollectorBehindOnlyWhenChanged(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.Version = "v9.0.0" })
	host := e.seed() // collector 0.1.0
	if body := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); !strings.Contains(body, "update available") {
		t.Error("collector 0.1.0 should be behind")
	}
	raw, _ := os.ReadFile("../snapshot/testdata/debian12.json")
	var snap map[string]any
	json.Unmarshal(raw, &snap)
	snap["collected_at"] = testNow.Add(time.Minute).Format(time.RFC3339)
	snap["collector"].(map[string]any)["version"] = strings.TrimPrefix(updates.CollectorChanged, "v")
	raw, _ = json.Marshal(snap)
	acc := ingest.Accepter{Store: e.st, Now: func() time.Time { return testNow.Add(time.Minute) }}
	if res, err := acc.Accept(t.Context(), host, "push", raw); err != nil || res.Status != http.StatusCreated {
		t.Fatalf("snapshot: %+v %v", res, err)
	}
	if body := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); strings.Contains(body, "update available") || !strings.Contains(body, `"pill ok">current`) {
		t.Error("a collector at CollectorChanged is current under a newer hub")
	}
	if body := e.get("/hosts", signedIn(e)).Body.String(); strings.Contains(body, ">behind<") {
		t.Error("the hosts list shouldn't call it behind")
	}
}
