// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/bans"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/logins"
	"github.com/realmwatch/heimdall/internal/store"
)

// newBansEnv: Cloudflare on, [bans] in propose mode, the seeded zones.
// One proposal touches acme (app-01), one only the other org (web-09).
func newBansEnv(t *testing.T, adjust ...func(*Config)) (e *env, acme, other int64, mine, theirs int64) {
	t.Helper()
	svc := &bans.Service{Cfg: config.BansDefaults, Cloudflare: true, TokenNote: "no ban token: run `sudo heimdall bans set-token`"}
	svc.Cfg.Mode = config.BansPropose
	e = newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.Cloudflare, c.Bans = true, svc
		for _, f := range adjust {
			f(c)
		}
	})
	acme, other = e.seedCloudflare()
	svc.Engine = &bans.Engine{Store: e.st, Ranker: &logins.Ranker{Store: e.st}, Cfg: svc.Cfg, Now: func() time.Time { return testNow }}
	ctx := t.Context()
	add := func(target string, org int64, host string) int64 {
		ev, _ := json.Marshal(bans.Evidence{Hosts: []bans.Host{{OrgID: org, Org: map[int64]string{acme: "acme", other: "other"}[org], Name: host}},
			Failures: 50, Usernames: 4, Days: 2, First: testNow.Add(-48 * time.Hour), Last: testNow, Prefix: "203.0.113.0/24", Known: "nothing known"})
		fs, _ := json.Marshal([]bans.Factor{{Name: "hosts", Value: 1, Points: 2}, {Name: "failures", Value: 50, Points: 5.7}})
		id, err := e.st.AddBan(ctx, store.Ban{Target: target, Kind: "address", Action: "challenge", Status: store.BanProposed, Mode: "propose",
			Score: 13.2, Breakdown: fs, Evidence: ev, Orgs: []int64{org}, Duration: 7 * 24 * time.Hour}, "heimdall", testNow)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	return e, acme, other, add("203.0.113.66", acme, "app-01"), add("203.0.113.77", other, "web-09")
}

func TestBansPageAdmin(t *testing.T) {
	t.Parallel()
	e, _, _, mine, _ := newBansEnv(t)
	w := e.get("/bans", signedIn(e))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	b := w.Body.String()
	for _, want := range []string{"203.0.113.66", "203.0.113.77", "Waiting for approval", `id="ban-` + strconv.FormatInt(mine, 10) + `"`,
		"hosts 1 → 2.0", "failures 50 → 5.7", "example.com", "turn on", "Pause all Cloudflare writes",
		"permissionGroupKeys=%5B%7B%22key%22%3A%22firewall_services%22", "Account &gt; Account Filter Lists &gt; Edit",
		"no write token", `title="Bans" aria-current="page"`, "ban.proposed"} {
		if !strings.Contains(b, want) {
			t.Errorf("page missing %q", want)
		}
	}
}

func TestBansScoping(t *testing.T) {
	t.Parallel()
	e, acme, _, _, theirs := newBansEnv(t)
	e.auth.viewer = &auth.Viewer{UserID: 2, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleOperator}}}
	b := e.get("/bans", signedIn(e)).Body.String()
	if !strings.Contains(b, "203.0.113.66") || !strings.Contains(b, "app-01") {
		t.Error("operator misses their own")
	}
	for _, leak := range []string{"203.0.113.77", "web-09"} {
		if strings.Contains(b, leak) {
			t.Errorf("operator sees %q", leak)
		}
	}
	// ...and can't act on another org's.
	if w := e.post("/bans/"+strconv.FormatInt(theirs, 10)+"/approve", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("approve other org's: %d", w.Code)
	}
	// Viewers get no page and no link.
	e.auth.viewer = &auth.Viewer{UserID: 3, SessionToken: goodToken, Scope: store.Scope{Orgs: map[int64]store.Role{acme: store.RoleViewer}}}
	if w := e.get("/bans", signedIn(e)); w.Code != http.StatusNotFound {
		t.Errorf("viewer: %d", w.Code)
	}
	if b := e.get("/", signedIn(e)).Body.String(); strings.Contains(b, `href="/bans"`) {
		t.Error("viewer sees the nav link")
	}
}

func TestBansActions(t *testing.T) {
	t.Parallel()
	e, _, _, mine, theirs := newBansEnv(t)
	ctx := t.Context()
	path := "/bans/" + strconv.FormatInt(mine, 10) + "/approve"
	// No CSRF token, or another origin: refused.
	if w := e.post(path, nil, signedIn(e), origin(e.baseURL)); w.Code != http.StatusForbidden {
		t.Errorf("no csrf: %d", w.Code)
	}
	if w := e.post(path, csrfForm(), signedIn(e), origin("https://evil.example.com")); w.Code != http.StatusForbidden {
		t.Errorf("cross-origin: %d", w.Code)
	}
	w := e.post(path, csrfForm(), signedIn(e), origin(e.baseURL))
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), "done=approve") {
		t.Fatalf("approve: %d %s", w.Code, w.Header().Get("Location"))
	}
	if b, _ := e.st.BanByID(ctx, mine); b.Status != store.BanPending || b.DecidedBy != "user:1" {
		t.Errorf("after approve: %+v", b)
	}
	// Approving again just shows it.
	if w := e.post(path, csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Errorf("again: %d", w.Code)
	}
	// Reject with a note.
	if w := e.post("/bans/"+strconv.FormatInt(theirs, 10)+"/reject", csrfForm("note", "a partner's scanner"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("reject: %d", w.Code)
	}
	if b, _ := e.st.BanByID(ctx, theirs); b.Status != store.BanRejected || b.Note != "a partner's scanner" {
		t.Errorf("after reject: %+v", b)
	}
	// One-click unban of an approved, unwritten ban ends it.
	if w := e.post("/bans/"+strconv.FormatInt(mine, 10)+"/unban", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("unban: %d", w.Code)
	}
	if b, _ := e.st.BanByID(ctx, mine); b.Status != store.BanEnded || b.EndReason != "unbanned" {
		t.Errorf("after unban: %+v", b)
	}
	// Pause and resume.
	if w := e.post("/bans/pause", csrfForm("note", "incident"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("pause: %d", w.Code)
	}
	if p, _ := e.st.BanPaused(ctx); !p.Paused || p.Note != "incident" {
		t.Errorf("paused: %+v", p)
	}
	if b := e.get("/bans", signedIn(e)).Body.String(); !strings.Contains(b, "Resume Cloudflare writes") || !strings.Contains(b, "pill bad\">paused") {
		t.Error("paused page")
	}
	e.post("/bans/resume", csrfForm(), signedIn(e), origin(e.baseURL))
	if p, _ := e.st.BanPaused(ctx); p.Paused {
		t.Error("still paused")
	}
	// Zone opt-in, and its column on /surface.
	if w := e.post("/bans/zones", csrfForm("zone", cfZone, "on", "1"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusSeeOther {
		t.Fatalf("zone: %d", w.Code)
	}
	zs, _ := e.st.BanZones(ctx)
	if z := zs[cfZone]; !z.Enabled || z.Zone != "example.com" || z.UpdatedBy != "user:1" {
		t.Errorf("zone: %+v", z)
	}
	if w := e.post("/bans/zones", csrfForm("zone", "ffffffffffffffffffffffffffffffff", "on", "1"), signedIn(e), origin(e.baseURL)); w.Code != http.StatusNotFound {
		t.Errorf("unknown zone: %d", w.Code)
	}
	if b := e.get("/surface", signedIn(e)).Body.String(); !strings.Contains(b, "<th>Ban rule</th>") || !strings.Contains(b, "writing</a>") {
		t.Error("surface ban column")
	}
}

func TestBansApproveNeedsWriteMode(t *testing.T) {
	t.Parallel()
	e, _, _, mine, _ := newBansEnv(t)
	// The same database behind a hub in shadow mode: nothing is approved
	// into Cloudflare.
	h, err := New(Config{BaseURL: e.baseURL, LocalLogin: true, SessionMax: time.Hour, Bans: &bans.Service{Cfg: config.Bans{Mode: config.BansShadow}}},
		e.st, e.auth, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	e.h = h
	if w := e.post("/bans/"+strconv.FormatInt(mine, 10)+"/approve", csrfForm(), signedIn(e), origin(e.baseURL)); w.Code != http.StatusConflict {
		t.Errorf("shadow approve: %d", w.Code)
	}
}
