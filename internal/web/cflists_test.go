// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

const cfAccount = "dddddddddddddddddddddddddddddddd"

func TestCloudflareListsMapping(t *testing.T) {
	syncs := 0
	ips := &ipinfo.Resolver{}
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IPs, c.Cloudflare = ips, true
		c.CloudflareLists = func(context.Context) error { syncs++; return nil }
	})
	ips.Store = e.st
	e.seed()
	ctx := t.Context()
	if _, err := e.st.ReplaceCloudflareIPLists(ctx, []string{cfAccount}, []store.CloudflareIPList{
		{ID: "offices01", AccountID: cfAccount, Name: "offices", Items: 1, Description: "Where the team works from"},
		{ID: "blocked01", AccountID: cfAccount, Name: "blocked", Items: 9},
	}, testNow); err != nil {
		t.Fatal(err)
	}
	e.st.RecordIPSourceRun(ctx, cloudflare.ListsSource, testNow, 0, nil)

	// The card: every list, ignored at first, for admins only.
	w := e.get("/cloudflare", signedIn(e))
	b := w.Body.String()
	for _, want := range []string{`id="ip-lists"`, "offices", "Where the team works from", `name="kind-offices01"`,
		`<option value="ignore" selected>`, "Save and sync", "https://dash.cloudflare.com/" + cfAccount + "/configurations/lists/offices01"} {
		if !strings.Contains(b, want) {
			t.Errorf("card lacks %q", want)
		}
	}
	e.asBob()
	if b := e.get("/cloudflare", signedIn(e)).Body.String(); strings.Contains(b, "ip-lists") {
		t.Error("a viewer sees the mapping")
	}
	if w := e.formPost("/cloudflare/lists", csrfForm("kind-offices01", "office")); w.Code != http.StatusNotFound {
		t.Errorf("viewer saved the mapping: %d", w.Code)
	}
	e.auth.viewer = nil // the admin again

	// Saving maps the list and syncs; an unknown kind is ignored.
	w = e.formPost("/cloudflare/lists", csrfForm("kind-offices01", "office", "kind-blocked01", "tailnet"))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/cloudflare#ip-lists" || syncs != 1 {
		t.Fatalf("save: %d %q, %d syncs", w.Code, w.Header().Get("Location"), syncs)
	}
	lists, _ := e.st.CloudflareIPLists(ctx)
	if lists[0].Kind != store.CFListIgnore || lists[1].Kind != store.IPKindOffice || lists[1].UpdatedBy == "" {
		t.Errorf("mapping: %+v", lists)
	}
	if e.formPost("/cloudflare/lists", csrfForm("kind-offices01", "office")); syncs != 1 {
		t.Error("synced without a change")
	}

	// Its labels on /ips, grouped under the list and read-only, and on
	// the address's page as "list · comment".
	if err := e.st.ReplaceIPLabels(ctx, 0, store.IPListSource("offices01"), []store.IPLabel{{Prefix: netip.MustParsePrefix("203.0.113.4/32"),
		Kind: store.IPKindOffice, Name: "offices", Person: "Alice Example - Developer"}}, testNow); err != nil {
		t.Fatal(err)
	}
	e.st.RecordIPSourceRun(ctx, store.IPListSource("offices01"), testNow, 1, nil)
	manual, err := e.st.AddIPLabel(ctx, "test", store.IPLabel{Prefix: netip.MustParsePrefix("203.0.113.4/32"), Kind: store.IPKindStaff, Name: "Alice home"})
	if err != nil {
		t.Fatal(err)
	}
	b = e.get("/ips", signedIn(e)).Body.String()
	i, j := strings.Index(b, "From Cloudflare IP lists"), strings.Index(b, `id="ips-global"`)
	if i < 0 || j < i {
		t.Fatalf("no list section before every org's labels:\n%s", b)
	}
	sec, rest := b[i:j], b[j:]
	for _, want := range []string{"offices", "office</span>", "1 item", "open in Cloudflare", "Alice Example - Developer", `href="/cloudflare#ip-lists"`} {
		if !strings.Contains(sec, want) {
			t.Errorf("list section lacks %q", want)
		}
	}
	if strings.Contains(sec, "/remove") || strings.Contains(rest, "cloudflare:list:") {
		t.Error("list labels are removable or listed with the others")
	}
	if !strings.Contains(rest, "/ips/labels/"+strconv.FormatInt(manual, 10)+"/remove") {
		t.Error("the manual label lost its remove button")
	}
	b = e.get("/ips/203.0.113.4", signedIn(e)).Body.String()
	for _, want := range []string{"offices · Alice Example - Developer</a>", "offices · <a href=\"/ips/person/Alice%20Example%20-%20Developer\">", "a Cloudflare IP list", "Alice home"} {
		if !strings.Contains(b, want) {
			t.Errorf("IP page lacks %q", want)
		}
	}
	if strings.Index(b, "a Cloudflare IP list") > strings.Index(b, "Alice home") {
		t.Error("the manual label ranks above the list's")
	}
}

// Without lists or a token, the card says so.
func TestCloudflareListsEmpty(t *testing.T) {
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) { c.Cloudflare = true })
	b := e.get("/cloudflare", signedIn(e)).Body.String()
	if !strings.Contains(b, "Not read yet: there") || strings.Contains(b, "Save and sync") {
		t.Errorf("empty card:\n%s", b)
	}
	e.st.RecordIPSourceRun(t.Context(), cloudflare.ListsSource, testNow, 0, errorString(cloudflare.ListsPermission))
	if b := e.get("/cloudflare", signedIn(e)).Body.String(); !strings.Contains(b, "Account &gt; Account Filter Lists &gt; Read)") {
		t.Errorf("no permission error:\n%s", b)
	}
}

type errorString string

func (e errorString) Error() string { return string(e) }
