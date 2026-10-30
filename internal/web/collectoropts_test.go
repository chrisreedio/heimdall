// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// pre returns the text of <pre id="id"> with tags stripped, as a copy
// button would copy it.
func pre(t *testing.T, body, id string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)<pre id="` + id + `">(.*?)</pre>`).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no <pre id=%q>", id)
	}
	return html.UnescapeString(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(m[1], ""))
}

func TestAddHostCollectorOptions(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IngestURL, c.Version = "https://ingest.example.com", "v0.4.0"
	})
	e.seed()
	csrf := auth.CSRFToken(goodToken)
	// A new org's default is both on, on the form and in the commands.
	form := e.get("/hosts/new", signedIn(e)).Body.String()
	for _, want := range []string{`name="watch_privilege_users" value="1" checked`, `name="watch_logins" value="1" checked`, `name="remember_opts" value="1">`} {
		if !strings.Contains(form, want) {
			t.Errorf("form missing %q", want)
		}
	}
	w := e.post("/hosts/new", url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "name": {"box-1"}}, signedIn(e), origin(e.baseURL))
	body := w.Body.String()
	if w.Code != http.StatusOK {
		t.Fatalf("add: %d", w.Code)
	}
	if got := pre(t, body, "cmd-linux"); !strings.HasSuffix(got, "sudo sh install.sh --hub https://ingest.example.com --watch-privilege-users --watch-logins") {
		t.Errorf("linux = %q", got)
	}
	if got := pre(t, body, "cmd-cloud"); !strings.HasSuffix(got, `--token-stdin --watch-privilege-users --watch-logins"]`) {
		t.Errorf("cloud = %q", got)
	}
	if got := pre(t, body, "cmd-win"); strings.Contains(got, "--watch") {
		t.Errorf("windows changed: %q", got)
	}
	// The command comes first, then the token.
	if strings.Index(body, `id="cmd-linux"`) > strings.Index(body, `id="token"`) {
		t.Error("the token should come after the install command")
	}
	for _, want := range []string{`data-collector-opts hidden`, `data-collector-flag="--watch-logins" checked`, "shown only this once"} {
		if !strings.Contains(body, want) {
			t.Errorf("result missing %q", want)
		}
	}

	// Only failed logins, remembered as the org's default.
	f := url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "name": {"box-2"}, "opts": {"1"}, "watch_logins": {"1"}, "remember_opts": {"1"}}
	body = e.post("/hosts/new", f, signedIn(e), origin(e.baseURL)).Body.String()
	if got := pre(t, body, "cmd-linux"); !strings.HasSuffix(got, "--hub https://ingest.example.com --watch-logins") {
		t.Errorf("linux = %q", got)
	}
	if !strings.Contains(body, "Saved as acme's default") {
		t.Error("no saved notice")
	}
	orgs, _ := e.st.ListOrgs(t.Context())
	if orgs[0].Collector != (store.CollectorDefaults{WatchLogins: true}) {
		t.Errorf("default = %+v", orgs[0].Collector)
	}
	saved, _ := e.st.LastAuditAt(t.Context(), "org.collector_defaults")
	if saved.IsZero() {
		t.Error("saving the default wasn't audited")
	}
	// The form now starts from it, and a submit without the checkboxes
	// (an older form, a script) uses it too.
	if form = e.get("/hosts/new", signedIn(e)).Body.String(); strings.Contains(form, `name="watch_privilege_users" value="1" checked`) || !strings.Contains(form, `name="watch_logins" value="1" checked`) {
		t.Error("form doesn't start from the saved default")
	}
	body = e.post("/hosts/new", url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "name": {"box-3"}}, signedIn(e), origin(e.baseURL)).Body.String()
	if got := pre(t, body, "cmd-linux"); !strings.HasSuffix(got, "--hub https://ingest.example.com --watch-logins") {
		t.Errorf("linux = %q", got)
	}
	// Not remembered: the default stays, nothing is audited.
	f = url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "name": {"box-4"}, "opts": {"1"}}
	body = e.post("/hosts/new", f, signedIn(e), origin(e.baseURL)).Body.String()
	if got := pre(t, body, "cmd-linux"); !strings.HasSuffix(got, "--hub https://ingest.example.com") {
		t.Errorf("linux = %q", got)
	}
	if at, _ := e.st.LastAuditAt(t.Context(), "org.collector_defaults"); !at.Equal(saved) {
		t.Error("audited without remembering")
	}
	// A rejected submit keeps the choices.
	f = url.Values{"csrf": {csrf}, "env": {"acme/prod"}, "name": {"Bad Name!"}, "opts": {"1"}, "watch_privilege_users": {"1"}}
	body = e.post("/hosts/new", f, signedIn(e), origin(e.baseURL)).Body.String()
	if !strings.Contains(body, `name="watch_privilege_users" value="1" checked`) || strings.Contains(body, `name="watch_logins" value="1" checked`) {
		t.Error("rejected submit lost the options")
	}
}

func TestEnrollCollectorOptions(t *testing.T) {
	t.Parallel()
	e := newEnvCfg(t, "http://127.0.0.1:8080", nil, func(c *Config) {
		c.IngestURL, c.Version = "https://ingest.example.com", "v0.4.0"
	})
	e.seed()
	f := url.Values{"csrf": {auth.CSRFToken(goodToken)}, "env": {"acme/prod"}, "expires": {"24h"}, "opts": {"1"}, "watch_privilege_users": {"1"}, "watch_logins": {"1"}}
	body := e.post("/hosts/enroll", f, signedIn(e), origin(e.baseURL)).Body.String()
	if got := pre(t, body, "cmd-each"); !strings.HasSuffix(got, "--enroll --watch-privilege-users --watch-logins") {
		t.Errorf("each = %q", got)
	}
	if got := pre(t, body, "cmd-many"); !strings.Contains(got, "--enroll-stdin --watch-privilege-users --watch-logins'\ndone\nunset KEY") {
		t.Errorf("many = %q", got)
	}
	if got := pre(t, body, "cmd-cloud"); !strings.HasSuffix(got, `--enroll-stdin --watch-privilege-users --watch-logins"]`) {
		t.Errorf("cloud = %q", got)
	}
	if got := pre(t, body, "cmd-win"); strings.Contains(got, "--watch") {
		t.Errorf("windows changed: %q", got)
	}
	if strings.Index(body, `id="cmd-each"`) > strings.Index(body, `id="enroll-key"`) {
		t.Error("the key should come after the install commands")
	}
	f.Del("watch_privilege_users")
	f.Del("watch_logins")
	body = e.post("/hosts/enroll", f, signedIn(e), origin(e.baseURL)).Body.String()
	if got := pre(t, body, "cmd-each"); !strings.HasSuffix(got, "--enroll") {
		t.Errorf("each = %q", got)
	}
}
