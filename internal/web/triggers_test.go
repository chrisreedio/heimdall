// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"
	"time"
)

func TestHostPageChangeWatch(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	e.seed()
	if body := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); strings.Contains(body, "change watch") {
		t.Error("a collector that doesn't report triggers shows a change watch pill")
	}
	host, err := e.st.HostByName(t.Context(), "acme", "web-01")
	if err != nil {
		t.Fatal(err)
	}
	for state, want := range map[string]string{
		"changes=enabled,active; timer=enabled,active":    `<span class="pill ok" title="Reports as soon as packages change">change watch on</span>`,
		"changes=disabled,inactive; timer=enabled,active": `<span class="pill warn" title="Changes are only reported on the schedule">change watch off</span>`,
	} {
		e.st.SetHostTriggers(t.Context(), host.ID, state, time.Now())
		if body := e.get("/hosts/acme/web-01", signedIn(e)).Body.String(); !strings.Contains(body, want) {
			t.Errorf("%s: host page missing %s", state, want)
		}
	}
}
