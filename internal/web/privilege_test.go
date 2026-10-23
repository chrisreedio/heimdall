// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

func TestHostPagePrivilege(t *testing.T) {
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	host := e.seed()
	page := func() string {
		t.Helper()
		return e.get("/hosts/acme/web-01", signedIn(e)).Body.String()
	}
	if strings.Contains(page(), "Privileged access") {
		t.Fatal("privilege line shown for a host that never enabled the watch")
	}
	ctx := t.Context()
	at := testNow.Add(-time.Hour).Truncate(time.Second)
	events := []store.PrivilegeEvent{{At: at, Kind: "sudo"}, {At: at.Add(time.Second), Kind: "sudo"},
		{At: at.Add(2 * time.Second), Kind: "root-ssh"}, {At: testNow.Add(-48 * time.Hour), Kind: "su"}}
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, events, "on", testNow); err != nil {
		t.Fatal(err)
	}
	body := page()
	for _, want := range []string{"Privileged access", "2 sudo, 1 root SSH in the last 24 hours", "watched"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page missing %q", want)
		}
	}
	if _, _, err := e.st.RecordPrivilege(ctx, host.ID, nil, "partial", testNow); err != nil {
		t.Fatal(err)
	}
	if body := page(); !strings.Contains(body, "privilege watch partly removed") {
		t.Error("host page missing the watch-off warning")
	}
}
