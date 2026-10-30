// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestListenScope(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		addrs []string
		want  string
	}{
		{nil, "none"},
		{[]string{"127.0.0.1", "::1"}, "local"},
		{[]string{"100.101.102.103", "127.0.0.1"}, "tailnet"},
		{[]string{"10.0.0.4", "100.101.102.103"}, "private"},
		{[]string{"0.0.0.0", "::"}, "all"},
		{[]string{"203.0.113.9", "0.0.0.0"}, "public"},
	} {
		if got := listenScope(c.addrs); got != c.want {
			t.Errorf("listenScope(%v) = %q, want %q", c.addrs, got, c.want)
		}
	}
}

// The host page and list combine what sshd allows with whether anyone on
// the internet actually reached it.
func TestSSHExposure(t *testing.T) {
	t.Parallel()
	e := newEnv(t, "http://127.0.0.1:8080", nil)
	web := e.seed()
	ctx := t.Context()
	page := func() string { return e.get("/hosts/acme/web-01", signedIn(e)).Body.String() }
	list := func(q string) string { return e.get("/hosts"+q, signedIn(e)).Body.String() }

	if strings.Contains(page(), `id="ssh"`) {
		t.Error("no SSH fact before the collector reports one")
	}
	set := func(h store.HostSSH) {
		t.Helper()
		if err := e.st.SetHostSSH(ctx, web.ID, h, testNow); err != nil {
			t.Fatal(err)
		}
	}
	set(store.HostSSH{Source: "g", Ports: []int{22}, Listen: []string{"0.0.0.0", "::"}, Password: "yes", KbdInteractive: "no", PAM: "yes", RootLogin: "prohibit-password"})
	body := page()
	for _, want := range []string{"Listening on all addresses", "port 22", "passwords on", "reach unknown"} {
		if !strings.Contains(body, want) {
			t.Errorf("host page lacks %q", want)
		}
	}
	if !strings.Contains(list(""), ">SSH passwords<") || !strings.Contains(list("?only=ssh"), "web-01") {
		t.Error("the list should flag passwords and filter on them")
	}

	// The login watch saw only tailnet and private sources: no internet.
	failLogins(t, e, web, "100.101.102.103", 3, false)
	failLogins(t, e, web, "10.1.2.3", 2, false)
	if body := page(); !strings.Contains(body, "no internet attempts") {
		t.Error("tailnet and private sources aren't the internet")
	}

	// An internet address tried: reachable, and with passwords on, risky.
	failLogins(t, e, web, "203.0.113.50", 40, false)
	body = page()
	if !strings.Contains(body, `class="pill bad" href="#logins"`) || !strings.Contains(body, "reached from the internet") {
		t.Error("host page should say the internet reached SSH")
	}
	if !strings.Contains(list(""), "SSH open + passwords") {
		t.Error("the list should flag SSH open with passwords")
	}

	// Keys only: still reachable, no longer the worst case.
	set(store.HostSSH{Source: "g", Ports: []int{22}, Listen: []string{"0.0.0.0"}, Password: "no", KbdInteractive: "no", PAM: "yes", RootLogin: "no"})
	if l := list(""); !strings.Contains(l, ">SSH open<") || strings.Contains(l, "SSH open + ") {
		t.Error("keys only and reachable should be plain SSH open")
	}
	if body := page(); !strings.Contains(body, "keys only") {
		t.Error("host page should say keys only")
	}
}
