// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build dev

package main

import (
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/realmwatch/heimdall/internal/netx"
)

// Dev builds only: HEIMDALL_DEV_FAKE_DISCORD=http://127.0.0.1:<port> sends
// agent hand-offs to a local fake Discord instead of discord.com, so the
// feature can be tried without posting anywhere real. Release builds don't
// contain this file.
func init() {
	raw := os.Getenv("HEIMDALL_DEV_FAKE_DISCORD")
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" {
		return
	}
	if ip := net.ParseIP(u.Hostname()); ip == nil || !ip.IsLoopback() {
		return
	}
	handoffClient = func() *netx.Client {
		return netx.NewForTest(&http.Client{Transport: fakeDiscord{u}})
	}
}

type fakeDiscord struct{ base *url.URL }

func (f fakeDiscord) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host, r.Host = f.base.Scheme, f.base.Host, f.base.Host
	return http.DefaultTransport.RoundTrip(r)
}
