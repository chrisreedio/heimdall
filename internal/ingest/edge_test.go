// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

// CF-Connecting-IP is trusted only when the proxy's own (last) hop is a
// trusted edge address; every other way to send it is ignored.
func TestClientIPBehindCloudflare(t *testing.T) {
	edge := netip.MustParsePrefix("198.51.100.0/24") // stands in for Cloudflare's ranges
	trusted := func(a netip.Addr) bool { return edge.Contains(a) }
	for _, c := range []struct {
		name, remote string
		xff, cf      []string
		noHook       bool
		want         string
	}{
		{"edge hop: real client", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"203.0.113.9"}, false, "203.0.113.9"},
		{"edge hop, IPv6 client", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"2001:db8::9"}, false, "2001:db8::9"},
		{"edge hop, no header", "127.0.0.1:5000", []string{"198.51.100.7"}, nil, false, "198.51.100.7"},
		{"client claims an edge hop before the proxy's", "127.0.0.1:5000", []string{"198.51.100.7, 192.0.2.66"}, []string{"203.0.113.9"}, false, "192.0.2.66"},
		{"direct to the proxy, spoofed header", "127.0.0.1:5000", []string{"192.0.2.66"}, []string{"203.0.113.9"}, false, "192.0.2.66"},
		{"not via loopback proxy", "198.51.100.7:443", []string{"198.51.100.7"}, []string{"203.0.113.9"}, false, "198.51.100.7"},
		{"two headers", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"203.0.113.9", "203.0.113.10"}, false, "198.51.100.7"},
		{"list in one header", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"203.0.113.9, 203.0.113.10"}, false, "198.51.100.7"},
		{"garbage header", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"not-an-ip"}, false, "198.51.100.7"},
		{"loopback claimed", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"127.0.0.1"}, false, "198.51.100.7"},
		{"hook off", "127.0.0.1:5000", []string{"198.51.100.7"}, []string{"203.0.113.9"}, true, "198.51.100.7"},
		{"mapped edge hop", "127.0.0.1:5000", []string{"::ffff:198.51.100.7"}, []string{"203.0.113.9"}, false, "203.0.113.9"},
	} {
		h := &Handler{behindProxy: true, TrustedEdge: trusted}
		if c.noHook {
			h.TrustedEdge = nil
		}
		r := httptest.NewRequest("POST", Path, nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		for _, v := range c.cf {
			r.Header.Add("CF-Connecting-IP", v)
		}
		if got := h.clientIP(r).String(); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// Without behind_proxy nothing forwarded is trusted at all.
	h := &Handler{TrustedEdge: trusted}
	r := httptest.NewRequest("POST", Path, nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	r.Header.Set("CF-Connecting-IP", "203.0.113.9")
	if got := h.clientIP(r).String(); got != "127.0.0.1" {
		t.Errorf("behind_proxy off: %s", got)
	}
}
