// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"crypto/sha256"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
)

// Behind `tailscale serve` (ui.behind_tailscale_serve) every request comes
// from loopback; tailscale serve says who it's really from in
// X-Forwarded-For, and for tailnet users in Tailscale-User-Login and
// Tailscale-User-Name. Behind another proxy on the box (ui.behind_proxy:
// cloudflared, Caddy, nginx) only the address is taken, from the same
// last hop, or from CF-Connecting-IP when that hop is Cloudflare's edge
// (Caddy behind Cloudflare's proxy). Those headers are trusted only when an
// option is on and the request came from loopback: anything else could set
// them.

type tsUserKey struct{}

// tsUser is the tailnet identity tailscale serve passed with a request.
type tsUser struct{ Login, Name string }

// fromProxy takes the client address (and, from tailscale serve, the
// tailnet identity) from the proxy's headers, as described above.
func (s *server) fromProxy(next http.Handler) http.Handler {
	ts := s.cfg.BehindTailscaleServe
	if !ts && !s.cfg.BehindProxy {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if a, perr := netip.ParseAddr(host); err != nil || perr != nil || !a.Unmap().IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}
		ctx := r.Context()
		if ts {
			if u := (tsUser{Login: headerText(r.Header.Get("Tailscale-User-Login")), Name: headerText(r.Header.Get("Tailscale-User-Name"))}); u.Login != "" {
				ctx = context.WithValue(ctx, tsUserKey{}, u)
			}
		}
		r = r.WithContext(ctx) // a copy, so the caller's request is left alone
		if ip, ok := lastForwarded(r); ok {
			if c, ok := s.edgeClient(r, ip); ok {
				ip = c
			}
			r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
		}
		next.ServeHTTP(w, r)
	})
}

// lastForwarded is the last X-Forwarded-For hop: the one tailscale serve
// added. Earlier hops are whatever the client sent.
func lastForwarded(r *http.Request) (netip.Addr, bool) {
	vs := r.Header.Values("X-Forwarded-For")
	if len(vs) == 0 {
		return netip.Addr{}, false
	}
	hops := strings.Split(vs[len(vs)-1], ",")
	a, err := netip.ParseAddr(strings.TrimSpace(hops[len(hops)-1]))
	if err != nil || a.Zone() != "" {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// edgeClient is CF-Connecting-IP when hop is Cloudflare's edge (as with
// Caddy behind Cloudflare's proxy) and the header holds one address.
// Cloudflare sets it itself; after any other hop it's ignored.
func (s *server) edgeClient(r *http.Request, hop netip.Addr) (netip.Addr, bool) {
	if !s.cfg.BehindProxy || s.cfg.TrustedEdge == nil || !s.cfg.TrustedEdge(hop) {
		return netip.Addr{}, false
	}
	v := r.Header.Values("CF-Connecting-IP")
	if len(v) != 1 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(strings.TrimSpace(v[0]))
	if err != nil || a.Zone() != "" || a.IsUnspecified() || a.IsLoopback() {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// headerText decodes a header that may be RFC 2047 encoded (tailscale
// serve encodes names that aren't ASCII), keeping it short and printable.
func headerText(v string) string {
	if d, err := new(mime.WordDecoder).DecodeHeader(v); err == nil {
		v = d
	}
	v = strings.TrimSpace(v)
	if len(v) > 200 || strings.ContainsFunc(v, func(r rune) bool { return !unicode.IsPrint(r) }) {
		return ""
	}
	return v
}

// noteTailscaleUser records the tailnet identity a new session signed in
// with, if tailscale serve passed one.
func (s *server) noteTailscaleUser(r *http.Request, token string) {
	u, ok := r.Context().Value(tsUserKey{}).(tsUser)
	if !ok {
		return
	}
	if err := s.st.SetSessionTailscale(r.Context(), sha256.Sum256([]byte(token)), u.Login, u.Name); err != nil {
		s.log.Warn("could not record the session's tailnet user", "err", err)
	}
}
