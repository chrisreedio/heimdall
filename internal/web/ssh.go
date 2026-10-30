// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/ipinfo"
	"github.com/realmwatch/heimdall/internal/store"
)

// sshWindow is how far back failed logins from internet addresses count
// as evidence that a host's SSH is reachable from the internet.
const sshWindow = 14 * 24 * time.Hour

// sshView is a host's SSH as its pages show it: what sshd allows (from
// the collector, the inside view) and whether anyone on the internet
// actually reached it (failed logins from public addresses, which a cloud
// firewall in front of the server would have stopped).
type sshView struct {
	Known      bool // the collector reported sshd's settings
	None       bool // no sshd
	Unreadable bool // sshd_config is root-only, so only the listening addresses are known
	Ports      string
	Scope      string // public, all, private, tailnet, local or none (listenScope)
	Password   string // on, off or "" unknown
	Root       string // sshd's PermitRootLogin, "" unknown

	Watching bool      // the login watch reports, so Internet means something
	Internet int       // internet addresses that tried to log in, within sshWindow
	Last     time.Time // the latest such attempt
}

// newSSHView combines a host's sshd settings (ok false: never reported)
// with its failed logins since sshWindow.
func newSSHView(h store.HostSSH, ok, watching bool, fails []store.HostLoginFailure) sshView {
	v := sshView{Known: ok, Watching: watching}
	if ok {
		v.None, v.Unreadable = h.Source == "none", h.Source == "unreadable"
		ports := make([]string, len(h.Ports))
		for i, p := range h.Ports {
			ports[i] = strconv.Itoa(p)
		}
		v.Ports = strings.Join(ports, ", ")
		v.Scope = listenScope(h.Listen)
		if on, known := h.PasswordLogin(); known {
			v.Password = map[bool]string{true: "on", false: "off"}[on]
		}
		v.Root = h.RootLogin
	}
	for _, f := range fails {
		if a, err := netip.ParseAddr(f.IP); err == nil && internetAddr(a) {
			v.Internet++
			if f.Last.After(v.Last) {
				v.Last = f.Last
			}
		}
	}
	return v
}

// internetAddr reports whether a is outside every internal range: the
// tailnet, private networks, loopback and the like.
func internetAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsValid() && !slices.ContainsFunc(ipinfo.InternalRanges, func(p netip.Prefix) bool { return p.Contains(a) })
}

// listenScope is the widest of the addresses sshd listens on: public (a
// public address), all (every address: as reachable as the network lets
// it be), private, tailnet, local (loopback), or none.
func listenScope(addrs []string) string {
	scopes := []string{"none", "local", "tailnet", "private", "all", "public"}
	worst := 0
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap()
		i := 5
		switch {
		case a.IsUnspecified():
			i = 4
		case a.IsLoopback():
			i = 1
		case ipinfo.Tailnet.Contains(a) || ipinfo.Tailnet6.Contains(a):
			i = 2
		case a.IsPrivate() || a.IsLinkLocalUnicast():
			i = 3
		}
		worst = max(worst, i)
	}
	return scopes[worst]
}

// Listening describes Scope for people.
func (v sshView) Listening() string {
	return map[string]string{
		"public": "a public address", "all": "all addresses", "private": "private networks",
		"tailnet": "the tailnet only", "local": "this server only", "none": "nothing",
	}[v.Scope]
}

// Exposed: someone on the internet reached sshd recently.
func (v sshView) Exposed() bool { return v.Internet > 0 }

// Risky: sshd is reachable from the internet and takes passwords or root
// logins with a password, the combination worth fixing first.
func (v sshView) Risky() bool { return v.Exposed() && (v.Password == "on" || v.Root == "yes") }

// Flag is the host list's filter: anything about SSH worth a look.
func (v sshView) Flag() bool { return v.Exposed() || v.Password == "on" || v.Root == "yes" }

// sshFor is one host's sshView.
func (s *server) sshFor(r *http.Request, v *auth.Viewer, hostID int64) (sshView, error) {
	ctx := r.Context()
	h, ok, err := s.st.HostSSHOf(ctx, hostID)
	if err != nil {
		return sshView{}, err
	}
	w, err := s.st.LoginWatchOf(ctx, hostID)
	if err != nil {
		return sshView{}, err
	}
	fails, err := s.st.LoginFailuresSince(ctx, v.Scope, hostID, "", s.now().Add(-sshWindow))
	if err != nil {
		return sshView{}, err
	}
	watching := w.Source != "" && w.Source != "none" && w.Source != "unreadable"
	return newSSHView(h, ok, watching, fails), nil
}
