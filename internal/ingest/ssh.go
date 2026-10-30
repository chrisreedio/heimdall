// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// SSHHeader carries the host's sshd settings and the addresses listening
// on its ports:
//
//	X-Heimdall-SSH: v1 src=g port=22 listen=0.0.0.0,0:0:0:0:0:0:0:0 password=no kbd=no pam=yes root=prohibit-password
//
// src is where they came from (g: `sshd -G`, files: sshd_config read
// directly, unreadable, none: no sshd, the only field then); "-" lists
// nothing and "?" is unknown. A header for the same reason as PHPHeader.
// Without it (an older collector) the stored state is left as it is.
const SSHHeader = "X-Heimdall-SSH"

// parseSSH parses an SSHHeader value. ok is false when it's malformed.
func parseSSH(v string) (h store.HostSSH, ok bool) {
	if len(v) > 512 {
		return h, false
	}
	f := strings.Fields(v)
	if len(f) < 2 || f[0] != "v1" {
		return h, false
	}
	kv := map[string]string{}
	for _, x := range f[1:] {
		k, val, found := strings.Cut(x, "=")
		if !found {
			return h, false
		}
		kv[k] = val
	}
	switch h.Source = kv["src"]; h.Source {
	case "none":
		return h, true
	case "g", "files", "unreadable":
	default:
		return h, false
	}
	h.Ports, h.Listen = []int{}, []string{}
	for p := range strings.SplitSeq(kv["port"], ",") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return h, false
		}
		if !slices.Contains(h.Ports, n) && len(h.Ports) < 16 {
			h.Ports = append(h.Ports, n)
		}
	}
	if l := kv["listen"]; l != "-" && l != "" {
		for a := range strings.SplitSeq(l, ",") {
			ip, err := netip.ParseAddr(a)
			if err != nil {
				return h, false
			}
			if s := ip.Unmap().String(); !slices.Contains(h.Listen, s) && len(h.Listen) < 16 {
				h.Listen = append(h.Listen, s)
			}
		}
	}
	yn := func(s string) string {
		if s == "yes" || s == "no" {
			return s
		}
		return ""
	}
	h.Password, h.KbdInteractive, h.PAM = yn(kv["password"]), yn(kv["kbd"]), yn(kv["pam"])
	switch r := kv["root"]; r {
	case "yes", "no", "prohibit-password", "forced-commands-only":
		h.RootLogin = r
	}
	return h, true
}

func (h *Handler) recordSSH(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(SSHHeader)
	if len(vals) != 1 {
		return
	}
	s, ok := parseSSH(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + SSHHeader + " header")
		return
	}
	if err := h.store.SetHostSSH(ctx, host.ID, s, h.acc.Now()); err != nil {
		log.Warn("SSH settings not recorded", "err", err)
	}
}
