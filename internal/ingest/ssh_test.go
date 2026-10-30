// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"reflect"
	"testing"

	"github.com/realmwatch/heimdall/internal/store"
)

func TestParseSSH(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		in   string
		want store.HostSSH
		ok   bool
	}{
		{"v1 src=g port=22 listen=0.0.0.0,0:0:0:0:0:0:0:0 password=no kbd=no pam=yes root=prohibit-password",
			store.HostSSH{Source: "g", Ports: []int{22}, Listen: []string{"0.0.0.0", "::"}, Password: "no", KbdInteractive: "no", PAM: "yes", RootLogin: "prohibit-password"}, true},
		{"v1 src=files port=2222,2200 listen=- password=yes kbd=? pam=? root=?",
			store.HostSSH{Source: "files", Ports: []int{2222, 2200}, Listen: []string{}, Password: "yes"}, true},
		{"v1 src=unreadable port=22 listen=100.101.102.103 password=? kbd=? pam=? root=?",
			store.HostSSH{Source: "unreadable", Ports: []int{22}, Listen: []string{"100.101.102.103"}}, true},
		{"v1 src=none", store.HostSSH{Source: "none"}, true},
		{"v2 src=none", store.HostSSH{}, false},
		{"v1 src=bogus port=22", store.HostSSH{}, false},
		{"v1 src=g port=0 listen=-", store.HostSSH{}, false},
		{"v1 src=g port=22 listen=not-an-ip", store.HostSSH{}, false},
		{"v1 src=g port=22 listen", store.HostSSH{}, false},
	} {
		got, ok := parseSSH(c.in)
		if ok != c.ok || (ok && !reflect.DeepEqual(got, c.want)) {
			t.Errorf("parseSSH(%q) = %+v %v, want %+v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}
