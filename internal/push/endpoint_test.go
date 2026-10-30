// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"strings"
	"testing"

	"github.com/realmwatch/heimdall/internal/netx"
)

// Only https endpoints on the browsers' push services are accepted, so a
// subscription can't point the hub at an internal address.
func TestCheckEndpoint(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{
		"https://fcm.googleapis.com/fcm/send/dXJ1:APA91bH",
		"https://fcm.googleapis.com:443/wp/abc",
		"https://web.push.apple.com/QGuQyavXutnMH4JYAYRx",
		"https://updates.push.services.mozilla.com/wpush/v2/gAAAAAB",
		"https://wns2-par02p.notify.windows.com/w/?token=BQYAAAB",
	} {
		if err := CheckEndpoint(ok); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"http://fcm.googleapis.com/fcm/send/x",       // not https
		"https://fcm.googleapis.com:8443/fcm/send/x", // another port
		"https://169.254.169.254/latest/meta-data",   // IP literals
		"https://10.0.0.5/push",
		"https://[2001:db8::1]/push",
		"https://example.com/push", // other hosts
		"https://push.apple.com/x", // the bare suffix isn't a host under it
		"https://evilpush.apple.com.example.com/x",
		"https://fcm.googleapis.com.example.com/x",
		"https://notfcm.googleapis.com/x",
		"https://user:pass@fcm.googleapis.com/x", // credentials
		"https://FCM.googleapis.com/x",           // browsers give lowercase hosts
		"https://fcm.googleapis.com/x#frag",
		"ftp://fcm.googleapis.com/x",
		"fcm.googleapis.com/x",
		"",
		"https://fcm.googleapis.com/" + strings.Repeat("a", maxEndpoint),
	} {
		if err := CheckEndpoint(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if !devLoopback { // release builds: no loopback, even over https
		for _, bad := range []string{"http://127.0.0.1:9999/push", "https://127.0.0.1/push", "https://[::1]/push", "https://localhost/push"} {
			if CheckEndpoint(bad) == nil {
				t.Errorf("loopback endpoint %s accepted outside a dev build", bad)
			}
		}
	}
}

func TestPushHostsAllowlist(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]bool{
		"fcm.googleapis.com": true, "web.push.apple.com": true, "api.push.apple.com": true,
		"updates.push.services.mozilla.com": true, "db5p.notify.windows.com": true,
		"googleapis.com": false, "push.apple.com": false, "notify.windows.com": false, "example.com": false,
		"203.0.113.7": false, "::1": false,
	} {
		if got := netx.PushHost(host); got != want {
			t.Errorf("PushHost(%q) = %v", host, got)
		}
	}
}

func TestParseKeys(t *testing.T) {
	t.Parallel()
	b := newTestBrowser(t)
	pub, sec, err := ParseKeys(b64.EncodeToString(b.p256dh), b64.EncodeToString(b.auth)+"==")
	if err != nil || len(pub) != 65 || len(sec) != 16 {
		t.Fatalf("good keys: %v", err)
	}
	notOnCurve := append([]byte{4}, make([]byte, 64)...)
	for _, c := range [][2]string{
		{b64.EncodeToString(notOnCurve), b64.EncodeToString(b.auth)},
		{b64.EncodeToString(b.p256dh), b64.EncodeToString(b.auth[:8])},
		{"not base64!", b64.EncodeToString(b.auth)},
		{"", ""},
	} {
		if _, _, err := ParseKeys(c[0], c[1]); err == nil {
			t.Errorf("keys %q accepted", c)
		}
	}
}
