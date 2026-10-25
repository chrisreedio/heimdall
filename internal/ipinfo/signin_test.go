// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"crypto/sha256"
	"net/netip"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

func TestSignInsSource(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	org, _ := st.CreateOrg(ctx, "test", "acme", "")
	uid, err := st.CreateLocalUser(ctx, "test", "alice@example.com", "", true, "x", []byte("0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	for i, ip := range []string{"203.0.113.7", "127.0.0.1", "::"} {
		if err := st.CreateSession(ctx, sha256.Sum256([]byte{byte(i)}), uid, now.Add(-time.Hour), now.Add(time.Hour), ip, "ua"); err != nil {
			t.Fatal(err)
		}
	}
	src := SignIns{Store: st}
	ls, err := src.Lookup(ctx, org.ID, netip.MustParseAddr("203.0.113.7"), now)
	if err != nil || len(ls) != 1 {
		t.Fatalf("labels = %+v, %v", ls, err)
	}
	if l := ls[0]; l.Kind != store.IPKindStaff || !l.Guess || l.Person != "alice@example.com" || l.Name != "Signed in to Heimdall" ||
		l.Prefix != netip.MustParsePrefix("203.0.113.7/32") {
		t.Errorf("label = %+v", l)
	}
	if ls, _ := src.Lookup(ctx, org.ID, netip.MustParseAddr("203.0.113.7"), now.Add(14*time.Hour)); len(ls) != 0 {
		t.Errorf("matched a sign-in more than 12h away: %+v", ls)
	}
	// Behind a proxy every session is loopback: never a match.
	for _, ip := range []string{"127.0.0.1", "::"} {
		if ls, _ := src.Lookup(ctx, org.ID, netip.MustParseAddr(ip), now); len(ls) != 0 {
			t.Errorf("%s matched: %+v", ip, ls)
		}
	}
	// A known label still ranks first: the sign-in is only a guess.
	if _, err := st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: org.ID, Prefix: netip.MustParsePrefix("203.0.113.0/24"),
		Kind: store.IPKindInfra, Name: "VPN"}); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{Store: st, Sources: []Source{src}}
	if v := r.Resolve(ctx, org.ID, "203.0.113.7", "", now); v.Kind() != store.IPKindInfra || len(v.Labels) != 2 || !v.Labels[1].Guess {
		t.Errorf("verdict = %+v", v)
	}
}
