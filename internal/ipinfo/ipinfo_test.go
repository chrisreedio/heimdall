// SPDX-License-Identifier: AGPL-3.0-or-later

package ipinfo

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/store/storetest"
)

type fakeSource struct{}

func (fakeSource) Name() string { return "fake" }
func (fakeSource) Lookup(_ context.Context, _ int64, ip netip.Addr, _ time.Time) ([]Label, error) {
	if ip == netip.MustParseAddr("100.70.0.9") {
		return []Label{{Kind: store.IPKindStaff, Name: "signed in", Person: "alice@example.com", Source: "fake",
			Prefix: netip.PrefixFrom(ip, 32), Guess: true}}, nil
	}
	return nil, nil
}

func TestResolve(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	org, err := st.CreateOrg(ctx, "test", "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	office, _ := store.ParseIPPrefix("203.0.113.0/24")
	if _, err := st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: org.ID, Prefix: office, Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	forge, _ := store.ParseIPPrefix("198.51.100.7")
	if err := st.ReplaceIPLabels(ctx, 0, "service:forge", []store.IPLabel{{Prefix: forge, Kind: store.IPKindAutomation, Name: "Laravel Forge"}}, now); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{Store: st, Sources: []Source{fakeSource{}}, UserHints: []UserHint{func(u string) (Label, bool) {
		return Label{Kind: store.IPKindAutomation, Name: "Laravel Forge", Source: "service:forge"}, u == "forge"
	}}}
	for _, c := range []struct{ ip, user, kind, name string }{
		{"203.0.113.40", "", store.IPKindStaff, "Office"},
		{"198.51.100.7", "", store.IPKindAutomation, "Laravel Forge"},
		{"100.70.0.9", "", store.IPKindTailnet, "Tailnet"}, // known beats guessed
		{"100.70.0.10", "", store.IPKindTailnet, "Tailnet"},
		{"10.1.2.3", "", store.IPKindPrivate, "Private network"},
		{"127.0.0.1", "", store.IPKindPrivate, "This server"},
		{"192.0.2.1", "", store.IPKindUnknown, ""},
		{"192.0.2.1", "forge", store.IPKindAutomation, "Laravel Forge"},
		{"?", "", store.IPKindUnknown, ""},
	} {
		v := r.Resolve(ctx, org.ID, c.ip, c.user, now)
		if v.Kind() != c.kind || v.Best().Name != c.name {
			t.Errorf("%s/%s: %s %q, want %s %q (%+v)", c.ip, c.user, v.Kind(), v.Best().Name, c.kind, c.name, v.Labels)
		}
	}
	if v := r.Resolve(ctx, org.ID, "100.70.0.9", "", now); len(v.Labels) != 2 || v.Labels[1].Person != "alice@example.com" {
		t.Errorf("guess missing: %+v", v.Labels)
	}
	// A sync replaces its source's labels; manual ones stay.
	if err := st.ReplaceIPLabels(ctx, 0, "service:forge", nil, now); err != nil {
		t.Fatal(err)
	}
	if v := r.Resolve(ctx, org.ID, "198.51.100.7", "", now); v.Kind() != store.IPKindUnknown {
		t.Errorf("after resync: %+v", v.Labels)
	}
	ls, _ := st.IPLabels(ctx, org.ID)
	if len(ls) != 1 || ls[0].Name != "Office" {
		t.Fatalf("labels %+v", ls)
	}
	if err := st.RemoveIPLabel(ctx, "test", org.ID, ls[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ParseIPPrefix("nope"); err == nil {
		t.Error("bad prefix accepted")
	}
}

func TestHostsSource(t *testing.T) {
	st := storetest.New(t)
	ctx := t.Context()
	org, _ := st.CreateOrg(ctx, "test", "acme", "")
	st.CreateEnv(ctx, "test", "acme", "prod", "")
	h, _, err := st.AddHost(ctx, "test", "acme", "prod", "web-01", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.RecordReportIP(ctx, h.ID, "::ffff:198.51.100.20"); err != nil {
		t.Fatal(err)
	}
	r := &Resolver{Store: st, Sources: []Source{Hosts{Store: st}}}
	if v := r.Resolve(ctx, org.ID, "198.51.100.20", "", time.Now()); v.Kind() != store.IPKindInfra || v.Best().Name != "web-01" {
		t.Errorf("own host: %+v", v.Labels)
	}
}
