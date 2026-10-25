// SPDX-License-Identifier: AGPL-3.0-or-later

package bans

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/ipinfo"
	"github.com/chrisreedio/heimdall/internal/logins"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/store/storetest"
)

var testNow = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

const zoneA = "0123456789abcdef0123456789abcdef"

type rig struct {
	t      *testing.T
	st     *store.Store
	hosts  map[string]store.IngestHost
	now    time.Time
	cards  []notify.Alert
	mu     sync.Mutex
	engine *Engine
	enf    *Enforcer
	cf     *fakeCF
}

func newRig(t *testing.T, mode string) *rig {
	t.Helper()
	st := storetest.New(t)
	ctx := t.Context()
	r := &rig{t: t, st: st, hosts: map[string]store.IngestHost{}, now: testNow}
	for _, org := range []string{"acme", "globex"} {
		st.CreateOrg(ctx, "test", org, "")
		st.CreateEnv(ctx, "test", org, "prod", "")
		for _, name := range []string{"web-01", "web-02", "web-03"} {
			if _, _, err := st.AddHost(ctx, "test", org, "prod", name, nil); err != nil {
				t.Fatal(err)
			}
			h, _ := st.HostByName(ctx, org, name)
			r.hosts[org+"/"+name] = h
		}
	}
	cfg := config.BansDefaults
	cfg.Mode = mode
	now := func() time.Time { return r.now }
	ips := &ipinfo.Resolver{Store: st, Sources: []ipinfo.Source{ipinfo.Hosts{Store: st}, ipinfo.SignIns{Store: st}}}
	cf, client := newFakeCF(t)
	r.cf = cf
	r.enf = &Enforcer{Client: client, Store: st, Cfg: cfg, Now: now, Sleep: func(context.Context, time.Duration) error { return nil }}
	r.engine = &Engine{Store: st, Ranker: &logins.Ranker{Store: st, IPs: ips}, Cfg: cfg, Now: now, BaseURL: "https://heimdall.example.com",
		Kick: r.enf.Kick, Notify: func(_ context.Context, a notify.Alert) error {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.cards = append(r.cards, a)
			return nil
		}}
	return r
}

func (r *rig) setCfg(f func(*config.Bans)) {
	f(&r.engine.Cfg)
	f(&r.enf.Cfg)
}

// fail records failures from ip on a host, an hour ago.
func (r *rig) fail(host, ip string, n, users int, succeeded bool) {
	r.t.Helper()
	at := r.now.Add(-time.Hour)
	day := store.LoginDay{Day: at.Format(time.DateOnly), Failures: n, Addresses: 1,
		Rows: []store.LoginFailure{{IP: ip, Failures: n, Usernames: users, First: at.Add(-time.Hour), Last: at, Succeeded: succeeded}}}
	if err := r.st.RecordLogins(r.t.Context(), r.hosts[host].ID, store.LoginReport{Source: "journal", Days: []store.LoginDay{day}}, r.now); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) run() Result {
	r.t.Helper()
	res, err := r.engine.Run(r.t.Context())
	if err != nil {
		r.t.Fatal(err)
	}
	return res
}

func (r *rig) sync() {
	r.t.Helper()
	if err := r.enf.Sync(r.t.Context()); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) bans(statuses ...string) []store.Ban {
	r.t.Helper()
	bs, err := r.st.Bans(r.t.Context(), store.BanQuery{Statuses: statuses})
	if err != nil {
		r.t.Fatal(err)
	}
	return bs
}

func find(cs []Candidate, target string) *Candidate {
	for i := range cs {
		if TargetString(cs[i].Target) == target {
			return &cs[i]
		}
	}
	return nil
}

func TestScore(t *testing.T) {
	r := newRig(t, config.BansShadow)
	ctx := t.Context()
	// A spray across three hosts: over, and blocked (3 hosts).
	for _, h := range []string{"acme/web-01", "acme/web-02", "globex/web-01"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	// One host, a few tries: under.
	r.fail("acme/web-01", "203.0.113.8", 6, 1, false)
	// Failed and then got in: over on the strength of that alone, blocked.
	r.fail("acme/web-03", "203.0.113.9", 3, 1, true)
	// Five addresses in one /24, each well under the threshold: a network.
	for i := 1; i <= 5; i++ {
		r.fail("acme/web-02", "198.51.100."+string(rune('0'+i)), 6, 1, false)
	}
	// IPv6 bans cover the /64.
	r.fail("acme/web-01", "2001:db8:1:2::77", 200, 20, false)
	r.fail("acme/web-02", "2001:db8:1:2::77", 200, 20, false)

	cs, err := r.engine.Candidates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	spray := find(cs, "203.0.113.7")
	if spray == nil || !spray.Over || spray.Action != Block || spray.Skip != "" || len(spray.Orgs) != 2 {
		t.Fatalf("spray: %+v", spray)
	}
	if spray.Factors[0].Name != "hosts" || spray.Factors[0].Points != 6 {
		t.Errorf("hosts factor: %+v", spray.Factors)
	}
	if c := find(cs, "203.0.113.8"); c == nil || c.Over {
		t.Errorf("small one: %+v", c)
	}
	if c := find(cs, "203.0.113.9"); c == nil || !c.Over || c.Action != Block || !slices.ContainsFunc(c.Factors, func(f Factor) bool { return f.Name == "succeeded" }) {
		t.Errorf("then succeeded: %+v", c)
	}
	net := find(cs, "198.51.100.0/24")
	if net == nil || !net.Over || net.Kind != KindNetwork || net.Action != Challenge || len(net.Evidence.Members) != 5 {
		t.Fatalf("network: %+v", net)
	}
	if c := find(cs, "2001:db8:1:2::/64"); c == nil || !c.Over {
		t.Errorf("v6: %+v", c)
	}
	if cs[0].Score < cs[len(cs)-1].Score {
		t.Error("not sorted")
	}

	// A label anywhere in the network (in any org) makes it friendly.
	globex := r.hosts["globex/web-01"].OrgID
	if _, err := r.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: globex, Prefix: netip.MustParsePrefix("198.51.100.200/32"),
		Kind: store.IPKindStaff, Name: "Office"}); err != nil {
		t.Fatal(err)
	}
	cs, _ = r.engine.Candidates(ctx)
	if net := find(cs, "198.51.100.0/24"); net == nil || !strings.Contains(net.Skip, "198.51.100.200/32") {
		t.Errorf("network with a friendly inside: %+v", net)
	}
	// An address one org vouches for is never a candidate, even if
	// another org doesn't know it.
	acme := r.hosts["acme/web-01"].OrgID
	r.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: acme, Prefix: netip.MustParsePrefix("203.0.113.7/32"), Kind: store.IPKindAutomation, Name: "CI"})
	cs, _ = r.engine.Candidates(ctx)
	if c := find(cs, "203.0.113.7"); c != nil {
		t.Errorf("vouched address scored: %+v", c)
	}
}

func TestBanDuration(t *testing.T) {
	cfg := config.BansDefaults
	day := 24 * time.Hour
	for n, want := range map[int]time.Duration{0: 7 * day, 1: 14 * day, 2: 28 * day, 3: 56 * day, 4: 90 * day, 30: 90 * day} {
		if got := BanDuration(cfg, n); got != want {
			t.Errorf("offense %d: %v, want %v", n+1, got, want)
		}
	}
}

func TestShadowMode(t *testing.T) {
	r := newRig(t, config.BansShadow)
	for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	res := r.run()
	if res.Shadow != 1 || res.Proposed != 0 {
		t.Fatalf("%+v", res)
	}
	// Again: the same row is refreshed, not duplicated.
	if res := r.run(); res.Shadow != 0 {
		t.Errorf("second run: %+v", res)
	}
	bs := r.bans()
	if len(bs) != 1 || bs[0].Status != store.BanShadow || bs[0].Target != "203.0.113.7" || !bs[0].ExpiresAt.Equal(r.now.Add(7*24*time.Hour)) {
		t.Fatalf("%+v", bs)
	}
	if fs, ev := Decode(bs[0]); len(fs) == 0 || len(ev.Hosts) != 3 || ev.Failures != 120 {
		t.Errorf("breakdown %+v evidence %+v", fs, ev)
	}
	if len(r.cards) != 0 {
		t.Errorf("shadow mode notified: %+v", r.cards)
	}
	// The enforcer writes nothing in shadow mode.
	r.sync()
	if r.cf.writes != 0 {
		t.Errorf("%d Cloudflare writes in shadow mode", r.cf.writes)
	}
	// The optional daily digest.
	r.setCfg(func(c *config.Bans) { c.ShadowDigest = true })
	r.run()
	r.run()
	if len(r.cards) != 1 || r.cards[0].Kind != notify.KindBanShadow || r.cards[0].Ban.Would != 1 {
		t.Fatalf("digest: %+v", r.cards)
	}
}

func TestProposeApproveEnforce(t *testing.T) {
	r := newRig(t, config.BansPropose)
	ctx := t.Context()
	for _, h := range []string{"acme/web-01", "acme/web-02", "globex/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	if res := r.run(); res.Proposed != 1 {
		t.Fatalf("%+v", res)
	}
	if res := r.run(); res.Proposed != 0 {
		t.Fatalf("proposed twice: %+v", res)
	}
	if len(r.cards) != 1 {
		t.Fatalf("cards: %d", len(r.cards))
	}
	card := r.cards[0]
	if card.Kind != notify.KindBan || card.Ban.Target != "203.0.113.7" || card.Ban.Action != Block || card.Ban.Days != 7 ||
		!strings.HasPrefix(card.URL, "https://heimdall.example.com/bans#ban-") || len(card.Ban.Hosts) != 3 {
		t.Fatalf("card %+v %+v", card, card.Ban)
	}
	text := card.Text()
	for _, want := range []string{"203.0.113.7", "203.0.113.0/24", "120 on 3 hosts", "block for 7 days", "Approve / review", "nothing known"} {
		if !strings.Contains(text, want) {
			t.Errorf("card text missing %q:\n%s", want, text)
		}
	}
	// Nothing is written before approval.
	r.sync()
	if got := r.cf.itemIPs("heimdall_block"); len(got) != 0 {
		t.Fatalf("written before approval: %v", got)
	}
	b := r.bans(store.BanProposed)[0]
	if err := r.st.DecideBan(ctx, b.ID, true, "user:1", "", r.now); err != nil {
		t.Fatal(err)
	}
	if err := r.st.DecideBan(ctx, b.ID, true, "user:1", "", r.now); !store.IsBanState(err) {
		t.Errorf("approved twice: %v", err)
	}
	// A zone opts in: its rules are written with the items.
	if err := r.st.SetBanZone(ctx, zoneA, "example.com", true, "user:1", r.now); err != nil {
		t.Fatal(err)
	}
	r.sync()
	if got := r.cf.itemIPs("heimdall_block"); !slices.Equal(got, []string{"203.0.113.7"}) {
		t.Fatalf("block list: %v", got)
	}
	b, _ = r.st.BanByID(ctx, b.ID)
	if b.Status != store.BanActive || b.ItemID == "" || !b.ExpiresAt.Equal(r.now.Add(7*24*time.Hour)) {
		t.Fatalf("after sync: %+v", b)
	}
	rs := r.cf.rulesets[zoneA]
	if rs == nil || len(rs.Rules) != 2 || rs.Rules[0].Expression != "ip.src in $heimdall_challenge" ||
		rs.Rules[0].Action != "managed_challenge" || rs.Rules[1].Action != "block" || rs.Rules[1].Ref != "heimdall_bans_block" {
		t.Fatalf("rules: %+v", rs)
	}
	zs, _ := r.st.BanZones(ctx)
	if z := zs[zoneA]; z.State != store.BanZoneOK || len(z.Rules) != 2 {
		t.Errorf("zone %+v", z)
	}
	// Idempotent: another sync writes nothing.
	writes := r.cf.writes
	r.sync()
	if r.cf.writes != writes {
		t.Errorf("a quiet sync wrote %d times", r.cf.writes-writes)
	}

	// Pause halts writes: an unban waits.
	if err := r.st.SetBanPaused(ctx, true, "user:2", "testing", r.now); err != nil {
		t.Fatal(err)
	}
	if err := r.st.Unban(ctx, b.ID, "user:1", r.now); err != nil {
		t.Fatal(err)
	}
	r.sync()
	if r.cf.writes != writes {
		t.Error("wrote while paused")
	}
	if b, _ = r.st.BanByID(ctx, b.ID); b.Status != store.BanLifting {
		t.Errorf("paused unban: %s", b.Status)
	}
	r.st.SetBanPaused(ctx, false, "user:2", "", r.now)
	r.sync()
	if b, _ = r.st.BanByID(ctx, b.ID); b.Status != store.BanEnded || b.EndReason != "unbanned" || len(r.cf.itemIPs("heimdall_block")) != 0 {
		t.Errorf("after resume: %+v %v", b, r.cf.itemIPs("heimdall_block"))
	}
	// An unbanned mistake doesn't count as an offense.
	if n, _, _ := r.st.BanOffenses(ctx, "203.0.113.7", r.now.AddDate(-1, 0, 0)); n != 0 {
		t.Errorf("offenses %d", n)
	}
	// Opting the zone out removes only Heimdall's rules.
	r.cf.rulesets[zoneA].Rules = append(r.cf.rulesets[zoneA].Rules, cfRule("theirs", "http.host eq \"x\"", "block"))
	r.st.SetBanZone(ctx, zoneA, "example.com", false, "user:1", r.now)
	r.sync()
	if rules := r.cf.rulesets[zoneA].Rules; len(rules) != 1 || rules[0].Ref != "theirs" {
		t.Errorf("after opt-out: %+v", rules)
	}
	audits, _ := r.st.BanAudits(ctx, 100)
	var actions []string
	for _, a := range audits {
		actions = append(actions, a.Action)
	}
	for _, want := range []string{"ban.proposed", "approve", "cf.list.create", "cf.ruleset.create", "cf.item.add", "pause", "unban", "resume", "cf.item.delete", "cf.rule.delete", "zone.on", "zone.off"} {
		if !slices.Contains(actions, want) {
			t.Errorf("audit missing %s: %v", want, actions)
		}
	}
}

func TestExpiryAndRepeatOffense(t *testing.T) {
	r := newRig(t, config.BansAuto)
	ctx := t.Context()
	for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	if res := r.run(); res.Auto != 1 {
		t.Fatalf("%+v", res)
	}
	if len(r.cards) != 1 || !r.cards[0].Ban.Auto || !strings.Contains(r.cards[0].Subject(), "banned 203.0.113.7") {
		t.Fatalf("auto card: %+v", r.cards)
	}
	r.sync()
	b := r.bans(store.BanActive)[0]
	// A week later it expires and Heimdall takes it down.
	r.now = r.now.Add(7*24*time.Hour + time.Minute)
	r.sync()
	if b, _ = r.st.BanByID(ctx, b.ID); b.Status != store.BanEnded || b.EndReason != "expired" {
		t.Fatalf("expired: %+v", b)
	}
	if len(r.cf.itemIPs("heimdall_block")) != 0 {
		t.Error("still in the list")
	}
	// It comes back: the next ban is twice as long.
	for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	r.run()
	nb := r.bans(store.BanPending)
	if len(nb) != 1 || nb[0].Offense != 2 || nb[0].Duration != 14*24*time.Hour {
		t.Fatalf("repeat: %+v", nb)
	}
}

func TestAutoCaps(t *testing.T) {
	r := newRig(t, config.BansAuto)
	r.setCfg(func(c *config.Bans) { c.MaxPerHour = 1 })
	for _, ip := range []string{"203.0.113.7", "203.0.113.70"} {
		for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
			r.fail(h, ip, 40, 8, false)
		}
	}
	res := r.run()
	if res.Auto != 1 || res.Proposed != 1 {
		t.Fatalf("over the cap, a person decides: %+v", res)
	}
	// Approving the second still waits for the hour's cap.
	p := r.bans(store.BanProposed)[0]
	r.st.DecideBan(t.Context(), p.ID, true, "user:1", "", r.now)
	r.sync()
	if got := len(r.bans(store.BanActive)); got != 1 {
		t.Errorf("active %d", got)
	}
	if w := r.bans(store.BanPending); len(w) != 1 || !strings.Contains(w[0].LastError, "at most 1 new bans an hour") {
		t.Errorf("waiting: %+v", w)
	}
	r.now = r.now.Add(61 * time.Minute)
	r.sync()
	if got := len(r.bans(store.BanActive)); got != 2 {
		t.Errorf("after an hour, active %d", got)
	}
}

func TestEnforcerRetries(t *testing.T) {
	r := newRig(t, config.BansPropose)
	ctx := t.Context()
	for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	r.run()
	b := r.bans(store.BanProposed)[0]
	r.st.DecideBan(ctx, b.ID, true, "user:1", "", r.now)
	r.cf.failAdd = 1
	if err := r.enf.Sync(ctx); err == nil {
		t.Fatal("no error")
	}
	b, _ = r.st.BanByID(ctx, b.ID)
	if b.Status != store.BanPending || b.Attempts != 1 || b.LastError == "" || !b.NextTryAt.After(r.now) {
		t.Fatalf("after a failed write: %+v", b)
	}
	if st, _ := LastSync(ctx, r.st); st.Error == "" {
		t.Error("sync error not recorded")
	}
	// Not retried before its time...
	r.sync()
	if b, _ = r.st.BanByID(ctx, b.ID); b.Status != store.BanPending {
		t.Fatal("retried early")
	}
	// ...then it goes through.
	r.now = r.now.Add(2 * time.Minute)
	r.sync()
	if b, _ = r.st.BanByID(ctx, b.ID); b.Status != store.BanActive || b.Attempts != 0 {
		t.Fatalf("after retry: %+v", b)
	}

	// An item already in the list (a lost answer) is adopted, not added twice.
	r.fail("acme/web-01", "203.0.113.99", 400, 20, true)
	r.run()
	nb := r.bans(store.BanProposed)[0]
	l := r.cf.list("heimdall_block")
	l.Items["pre"] = cfItem("pre", "203.0.113.99")
	r.st.DecideBan(ctx, nb.ID, true, "user:1", "", r.now)
	r.sync()
	if nb, _ = r.st.BanByID(ctx, nb.ID); nb.Status != store.BanActive || nb.ItemID != "pre" || len(l.Items) != 2 {
		t.Fatalf("adopt: %+v %v", nb, l.Items)
	}
}

func TestVouchedBeforeFiring(t *testing.T) {
	r := newRig(t, config.BansPropose)
	ctx := t.Context()
	for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	r.run()
	b := r.bans(store.BanProposed)[0]
	r.st.DecideBan(ctx, b.ID, true, "user:1", "", r.now)
	// Between approval and the write, someone labels it.
	r.st.AddIPLabel(ctx, "test", store.IPLabel{OrgID: r.hosts["globex/web-01"].OrgID, Prefix: netip.MustParsePrefix("203.0.113.0/28"), Kind: store.IPKindStaff, Name: "VPN"})
	r.sync()
	if b, _ = r.st.BanByID(ctx, b.ID); b.Status != store.BanEnded || !strings.HasPrefix(b.EndReason, "vouched") {
		t.Fatalf("%+v", b)
	}
	if got := r.cf.itemIPs("heimdall_block"); len(got) != 0 {
		t.Errorf("written: %v", got)
	}
	// One of our own hosts' report address is never proposed either.
	r.st.RecordReportIP(ctx, r.hosts["acme/web-01"].ID, "192.0.2.10")
	for _, h := range []string{"acme/web-02", "acme/web-03", "globex/web-01"} {
		r.fail(h, "192.0.2.10", 400, 20, true)
	}
	cs, _ := r.engine.Candidates(ctx)
	if c := find(cs, "192.0.2.10"); c != nil && c.Skip == "" {
		t.Errorf("own host proposed: %+v", c)
	}
}

func TestPlanLimits(t *testing.T) {
	r := newRig(t, config.BansPropose)
	ctx := t.Context()
	// The account allows one list: blocks fall back to the challenge list.
	r.cf.failListNew = "heimdall_block"
	// The zone has no room for more rules.
	r.cf.failRule = zoneA
	r.st.SetBanZone(ctx, zoneA, "example.com", true, "user:1", r.now)
	r.fail("acme/web-01", "203.0.113.9", 3, 1, true)
	r.run()
	b := r.bans(store.BanProposed)[0]
	if b.Action != Block {
		t.Fatalf("%+v", b)
	}
	r.st.DecideBan(ctx, b.ID, true, "user:1", "", r.now)
	if err := r.enf.Sync(ctx); err == nil || !strings.Contains(err.Error(), "maximum number of rules") {
		t.Fatalf("sync: %v", err)
	}
	zs, _ := r.st.BanZones(ctx)
	if z := zs[zoneA]; z.State != store.BanZoneError || !strings.Contains(z.Note, "maximum number of rules") {
		t.Errorf("zone: %+v", z)
	}
	l, _ := Lists(ctx, r.st)
	if !l.Fallback || l.Block.ID != "" || !strings.Contains(l.Note, "challenged instead") {
		t.Errorf("lists: %+v", l)
	}
	if got := r.cf.itemIPs("heimdall_challenge"); !slices.Equal(got, []string{"203.0.113.9"}) {
		t.Errorf("fallback list: %v", got)
	}
}

func TestGuardInternal(t *testing.T) {
	g := &Guard{internal: internalRanges}
	for _, s := range []string{"10.1.2.3/32", "100.100.1.1/32", "fd7a:115c:a1e0::5/128", "127.0.0.1/32", "0.0.0.0/0"} {
		if _, ok := g.Friendly(netip.MustParsePrefix(s)); !ok {
			t.Errorf("%s not friendly", s)
		}
	}
	if why, ok := g.Friendly(netip.MustParsePrefix("203.0.113.7/32")); ok {
		t.Errorf("public address friendly: %s", why)
	}
	var nilGuard *Guard
	if _, ok := nilGuard.Friendly(netip.MustParsePrefix("203.0.113.7/32")); !ok {
		t.Error("a missing guard must refuse")
	}
}

func TestTokenURL(t *testing.T) {
	u := TokenURL()
	if !strings.HasPrefix(u, "https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=") ||
		!strings.Contains(u, "%5B%7B%22key%22%3A%22firewall_services%22%2C%22type%22%3A%22edit%22%7D%5D") ||
		!strings.HasSuffix(u, "&name=Heimdall%20bans") {
		t.Errorf("%s", u)
	}
}

func TestShadowStillLiftsLeftovers(t *testing.T) {
	r := newRig(t, config.BansAuto)
	for _, h := range []string{"acme/web-01", "acme/web-02", "acme/web-03"} {
		r.fail(h, "203.0.113.7", 40, 8, false)
	}
	r.run()
	r.sync()
	b := r.bans(store.BanActive)[0]
	// Back to shadow: nothing new is written, but the old ban still
	// comes down when it expires.
	r.setCfg(func(c *config.Bans) { c.Mode = config.BansShadow })
	writes := r.cf.writes
	r.sync()
	if r.cf.writes != writes {
		t.Error("shadow mode wrote")
	}
	r.now = r.now.Add(8 * 24 * time.Hour)
	r.sync()
	if b, _ = r.st.BanByID(t.Context(), b.ID); b.Status != store.BanEnded || len(r.cf.itemIPs("heimdall_block")) != 0 {
		t.Errorf("leftover: %+v", b)
	}
}
