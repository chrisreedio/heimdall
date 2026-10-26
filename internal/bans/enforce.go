// SPDX-License-Identifier: AGPL-3.0-or-later

package bans

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/cloudflare"
	"github.com/realmwatch/heimdall/internal/config"
	"github.com/realmwatch/heimdall/internal/store"
)

// Enforcer writes bans to Cloudflare and takes them down again: it keeps
// the account's two IP lists (challenge, block), one custom rule per list
// in each opted-in zone, and the lists' items in step with the bans
// table. It's the only writer. Every write is checked against the pause
// switch first, recorded in the ban audit log, and idempotent: what's
// already there is adopted, not added twice. A failed write leaves the
// ban as it was, to be retried with backoff. Expiry is Heimdall's (lists
// have no TTL): an expired ban is lifted here.
type Enforcer struct {
	Client *cloudflare.Client // the write token's; nil: no token, nothing is written
	Store  *store.Store
	Cfg    config.Bans
	Edge   *cloudflare.Edge // for the last IFF check; nil: the built-in list
	Now    func() time.Time
	Log    *slog.Logger
	// Sleep waits between polls of a bulk operation (tests return at once).
	Sleep    func(context.Context, time.Duration) error
	Interval time.Duration // 0: a minute

	once sync.Once
	kick chan struct{}
	mu   sync.Mutex // one sync at a time
}

func (e *Enforcer) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

func (e *Enforcer) Name() string { return "bans:cloudflare" }
func (e *Enforcer) Every() time.Duration {
	if e.Interval > 0 {
		return e.Interval
	}
	return time.Minute
}

func (e *Enforcer) kicks() chan struct{} {
	e.once.Do(func() { e.kick = make(chan struct{}, 1) })
	return e.kick
}

// Kick asks for a sync now (an approval, an unban, a resume), without
// waiting.
func (e *Enforcer) Kick() {
	select {
	case e.kicks() <- struct{}{}:
	default:
	}
}

// Rule refs: how Heimdall finds its own rules among a zone's custom rules.
const (
	refPrefix   = "heimdall_bans_"
	ruleDescFmt = "Heimdall bans: %s (managed by Heimdall; turn it off on its Bans page)"
)

// ListsState is what the hub knows about its lists.
type ListsState struct {
	Account   string    `json:"account"`
	Challenge ListRef   `json:"challenge"`
	Block     ListRef   `json:"block"`
	Fallback  bool      `json:"fallback"` // no block list (a plan limit): blocks go in the challenge list
	Note      string    `json:"note,omitempty"`
	At        time.Time `json:"at"`
}

// ListRef is one list.
type ListRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// SyncState is how the last sync went, for /bans and the CLI.
type SyncState struct {
	At    time.Time `json:"at"`
	Error string    `json:"error,omitempty"`
}

// State keys.
const (
	listsKey = "lists"
	syncKey  = "enforcer"
)

// Lists reads the stored list state.
func Lists(ctx context.Context, st *store.Store) (ListsState, error) {
	var l ListsState
	_, err := st.BanStateGet(ctx, listsKey, &l)
	return l, err
}

// LastSync reads how the last sync went.
func LastSync(ctx context.Context, st *store.Store) (SyncState, error) {
	var s SyncState
	_, err := st.BanStateGet(ctx, syncKey, &s)
	return s, err
}

// errPaused stops a sync between writes.
var errPaused = errors.New("paused: no Cloudflare writes")

func (e *Enforcer) checkPause(ctx context.Context) error {
	p, err := e.Store.BanPaused(ctx)
	if err != nil {
		return err
	}
	if p.Paused {
		return errPaused
	}
	return nil
}

func (e *Enforcer) audit(ctx context.Context, action, zoneID, target string, err error, detail map[string]any) {
	a := store.BanAudit{At: e.now(), Actor: "heimdall", Action: action, ZoneID: zoneID, Target: target, Result: "ok", Detail: detail}
	if err != nil {
		a.Result = "error"
		if a.Detail == nil {
			a.Detail = map[string]any{}
		}
		a.Detail["error"] = err.Error()
	}
	if aerr := e.Store.AddBanAudit(ctx, a); aerr != nil && e.Log != nil {
		e.Log.Warn("ban audit failed", "err", aerr)
	}
}

// Sync expires bans whose time is up, then (unless paused, and with a
// token) writes what's pending and lifts what's due.
func (e *Enforcer) Sync(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	err := e.sync(ctx)
	if errors.Is(err, errPaused) {
		err = nil
	}
	st := SyncState{At: e.now().UTC()}
	if err != nil {
		st.Error = err.Error()
	}
	if serr := e.Store.BanStateSet(ctx, syncKey, st, e.now()); err == nil {
		err = serr
	}
	return err
}

func (e *Enforcer) sync(ctx context.Context) error {
	now := e.now()
	if n, err := e.Store.ExpireBans(ctx, now); err != nil {
		return err
	} else if n > 0 && e.Log != nil {
		e.Log.Info("bans expired", "count", n)
	}
	if err := e.checkPause(ctx); err != nil {
		return err
	}
	if !e.Cfg.Writes() {
		// Shadow or off: never add anything, but still take down bans an
		// earlier propose or auto mode left behind, as they expire.
		if e.Client == nil {
			return nil
		}
		lists, err := Lists(ctx, e.Store)
		if err != nil || lists.Account == "" {
			return err
		}
		return e.lift(ctx, lists)
	}
	if e.Client == nil {
		return e.waitAll(ctx, "no write token: run `sudo heimdall bans set-token`")
	}
	lists, err := e.ensureLists(ctx)
	if err != nil {
		_ = e.waitAll(ctx, "lists: "+err.Error())
		return err
	}
	var errs []error
	errs = append(errs, e.zones(ctx, lists))
	errs = append(errs, e.apply(ctx, lists))
	errs = append(errs, e.lift(ctx, lists))
	return errors.Join(errs...)
}

// waitAll notes on every pending ban why it isn't written yet.
func (e *Enforcer) waitAll(ctx context.Context, why string) error {
	bs, err := e.Store.Bans(ctx, store.BanQuery{Statuses: []string{store.BanPending}})
	if err != nil {
		return err
	}
	for _, b := range bs {
		if err := e.Store.BanWaiting(ctx, b.ID, why); err != nil {
			return err
		}
	}
	return nil
}

// account is [bans] account_id, or the only account the token sees.
func (e *Enforcer) account(ctx context.Context, prev ListsState) (string, error) {
	if e.Cfg.AccountID != "" {
		return e.Cfg.AccountID, nil
	}
	if prev.Account != "" {
		return prev.Account, nil
	}
	as, err := e.Client.Accounts(ctx)
	if err != nil {
		return "", fmt.Errorf("listing accounts: %w", err)
	}
	if len(as) != 1 {
		return "", fmt.Errorf("the token sees %d accounts; set [bans] account_id", len(as))
	}
	return as[0].ID, nil
}

// ensureLists finds or creates the two lists. When the block list can't
// be created (a plan's list limit), blocks fall back to the challenge
// list: weaker, never silently dropped, and noted on /bans.
func (e *Enforcer) ensureLists(ctx context.Context) (ListsState, error) {
	prev, err := Lists(ctx, e.Store)
	if err != nil {
		return prev, err
	}
	if prev.Challenge.ID != "" && prev.Challenge.Name == e.Cfg.ChallengeList && prev.Block.Name == e.Cfg.BlockList &&
		(prev.Block.ID != "" || prev.Fallback) && e.now().Sub(prev.At) < listsRecheck {
		return prev, nil // known and recent: no call
	}
	acct, err := e.account(ctx, prev)
	if err != nil {
		return prev, err
	}
	have, err := e.Client.Lists(ctx, acct)
	if err != nil {
		return prev, fmt.Errorf("reading lists: %w", err)
	}
	st := ListsState{Account: acct, At: e.now().UTC()}
	find := func(name string) ListRef {
		for _, l := range have {
			if l.Name == name && (l.Kind == "" || l.Kind == "ip") {
				return ListRef{ID: l.ID, Name: l.Name}
			}
		}
		return ListRef{Name: name}
	}
	st.Challenge, st.Block = find(e.Cfg.ChallengeList), find(e.Cfg.BlockList)
	create := func(ref *ListRef, what string) error {
		if ref.ID != "" {
			return nil
		}
		if err := e.checkPause(ctx); err != nil {
			return err
		}
		l, err := e.Client.CreateList(ctx, acct, ref.Name, "Heimdall bans ("+what+"); managed by Heimdall, items expire on their own")
		e.audit(ctx, "cf.list.create", "", ref.Name, err, map[string]any{"list": ref.Name})
		if err != nil {
			return err
		}
		ref.ID = l.ID
		return nil
	}
	if err := create(&st.Challenge, Challenge); err != nil {
		return prev, fmt.Errorf("creating list %s: %w", st.Challenge.Name, err)
	}
	if err := create(&st.Block, Block); err != nil {
		if errors.Is(err, errPaused) {
			return prev, err
		}
		st.Fallback = true
		st.Note = "couldn't create the block list (" + err.Error() + "): blocks are challenged instead"
	}
	return st, e.Store.BanStateSet(ctx, listsKey, st, e.now())
}

// listsRecheck is how often the lists are looked up again (someone may
// have deleted one in the dashboard).
const listsRecheck = time.Hour

// listFor is the list a ban of an action goes in.
func listFor(l ListsState, action string) ListRef {
	if action == Block && !l.Fallback && l.Block.ID != "" {
		return l.Block
	}
	return l.Challenge
}

// wantRules are the custom rules each opted-in zone gets.
func wantRules(l ListsState) []cloudflare.Rule {
	mk := func(action string, list ListRef) cloudflare.Rule {
		return cloudflare.Rule{Ref: refPrefix + action, Description: fmt.Sprintf(ruleDescFmt, action),
			Expression: "ip.src in $" + list.Name, Action: RuleAction[action], Enabled: true}
	}
	out := []cloudflare.Rule{mk(Challenge, l.Challenge)}
	if !l.Fallback && l.Block.ID != "" {
		out = append(out, mk(Block, l.Block))
	}
	return out
}

func ours(r cloudflare.Rule) bool {
	return strings.HasPrefix(r.Ref, refPrefix) || strings.HasPrefix(r.Description, "Heimdall bans: ")
}

// reverify is how often a zone whose rules are in place is checked again
// (someone may have deleted or edited them in the dashboard).
const reverify = 6 * time.Hour

func (e *Enforcer) zones(ctx context.Context, l ListsState) error {
	zs, err := e.Store.BanZones(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, z := range zs {
		switch {
		case z.Enabled && (z.State != store.BanZoneOK || e.now().Sub(z.AppliedAt) > reverify):
			errs = append(errs, e.applyRules(ctx, z, l))
		case !z.Enabled && z.State != store.BanZoneOff:
			errs = append(errs, e.removeRules(ctx, z))
		}
		if errors.Is(errors.Join(errs...), errPaused) {
			return errPaused
		}
	}
	return errors.Join(errs...)
}

// applyRules puts Heimdall's rules in a zone, adding or fixing only its
// own (found by ref or description). Anything else in the zone is never
// touched. A failure (a plan's rule limit, no permission) is stored on
// the zone and shown on /bans.
func (e *Enforcer) applyRules(ctx context.Context, z store.BanZone, l ListsState) error {
	fail := func(err error) error {
		if errors.Is(err, errPaused) {
			return err
		}
		note := err.Error()
		if cloudflare.IsPermission(err) {
			note += " (the ban token needs Zone > Zone WAF > Edit for this zone)"
		}
		e.audit(ctx, "cf.rules", z.ZoneID, z.Zone, err, nil)
		if serr := e.Store.SetBanZoneState(ctx, z.ZoneID, store.BanZoneError, note, z.RulesetID, z.Rules, e.now()); serr != nil {
			return serr
		}
		return fmt.Errorf("%s rules: %w", z.Zone, err)
	}
	want := wantRules(l)
	rs, found, err := e.Client.CustomEntrypoint(ctx, z.ZoneID)
	if err != nil {
		return fail(err)
	}
	if !found {
		if err := e.checkPause(ctx); err != nil {
			return err
		}
		rs, err = e.Client.CreateCustomEntrypoint(ctx, z.ZoneID, want)
		e.audit(ctx, "cf.ruleset.create", z.ZoneID, z.Zone, err, nil)
		if err != nil {
			return fail(err)
		}
	} else {
		for _, w := range want {
			var have *cloudflare.Rule
			for i := range rs.Rules {
				if rs.Rules[i].Ref == w.Ref || rs.Rules[i].Description == w.Description {
					have = &rs.Rules[i]
					break
				}
			}
			if have != nil && have.Expression == w.Expression && have.Action == w.Action && have.Enabled {
				continue
			}
			if err := e.checkPause(ctx); err != nil {
				return err
			}
			action := "cf.rule.add"
			if have == nil {
				rs, err = e.Client.AddRule(ctx, z.ZoneID, rs.ID, w)
			} else {
				action, w.ID = "cf.rule.update", have.ID
				rs, err = e.Client.UpdateRule(ctx, z.ZoneID, rs.ID, w)
			}
			e.audit(ctx, action, z.ZoneID, z.Zone, err, map[string]any{"ref": w.Ref, "rule_action": w.Action})
			if err != nil {
				return fail(err)
			}
		}
	}
	rules := map[string]string{}
	for _, r := range rs.Rules {
		if ours(r) {
			rules[strings.TrimPrefix(r.Ref, refPrefix)] = r.ID
		}
	}
	return e.Store.SetBanZoneState(ctx, z.ZoneID, store.BanZoneOK, "", rs.ID, rules, e.now())
}

// removeRules deletes Heimdall's rules from a zone that opted out.
func (e *Enforcer) removeRules(ctx context.Context, z store.BanZone) error {
	rs, found, err := e.Client.CustomEntrypoint(ctx, z.ZoneID)
	if err == nil && found {
		for _, r := range rs.Rules {
			if !ours(r) {
				continue
			}
			if err = e.checkPause(ctx); err != nil {
				return err
			}
			err = e.Client.DeleteRule(ctx, z.ZoneID, rs.ID, r.ID)
			e.audit(ctx, "cf.rule.delete", z.ZoneID, z.Zone, err, map[string]any{"ref": r.Ref})
			if err != nil {
				break
			}
		}
	}
	if err != nil {
		if serr := e.Store.SetBanZoneState(ctx, z.ZoneID, store.BanZoneError, "removing the rules: "+err.Error(), z.RulesetID, z.Rules, e.now()); serr != nil {
			return serr
		}
		return fmt.Errorf("%s rules: %w", z.Zone, err)
	}
	return e.Store.SetBanZoneState(ctx, z.ZoneID, store.BanZoneOff, "", "", nil, e.now())
}

// backoff is when a ban whose write failed n times is tried again.
func backoff(now time.Time, attempts int) time.Time {
	return now.Add(min(time.Minute<<min(attempts, 10), time.Hour))
}

func due(b store.Ban, now time.Time) bool { return b.NextTryAt.IsZero() || !b.NextTryAt.After(now) }

// items reads a list's items by target.
func (e *Enforcer) items(ctx context.Context, acct, listID string) (map[netip.Prefix]cloudflare.ListItem, error) {
	its, err := e.Client.ListItems(ctx, acct, listID)
	if err != nil {
		return nil, err
	}
	out := map[netip.Prefix]cloudflare.ListItem{}
	for _, it := range its {
		if p, ok := ParseTarget(it.IP); ok {
			out[p] = it
		}
	}
	return out, nil
}

// wait polls a bulk operation until it's done.
func (e *Enforcer) wait(ctx context.Context, acct, opID string) error {
	if opID == "" {
		return nil
	}
	sleep := e.Sleep
	if sleep == nil {
		sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
	for range 60 {
		op, err := e.Client.Operation(ctx, acct, opID)
		if err != nil {
			return err
		}
		switch op.Status {
		case "completed":
			return nil
		case "failed":
			return fmt.Errorf("bulk operation failed: %s", op.Error)
		}
		if err := sleep(ctx, time.Second); err != nil {
			return err
		}
	}
	return errors.New("bulk operation still running; will check again")
}

// apply writes pending bans, within the caps, one bulk operation per list.
func (e *Enforcer) apply(ctx context.Context, l ListsState) error {
	now := e.now()
	pending, err := e.Store.Bans(ctx, store.BanQuery{Statuses: []string{store.BanPending}, Limit: 100000})
	if err != nil || len(pending) == 0 {
		return err
	}
	counts, err := e.Store.CountBans(ctx, now.Add(-time.Hour))
	if err != nil {
		return err
	}
	room := min(e.Cfg.MaxPerHour-counts.StartedSince, e.Cfg.MaxActive-counts.Active)
	guard, err := LoadGuard(ctx, e.Store, e.Edge, now, nil)
	if err != nil {
		return err
	}
	byList := map[string][]store.Ban{}
	// Oldest first: the order they were approved in.
	for i := len(pending) - 1; i >= 0; i-- {
		b := pending[i]
		if !due(b, now) {
			continue
		}
		p, ok := ParseTarget(b.Target)
		if !ok {
			continue
		}
		// The last IFF check, right before firing.
		if why, friendly := guard.Friendly(p); friendly {
			if err := e.Store.CancelBan(ctx, b.ID, "vouched: "+why, "heimdall", now); err != nil {
				return err
			}
			continue
		}
		if room <= 0 {
			why := fmt.Sprintf("waiting: at most %d new bans an hour and %d active", e.Cfg.MaxPerHour, e.Cfg.MaxActive)
			if err := e.Store.BanWaiting(ctx, b.ID, why); err != nil {
				return err
			}
			continue
		}
		room--
		id := listFor(l, b.Action).ID
		byList[id] = append(byList[id], b)
	}
	var errs []error
	for listID, bs := range byList {
		errs = append(errs, e.applyList(ctx, l.Account, listID, bs))
		if errors.Is(errors.Join(errs...), errPaused) {
			return errPaused
		}
	}
	return errors.Join(errs...)
}

func (e *Enforcer) applyList(ctx context.Context, acct, listID string, bs []store.Ban) error {
	now := e.now()
	failAll := func(bs []store.Ban, err error) error {
		var errs []error
		for _, b := range bs {
			errs = append(errs, e.Store.BanWriteFailed(ctx, b.ID, "cf.item.add", err, backoff(now, b.Attempts), now))
		}
		return errors.Join(append(errs, err)...)
	}
	have, err := e.items(ctx, acct, listID)
	if err != nil {
		return failAll(bs, err)
	}
	var add []store.Ban
	var items []cloudflare.NewItem
	for _, b := range bs {
		p, _ := ParseTarget(b.Target)
		if it, ok := have[p]; ok { // already there (a retry after a lost answer): adopt it
			if err := e.Store.BanApplied(ctx, b.ID, listID, it.ID, now); err != nil {
				return err
			}
			continue
		}
		add = append(add, b)
		items = append(items, cloudflare.NewItem{IP: b.Target,
			Comment: fmt.Sprintf("heimdall ban #%d, %s until %s", b.ID, b.Action, now.Add(b.Duration).UTC().Format("2006-01-02"))})
	}
	if len(add) == 0 {
		return nil
	}
	if err := e.checkPause(ctx); err != nil {
		return err
	}
	op, err := e.Client.AddItems(ctx, acct, listID, items)
	if err == nil {
		err = e.wait(ctx, acct, op)
	}
	if err != nil {
		return failAll(add, err)
	}
	if have, err = e.items(ctx, acct, listID); err != nil {
		return failAll(add, err)
	}
	var errs []error
	for _, b := range add {
		p, _ := ParseTarget(b.Target)
		it, ok := have[p]
		if !ok {
			errs = append(errs, e.Store.BanWriteFailed(ctx, b.ID, "cf.item.add", errors.New("not in the list after adding it"), backoff(now, b.Attempts), now))
			continue
		}
		errs = append(errs, e.Store.BanApplied(ctx, b.ID, listID, it.ID, now))
	}
	if e.Log != nil {
		e.Log.Info("bans written to Cloudflare", "count", len(add))
	}
	return errors.Join(errs...)
}

// lift removes expired and unbanned bans from their lists.
func (e *Enforcer) lift(ctx context.Context, l ListsState) error {
	now := e.now()
	bs, err := e.Store.Bans(ctx, store.BanQuery{Statuses: []string{store.BanLifting}, Limit: 100000})
	if err != nil || len(bs) == 0 {
		return err
	}
	byList := map[string][]store.Ban{}
	for _, b := range bs {
		if !due(b, now) {
			continue
		}
		id := b.ListID
		if id == "" {
			id = listFor(l, b.Action).ID
		}
		byList[id] = append(byList[id], b)
	}
	var errs []error
	for listID, bs := range byList {
		errs = append(errs, e.liftList(ctx, l.Account, listID, bs))
		if errors.Is(errors.Join(errs...), errPaused) {
			return errPaused
		}
	}
	return errors.Join(errs...)
}

func (e *Enforcer) liftList(ctx context.Context, acct, listID string, bs []store.Ban) error {
	now := e.now()
	failAll := func(bs []store.Ban, err error) error {
		var errs []error
		for _, b := range bs {
			errs = append(errs, e.Store.BanWriteFailed(ctx, b.ID, "cf.item.delete", err, backoff(now, b.Attempts), now))
		}
		return errors.Join(append(errs, err)...)
	}
	have, err := e.items(ctx, acct, listID)
	if err != nil {
		return failAll(bs, err)
	}
	var del []store.Ban
	var ids []string
	for _, b := range bs {
		p, _ := ParseTarget(b.Target)
		it, ok := have[p]
		if !ok { // gone already (removed by hand, or a retry): done
			if err := e.Store.BanLifted(ctx, b.ID, now); err != nil {
				return err
			}
			continue
		}
		// Only remove the item Heimdall added (or one for the same target).
		del, ids = append(del, b), append(ids, it.ID)
	}
	if len(del) == 0 {
		return nil
	}
	if err := e.checkPause(ctx); err != nil {
		return err
	}
	op, err := e.Client.DeleteItems(ctx, acct, listID, ids)
	if err == nil {
		err = e.wait(ctx, acct, op)
	}
	if err != nil {
		return failAll(del, err)
	}
	var errs []error
	for _, b := range del {
		errs = append(errs, e.Store.BanLifted(ctx, b.ID, now))
	}
	return errors.Join(errs...)
}

// Loop runs s shortly after start, then on its schedule and whenever
// kick fires, until ctx ends. A failure is logged and retried on schedule.
func Loop(ctx context.Context, log *slog.Logger, s interface {
	Name() string
	Every() time.Duration
	Sync(context.Context) error
}, kick <-chan struct{}) {
	first := time.NewTimer(30 * time.Second)
	defer first.Stop()
	tick := time.NewTicker(s.Every())
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-first.C:
		case <-tick.C:
		case <-kick:
		}
		if err := s.Sync(ctx); err != nil && log != nil {
			log.Warn("bans sync failed", "part", s.Name(), "err", err)
		}
	}
}

// Kicks is the channel Kick fires, for Loop.
func (e *Enforcer) Kicks() <-chan struct{} { return e.kicks() }
