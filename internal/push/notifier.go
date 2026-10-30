// SPDX-License-Identifier: AGPL-3.0-or-later

package push

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/notify"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
	"github.com/realmwatch/heimdall/internal/updates"
)

// The notifier watches what the dashboard and the chat alerts already
// detect, through the store, rather than detecting anything itself: new
// anomalies (sorted by notify.AlertRule, as chat alerts are), hosts' known-
// exploited counts, threat-news matches and ban proposals. It runs in its
// own goroutine and only reads from the store's read pool on its tick, so
// it never holds up ingest or a page; sending happens in another goroutine,
// fed by a bounded queue. Each user gets only events in orgs their role
// can see, on the terms of their own settings.

// Event is something a user may be told about.
type Event struct {
	Kind  string
	Host  store.PushHost // the host it's about (OrgID decides who may see it)
	Orgs  []int64        // a ban: the orgs whose hosts it touched (their operators see it)
	Count int
	Ref   int64 // a ban's ID
}

// visible reports whether a user with this scope may hear about the event:
// they can see the host's org, or for a ban, operate one it touched.
func (e Event) visible(sc store.Scope) bool {
	if e.Kind == KindBan {
		return sc.Admin || slices.ContainsFunc(e.Orgs, sc.CanOperate)
	}
	return sc.CanView(e.Host.OrgID)
}

// Notifier turns events into notifications.
type Notifier struct {
	Store *store.Store
	Log   *slog.Logger
	Now   func() time.Time
	// Sender delivers messages; nil until Start, which makes one with the
	// hub's VAPID key unless a test set Deliver.
	Sender *Sender
	// Deliver replaces Sender (tests).
	Deliver func(ctx context.Context, t Target, m Message) error
	// HTTP is the client for push services (NewClient).
	HTTP *http.Client
	// Subject is the VAPID contact (the hub's https URL).
	Subject string
	// Version is the hub's; collectors are "behind" only on a release.
	Version string
	// SessionIdle is ui.session_idle: a normal session idle longer than
	// this is signed out, so its subscriptions get nothing.
	SessionIdle time.Duration
	// Name is the hub's display name, for the generic "needs attention".
	Name func(ctx context.Context) string
	// Every is how often events are looked for (default 30s); Window is
	// how long repeats collapse into one notification (default 10 minutes).
	Every, Window time.Duration
	// Retry is how sends back off (default 3 tries, from 2s).
	Retry Retry

	keyMu sync.Mutex
	vapid *VAPID

	jobs chan job

	// Owned by the Run goroutine.
	seen    seen
	windows map[string]*window
}

// Retry is how a send is retried after a push service's 429 or 5xx, or a
// network error. Retry-After is honored up to Max.
type Retry struct {
	Attempts  int
	Base, Max time.Duration
}

type job struct {
	user   int64
	subs   []store.PushSubscription
	notice Notice
	detail string
}

// seen is what the last tick saw, so the next one reports only what's new.
type seen struct {
	ok      bool
	anomaly int64             // newest anomaly ID
	ban     int64             // newest proposed ban ID
	kev     map[int64]int     // host ID -> open known-exploited findings
	news    map[[2]int64]bool // (item, host) confirmed matches
}

// window is one user's recent notification with a tag: repeats inside it
// wait, and go as one with the total count when it ends.
type window struct {
	user    int64
	start   time.Time
	total   int
	pending bool
	notice  Notice
	subs    []store.PushSubscription
	detail  string
}

// queueSize bounds the send queue; a full queue drops (and logs) a notice
// rather than hold up the tick.
const queueSize = 512

// maxHostsNamed is how many hosts of one kind in one tick get their own
// notification; more become one "on 12 hosts".
const maxHostsNamed = 3

func (n *Notifier) defaults() {
	if n.Every <= 0 {
		n.Every = 30 * time.Second
	}
	if n.Window <= 0 {
		n.Window = 10 * time.Minute
	}
	if n.Retry.Attempts <= 0 {
		n.Retry = Retry{Attempts: 3, Base: 2 * time.Second, Max: time.Minute}
	}
	if n.Now == nil {
		n.Now = time.Now
	}
	if n.Log == nil {
		n.Log = slog.New(slog.DiscardHandler)
	}
	if n.jobs == nil {
		n.jobs = make(chan job, queueSize)
	}
	if n.windows == nil {
		n.windows = map[string]*window{}
	}
}

// Key returns the hub's VAPID key, making and storing it on first use.
func (n *Notifier) Key(ctx context.Context) (*VAPID, error) {
	n.keyMu.Lock()
	defer n.keyMu.Unlock()
	if n.vapid != nil {
		return n.vapid, nil
	}
	raw, err := n.Store.PushVAPIDKey(ctx, NewVAPIDKey, time.Now())
	if err != nil {
		return nil, err
	}
	v, err := ParseVAPID(raw)
	if err != nil {
		return nil, err
	}
	n.vapid = v
	return v, nil
}

// PublicKey is the VAPID public key browsers subscribe with.
func (n *Notifier) PublicKey(ctx context.Context) (string, error) {
	v, err := n.Key(ctx)
	if err != nil {
		return "", err
	}
	return v.PublicKey(), nil
}

// Start looks for events every n.Every, and sends, until ctx ends. Set the
// fields first; don't change them after.
func (n *Notifier) Start(ctx context.Context) {
	n.defaults()
	go n.worker(ctx)
	go n.run(ctx)
}

func (n *Notifier) run(ctx context.Context) {
	t := time.NewTicker(n.Every)
	defer t.Stop()
	if err := n.Tick(ctx); err != nil { // the first tick only learns what's there
		n.Log.Warn("push notifications: first look failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := n.Tick(ctx); err != nil {
				n.Log.Warn("push notifications failed", "err", err)
			}
		}
	}
}

// Test queues a test notification to every device of a user's. It returns
// how many devices it's for.
func (n *Notifier) Test(ctx context.Context, userID int64) (int, error) {
	if n.jobs == nil {
		return 0, errors.New("notifications aren't running")
	}
	subs, err := n.Store.UserPushSubscriptions(ctx, userID)
	if err != nil || len(subs) == 0 {
		return 0, err
	}
	if !n.enqueue(job{user: userID, subs: subs, notice: Notice{Kind: kindTest}}) {
		return 0, errors.New("the send queue is full; try again in a minute")
	}
	return len(subs), nil
}

// Tick looks for new events and sends, holds or digests them for each
// user, then sends what's due: collapsed repeats, notices held for quiet
// hours that have ended, and daily digests.
func (n *Notifier) Tick(ctx context.Context) error {
	n.defaults()
	now := n.Now()
	events, err := n.poll(ctx)
	if err != nil {
		return err
	}
	recips, err := n.Store.PushRecipients(ctx, now, n.SessionIdle)
	if err != nil || len(recips) == 0 {
		return err
	}
	var errs []error
	for _, r := range recips {
		sc, err := n.Store.ScopeFor(ctx, r.UserID)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var mine []Event
		for _, e := range events {
			if e.visible(sc) {
				mine = append(mine, e)
			}
		}
		for _, nt := range group(mine) {
			errs = append(errs, n.route(ctx, r, nt, now))
		}
	}
	n.flushWindows(now)
	errs = append(errs, n.releaseHeld(ctx, recips, now), n.digests(ctx, recips, now))
	return errors.Join(errs...)
}

// route applies a user's settings to one notice.
func (n *Notifier) route(ctx context.Context, r store.PushRecipient, nt Notice, now time.Time) error {
	switch d := Decide(r.Settings, nt.Kind, now); d {
	case Send:
		n.collapse(r, nt, now)
	case Hold, ToDigest:
		return n.Store.HoldPush(ctx, r.UserID, d == ToDigest, store.PushHeld{Kind: nt.Kind,
			OrgSlug: nt.OrgSlug, Host: nt.Host, Hosts: nt.Hosts, Count: nt.Count, Ref: nt.Ref, At: now})
	}
	return nil
}

// collapse sends a notice now, unless one with its tag went to this user
// within the window: then it's counted, and the total goes when the
// window ends (replacing the first on the device, as they share a tag).
func (n *Notifier) collapse(r store.PushRecipient, nt Notice, now time.Time) {
	key := fmt.Sprintf("%d|%s", r.UserID, nt.Tag())
	if w := n.windows[key]; w != nil && now.Sub(w.start) < n.Window {
		w.total += max(nt.Count, 1)
		w.pending, w.notice, w.subs, w.detail = true, nt, r.Subs, r.Settings.Detail
		return
	}
	n.windows[key] = &window{user: r.UserID, start: now, total: max(nt.Count, 1)}
	n.enqueue(job{user: r.UserID, subs: r.Subs, notice: nt, detail: r.Settings.Detail})
}

// flushWindows sends the totals of windows that ended with repeats, and
// forgets quiet ones.
func (n *Notifier) flushWindows(now time.Time) {
	for key, w := range n.windows {
		if now.Sub(w.start) < n.Window {
			continue
		}
		if !w.pending {
			delete(n.windows, key)
			continue
		}
		nt := w.notice
		nt.Count = w.total
		n.enqueue(job{user: w.user, subs: w.subs, notice: nt, detail: w.detail})
		w.start, w.pending = now, false
	}
}

// releaseHeld sends what waited for quiet hours, for users whose quiet
// hours are over: the notice itself if there's one, else a summary.
func (n *Notifier) releaseHeld(ctx context.Context, recips []store.PushRecipient, now time.Time) error {
	waiting, err := n.Store.PushHeldUsers(ctx, false)
	if err != nil || len(waiting) == 0 {
		return err
	}
	var errs []error
	for _, r := range recips {
		if !waiting[r.UserID] || InQuiet(r.Settings, now) {
			continue
		}
		held, err := n.Store.TakePushHeld(ctx, r.UserID, false)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if nt, ok := heldNotice(held); ok {
			n.enqueue(job{user: r.UserID, subs: r.Subs, notice: nt, detail: r.Settings.Detail})
		}
	}
	return errors.Join(errs...)
}

// heldNotice is one notice for what was held: itself, or a summary.
func heldNotice(held []store.PushHeld) (Notice, bool) {
	switch len(held) {
	case 0:
		return Notice{}, false
	case 1:
		h := held[0]
		return Notice{Kind: h.Kind, OrgSlug: h.OrgSlug, Host: h.Host, Hosts: h.Hosts, Count: h.Count, Ref: h.Ref}, true
	}
	return Notice{Kind: kindHeld, Parts: tally(held)}, true
}

// tally counts held notices by kind, in the settings page's order.
func tally(held []store.PushHeld) []Part {
	by := map[string]int{}
	for _, h := range held {
		by[h.Kind] += max(h.Count, 1)
	}
	var out []Part
	for _, k := range Kinds {
		if by[k] > 0 {
			out = append(out, Part{What: k, N: by[k]})
		}
	}
	return out
}

// digests sends each user's daily digest when it's due: what they chose to
// get as a digest, and the fleet's counts in their scope. An empty digest
// isn't sent, but the day is still marked done.
func (n *Notifier) digests(ctx context.Context, recips []store.PushRecipient, now time.Time) error {
	var facts []fleetFact
	var factsErr error
	loaded := false
	var errs []error
	for _, r := range recips {
		due, day := DigestDue(r.Settings, now)
		if !due {
			continue
		}
		held, err := n.Store.TakePushHeld(ctx, r.UserID, true)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ps := tally(held)
		if ModeOf(r.Settings, KindFleet) == Digest {
			if !loaded {
				facts, factsErr = n.fleetFacts(ctx, now)
				loaded = true
			}
			if factsErr != nil {
				errs = append(errs, factsErr)
			} else {
				sc, err := n.Store.ScopeFor(ctx, r.UserID)
				if err != nil {
					errs = append(errs, err)
					continue
				}
				ps = append(ps, fleetParts(facts, sc)...)
			}
		}
		if len(ps) > 0 {
			n.enqueue(job{user: r.UserID, subs: r.Subs, notice: Notice{Kind: kindDigest, Parts: ps}, detail: r.Settings.Detail})
		}
		errs = append(errs, n.Store.SetPushDigestDay(ctx, r.UserID, day))
	}
	return errors.Join(errs...)
}

// fleetFact is what the digest counts about one host.
type fleetFact struct {
	org                   int64
	security, eol, behind bool
}

// fleetFacts reads every host's digest facts: pending security updates,
// software within 90 days of its end of life, and a collector that
// upgrading would change (only on a release build, as the host list shows).
func (n *Notifier) fleetFacts(ctx context.Context, now time.Time) ([]fleetFact, error) {
	states, err := n.Store.PushHostStates(ctx)
	if err != nil {
		return nil, err
	}
	rep, err := report.Build(ctx, n.Store, report.Filter{Scope: store.AllScope, CountsOnly: true}, now)
	if err != nil {
		return nil, err
	}
	soon := map[string]bool{}
	for _, h := range rep.Hosts {
		soon[h.Org+"/"+h.Name] = eolSoon(h)
	}
	release := releaseTag(n.Version)
	out := make([]fleetFact, 0, len(states))
	for _, h := range states {
		out = append(out, fleetFact{org: h.OrgID, security: h.PendingSecurity > 0, eol: soon[h.OrgSlug+"/"+h.Name],
			behind: release && h.CollectorVersion != "" && updates.CollectorBehind(h.CollectorVersion)})
	}
	return out, nil
}

// eolSoon: the host's OS, a runtime or a site's PHP or framework reaches
// its end of life within 90 days (web's lifeState "soon").
func eolSoon(h report.Host) bool {
	soon := func(l *report.Lifecycle) bool {
		return l != nil && l.Known && !l.EOL && l.EOLDate != nil && l.DaysLeft <= 90
	}
	if soon(h.OSLife) {
		return true
	}
	for _, rt := range h.Runtimes {
		if soon(rt.Life) {
			return true
		}
	}
	for _, s := range h.Sites {
		if soon(s.PHPLife) || soon(s.FrameworkLife) {
			return true
		}
	}
	return false
}

// releaseTag matches a release version ("v0.5.0").
func releaseTag(v string) bool {
	var a, b, c int
	var rest string
	k, _ := fmt.Sscanf(v+" x", "v%d.%d.%d %s", &a, &b, &c, &rest)
	return k == 4 && rest == "x"
}

func fleetParts(facts []fleetFact, sc store.Scope) []Part {
	var sec, eol, behind int
	for _, f := range facts {
		if !sc.CanView(f.org) {
			continue
		}
		sec += b2i(f.security)
		eol += b2i(f.eol)
		behind += b2i(f.behind)
	}
	var out []Part
	for _, p := range []Part{{"security", sec}, {"eol", eol}, {"behind", behind}} {
		if p.N > 0 {
			out = append(out, p)
		}
	}
	return out
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// group turns one user's events from one tick into notices: one per host
// and kind (counts added up), or one for the kind when it's on more than
// maxHostsNamed hosts; one per ban, or one for several.
func group(events []Event) []Notice {
	var out []Notice
	for _, kind := range Kinds {
		var bans []Event
		type hk struct{ org, host string }
		counts := map[hk]int{}
		var order []hk
		total := 0
		for _, e := range events {
			if e.Kind != kind {
				continue
			}
			if kind == KindBan {
				bans = append(bans, e)
				continue
			}
			k := hk{e.Host.OrgSlug, e.Host.Name}
			if _, ok := counts[k]; !ok {
				order = append(order, k)
			}
			counts[k] += max(e.Count, 1)
			total += max(e.Count, 1)
		}
		switch {
		case len(bans) == 1:
			out = append(out, Notice{Kind: KindBan, Count: 1, Ref: bans[0].Ref})
		case len(bans) > 1:
			out = append(out, Notice{Kind: KindBan, Count: len(bans)})
		case len(order) > maxHostsNamed:
			out = append(out, Notice{Kind: kind, Hosts: len(order), Count: total})
		default:
			for _, k := range order {
				out = append(out, Notice{Kind: kind, OrgSlug: k.org, Host: k.host, Count: counts[k]})
			}
		}
	}
	return out
}

// anomalyKind sorts a new anomaly: silence and unknown-address privilege
// have kinds of their own; otherwise it's an anomaly notification when a
// chat alert would be sent for it (notify.AlertRule), else nothing.
func anomalyKind(rule, severity string) string {
	switch rule {
	case "silence", "silent_online":
		return KindSilent
	case "privilege_unknown_source":
		return KindPrivilege
	}
	if notify.AlertRule(rule, severity) {
		return KindAnomaly
	}
	return ""
}

// poll returns what's new since the last poll. The first poll only learns
// what's there: nothing open when the hub starts is sent again.
func (n *Notifier) poll(ctx context.Context) ([]Event, error) {
	anoms, err := n.Store.OpenAnomalies(ctx, store.AllScope)
	if err != nil {
		return nil, err
	}
	proposed, err := n.Store.Bans(ctx, store.BanQuery{Statuses: []string{store.BanProposed}, Limit: 1000})
	if err != nil {
		return nil, err
	}
	kev, kevHosts, err := n.Store.HostKEVCounts(ctx)
	if err != nil {
		return nil, err
	}
	matches, err := n.Store.NewsMatches(ctx)
	if err != nil {
		return nil, err
	}
	news := make(map[[2]int64]bool, len(matches))
	for _, m := range matches {
		news[[2]int64{m.ItemID, m.Host.ID}] = true
	}
	prev := n.seen
	next := seen{ok: true, anomaly: prev.anomaly, ban: prev.ban, kev: kev, news: news}
	var out []Event
	for _, a := range anoms {
		next.anomaly = max(next.anomaly, a.ID)
		if !prev.ok || a.ID <= prev.anomaly {
			continue
		}
		if kind := anomalyKind(a.Rule, a.Severity); kind != "" {
			out = append(out, Event{Kind: kind, Host: store.PushHost{ID: a.Host.ID, OrgID: a.Host.OrgID, OrgSlug: a.Host.OrgSlug, Name: a.Host.Name}, Count: 1})
		}
	}
	for _, b := range proposed {
		next.ban = max(next.ban, b.ID)
		if prev.ok && b.ID > prev.ban {
			out = append(out, Event{Kind: KindBan, Orgs: b.Orgs, Count: 1, Ref: b.ID})
		}
	}
	if prev.ok {
		for id, c := range kev {
			if d := c - prev.kev[id]; d > 0 {
				out = append(out, Event{Kind: KindKEV, Host: kevHosts[id], Count: d})
			}
		}
		for _, m := range matches {
			if !prev.news[[2]int64{m.ItemID, m.Host.ID}] {
				out = append(out, Event{Kind: KindNews, Host: m.Host, Count: 1})
			}
		}
	}
	n.seen = next
	slices.SortStableFunc(out, func(a, b Event) int {
		return strings.Compare(a.Host.OrgSlug+"/"+a.Host.Name, b.Host.OrgSlug+"/"+b.Host.Name)
	})
	return out, nil
}

func (n *Notifier) enqueue(j job) bool {
	select {
	case n.jobs <- j:
		return true
	default:
		n.Log.Warn("push notification dropped: send queue full", "user", j.user, "kind", j.notice.Kind)
		return false
	}
}

func (n *Notifier) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case j := <-n.jobs:
			n.deliver(ctx, j)
		}
	}
}

// deliver sends one notice to each of a user's devices.
func (n *Notifier) deliver(ctx context.Context, j job) {
	name := ""
	if n.Name != nil {
		name = n.Name(ctx)
	}
	m, err := j.notice.message(name, j.detail)
	if err != nil {
		n.Log.Error("push notification", "err", err)
		return
	}
	for _, sub := range j.subs {
		n.sendOne(ctx, sub, m, j.notice.Kind)
	}
}

// sendOne sends with retries, records how it went, and deletes a
// subscription its push service says is gone.
func (n *Notifier) sendOne(ctx context.Context, sub store.PushSubscription, m Message, kind string) {
	t := Target{Endpoint: sub.Endpoint, P256DH: sub.P256DH, Auth: sub.Auth}
	var err error
	wait := n.Retry.Base
	for try := 1; try <= n.Retry.Attempts; try++ {
		err = n.send(ctx, t, m)
		if err == nil || errors.Is(err, ErrGone) || !temporary(err) || try == n.Retry.Attempts {
			break
		}
		d := wait
		var se *StatusError
		if errors.As(err, &se) && se.RetryAfter > 0 {
			d = se.RetryAfter
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(min(d, n.Retry.Max)):
		}
		wait *= 4
	}
	now := n.Now()
	switch {
	case err == nil:
		err = n.Store.MarkPushResult(ctx, sub.ID, now, "")
	case errors.Is(err, ErrGone):
		n.Log.Info("push subscription gone; removed", "user", sub.UserID, "device", sub.Label)
		err = n.Store.DropPushSubscription(ctx, sub.ID)
	default:
		n.Log.Warn("push notification failed", "user", sub.UserID, "device", sub.Label, "kind", kind, "err", errText(err))
		err = n.Store.MarkPushResult(ctx, sub.ID, now, errText(err))
	}
	if err != nil {
		n.Log.Warn("push notification: couldn't record the result", "err", err)
	}
}

func (n *Notifier) send(ctx context.Context, t Target, m Message) error {
	if n.Deliver != nil {
		return n.Deliver(ctx, t, m)
	}
	if n.Sender == nil {
		v, err := n.Key(ctx)
		if err != nil {
			return err
		}
		n.Sender = &Sender{HTTP: n.HTTP, VAPID: v, Subject: n.Subject, Now: n.Now}
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return n.Sender.Send(ctx, t, m)
}

// temporary: worth trying again (a 429, a 5xx, or no answer at all).
func temporary(err error) bool {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Temporary()
	}
	return !errors.Is(err, ErrEndpoint)
}

// errText is an error without the endpoint URL, which is a credential of
// sorts (anyone holding it can send to the device, given the keys).
func errText(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Op + ": " + ue.Err.Error()
	}
	return err.Error()
}
