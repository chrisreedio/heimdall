// SPDX-License-Identifier: AGPL-3.0-or-later

package bans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/config"
	"github.com/chrisreedio/heimdall/internal/logins"
	"github.com/chrisreedio/heimdall/internal/notify"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Engine is command and control: it scores the candidates and, by mode,
// records them (shadow), proposes them, or bans them within the caps
// (auto). It never writes to Cloudflare itself; the Enforcer does.
type Engine struct {
	Store  *store.Store
	Ranker *logins.Ranker
	Cfg    config.Bans
	Now    func() time.Time
	Log    *slog.Logger
	// Notify sends a card to the hub's destinations (nil: none).
	Notify func(context.Context, notify.Alert) error
	// BaseURL is the UI's, for the card's link to /bans.
	BaseURL string
	// Kick asks the Enforcer to run now (nil: wait for its schedule).
	Kick func()
}

func (e *Engine) now() time.Time {
	if e.Now == nil {
		return time.Now()
	}
	return e.Now()
}

// Offense lookback: earlier bans this recent double the next one.
const offenseLookback = 365 * 24 * time.Hour

// rejectQuiet is how long a rejected target isn't proposed again.
const rejectQuiet = 7 * 24 * time.Hour

// maxCards is how many proposals one run sends a card for each; beyond
// that, one summary card.
const maxCards = 5

// Result is what one run did.
type Result struct {
	Candidates int // scored
	Over       int // at or over the threshold, not skipped
	Shadow     int // new shadow records
	Proposed   int
	Auto       int // banned without approval
	Lapsed     int
}

// Name and Every make the engine a syncer (ipinfo.Syncer's shape).
func (e *Engine) Name() string         { return "bans:engine" }
func (e *Engine) Every() time.Duration { return e.Cfg.Every.Duration }

// Sync runs once.
func (e *Engine) Sync(ctx context.Context) error {
	_, err := e.Run(ctx)
	return err
}

// Run scores the candidates and acts on them by mode.
func (e *Engine) Run(ctx context.Context) (Result, error) {
	var res Result
	if !e.Cfg.On() {
		return res, nil
	}
	now := e.now()
	if e.Cfg.Writes() {
		n, err := e.Store.LapseProposals(ctx, now.Add(-e.Cfg.ProposalTTL.Duration), now)
		if err != nil {
			return res, err
		}
		res.Lapsed = n
	}
	cands, err := e.Candidates(ctx)
	if err != nil {
		return res, err
	}
	res.Candidates = len(cands)
	var cards []notify.Alert
	var errs []error
	for _, c := range cands {
		if !c.Over || c.Skip != "" {
			continue
		}
		res.Over++
		b, ok, err := e.ban(ctx, c, now)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if !ok {
			continue
		}
		switch b.Status {
		case store.BanShadow:
			res.Shadow++
		case store.BanProposed:
			res.Proposed++
			cards = append(cards, e.Card(b, c))
		case store.BanPending:
			res.Auto++
			cards = append(cards, e.Card(b, c))
		}
	}
	if res.Auto > 0 && e.Kick != nil {
		e.Kick()
	}
	if err := e.sendCards(ctx, cards); err != nil {
		errs = append(errs, err)
	}
	if e.Cfg.Mode == config.BansShadow && e.Cfg.ShadowDigest {
		if err := e.shadowDigest(ctx, now); err != nil {
			errs = append(errs, err)
		}
	}
	if e.Log != nil && res.Over > 0 {
		e.Log.Info("bans scored", "mode", e.Cfg.Mode, "candidates", res.Candidates, "over", res.Over,
			"shadow", res.Shadow, "proposed", res.Proposed, "auto", res.Auto)
	}
	return res, errors.Join(errs...)
}

// ban records one candidate by mode. ok is false when nothing new was
// recorded (already open, rejected lately, or a refreshed shadow row).
func (e *Engine) ban(ctx context.Context, c Candidate, now time.Time) (store.Ban, bool, error) {
	target := TargetString(c.Target)
	if open, found, err := e.Store.OpenBan(ctx, target); err != nil || found {
		return open, false, err
	}
	earlier, rejected, err := e.Store.BanOffenses(ctx, target, now.Add(-offenseLookback))
	if err != nil {
		return store.Ban{}, false, err
	}
	if !rejected.IsZero() && now.Sub(rejected) < rejectQuiet {
		return store.Ban{}, false, nil
	}
	breakdown, _ := json.Marshal(c.Factors)
	evidence, _ := json.Marshal(c.Evidence)
	b := store.Ban{Target: target, Kind: c.Kind, Action: c.Action, Mode: e.Cfg.Mode, Score: c.Score,
		Breakdown: breakdown, Evidence: evidence, Orgs: c.Orgs, Offense: earlier + 1, Duration: BanDuration(e.Cfg, earlier)}
	switch e.Cfg.Mode {
	case config.BansShadow:
		b.Status, b.ExpiresAt = store.BanShadow, now.Add(b.Duration)
		id, added, err := e.Store.RecordShadow(ctx, b, now)
		b.ID = id
		return b, added, err
	case config.BansAuto:
		b.Status, b.DecidedBy, b.DecidedAt = store.BanPending, "auto", now
		if why, err := e.overCap(ctx, now); err != nil {
			return b, false, err
		} else if why != "" {
			b.Status, b.DecidedBy, b.DecidedAt = store.BanProposed, "", time.Time{} // over the caps: a person decides
		}
	default:
		b.Status = store.BanProposed
	}
	id, err := e.Store.AddBan(ctx, b, "heimdall", now)
	if errors.Is(err, store.ErrExists) {
		return b, false, nil
	}
	b.ID = id
	return b, err == nil, err
}

// overCap says which cap a new ban would break ("" none). Pending bans
// count as active: they're about to be.
func (e *Engine) overCap(ctx context.Context, now time.Time) (string, error) {
	c, err := e.Store.CountBans(ctx, now.Add(-time.Hour))
	if err != nil {
		return "", err
	}
	pending, err := e.Store.Bans(ctx, store.BanQuery{Statuses: []string{store.BanPending}, Limit: 100000})
	if err != nil {
		return "", err
	}
	switch {
	case c.StartedSince+len(pending) >= e.Cfg.MaxPerHour:
		return fmt.Sprintf("at most %d new bans an hour", e.Cfg.MaxPerHour), nil
	case c.Active+len(pending) >= e.Cfg.MaxActive:
		return fmt.Sprintf("at most %d active bans", e.Cfg.MaxActive), nil
	}
	return "", nil
}

// BanURL is a ban's place on the hub's ban page.
func (e *Engine) BanURL(id int64) string {
	return strings.TrimSuffix(e.BaseURL, "/") + fmt.Sprintf("/bans#ban-%d", id)
}

// Card is the notification for a proposed or automatic ban.
func (e *Engine) Card(b store.Ban, c Candidate) notify.Alert {
	ev := c.Evidence
	ab := &notify.AlertBan{ID: b.ID, Target: b.Target, Kind: b.Kind, Action: b.Action, Reason: ev.Reason,
		Days: int(b.Duration.Hours() / 24), Offense: b.Offense, Score: b.Score, Auto: b.Status == store.BanPending,
		Prefix: ev.Prefix, Network: ev.Network, Failures: ev.Failures, Usernames: ev.Usernames, Members: len(ev.Members),
		First: ev.First, Last: ev.Last, Succeeded: len(ev.Succeeded) > 0, Known: ev.Known}
	for _, h := range ev.Hosts {
		ab.Hosts = append(ab.Hosts, h.Org+"/"+h.Name)
	}
	return notify.Alert{Kind: notify.KindBan, GeneratedAt: e.now().UTC(), Hosts: ab.Hosts, Count: 1,
		URL: e.BanURL(b.ID), Ban: ab}
}

func (e *Engine) sendCards(ctx context.Context, cards []notify.Alert) error {
	if e.Notify == nil || len(cards) == 0 {
		return nil
	}
	if len(cards) > maxCards {
		// A wave: the last card says how many more wait on the page.
		cards[maxCards-1].Ban.More = len(cards) - maxCards
		cards = cards[:maxCards]
	}
	var errs []error
	for _, c := range cards {
		errs = append(errs, e.Notify(ctx, c))
	}
	return errors.Join(errs...)
}

// shadowDigestKey remembers when the shadow digest last went out.
const shadowDigestKey = "shadow_digest_at"

// shadowDigest sends, once a day, what shadow mode would have banned in
// the last 24 hours. Nothing to report sends nothing.
func (e *Engine) shadowDigest(ctx context.Context, now time.Time) error {
	if e.Notify == nil {
		return nil
	}
	var last time.Time
	if _, err := e.Store.BanStateGet(ctx, shadowDigestKey, &last); err != nil {
		return err
	}
	if !last.IsZero() && now.Sub(last) < 24*time.Hour {
		return nil
	}
	if last.IsZero() {
		last = now.Add(-24 * time.Hour)
	}
	bs, err := e.Store.Bans(ctx, store.BanQuery{Statuses: []string{store.BanShadow}, Since: last})
	if err != nil {
		return err
	}
	if err := e.Store.BanStateSet(ctx, shadowDigestKey, now.UTC(), now); err != nil {
		return err
	}
	if len(bs) == 0 {
		return nil
	}
	ab := &notify.AlertBan{Would: len(bs)}
	for _, b := range bs {
		ab.Top = append(ab.Top, fmt.Sprintf("%s (%s, score %.1f)", b.Target, b.Action, b.Score))
	}
	return e.Notify(ctx, notify.Alert{Kind: notify.KindBanShadow, GeneratedAt: now.UTC(), Count: len(bs),
		URL: strings.TrimSuffix(e.BaseURL, "/") + "/bans", Ban: ab})
}
