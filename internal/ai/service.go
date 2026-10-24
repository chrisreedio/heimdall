// SPDX-License-Identifier: AGPL-3.0-or-later

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/chrisreedio/heimdall/internal/store"
)

// Service runs analyses: on demand from the UI (in the background, so a
// slow model never holds a request open) and the scheduled fleet briefs.
type Service struct {
	Provider       Provider
	Store          *store.Store
	Log            *slog.Logger
	Now            func() time.Time
	StaleAfter     time.Duration // hosts.stale_after
	MaxInputTokens int
	Timeout        time.Duration // per run
	BriefEvery     time.Duration // 0 = no scheduled briefs
	// MinGap is the per-host (and per-org brief) rate limit; default 1m.
	MinGap time.Duration

	sem chan struct{}
}

// ScheduleActor is the audit actor for scheduled briefs.
const ScheduleActor = "hub:schedule"

func (s *Service) Deployment() string { return s.Provider.Deployment() }

func (s *Service) minGap() time.Duration {
	if s.MinGap > 0 {
		return s.MinGap
	}
	return time.Minute
}

// Stale is when a "running" row is treated as abandoned (e.g. the hub
// restarted mid-run).
func (s *Service) Stale() time.Duration { return s.Timeout + time.Minute }

// acquire limits concurrent model calls (to two, after Init).
func (s *Service) acquire() func() {
	if s.sem == nil {
		return func() {}
	}
	s.sem <- struct{}{}
	return func() { <-s.sem }
}

// Init readies the service; call it once before use.
func (s *Service) Init() { s.sem = make(chan struct{}, 2) }

// StartHost begins "explain this host" in the background. It returns
// store.ErrAIBusy or store.ErrAITooSoon when rate limited.
func (s *Service) StartHost(ctx context.Context, actor string, org store.Org, host store.IngestHost) error {
	id, err := s.Store.StartAIRun(ctx, org.ID, host.ID, store.AIHost, actor, s.Deployment(), s.Now(), s.minGap(), s.Stale())
	if err != nil {
		return err
	}
	go s.runHost(id, actor, org, host)
	return nil
}

// StartBrief begins an org's brief in the background.
func (s *Service) StartBrief(ctx context.Context, actor string, org store.Org) error {
	id, err := s.Store.StartAIRun(ctx, org.ID, 0, store.AIBrief, actor, s.Deployment(), s.Now(), s.minGap(), s.Stale())
	if err != nil {
		return err
	}
	go s.runBrief(id, actor, org)
	return nil
}

func (s *Service) runHost(id int64, actor string, org store.Org, host store.IngestHost) {
	defer s.acquire()()
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	src := Sources{Store: s.Store, Now: s.Now(), StaleAfter: s.StaleAfter}
	facts, allowed, err := src.BuildHost(ctx, org, host, s.MaxInputTokens)
	s.finish(ctx, id, actor, "ai.explain", org, host.Name, hostTask, facts, allowed, err)
}

func (s *Service) runBrief(id int64, actor string, org store.Org) {
	defer s.acquire()()
	ctx, cancel := context.WithTimeout(context.Background(), s.Timeout)
	defer cancel()
	now := s.Now()
	period := s.BriefEvery
	if period <= 0 {
		period = 24 * time.Hour
	}
	src := Sources{Store: s.Store, Now: now, StaleAfter: s.StaleAfter}
	facts, allowed, _, err := src.BuildFleet(ctx, org, now.Add(-period), s.MaxInputTokens)
	s.finish(ctx, id, actor, "ai.brief", org, org.Slug, briefTask, facts, allowed, err)
}

// finish calls the model (unless gathering the facts failed), validates
// the answer, stores the outcome and writes the audit entry. Prompts are
// never logged or stored.
func (s *Service) finish(ctx context.Context, id int64, actor, action string, org store.Org, target, task string,
	facts []byte, allowed Allowed, err error) {
	var resp *Response
	var res *Result
	if err == nil {
		resp, err = s.Provider.Complete(ctx, buildPrompt(task, facts))
	}
	if err == nil {
		res, err = Parse(resp.Text, allowed)
	}
	status, msg, model, in, out := "ok", "", "", 0, 0
	var latency time.Duration
	if resp != nil {
		model, in, out, latency = clip(resp.Model, 100), resp.InputTokens, resp.OutputTokens, resp.Latency
	}
	var result []byte
	if err != nil {
		status, msg = "error", KindOf(err).String()
		s.Log.Warn("AI analysis failed", "action", action, "org", org.Slug, "target", target, "err", err)
	} else {
		result, _ = json.Marshal(res)
		s.Log.Info("AI analysis done", "action", action, "org", org.Slug, "target", target, "deployment", s.Deployment(),
			"input_tokens", in, "output_tokens", out, "latency_ms", latency.Milliseconds())
	}
	// Record even if the run's own deadline passed.
	bg, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if ferr := s.Store.FinishAIRun(bg, id, status, model, in, out, msg, result, s.Now()); ferr != nil {
		s.Log.Error("storing AI analysis failed", "err", ferr)
	}
	detail := map[string]any{"deployment": s.Deployment(), "status": status, "input_tokens": in, "output_tokens": out,
		"latency_ms": latency.Milliseconds(), "facts_bytes": len(facts)}
	if err != nil {
		detail["error"] = KindOf(err).String()
	}
	if aerr := s.Store.Audit(bg, store.AuditEntry{Actor: actor, Action: action, OrgID: org.ID, Target: target, Detail: detail}); aerr != nil {
		s.Log.Error("audit failed", "err", aerr)
	}
}

// Run makes the scheduled briefs: shortly after start, then hourly, each
// org whose last brief is at least BriefEvery old gets a new one. Briefs
// run one after another.
func (s *Service) Run(ctx context.Context) {
	if s.BriefEvery <= 0 {
		return
	}
	t := time.NewTimer(2 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		s.briefsDue(ctx)
		t.Reset(time.Hour)
	}
}

func (s *Service) briefsDue(ctx context.Context) {
	orgs, err := s.Store.ListOrgs(ctx)
	if err != nil {
		s.Log.Warn("AI brief schedule failed", "err", err)
		return
	}
	reported, err := s.Store.HostsWithSnapshots(ctx)
	if err != nil {
		s.Log.Warn("AI brief schedule failed", "err", err)
		return
	}
	has := map[int64]bool{}
	for _, h := range reported {
		has[h.OrgID] = true
	}
	for _, o := range orgs {
		if !has[o.ID] || ctx.Err() != nil {
			continue
		}
		last, err := s.Store.LastAIBrief(ctx, o.ID)
		if err != nil {
			s.Log.Warn("AI brief schedule failed", "err", err)
			return
		}
		// A little slack, so a daily brief doesn't drift an hour a day.
		if !last.IsZero() && s.Now().Sub(last) < s.BriefEvery-30*time.Minute {
			continue
		}
		id, err := s.Store.StartAIRun(ctx, o.ID, 0, store.AIBrief, ScheduleActor, s.Deployment(), s.Now(), s.minGap(), s.Stale())
		if errors.Is(err, store.ErrAIBusy) || errors.Is(err, store.ErrAITooSoon) {
			continue
		}
		if err != nil {
			s.Log.Warn("AI brief schedule failed", "err", err)
			return
		}
		s.runBrief(id, ScheduleActor, o)
	}
}

// View is what the UI shows for a brief or a host: the last good result,
// plus the state of the latest attempt.
type View struct {
	Result       *Result
	At           time.Time // when the shown result was generated
	Deployment   string
	InputTokens  int
	OutputTokens int
	Running      bool
	Error        string // fixed text; set when the latest attempt failed
	ErrorAt      time.Time
}

// ViewOf summarizes runs (newest first).
func ViewOf(runs []store.AIRun, now time.Time, stale time.Duration) View {
	var v View
	for i, r := range runs {
		switch {
		case r.Status == "running":
			if i == 0 && now.Sub(r.CreatedAt) < stale {
				v.Running = true
			} else if i == 0 {
				v.Error, v.ErrorAt = ErrTimeout.String(), r.CreatedAt
			}
			continue
		case r.Status == "error":
			if i == 0 {
				v.Error, v.ErrorAt = r.Error, r.CreatedAt
				if v.Error == "" {
					v.Error = ErrUnknown.String()
				}
			}
			continue
		}
		if res, ok := Decode(r.Result); ok {
			v.Result, v.At, v.Deployment, v.InputTokens, v.OutputTokens = res, r.CreatedAt, r.Deployment, r.InputTokens, r.OutputTokens
			return v
		}
	}
	return v
}
