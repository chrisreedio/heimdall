// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/store"
)

// "Hand off all": an AI plan step whose package update applies to several
// repositories gets one more button, opening a confirm page for all of
// them. Sending posts each repository's own hand-off, exactly as its own
// button would (the same message, rate limits and audit entry), so the
// agent opens one pull request per repository.

// handoffBatchMax is the most repositories one batch hands off.
const handoffBatchMax = 20

// handoffBatchLink is a step's "all of them" button, when it has several
// (and no more than handoffBatchMax). back is where Cancel goes.
func handoffBatchLink(links []handoffLink, back string) (handoffLink, bool) {
	if len(links) < 2 || len(links) > handoffBatchMax {
		return handoffLink{}, false
	}
	q := url.Values{}
	for _, l := range links {
		q.Add("o", l.org)
		q.Add("h", l.Host)
		q.Add("r", l.root)
	}
	q.Set("back", back)
	n := strconv.Itoa(len(links))
	return handoffLink{Site: "All " + n, URL: "/handoff/batch?" + q.Encode(),
		Title: "One confirm page for all " + n + ": the agent opens one pull request per repository"}, true
}

// aiBack is where a hand-off from this plan returns: its host page, or
// the dashboard for a brief.
func aiBack(view *aiView) string {
	if view.Host != "" {
		return hostURL(view.Org.Slug, view.Host)
	}
	return "/"
}

// handoffKeys are a hand-off's rate-limit keys: per site and agent, and
// per repository and agent (one pull request covers a repository's sites).
func handoffKeys(t handoffTarget) []string {
	keys := []string{"site\x00" + strconv.FormatInt(t.host.ID, 10) + "\x00" + t.site.Root + "\x00" + t.agent.Name}
	if k := handoff.RepoKey(t.repo.Repo()); k != "" {
		keys = append(keys, "repo\x00"+k+"\x00"+t.agent.Name)
	}
	return keys
}

type handoffBatchItem struct {
	handoffBody
	Short   string // the repository's short name, or the site's for none
	Limited bool   // handed to this agent in the last few minutes: skipped
	Result  string // after sending: "sent", "failed" or "skipped"
	t       handoffTarget
	target  handoff.Target
	msg     handoff.Message
}

type handoffBatchBody struct {
	Agents       []string
	Agent        string
	Target       string // handoff.TargetDefault or handoff.TargetEach
	Back         string
	Items        []handoffBatchItem
	Query        []handoffBatchSite // the sites, for the forms
	Notice       string
	Sent         bool
	SentN, Fails int
	Skipped      int
}

type handoffBatchSite struct{ Org, Host, Root string }

// loadHandoffBatch resolves a batch's sites (o, h and r, side by side) and
// builds each one's message with its request ID (ids, or new ones). ok is
// false (answer 404) when the request is malformed, too big, or any site
// is one the viewer couldn't hand off on its own.
func (s *server) loadHandoffBatch(ctx context.Context, v *auth.Viewer, f url.Values, ids []string) (handoffBatchBody, bool, error) {
	orgs, hs, rs := f["o"], f["h"], f["r"]
	body := handoffBatchBody{Agents: agentNames(s.cfg.Agents), Back: safeNext(f.Get("back")), Target: handoff.TargetDefault}
	if len(orgs) == 0 || len(orgs) > handoffBatchMax || len(hs) != len(orgs) || len(rs) != len(orgs) || (ids != nil && len(ids) != len(orgs)) {
		return body, false, nil
	}
	if f.Get("target") == handoff.TargetEach {
		body.Target = handoff.TargetEach
	}
	seen := map[string]bool{}
	for i := range orgs {
		t, ok, err := s.loadHandoff(ctx, v, orgs[i], hs[i], rs[i], f.Get("agent"))
		if err != nil || !ok {
			return body, false, err
		}
		body.Agent = t.agent.Name
		// One per repository (or per site without one): another site on
		// the same repository is covered by the first's pull request.
		key := handoff.RepoKey(t.repo.Repo())
		if key == "" {
			key = "site\x00" + strconv.FormatInt(t.host.ID, 10) + "\x00" + t.site.Root
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		target := handoff.Target{Mode: handoff.TargetDefault}
		if body.Target == handoff.TargetEach && len(handoff.Branches(t.sites)) > 0 {
			target = handoff.Target{Mode: handoff.TargetEach}
		}
		id := handoff.RequestID()
		if ids != nil {
			if id = ids[i]; !handoff.ValidRequestID(id) {
				return body, false, nil
			}
		}
		msg, err := s.handoffMessage(t, v, id, target)
		if err != nil {
			continue // nothing fixable there any more
		}
		item := handoffBatchItem{handoffBody: s.handoffBody(t, msg, id, target), t: t, target: target, msg: msg}
		item.Short = handoff.RepoShort(t.repo.Repo())
		if item.Short == "" {
			item.Short = item.Host + " · " + item.Root
			if item.Site != "" {
				item.Short = item.Host + " · " + item.Site
			}
		}
		item.Limited = s.handoffLimit.limited(s.now(), handoffKeys(t)...)
		body.Items = append(body.Items, item)
		body.Query = append(body.Query, handoffBatchSite{orgs[i], hs[i], rs[i]})
	}
	return body, len(body.Items) > 0, nil
}

// handoffBatchPage is the batch's confirm step: every message that will be
// posted.
func (s *server) handoffBatchPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	body, ok, err := s.loadHandoffBatch(r.Context(), v, r.URL.Query(), nil)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !ok {
		s.notFound(w, r, v)
		return
	}
	s.render(w, r, http.StatusOK, "handoffbatch", v, "Hand off to agent", "sites", body)
}

// handoffBatchSend posts each repository's hand-off the operator confirmed.
func (s *server) handoffBatchSend(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	f := r.PostForm
	if f.Get("agent") == "" {
		s.notFound(w, r, v)
		return
	}
	body, ok, err := s.loadHandoffBatch(r.Context(), v, f, f["request_id"])
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !ok {
		s.notFound(w, r, v)
		return
	}
	digests := f["digest"]
	changed := len(digests) != len(body.Items)
	for i := 0; !changed && i < len(body.Items); i++ {
		changed = digests[i] != body.Items[i].Digest
	}
	if changed {
		// Something changed since the page was shown: show it again, with
		// new request IDs, and send nothing.
		if body, ok, err = s.loadHandoffBatch(r.Context(), v, f, nil); err != nil || !ok {
			s.notFound(w, r, v)
			return
		}
		body.Notice = "The messages changed since you opened this page (new findings, sites, branches or repositories). Check them again before sending."
		s.render(w, r, http.StatusConflict, "handoffbatch", v, "Hand off to agent", "sites", body)
		return
	}
	for i := range body.Items {
		it := &body.Items[i]
		if s.handoffLimit.allow(s.now(), handoffKeys(it.t)...) >= 0 {
			it.Result = "skipped"
			body.Skipped++
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), handoffPostTimeout)
		postErr := it.t.agent.Poster.PostPayloadFile(ctx, it.msg.Payload, it.msg.FileName, it.msg.File)
		cancel()
		s.auditHandoff(r, v, it.t, it.msg, it.RequestID, it.target, postErr, len(body.Items))
		if postErr != nil {
			it.Result = "failed"
			body.Fails++
		} else {
			it.Result = "sent"
			body.SentN++
		}
	}
	body.Sent = true
	s.render(w, r, http.StatusOK, "handoffbatch", v, "Hand off to agent", "sites", body)
}

// auditHandoff logs a hand-off as handoff.send; batch is the number of
// repositories handed off together (0 for one on its own).
func (s *server) auditHandoff(r *http.Request, v *auth.Viewer, t handoffTarget, msg handoff.Message, id string, target handoff.Target, postErr error, batch int) {
	branches := target.Branches
	if target.Mode == handoff.TargetEach {
		branches = handoff.Branches(t.sites)
	}
	if branches == nil {
		branches = []string{}
	}
	detail := map[string]any{"agent": t.agent.Name, "host": t.host.Name, "site": t.site.Root, "request_id": id,
		"packages": msg.Packages, "omitted": msg.Omitted, "repo": t.repo.Repo(), "ok": postErr == nil,
		"target": target.Mode, "branches": branches, "sites": len(t.sites)}
	if batch > 0 {
		detail["batch"] = batch
	}
	if postErr != nil {
		s.log.Warn("hand-off not posted", "agent", t.agent.Name, "host", t.host.Name, "site", t.site.Root, "err", postErr)
		detail["error"] = "post failed"
	}
	if err := s.st.Audit(r.Context(), store.AuditEntry{Actor: actorOf(v), Action: "handoff.send", OrgID: t.host.OrgID,
		Target: t.host.Name, Detail: detail, IP: clientIP(r)}); err != nil {
		s.log.Error("hand-off audit failed", "err", err)
	}
}
