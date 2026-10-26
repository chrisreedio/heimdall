// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"cmp"
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/handoff"
	"github.com/realmwatch/heimdall/internal/report"
	"github.com/realmwatch/heimdall/internal/store"
)

// "Hand off to agent": an operator asks a coding agent (a Discord bot,
// [[agents]] in the config) to open a pull request that updates a site's
// vulnerable Composer and npm packages. The confirm page shows exactly the
// message that will be posted; sending is a POST with the CSRF token,
// rate-limited per site and agent, and audit-logged as handoff.send.

// handoffEvery is how often one site can be handed to one agent.
const handoffEvery = 5 * time.Minute

// handoffPostTimeout bounds the post to Discord, retry included.
const handoffPostTimeout = 20 * time.Second

type handoffLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// allow records an attempt for key unless one was made within handoffEvery.
func (l *handoffLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	if t, ok := l.last[key]; ok && now.Sub(t) < handoffEvery {
		return false
	}
	for k, t := range l.last {
		if now.Sub(t) >= handoffEvery {
			delete(l.last, k)
		}
	}
	l.last[key] = now
	return true
}

// handoffNotices are the fixed messages the site page can show after one.
var handoffNotices = map[string]string{
	"sent":   "Handed off. The agent was asked to open a pull request.",
	"failed": "Couldn't post the hand-off to Discord. The hub log has the details.",
}

// repoNotices are the fixed messages after saving a site's repository.
var repoNotices = map[string]string{
	"saved":   "Repository saved.",
	"cleared": "Repository cleared.",
	"invalid": "That isn't a repository URL Heimdall accepts: https://host/owner/repo, ssh://git@host/owner/repo or git@host:owner/repo.",
}

// canHandoff: agents are configured and the viewer may operate in the org.
func (s *server) canHandoff(v *auth.Viewer, orgID int64) bool {
	return len(s.cfg.Agents) > 0 && v.Scope.CanOperate(orgID)
}

func (s *server) agent(name string) (handoff.Agent, bool) {
	for _, a := range s.cfg.Agents {
		if a.Name == name {
			return a, true
		}
	}
	return handoff.Agent{}, false
}

func agentNames(agents []handoff.Agent) []string {
	out := make([]string, len(agents))
	for i, a := range agents {
		out[i] = a.Name
	}
	return out
}

// handoffFindings are a site's fixable findings an agent can act on: its
// Composer packages, and npm packages from allowlisted package-lock.json
// files inside the site.
func handoffFindings(h report.Host, root string) []handoff.Finding {
	var out []handoff.Finding
	for _, f := range h.Findings {
		if f.Fixed == "" || f.Site == "" {
			continue
		}
		hf := handoff.Finding{Package: f.Package, Installed: f.Version, Fixed: f.Fixed, Advisory: f.Advisory,
			Severity: f.Severity, CVEs: f.CVEs, KEV: f.KEV, EPSS: f.EPSS}
		switch {
		case f.Site == root:
			hf.Ecosystem = "composer"
		case strings.HasPrefix(f.Site, strings.TrimSuffix(root, "/")+"/") && strings.HasSuffix(f.Site, "/package-lock.json"):
			hf.Ecosystem, hf.Lockfile = "npm", f.Site
		default:
			continue
		}
		out = append(out, hf)
	}
	return out
}

// handoffURL is the confirm page for a site (and optionally an agent).
func handoffURL(org, host, root, agent string) string {
	q := url.Values{"root": {root}}
	if agent != "" {
		q.Set("agent", agent)
	}
	return "/hosts/" + url.PathEscape(org) + "/" + url.PathEscape(host) + "/handoff?" + q.Encode()
}

func siteName(site report.Site) string {
	if len(site.ServerNames) > 0 && site.ServerNames[0] != "_" {
		return site.ServerNames[0]
	}
	return ""
}

// handoffLink is a "Hand off to agent" button for one site.
type handoffLink struct {
	Site string // the site's name, when a step covers several sites
	URL  string
}

// aiHandoffs adds hand-off buttons to the AI plan's Composer steps: one
// per site of the host that has a fixable finding in a package the step's
// (allowlisted) composer update command names. OS patching and reboots
// aren't pull requests, so they never get one.
func aiHandoffs(view *aiView, org, host string, sites []siteSection, h report.Host) {
	if view == nil || view.Result == nil {
		return
	}
	for i, a := range view.Result.Actions {
		rest, ok := strings.CutPrefix(a.Command, "composer update ")
		if !ok {
			continue
		}
		pkgs := strings.Fields(strings.TrimSuffix(rest, " --with-dependencies"))
		var links, named []handoffLink
		text := strings.ToLower(a.Title + " " + a.Why)
		for _, site := range sites {
			hit := slices.ContainsFunc(handoffFindings(h, site.Root), func(f handoff.Finding) bool {
				return f.Ecosystem == "composer" && slices.Contains(pkgs, f.Package)
			})
			if !hit {
				continue
			}
			l := handoffLink{Site: cmp.Or(siteName(site.Site), site.Root), URL: handoffURL(org, host, site.Root, "")}
			links = append(links, l)
			// A step about one site names it (its domain or root): offer only that one.
			if n := strings.ToLower(siteName(site.Site)); (n != "" && strings.Contains(text, n)) || strings.Contains(text, strings.ToLower(site.Root)) {
				named = append(named, l)
			}
		}
		if len(named) > 0 {
			links = named
		}
		if len(links) == 1 {
			links[0].Site = ""
		}
		if len(links) > 0 {
			if view.Handoffs == nil {
				view.Handoffs = map[int][]handoffLink{}
			}
			view.Handoffs[i] = links
		}
	}
}

type handoffBody struct {
	Org, Host, Root, Site string
	SiteURL               string
	Agents                []string
	Agent                 string
	Repo, RepoWeb         string
	RepoManual            bool
	Content               string
	Digest, RequestID     string
	Packages, Omitted     int
	File, FileName        string // the attached JSON, shown for review
	Notice                string
	Sent                  bool
}

// handoffTarget is what both the confirm page and the send need.
type handoffTarget struct {
	host  store.IngestHost
	site  report.Site
	h     report.Host
	repo  store.SiteRepo
	agent handoff.Agent
}

// loadHandoff resolves and checks a hand-off request. ok is false when
// the caller should answer 404 (a missing or out-of-scope host or site,
// no agents, an unknown agent, or a viewer below operator).
func (s *server) loadHandoff(ctx context.Context, v *auth.Viewer, org, hostName, root, agentName string) (handoffTarget, bool, error) {
	var t handoffTarget
	host, err := s.st.HostByName(ctx, org, hostName)
	if err != nil {
		var verr *store.ValidationError
		if errors.Is(err, store.ErrNotFound) || errors.As(err, &verr) {
			return t, false, nil
		}
		return t, false, err
	}
	if !v.Scope.CanView(host.OrgID) || !s.canHandoff(v, host.OrgID) {
		return t, false, nil
	}
	t.host = host
	if agentName == "" {
		agentName = s.cfg.Agents[0].Name
	}
	if t.agent, err = s.agentOK(agentName); err != nil {
		return t, false, nil
	}
	rep, err := report.Build(ctx, s.st, report.Filter{Org: host.OrgSlug, Host: host.Name, Scope: v.Scope}, s.now())
	if err != nil {
		return t, false, err
	}
	found := false
	for _, rh := range rep.Hosts {
		if rh.Name == host.Name {
			t.h = rh
			for _, site := range rh.Sites {
				if site.Root == root {
					t.site, found = site, true
				}
			}
		}
	}
	if !found {
		return t, false, nil
	}
	repos, err := s.st.SiteRepos(ctx, host.ID)
	if err != nil {
		return t, false, err
	}
	t.repo = repos[root]
	return t, true, nil
}

func (s *server) agentOK(name string) (handoff.Agent, error) {
	a, ok := s.agent(name)
	if !ok {
		return a, store.ErrNotFound
	}
	return a, nil
}

func (s *server) handoffMessage(t handoffTarget, v *auth.Viewer, requestID string) (handoff.Message, error) {
	return handoff.Build(t.agent, handoff.Request{
		Version: s.cfg.Version, Org: t.host.OrgSlug, Host: t.host.Name, Site: siteName(t.site),
		SitePath: t.site.Root, Repo: t.repo.Repo(), Findings: handoffFindings(t.h, t.site.Root),
		RequestID: requestID, RequestedBy: v.DisplayName,
		Link:  strings.TrimSuffix(s.cfg.BaseURL, "/") + siteURL(t.host.OrgSlug, t.host.Name, t.site.Root),
		Facts: siteFacts(t.site),
	})
}

func siteFacts(site report.Site) handoff.SiteFacts {
	f := handoff.SiteFacts{DocumentRoot: site.DocumentRoot, ServerNames: site.ServerNames, Framework: site.Framework,
		FrameworkVersion: site.FrameworkVersion, PHP: site.PHPFPM, PHPRequirement: site.PHPRequirement}
	if site.DeployedAt != nil {
		f.DeployedAt = site.DeployedAt.UTC().Format(time.RFC3339)
	}
	return f
}

func (s *server) handoffBody(t handoffTarget, msg handoff.Message, requestID string) handoffBody {
	repo := t.repo.Repo()
	return handoffBody{
		Org: t.host.OrgSlug, Host: t.host.Name, Root: t.site.Root, Site: siteName(t.site),
		SiteURL: siteURL(t.host.OrgSlug, t.host.Name, t.site.Root),
		Agents:  agentNames(s.cfg.Agents), Agent: t.agent.Name,
		Repo: repo, RepoWeb: handoff.WebURL(repo), RepoManual: t.repo.Manual != "",
		Content: msg.Content, Digest: msg.Digest, RequestID: requestID,
		Packages: msg.Packages, Omitted: msg.Omitted,
		File: string(msg.File), FileName: msg.FileName,
	}
}

// handoffPage is the confirm step: exactly what will be posted.
func (s *server) handoffPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	q := r.URL.Query()
	t, ok, err := s.loadHandoff(r.Context(), v, r.PathValue("org"), r.PathValue("host"), q.Get("root"), q.Get("agent"))
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !ok {
		s.notFound(w, r, v)
		return
	}
	id := handoff.RequestID()
	msg, err := s.handoffMessage(t, v, id)
	if err != nil {
		s.notFound(w, r, v) // nothing fixable to hand off
		return
	}
	s.render(w, r, http.StatusOK, "handoff", v, "Hand off to agent", "sites", s.handoffBody(t, msg, id))
}

// handoffSend posts the message the operator confirmed.
func (s *server) handoffSend(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	f := r.PostForm
	t, ok, err := s.loadHandoff(r.Context(), v, r.PathValue("org"), r.PathValue("host"), f.Get("root"), f.Get("agent"))
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !ok || f.Get("agent") == "" {
		s.notFound(w, r, v)
		return
	}
	id := f.Get("request_id")
	if !handoff.ValidRequestID(id) {
		s.forbidden(w, r)
		return
	}
	msg, err := s.handoffMessage(t, v, id)
	if err != nil {
		s.notFound(w, r, v)
		return
	}
	body := s.handoffBody(t, msg, id)
	if f.Get("digest") != msg.Digest {
		// The findings or repository changed since the page was shown.
		body.Notice = "The message changed since you opened this page (new findings or a new repository). Check it again before sending."
		s.render(w, r, http.StatusConflict, "handoff", v, "Hand off to agent", "sites", body)
		return
	}
	key := strconv.FormatInt(t.host.ID, 10) + "\x00" + t.site.Root + "\x00" + t.agent.Name
	if !s.handoffLimit.allow(key, s.now()) {
		body.Notice = "This site was handed to " + t.agent.Name + " in the last few minutes. Try again later."
		s.render(w, r, http.StatusTooManyRequests, "handoff", v, "Hand off to agent", "sites", body)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handoffPostTimeout)
	defer cancel()
	postErr := t.agent.Poster.PostPayloadFile(ctx, msg.Payload, msg.FileName, msg.File)
	detail := map[string]any{"agent": t.agent.Name, "host": t.host.Name, "site": t.site.Root, "request_id": id,
		"packages": msg.Packages, "omitted": msg.Omitted, "repo": t.repo.Repo(), "ok": postErr == nil}
	if postErr != nil {
		s.log.Warn("hand-off not posted", "agent", t.agent.Name, "host", t.host.Name, "site", t.site.Root, "err", postErr)
		detail["error"] = "post failed"
	}
	if err := s.st.Audit(r.Context(), store.AuditEntry{Actor: actorOf(v), Action: "handoff.send", OrgID: t.host.OrgID,
		Target: t.host.Name, Detail: detail, IP: clientIP(r)}); err != nil {
		s.log.Error("hand-off audit failed", "err", err)
	}
	result := "sent"
	if postErr != nil {
		result = "failed"
	}
	http.Redirect(w, r, body.SiteURL+"&handoff="+result, http.StatusSeeOther)
}

// siteRepo sets or clears a site's repository (operator or admin).
func (s *server) siteRepo(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PostForm.Get("org"), r.PostForm.Get("host"))
	if err != nil || !v.Scope.CanOperate(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	root := r.PostForm.Get("root")
	back := siteURL(host.OrgSlug, host.Name, root)
	repo := strings.TrimSpace(r.PostForm.Get("repo"))
	if r.PostForm.Get("clear") != "" {
		repo = ""
	}
	var verr *store.ValidationError
	switch err := s.st.SetSiteRepo(r.Context(), actorOf(v), host.ID, root, repo); {
	case errors.As(err, &verr) && verr.Field == "repo":
		http.Redirect(w, r, back+"&repo=invalid#repo", http.StatusSeeOther)
	case errors.As(err, &verr):
		s.notFound(w, r, v)
	case err != nil:
		s.fail(w, r, v, err)
	case repo == "":
		http.Redirect(w, r, back+"&repo=cleared#repo", http.StatusSeeOther)
	default:
		http.Redirect(w, r, back+"&repo=saved#repo", http.StatusSeeOther)
	}
}
