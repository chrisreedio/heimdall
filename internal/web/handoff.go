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

	"github.com/realmwatch/heimdall/internal/ai"
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

// allow records an attempt for every key unless one of them had one
// within handoffEvery. It returns the index of the first key that did, or
// -1 when the attempt is allowed (and recorded for all of them).
func (l *handoffLimiter) allow(now time.Time, keys ...string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil {
		l.last = map[string]time.Time{}
	}
	for i, key := range keys {
		if t, ok := l.last[key]; ok && now.Sub(t) < handoffEvery {
			return i
		}
	}
	for k, t := range l.last {
		if now.Sub(t) >= handoffEvery {
			delete(l.last, k)
		}
	}
	for _, key := range keys {
		l.last[key] = now
	}
	return -1
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
		if f.Fixed == "" || f.Site == "" || f.Dev { // dev dependencies don't need attention
			continue
		}
		hf := handoff.Finding{Package: f.Package, Installed: f.Version, Fixed: f.Fixed, Advisory: f.Advisory,
			Severity: f.Severity, CVEs: f.CVEs, KEV: f.KEV, EPSS: f.EPSS}
		switch {
		case f.Site == root && f.Ecosystem == npmEcosystem: // the site's own package-lock.json
			hf.Ecosystem, hf.Lockfile = "npm", store.NpmManifest(root)
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

// handoffLink is a "Hand off to agent" button: for one site, or for a
// repository that several of the step's sites deploy.
type handoffLink struct {
	Host string
	// Site is the button's label when there are several, or when it's a
	// repository's: the repository's short name ("acme/app"), or the
	// site's name (with its host when another host has one of that name).
	Site  string
	Title string // the tooltip: which sites a repository's button covers
	URL   string
}

// handoffHost is a host of an AI plan that the viewer may hand off from:
// its own org's slug (so the links never assume one org), its report, and
// its sites' repositories and labels by root.
type handoffHost struct {
	Org    string
	Host   report.Host
	Repos  map[string]string // root → repository (store.SiteRepo.Repo); absent when unknown
	Labels map[string]string // root → production, staging or development
}

// handoffHostsOf builds aiHandoffs' hosts for an org's report: each host's
// site repositories and labels (set, or suggested from the names).
func (s *server) handoffHostsOf(ctx context.Context, orgID int64, hosts []report.Host) (map[string]handoffHost, error) {
	repos, err := s.st.SiteReposByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	labels, err := s.st.SiteLabelsByName(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]handoffHost{}
	for _, h := range hosts {
		hh := handoffHost{Org: h.Org, Host: h, Repos: map[string]string{}, Labels: map[string]string{}}
		for _, site := range h.Sites {
			key := store.SiteLabelKey(h.Org, h.Name, site.Root)
			if r := repos[key].Repo(); r != "" {
				hh.Repos[site.Root] = r
			}
			if l, ok := labels[key]; ok {
				hh.Labels[site.Root] = l
			} else {
				hh.Labels[site.Root] = suggestSiteLabel(site.ServerNames)
			}
		}
		out[h.Name] = hh
	}
	return out, nil
}

// handoffCand is a site a Composer step can be handed off for.
type handoffCand struct {
	link        handoffLink
	host, root  string
	name, label string
	repo        string // handoff.RepoKey of its repository, "" when unknown
	short       string // handoff.RepoShort
	hits        int    // its fixable findings in the step's packages
	versions    string // those findings' packages and installed versions
}

// aiHandoffs adds hand-off buttons to the AI plan's Composer steps. A site
// is offered when it has a fixable finding in a package the step's
// (allowlisted) composer update command for its host names; a command that
// knows its sites (ai.Command.Sites) offers only those. hosts are the
// plan's hosts the viewer may hand off from; others get no button. OS
// patching and reboots aren't pull requests, so they never get one.
//
// The agent opens a pull request against a repository, so sites that
// deploy the same one (staging and production, say) share one button,
// labelled by the repository and opening its representative site (see
// handoffRep). A site with no known repository keeps its own button.
func aiHandoffs(view *aiView, hosts map[string]handoffHost) {
	if view == nil || view.Result == nil || len(hosts) == 0 {
		return
	}
	for i, a := range view.Result.Actions {
		var cands, named []handoffCand
		text := strings.ToLower(a.Title + " " + a.Why)
		seen := map[string]bool{}
		for _, c := range a.Commands {
			rest, ok := strings.CutPrefix(c.Command, "composer update ")
			if !ok {
				continue
			}
			pkgs := strings.Fields(strings.TrimSuffix(rest, " --with-dependencies"))
			targets := c.Hosts
			if len(targets) == 0 { // stored before commands had hosts: the step's
				targets = a.Hosts
			}
			for _, name := range targets {
				hh, ok := hosts[name]
				if !ok {
					continue
				}
				only := c.SitesOf(name)
				for _, site := range hh.Host.Sites {
					label := cmp.Or(siteName(site), site.Root)
					if (len(only) > 0 && !slices.Contains(only, label) && !slices.Contains(only, site.Root)) || seen[name+"\x00"+site.Root] {
						continue
					}
					var versions []string
					for _, f := range handoffFindings(hh.Host, site.Root) {
						if f.Ecosystem == "composer" && slices.Contains(pkgs, f.Package) {
							versions = append(versions, f.Package+"@"+f.Installed)
						}
					}
					if len(versions) == 0 {
						continue
					}
					slices.Sort(versions)
					seen[name+"\x00"+site.Root] = true
					repo := hh.Repos[site.Root]
					cand := handoffCand{link: handoffLink{Host: name, Site: label, URL: handoffURL(hh.Org, name, site.Root, "")},
						host: name, root: site.Root, name: label, label: hh.Labels[site.Root],
						repo: handoff.RepoKey(repo), short: handoff.RepoShort(repo),
						hits: len(versions), versions: strings.Join(slices.Compact(versions), " ")}
					cands = append(cands, cand)
					// A step about one site names it (its domain or root): offer only that one.
					if n := strings.ToLower(siteName(site)); (n != "" && strings.Contains(text, n)) || strings.Contains(text, strings.ToLower(site.Root)) {
						named = append(named, cand)
					}
				}
			}
		}
		if len(named) > 0 {
			// Its repository's other sites stay: one pull request covers them.
			cands = slices.DeleteFunc(cands, func(c handoffCand) bool {
				return !slices.ContainsFunc(named, func(n handoffCand) bool {
					return n.host == c.host && n.root == c.root || n.repo != "" && n.repo == c.repo
				})
			})
		}
		if links := handoffLinks(cands); len(links) > 0 {
			if view.Handoffs == nil {
				view.Handoffs = map[int][]handoffLink{}
			}
			view.Handoffs[i] = links
		}
	}
}

// handoffLinks turns a step's sites into its buttons: one per repository,
// then one per site with none, each in the order its first site came.
func handoffLinks(cands []handoffCand) []handoffLink {
	groups := map[string][]handoffCand{}
	var repos []string // keys, in order
	var sites []handoffLink
	for _, c := range cands {
		switch {
		case c.repo == "":
			sites = append(sites, c.link)
		case groups[c.repo] == nil:
			repos = append(repos, c.repo)
			fallthrough
		default:
			groups[c.repo] = append(groups[c.repo], c)
		}
	}
	// Two repositories with one short name (github.com/acme/app and
	// gitlab.com/acme/app): label those by their full key.
	shorts := map[string]int{}
	for _, key := range repos {
		shorts[groups[key][0].short]++
	}
	var links []handoffLink
	for _, key := range repos {
		g := groups[key]
		rep := handoffRep(g)
		l := rep.link
		l.Site = g[0].short
		if shorts[l.Site] > 1 {
			l.Site = key
		}
		l.Title = handoffRepoTitle(g, rep)
		links = append(links, l)
	}
	if len(links)+len(sites) == 1 && (len(sites) == 1 || len(groups[repos[0]]) == 1) {
		links = append(links, sites...)
		links[0].Site = "" // the step's only button, for one site: "Hand off to agent"
		return links
	}
	// Two hosts can serve a site of the same name: say which host.
	clash := map[string]bool{}
	for _, l := range sites {
		clash[l.Site] = clash[l.Site] || slices.ContainsFunc(sites, func(o handoffLink) bool { return o.Site == l.Site && o.Host != l.Host })
	}
	for j := range sites {
		if clash[sites[j].Site] {
			sites[j].Site = sites[j].Host + " · " + sites[j].Site
		}
	}
	return append(links, sites...)
}

// handoffRep picks the site a repository's button opens: the one with the
// most of the step's fixable findings (so the pull request covers the
// most), then a production site, then by name, host and root.
func handoffRep(g []handoffCand) handoffCand {
	return slices.MinFunc(g, func(a, b handoffCand) int {
		return cmp.Or(
			cmp.Compare(b.hits, a.hits),
			cmp.Compare(rank(a.label != "production"), rank(b.label != "production")),
			cmp.Compare(a.name, b.name), cmp.Compare(a.host, b.host), cmp.Compare(a.root, b.root))
	})
}

func rank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// handoffRepoTitle is a repository button's tooltip: the sites it covers,
// the one whose findings it sends, and whether the others differ.
func handoffRepoTitle(g []handoffCand, rep handoffCand) string {
	name := func(c handoffCand) string { return c.host + " · " + c.name }
	if len(g) == 1 {
		return "Opens a pull request on " + g[0].short + " for " + name(rep)
	}
	var b strings.Builder
	b.WriteString("One pull request on " + g[0].short + " for " + strconv.Itoa(len(g)) + " sites: ")
	for j, c := range g {
		if j > 0 {
			b.WriteString(", ")
		}
		b.WriteString(name(c))
	}
	b.WriteString(". It sends " + name(rep) + "'s findings")
	if slices.ContainsFunc(g, func(c handoffCand) bool { return c.versions != rep.versions }) {
		b.WriteString("; the sites aren't all on the same versions")
	}
	b.WriteString(".")
	return b.String()
}

// hasComposer reports whether a plan has a Composer step (so a hand-off
// may apply).
func hasComposer(res *ai.Result) bool {
	return res != nil && slices.ContainsFunc(res.Actions, func(a ai.Action) bool {
		return slices.ContainsFunc(a.Commands, func(c ai.Command) bool { return strings.HasPrefix(c.Command, "composer update ") })
	})
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
	// Per site and agent, and per repository and agent: the sites that
	// deploy one repository share a button on AI plans, and one pull
	// request covers them, so another of them can't be sent right after.
	keys := []string{"site\x00" + strconv.FormatInt(t.host.ID, 10) + "\x00" + t.site.Root + "\x00" + t.agent.Name}
	repoKey := handoff.RepoKey(t.repo.Repo())
	if repoKey != "" {
		keys = append(keys, "repo\x00"+repoKey+"\x00"+t.agent.Name)
	}
	switch s.handoffLimit.allow(s.now(), keys...) {
	case 0:
		body.Notice = "This site was handed to " + t.agent.Name + " in the last few minutes. Try again later."
	case 1:
		body.Notice = "Another site on " + handoff.RepoShort(t.repo.Repo()) + " was handed to " + t.agent.Name +
			" in the last few minutes, and one pull request covers the repository. Try again later."
	}
	if body.Notice != "" {
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
