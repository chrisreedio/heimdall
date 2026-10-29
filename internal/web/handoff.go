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

// limited reports whether one of keys had an attempt within handoffEvery,
// recording nothing.
func (l *handoffLimiter) limited(now time.Time, keys ...string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		if t, ok := l.last[key]; ok && now.Sub(t) < handoffEvery {
			return true
		}
	}
	return false
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

// branchNotices are the fixed messages after saving a site's branch.
var branchNotices = map[string]string{
	"saved":   "Branch saved.",
	"cleared": "Branch cleared.",
	"invalid": "That isn't a branch name Heimdall accepts: letters, digits, \".\", \"_\", \"-\" and \"/\" only, such as main or env/beta.",
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
	// org and root are the site the button opens, for the batch button.
	org, root string
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
					cand := handoffCand{link: handoffLink{Host: name, Site: label, URL: handoffURL(hh.Org, name, site.Root, ""), org: hh.Org, root: site.Root},
						host: name, root: site.Root, name: label, label: hh.Labels[site.Root],
						repo: handoff.RepoKey(repo), short: handoff.RepoShort(repo),
						hits: len(versions), versions: strings.Join(slices.Compact(versions), " ")}
					cands = append(cands, cand)
					// A step about one site names it (its domain or root): offer
					// only that one. Not when the command lists its sites:
					// Heimdall worked those out, and the text may single out
					// one of several.
					if n := strings.ToLower(siteName(site)); len(only) == 0 && ((n != "" && strings.Contains(text, n)) || strings.Contains(text, strings.ToLower(site.Root))) {
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
			if all, ok := handoffBatchLink(links, aiBack(view)); ok {
				if view.HandoffAll == nil {
					view.HandoffAll = map[int]handoffLink{}
				}
				view.HandoffAll[i] = all
			}
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
	if len(links) == 0 && len(sites) == 1 {
		sites[0].Site = "" // the step's only button, for one site with no known repository: "Hand off to agent"
		return sites
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
	// Sites are every site on the repository the viewer may operate on,
	// this one first; Branches their distinct known branches. Target is
	// the chosen mode (handoff.TargetDefault, ...) and TargetBranch the
	// branch for TargetBranch.
	Sites                []handoffSiteRow
	Branches             []string
	Unknown              int // sites whose branch is unknown
	Target, TargetBranch string
	Content              string
	Digest, RequestID    string
	Packages, Omitted    int
	File, FileName       string // the attached JSON, shown for review
	Notice               string
	Sent                 bool
}

// handoffTarget is what both the confirm page and the send need.
type handoffTarget struct {
	host  store.IngestHost
	site  report.Site
	h     report.Host
	repo  store.SiteRepo
	agent handoff.Agent
	// sites deploy the same repository (this one first), with rows the
	// confirm page shows for them.
	sites []handoff.Site
	rows  []handoffSiteRow
}

// handoffSiteRow is one site on the confirm page.
type handoffSiteRow struct {
	Org, Host, Root, Name string
	URL                   string
	Label                 string
	Branch                string // "" when unknown
	BranchManual          bool   // set by an operator
	Commit                string // a detached HEAD's commit, shortened
	Versions              string // its installed versions of the hand-off's packages
	This                  bool   // the hand-off's own site
	Gets                  string // what the chosen target does for it (handoffBody)
	Targeted              bool
}

// handoffSites finds the sites that deploy t's repository and have a
// fixable finding in t's packages: t's own first, then the others in
// orgs the viewer may operate in (handoff.Build drops any without one of
// t's packages). Without a known repository it's t's site alone.
func (s *server) handoffSites(ctx context.Context, v *auth.Viewer, t *handoffTarget) error {
	labels, err := s.st.SiteLabelsByName(ctx)
	if err != nil {
		return err
	}
	add := func(org string, h report.Host, site report.Site, repo store.SiteRepo, this bool) {
		fs := handoffFindings(h, site.Root)
		if len(fs) == 0 {
			return
		}
		label, ok := labels[store.SiteLabelKey(org, h.Name, site.Root)]
		if !ok {
			label = suggestSiteLabel(site.ServerNames)
		}
		hs := handoff.Site{Host: h.Name, Site: siteName(site), SitePath: site.Root, Label: label, Branch: repo.Branch(), Findings: fs}
		row := handoffSiteRow{Org: org, Host: h.Name, Root: site.Root, Name: cmp.Or(siteName(site), site.Root),
			URL: siteURL(org, h.Name, site.Root), Label: label, Branch: repo.Branch(), BranchManual: repo.ManualBranch != "", This: this}
		if hs.Branch == "" && handoff.ValidCommit(repo.DetectedCommit) {
			hs.Commit, row.Commit = repo.DetectedCommit, repo.DetectedCommit[:12]
		}
		t.sites, t.rows = append(t.sites, hs), append(t.rows, row)
	}
	t.sites, t.rows = nil, nil
	add(t.host.OrgSlug, t.h, t.site, t.repo, true)
	if len(t.sites) == 0 {
		return nil // nothing to hand off (the page answers 404)
	}
	var vs []string
	for _, p := range handoff.SiteInstalled(t.sites[0], t.sites[0]) {
		vs = append(vs, p.Name+" "+p.Installed)
	}
	t.rows[0].Versions = strings.Join(vs, ", ")
	key := handoff.RepoKey(t.repo.Repo())
	if key == "" {
		return nil
	}
	all, err := s.st.RepoSites(ctx)
	if err != nil {
		return err
	}
	byHost := map[string][]store.RepoSite{}
	var hosts []string
	for _, rs := range all {
		if handoff.RepoKey(rs.Repo.Repo()) != key || !v.Scope.CanView(rs.OrgID) || !s.canHandoff(v, rs.OrgID) ||
			rs.HostID == t.host.ID && rs.Root == t.site.Root {
			continue
		}
		k := rs.Org + "\x00" + rs.Host
		if byHost[k] == nil {
			hosts = append(hosts, k)
		}
		byHost[k] = append(byHost[k], rs)
	}
	for _, k := range hosts {
		g := byHost[k]
		rep, err := report.Build(ctx, s.st, report.Filter{Org: g[0].Org, Host: g[0].Host, Scope: v.Scope}, s.now())
		if err != nil {
			return err
		}
		for _, rh := range rep.Hosts {
			if rh.Name != g[0].Host {
				continue
			}
			for _, rs := range g {
				for _, site := range rh.Sites {
					if site.Root == rs.Root {
						add(rs.Org, rh, site, rs.Repo, false)
					}
				}
			}
		}
	}
	// Only those with something of this hand-off to fix, as the message
	// lists them; production first, then staging and development.
	type pair struct {
		site handoff.Site
		row  handoffSiteRow
	}
	var others []pair
	for i := 1; i < len(t.sites); i++ {
		inst := handoff.SiteInstalled(t.sites[0], t.sites[i])
		if len(inst) == 0 {
			continue
		}
		var vs []string
		for _, p := range inst {
			vs = append(vs, p.Name+" "+p.Installed)
		}
		t.rows[i].Versions = strings.Join(vs, ", ")
		others = append(others, pair{t.sites[i], t.rows[i]})
	}
	slices.SortStableFunc(others, func(a, b pair) int {
		return cmp.Or(cmp.Compare(labelRank(a.row.Label), labelRank(b.row.Label)), cmp.Compare(a.row.Host, b.row.Host), cmp.Compare(a.row.Root, b.row.Root))
	})
	t.sites, t.rows = t.sites[:1], t.rows[:1]
	for _, o := range others {
		t.sites, t.rows = append(t.sites, o.site), append(t.rows, o.row)
	}
	return nil
}

func labelRank(l string) int {
	switch l {
	case "production":
		return 0
	case "staging":
		return 1
	case "development":
		return 2
	}
	return 3
}

// handoffTargetOf checks a submitted target against the sites' known
// branches (detected or set by an operator): the branch must be one of
// them, never other text. ok is false for anything else.
func handoffTargetOf(mode, branch string, known []string) (handoff.Target, bool) {
	if m, b, ok := strings.Cut(mode, ":"); ok && m == handoff.TargetBranch { // the confirm page's radio buttons
		mode, branch = m, b
	}
	switch mode {
	case "", handoff.TargetDefault:
		return handoff.Target{Mode: handoff.TargetDefault}, true
	case handoff.TargetBranch:
		if slices.Contains(known, branch) {
			return handoff.Target{Mode: handoff.TargetBranch, Branches: []string{branch}}, true
		}
	case handoff.TargetEach:
		if len(known) > 0 {
			return handoff.Target{Mode: handoff.TargetEach}, true
		}
	}
	return handoff.Target{}, false
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
	if err := s.handoffSites(ctx, v, &t); err != nil {
		return t, false, err
	}
	return t, true, nil
}

func (s *server) agentOK(name string) (handoff.Agent, error) {
	a, ok := s.agent(name)
	if !ok {
		return a, store.ErrNotFound
	}
	return a, nil
}

func (s *server) handoffMessage(t handoffTarget, v *auth.Viewer, requestID string, target handoff.Target) (handoff.Message, error) {
	return handoff.Build(t.agent, handoff.Request{
		Sites: t.sites, Target: target,
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

func (s *server) handoffBody(t handoffTarget, msg handoff.Message, requestID string, target handoff.Target) handoffBody {
	repo := t.repo.Repo()
	unknown := 0
	for _, r := range t.rows {
		if r.Branch == "" {
			unknown++
		}
	}
	tb := ""
	if target.Mode == handoff.TargetBranch {
		tb = target.Branches[0]
	}
	rows := slices.Clone(t.rows)
	for i := range rows {
		r := &rows[i]
		switch {
		case target.Mode == handoff.TargetEach && r.Branch != "":
			r.Gets, r.Targeted = "its own pull request, against "+r.Branch, true
		case target.Mode == handoff.TargetEach:
			r.Gets = "branch unknown: not targeted"
		case target.Mode == handoff.TargetBranch && r.Branch == tb:
			r.Gets, r.Targeted = "the pull request's branch", true
		case target.Mode == handoff.TargetBranch:
			r.Gets = "listed for the agent only"
		}
	}
	return handoffBody{
		Sites: rows, Branches: handoff.Branches(t.sites), Unknown: unknown,
		Target: cmp.Or(target.Mode, handoff.TargetDefault), TargetBranch: tb,
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
	status, notice := http.StatusOK, ""
	target, ok := handoffTargetOf(q.Get("target"), q.Get("branch"), handoff.Branches(t.sites))
	if !ok {
		status, notice = http.StatusBadRequest, badTargetNotice
		target = handoff.Target{Mode: handoff.TargetDefault}
	}
	id := handoff.RequestID()
	msg, err := s.handoffMessage(t, v, id, target)
	if err != nil {
		s.notFound(w, r, v) // nothing fixable to hand off
		return
	}
	body := s.handoffBody(t, msg, id, target)
	body.Notice = notice
	s.render(w, r, status, "handoff", v, "Hand off to agent", "sites", body)
}

// badTargetNotice: a target branch that isn't one of the sites' branches.
const badTargetNotice = "That branch isn't one of these sites' branches, so the default branch is shown. Pick a target from the list."

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
	// The target is checked against the sites' branches, never sent as
	// given; one that isn't theirs sends nothing.
	target, ok := handoffTargetOf(f.Get("target"), f.Get("branch"), handoff.Branches(t.sites))
	if !ok {
		def := handoff.Target{Mode: handoff.TargetDefault}
		msg, err := s.handoffMessage(t, v, id, def)
		if err != nil {
			s.notFound(w, r, v)
			return
		}
		body := s.handoffBody(t, msg, id, def)
		body.Notice = badTargetNotice
		s.render(w, r, http.StatusBadRequest, "handoff", v, "Hand off to agent", "sites", body)
		return
	}
	msg, err := s.handoffMessage(t, v, id, target)
	if err != nil {
		s.notFound(w, r, v)
		return
	}
	body := s.handoffBody(t, msg, id, target)
	if f.Get("digest") != msg.Digest {
		// The findings, repository, sites or target changed since the page
		// was shown: the digest covers the whole message and file.
		body.Notice = "The message changed since you opened this page (new findings, sites, branches or repository). Check it again before sending."
		s.render(w, r, http.StatusConflict, "handoff", v, "Hand off to agent", "sites", body)
		return
	}
	// Per site and agent, and per repository and agent: the sites that
	// deploy one repository share a button on AI plans, and one hand-off
	// covers them, so another of them can't be sent right after.
	switch s.handoffLimit.allow(s.now(), handoffKeys(t)...) {
	case 0:
		body.Notice = "This site was handed to " + t.agent.Name + " in the last few minutes. Try again later."
	case 1:
		body.Notice = "Another site on " + handoff.RepoShort(t.repo.Repo()) + " was handed to " + t.agent.Name +
			" in the last few minutes, and one hand-off covers the repository. Try again later."
	}
	if body.Notice != "" {
		s.render(w, r, http.StatusTooManyRequests, "handoff", v, "Hand off to agent", "sites", body)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), handoffPostTimeout)
	defer cancel()
	postErr := t.agent.Poster.PostPayloadFile(ctx, msg.Payload, msg.FileName, msg.File)
	s.auditHandoff(r, v, t, msg, id, target, postErr, 0)
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

// siteBranch sets or clears a site's branch (operator or admin), for a
// site whose checkout the collector can't see.
func (s *server) siteBranch(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PostForm.Get("org"), r.PostForm.Get("host"))
	if err != nil || !v.Scope.CanOperate(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	root := r.PostForm.Get("root")
	back := siteURL(host.OrgSlug, host.Name, root)
	branch := strings.TrimSpace(r.PostForm.Get("branch"))
	if r.PostForm.Get("clear") != "" {
		branch = ""
	}
	var verr *store.ValidationError
	switch err := s.st.SetSiteBranch(r.Context(), actorOf(v), host.ID, root, branch); {
	case errors.As(err, &verr) && verr.Field == "branch":
		http.Redirect(w, r, back+"&branch=invalid#branch", http.StatusSeeOther)
	case errors.As(err, &verr):
		s.notFound(w, r, v)
	case err != nil:
		s.fail(w, r, v, err)
	case branch == "":
		http.Redirect(w, r, back+"&branch=cleared#branch", http.StatusSeeOther)
	default:
		http.Redirect(w, r, back+"&branch=saved#branch", http.StatusSeeOther)
	}
}
