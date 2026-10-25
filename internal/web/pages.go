// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/findings"
	"github.com/chrisreedio/heimdall/internal/report"
	"github.com/chrisreedio/heimdall/internal/search"
	"github.com/chrisreedio/heimdall/internal/store"
	"github.com/chrisreedio/heimdall/internal/triggers"
	"github.com/chrisreedio/heimdall/internal/updates"
	"github.com/chrisreedio/heimdall/internal/version"
)

// ── Sign-in ────────────────────────────────────────────────────────────────

type loginBody struct {
	Next  string
	Email string
	Error string
	Local bool // show the password form
	SSO   bool // show "Sign in with Microsoft"
}

func (s *server) loginBody(next string) loginBody {
	return loginBody{Next: next, Local: s.cfg.LocalLogin, SSO: s.cfg.SSO != nil}
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, err := s.viewer(r); err == nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", nil, "Sign in", "", s.loginBody(next))
}

// loginError shows the sign-in page with a fixed, user-facing message.
func (s *server) loginError(w http.ResponseWriter, r *http.Request, status int, next, msg string) {
	body := s.loginBody(next)
	body.Error = msg
	s.render(w, r, status, "login", nil, "Sign in", "", body)
}

func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.LocalLogin {
		s.notFound(w, r, nil)
		return
	}
	if !s.sameOrigin(r) || !s.parseForm(w, r) {
		s.forbidden(w, r)
		return
	}
	email := strings.TrimSpace(r.PostForm.Get("email"))
	next := safeNext(r.PostForm.Get("next"))
	token, err := s.auth.Login(r.Context(), email, r.PostForm.Get("password"), strings.TrimSpace(otpField(r)),
		clientIP(r), r.UserAgent())
	if err != nil {
		status, msg := http.StatusUnauthorized, auth.ErrInvalidLogin.Error()
		switch {
		case errors.Is(err, auth.ErrThrottled):
			status, msg = http.StatusTooManyRequests, auth.ErrThrottled.Error()
		case !errors.Is(err, auth.ErrInvalidLogin):
			s.log.Error("login failed", "err", err)
		}
		if len(email) > 254 {
			email = ""
		}
		body := s.loginBody(next)
		body.Email, body.Error = email, msg
		s.render(w, r, status, "login", nil, "Sign in", "", body)
		return
	}
	s.noteTailscaleUser(r, token) // tsproxy.go
	s.setSession(w, token, int(s.cfg.SessionMax.Seconds()))
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	if err := s.auth.Logout(r.Context(), v.SessionToken); err != nil {
		s.log.Error("logout failed", "err", err)
	}
	s.setSession(w, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// orgFilter returns the requested org if the viewer can see it, plus the
// orgs they can see.
func (s *server) orgFilter(r *http.Request, v *auth.Viewer) (string, []store.Org, error) {
	all, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return "", nil, err
	}
	var orgs []store.Org
	for _, o := range all {
		if v.Scope.CanView(o.ID) {
			orgs = append(orgs, o)
		}
	}
	want := r.URL.Query().Get("org")
	for _, o := range orgs {
		if o.Slug == want {
			return want, orgs, nil
		}
	}
	return "", orgs, nil
}

// ── Host page ──────────────────────────────────────────────────────────────

type hostBody struct {
	Org, Name       string
	AutoName        bool // takes the hostname it reports first
	Tags            []string
	Env             string
	Envs            []store.Env // the org's environments, for moving the host
	CanAdmin        bool        // may rename the host
	Notice          string      // fixed messages only (see renameNotices)
	RenameError     string
	Reported        bool
	Summary         store.SnapshotSummary
	Reboot          string
	Report          report.Host
	OSFindings      []report.Finding
	Sites           []siteSection
	Stale           bool
	Pending         []store.InventoryPackage
	PendingSecurity int
	OSView          findingsView
	CollectorBehind bool // the host's collector is older than this hub's release
	CollectorKnown  bool // this hub is a release build, so the comparison means something
	ShowAll         bool // show every finding instead of the first findingsCap
	Packages        []store.InventoryPackage
	Commands        []command
	Anomalies       []store.AnomalyRow
	Privilege       *privilegeView // nil on Windows
	PackageMgr      string
	ShowOrgName     bool
	News            []newsRow // incidents in the news affecting this host
	ChangeWatch     string    // "on", "off", or "" if the collector doesn't report its triggers
	AI              *aiView   // AI triage card (nil when [ai] is off); see ai.go

	Tailnet *tailnetView // the host's tailnet device (nil when [tailscale] is off); see tailscale.go
	Logins  *loginsView  // failed logins (nil on Windows); see logins.go
	Surface surfaceHTML  // "public as ..." line, or "" (surface.go)
}

type command struct {
	Label, ID, Text string
	Note            string // shown under the command, if set
}

var safePackage = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]*$`)

func (s *server) hostPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	host, err := s.st.HostByName(ctx, r.PathValue("org"), r.PathValue("host"))
	var verr *store.ValidationError
	if errors.Is(err, store.ErrNotFound) || errors.As(err, &verr) {
		s.notFound(w, r, v)
		return
	}
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if !v.Scope.CanView(host.OrgID) {
		s.notFound(w, r, v) // same response as a missing host: no existence leak
		return
	}
	body := hostBody{Org: host.OrgSlug, Name: host.Name, AutoName: host.AutoName, CanAdmin: v.Scope.CanAdmin(host.OrgID)}
	if body.Tags, err = s.st.HostTags(ctx, host.ID); err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.Env = host.EnvSlug
	if body.CanAdmin {
		if body.Envs, err = s.st.ListEnvs(ctx, host.OrgSlug); err != nil {
			s.fail(w, r, v, err)
			return
		}
	}
	body.Notice = renameNotices[r.URL.Query().Get("renamed")]
	body.RenameError = renameErrors[r.URL.Query().Get("rename_error")]

	orgs, err := s.st.ListOrgs(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.ShowOrgName = len(orgs) > 1

	sum, err := s.st.LatestSnapshot(ctx, host.ID)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.render(w, r, http.StatusOK, "host", v, host.Name, "hosts", body)
		return
	case err != nil:
		s.fail(w, r, v, err)
		return
	}
	body.Reported, body.Summary = true, sum
	body.Reboot = "unknown"
	if sum.RebootRequired != nil {
		body.Reboot = map[bool]string{true: "required", false: "not required"}[*sum.RebootRequired]
	}
	body.Stale = s.cfg.StaleAfter > 0 && s.now().Sub(sum.ReceivedAt) > s.cfg.StaleAfter

	rep, err := report.Build(ctx, s.st, report.Filter{Org: host.OrgSlug, Host: host.Name, Scope: v.Scope}, s.now())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, h := range rep.Hosts {
		if h.Name == host.Name {
			body.Report = h
		}
	}
	body.OSFindings, body.Sites = splitFindings(body.Report)
	labels, err := s.st.SiteLabelsByName(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	repos, err := s.st.SiteRepos(ctx, host.ID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for i := range body.Sites {
		site := &body.Sites[i]
		if l, ok := labels[store.SiteLabelKey(host.OrgSlug, host.Name, site.Root)]; ok {
			site.Label, site.LabelSet = l, true
		} else {
			site.Label = suggestSiteLabel(site.ServerNames)
		}
		site.Repo = repos[site.Root].Repo()
		if s.canHandoff(v, host.OrgID) && len(handoffFindings(body.Report, site.Root)) > 0 {
			site.HandoffURL = handoffURL(host.OrgSlug, host.Name, site.Root, "")
		}
	}

	inv, err := s.st.Inventory(ctx, host)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.fail(w, r, v, err)
		return
	}
	body.Packages = inv.Packages
	for _, p := range inv.Packages {
		if p.PendingVersion != "" {
			body.Pending = append(body.Pending, p)
		}
	}
	// Security updates first, then by name.
	slices.SortStableFunc(body.Pending, func(a, b store.InventoryPackage) int {
		if a.PendingSecurity != b.PendingSecurity {
			if a.PendingSecurity {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	for _, p := range body.Pending {
		if p.PendingSecurity {
			body.PendingSecurity++
		}
	}
	body.ShowAll = r.URL.Query().Get("findings") == "all"
	body.PackageMgr = packageManager(inv)
	body.Commands = upgradeCommands(body.PackageMgr, body.Pending)
	body.OSView = buildFindingsView("/hosts/"+url.PathEscape(host.OrgSlug)+"/"+url.PathEscape(host.Name), packageManager(inv), r.URL.Query(),
		body.OSFindings, report.PackagesOf(inv), kernelInfo{Running: body.Report.Kernel, Newer: body.Report.NewerKernel})
	for _, f := range body.OSFindings {
		if f.NotRunning {
			body.OSView.OldKernelFindings++
		}
	}
	body.OSView.OldKernelCmd = oldKernelCommand(body.Report.OldKernels, body.OSView.OldKernelFindings)
	if v := strings.TrimSpace(sum.CollectorVersion); v != "" && releaseTag.MatchString(s.cfg.Version) {
		body.CollectorKnown = true
		body.CollectorBehind = updates.Newer(s.cfg.Version, "v"+strings.TrimPrefix(v, "v"))
	}
	if raw, err := s.st.HostTriggers(ctx, host.ID); err == nil {
		if t, err := triggers.Parse(raw); err == nil {
			body.ChangeWatch = t.ChangeWatch()
		}
	}

	if body.Anomalies, err = s.st.Anomalies(ctx, host.ID); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if s.cfg.News {
		entries, err := s.st.HostNews(ctx, host.ID)
		if err != nil {
			s.fail(w, r, v, err)
			return
		}
		body.News = newsRows(entries)
	}
	if body.Privilege, err = s.privilegeFor(ctx, host, body.PackageMgr); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if body.AI, err = s.aiHostFor(r, v, host); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if body.Tailnet, err = s.tailnetFor(ctx, host.ID, host.Name); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if body.Logins, err = s.loginsFor(ctx, v, host, body.PackageMgr); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if s.canHandoff(v, host.OrgID) {
		aiHandoffs(body.AI, host.OrgSlug, host.Name, body.Sites, body.Report)
	}
	body.Surface = s.surfaceLineFor(ctx, v, host.OrgID, host.Name, "")
	s.render(w, r, http.StatusOK, "host", v, host.Name, "hosts", body)
}

func packageManager(inv store.HostInventory) string {
	if inv.PackageManager != "" {
		return inv.PackageManager
	}
	if info, ok := findings.HostEcosystem(inv); ok {
		switch info.Scheme {
		case version.Dpkg:
			return "dpkg"
		case version.RPM:
			return "rpm"
		case version.APK:
			return "apk"
		}
	}
	return ""
}

// upgradeCommands builds copy-paste commands for pending updates: one for
// security updates only (when known) and one for everything.
func upgradeCommands(pm string, pending []store.InventoryPackage) []command {
	prefix := map[string]string{
		"dpkg": "sudo apt-get install --only-upgrade",
		"rpm":  "sudo dnf upgrade",
		"apk":  "sudo apk upgrade",
	}[pm]
	if prefix == "" || len(pending) == 0 {
		return nil
	}
	var all, sec []string
	for _, p := range pending {
		if !safePackage.MatchString(p.Name) || slices.Contains(all, p.Name) {
			continue
		}
		all = append(all, p.Name)
		if p.PendingSecurity {
			sec = append(sec, p.Name)
		}
	}
	var cmds []command
	if len(sec) > 0 && len(sec) < len(all) {
		cmds = append(cmds, command{Label: "Security updates only", ID: "cmd-security", Text: prefix + " " + strings.Join(sec, " ")})
	}
	if len(all) > 0 {
		cmds = append(cmds, command{Label: "All pending updates", ID: "cmd-all", Text: prefix + " " + strings.Join(all, " ")})
	}
	return cmds
}

// ── Search ─────────────────────────────────────────────────────────────────

type searchBody struct {
	Query    string
	Result   *search.Result
	Error    string
	Examples []string
}

func (s *server) searchPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 200 {
		q = q[:200]
	}
	body := searchBody{Query: q, Examples: []string{"openssl < 3.0.13", "php = 8.1", "CVE-2024-6387", "host:web"}}
	if q != "" {
		res, err := s.search(r.Context(), q, v.Scope)
		if err != nil {
			body.Error = err.Error()
		} else {
			body.Result = res
		}
	}
	s.render(w, r, http.StatusOK, "search", v, "Search", "search", body)
}

// ── Sites ──────────────────────────────────────────────────────────────────

// siteRow is one web app with the host it runs on.
type siteRow struct {
	report.Site
	Org, Host string
	Label     string // production, staging, development, or "" if unknown
	LabelSet  bool   // set by an admin (otherwise suggested from the names)
	CanAdmin  bool
}

// suggestSiteLabel guesses a site's label from its first server name:
// staging.example.com is staging, dev.example.com is development, and a
// plain name is production. "" when the site has no name to go by.
func suggestSiteLabel(names []string) string {
	if len(names) == 0 || names[0] == "_" || names[0] == "" {
		return ""
	}
	first, _, _ := strings.Cut(strings.ToLower(names[0]), ".")
	for _, part := range strings.FieldsFunc(first, func(r rune) bool { return r == '-' || r == '_' }) {
		switch part {
		case "staging", "stage", "stg", "uat", "qa", "preview", "preprod":
			return "staging"
		case "dev", "develop", "development", "test", "testing", "sandbox", "local":
			return "development"
		}
	}
	return "production"
}

// labelSites fills in each site's label: the one an admin set, or the
// suggestion.
func (s *server) labelSites(r *http.Request, v *auth.Viewer, rows []siteRow) error {
	set, err := s.st.SiteLabelsByName(r.Context())
	if err != nil {
		return err
	}
	orgs, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return err
	}
	admin := map[string]bool{}
	for _, o := range orgs {
		admin[o.Slug] = v.Scope.CanAdmin(o.ID)
	}
	for i := range rows {
		row := &rows[i]
		if l, ok := set[store.SiteLabelKey(row.Org, row.Host, row.Root)]; ok {
			row.Label, row.LabelSet = l, true
		} else {
			row.Label = suggestSiteLabel(row.ServerNames)
		}
		row.CanAdmin = admin[row.Org]
	}
	return nil
}

// lifeState classifies a lifecycle for badges: "eol", "soon" (≤90 days
// left), "ok" or "unknown".
func lifeState(l *report.Lifecycle) string {
	switch {
	case l == nil || !l.Known:
		return "unknown"
	case l.EOL:
		return "eol"
	case l.EOLDate != nil && l.DaysLeft <= 90:
		return "soon"
	}
	return "ok"
}

// lifecycleProblem reports EOL software or an unmet PHP requirement.
func lifecycleProblem(s report.Site) bool {
	return lifeState(s.PHPLife) == "eol" || lifeState(s.FrameworkLife) == "eol" ||
		(s.PHPSatisfied != nil && !*s.PHPSatisfied)
}

// needsAttention is what the dashboard tile counts.
func needsAttention(s report.Site) bool {
	return lifecycleProblem(s) || s.Counts.KEV > 0 || s.Counts.Critical > 0
}

type sitesBody struct {
	Org      string
	Orgs     []store.Org
	ShowOrgs bool
	Sites    []siteRow
	Label    string         // filter: production, staging, development, or ""
	Counts   map[string]int // sites per label, before filtering
	Labels   []string
	Notice   string
}

func (s *server) sitesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	rep, err := report.Build(r.Context(), s.st, report.Filter{Org: org, Scope: v.Scope, CountsOnly: true}, s.now())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := sitesBody{Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1, Labels: store.SiteLabels, Counts: map[string]int{}}
	var all []siteRow
	for _, h := range rep.Hosts {
		for _, site := range h.Sites {
			all = append(all, siteRow{Site: site, Org: h.Org, Host: h.Name})
		}
	}
	if err := s.labelSites(r, v, all); err != nil {
		s.fail(w, r, v, err)
		return
	}
	if l := r.URL.Query().Get("label"); slices.Contains(store.SiteLabels, l) {
		body.Label = l
	}
	for _, row := range all {
		body.Counts[row.Label]++
		if body.Label == "" || row.Label == body.Label {
			body.Sites = append(body.Sites, row)
		}
	}
	if r.URL.Query().Get("labeled") == "1" {
		body.Notice = "Label saved."
	}
	sortSites(body.Sites)
	s.render(w, r, http.StatusOK, "sites", v, "Sites", "sites", body)
}

// sortSites orders sites for attention: known-exploited first, then
// lifecycle or requirement problems, then by findings.
func sortSites(rows []siteRow) {
	b2i := func(b bool) int {
		if b {
			return 1
		}
		return 0
	}
	slices.SortStableFunc(rows, func(a, b siteRow) int {
		for _, d := range [][2]int{
			{b2i(a.Counts.KEV > 0), b2i(b.Counts.KEV > 0)},
			{b2i(lifecycleProblem(a.Site)), b2i(lifecycleProblem(b.Site))},
			{a.Counts.Critical, b.Counts.Critical}, {a.Counts.High, b.Counts.High},
			{a.Counts.Total, b.Counts.Total},
		} {
			if d[0] != d[1] {
				return d[1] - d[0]
			}
		}
		return strings.Compare(a.Org+"/"+a.Host+"/"+a.Root, b.Org+"/"+b.Host+"/"+b.Root)
	})
}

// siteSection is a site on the host page with its own findings.
type siteSection struct {
	report.Site
	Findings   []report.Finding
	Command    *command
	Label      string
	LabelSet   bool
	Repo       string // the site's repository ("" if unknown)
	HandoffURL string // "Hand off to agent", when allowed and there's something to fix
}

var composerName = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)

// composerCommand builds `composer update` for a site's fixable findings.
func composerCommand(id string, fs []report.Finding) *command {
	var names []string
	for _, f := range fs {
		if f.Fixed == "" || !composerName.MatchString(f.Package) || slices.Contains(names, f.Package) {
			continue
		}
		names = append(names, f.Package)
	}
	if len(names) == 0 {
		return nil
	}
	return &command{Label: "Update fixable packages (run in the site root)", ID: id,
		Text: "composer update " + strings.Join(names, " ") + " --with-dependencies"}
}

// splitFindings separates OS findings from each site's Composer findings.
func splitFindings(h report.Host) (osFindings []report.Finding, sites []siteSection) {
	bySite := map[string][]report.Finding{}
	for _, f := range h.Findings {
		if f.Site == "" {
			osFindings = append(osFindings, f)
		} else {
			bySite[f.Site] = append(bySite[f.Site], f)
		}
	}
	for i, site := range h.Sites {
		fs := bySite[site.Root]
		sites = append(sites, siteSection{Site: site, Findings: fs,
			Command: composerCommand("cmd-site-"+strconv.Itoa(i), fs)})
	}
	return osFindings, sites
}

// visibleHosts lists hosts (optionally in one org) that the viewer can see.
func (s *server) visibleHosts(r *http.Request, v *auth.Viewer, org string) ([]store.Host, error) {
	all, err := s.st.ListHosts(r.Context(), org)
	if err != nil {
		return nil, err
	}
	visible, err := s.st.VisibleOrgSlugs(r.Context(), v.Scope)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, h := range all {
		if visible[h.OrgSlug] {
			out = append(out, h)
		}
	}
	return out, nil
}

// otpField reads the login form's one-time code. It's named "totp" so
// password managers (1Password and others) recognise it; "code" is still
// accepted from a login page that was open across an upgrade.
func otpField(r *http.Request) string {
	if v := r.PostForm.Get("totp"); v != "" {
		return v
	}
	return r.PostForm.Get("code")
}

// Fixed messages a rename redirect can ask the host page to show, so the
// query string can't inject text.
var (
	renameNotices = map[string]string{"1": "Host renamed.", "tags": "Tags saved.", "env": "Environment changed."}
	renameErrors  = map[string]string{
		"invalid": "Names are letters, digits, '.', '-' or '_', starting and ending with a letter or digit.",
		"exists":  "Another host in this organization already has that name.",
		"tags":    "Tags are up to 64 lowercase letters, digits or ':._-'.",
		"env":     "Environment names are 1-63 lowercase letters, digits or '-'.",
	}
)

// hostRename renames a host (org admins only).
func (s *server) hostRename(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PathValue("org"), r.PathValue("host"))
	if err != nil || !v.Scope.CanAdmin(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	newName := strings.ToLower(strings.TrimSpace(r.PostForm.Get("name")))
	back := "/hosts/" + url.PathEscape(host.OrgSlug) + "/" + url.PathEscape(host.Name)
	if newName == host.Name {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	var verr *store.ValidationError
	switch err := s.st.RenameHost(r.Context(), actorOf(v), host.OrgSlug, host.Name, newName); {
	case errors.As(err, &verr):
		http.Redirect(w, r, back+"?rename_error=invalid", http.StatusSeeOther)
	case errors.Is(err, store.ErrExists):
		http.Redirect(w, r, back+"?rename_error=exists", http.StatusSeeOther)
	case err != nil:
		s.fail(w, r, v, err)
	default:
		http.Redirect(w, r, "/hosts/"+url.PathEscape(host.OrgSlug)+"/"+url.PathEscape(newName)+"?renamed=1", http.StatusSeeOther)
	}
}

// hostTags replaces a host's tags (org admins only).
func (s *server) hostTags(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PathValue("org"), r.PathValue("host"))
	if err != nil || !v.Scope.CanAdmin(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	var tags []string
	for t := range strings.SplitSeq(r.PostForm.Get("tags"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	back := "/hosts/" + url.PathEscape(host.OrgSlug) + "/" + url.PathEscape(host.Name)
	var verr *store.ValidationError
	switch err := s.st.SetHostTags(r.Context(), actorOf(v), host.ID, tags); {
	case errors.As(err, &verr):
		http.Redirect(w, r, back+"?rename_error=tags", http.StatusSeeOther)
	case err != nil:
		s.fail(w, r, v, err)
	default:
		http.Redirect(w, r, back+"?renamed=tags", http.StatusSeeOther)
	}
}

// hostEnv moves a host to another environment, creating it if it's new
// (org admins only).
func (s *server) hostEnv(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PathValue("org"), r.PathValue("host"))
	if err != nil || !v.Scope.CanAdmin(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	back := "/hosts/" + url.PathEscape(host.OrgSlug) + "/" + url.PathEscape(host.Name)
	env := strings.ToLower(strings.TrimSpace(r.PostForm.Get("env")))
	if n := strings.ToLower(strings.TrimSpace(r.PostForm.Get("new_env"))); n != "" {
		env = n
	}
	if err := s.ensureEnv(r, v, host.OrgSlug, env); err != nil {
		var verr *store.ValidationError
		if errors.As(err, &verr) {
			http.Redirect(w, r, back+"?rename_error=env", http.StatusSeeOther)
			return
		}
		s.fail(w, r, v, err)
		return
	}
	if err := s.st.MoveHost(r.Context(), actorOf(v), host.ID, env); err != nil {
		s.fail(w, r, v, err)
		return
	}
	http.Redirect(w, r, back+"?renamed=env", http.StatusSeeOther)
}

// ensureEnv creates an environment in an org unless it already exists.
func (s *server) ensureEnv(r *http.Request, v *auth.Viewer, org, env string) error {
	if _, err := s.st.CreateEnv(r.Context(), actorOf(v), org, env, ""); err != nil && !errors.Is(err, store.ErrExists) {
		return err
	}
	return nil
}

// siteLabel sets or clears a site's label (org admins only).
func (s *server) siteLabel(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	host, err := s.st.HostByName(r.Context(), r.PostForm.Get("org"), r.PostForm.Get("host"))
	if err != nil || !v.Scope.CanAdmin(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	label := r.PostForm.Get("label")
	if label == "auto" {
		label = ""
	}
	var verr *store.ValidationError
	switch err := s.st.SetSiteLabel(r.Context(), actorOf(v), host.ID, r.PostForm.Get("root"), label); {
	case errors.As(err, &verr):
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
	case err != nil:
		s.fail(w, r, v, err)
	default:
		back := "/sites?labeled=1"
		if f := r.PostForm.Get("filter"); slices.Contains(store.SiteLabels, f) {
			back += "&label=" + f
		}
		if b := r.PostForm.Get("back"); strings.HasPrefix(b, "/hosts/") {
			back = safeNext(b)
		}
		http.Redirect(w, r, back, http.StatusSeeOther)
	}
}

// ── Site page ──────────────────────────────────────────────────────────────

type siteBody struct {
	Org, Host, Env string
	Site           report.Site
	Label          string
	LabelSet       bool
	CanAdmin       bool
	Labels         []string
	View           findingsView
	Others         []report.Site // the host's other sites
	Notice         string
	// The site's repository: the one in use, and where it came from.
	Repo         store.SiteRepo
	CanOperate   bool   // may set the repository
	RepoNotice   string // fixed text after saving it
	RepoError    bool
	HandoffURL   string // "Hand off to agent", when allowed and there's something to fix
	HandoffNote  string // fixed text after a hand-off
	HandoffError bool

	Cloudflare cloudflareHTML // the Cloudflare card, or "" (cloudflare.go)
	Surface    surfaceHTML    // "public as ..." line, or "" (surface.go)
}

// sitePage shows one site (a web root on a host): its stack, lifecycle and
// Composer findings.
func (s *server) sitePage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	ctx := r.Context()
	host, err := s.st.HostByName(ctx, r.PathValue("org"), r.PathValue("host"))
	if err != nil || !v.Scope.CanView(host.OrgID) {
		s.notFound(w, r, v)
		return
	}
	root := r.URL.Query().Get("root")
	rep, err := report.Build(ctx, s.st, report.Filter{Org: host.OrgSlug, Host: host.Name, Scope: v.Scope}, s.now())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	var h report.Host
	for _, rh := range rep.Hosts {
		if rh.Name == host.Name {
			h = rh
		}
	}
	body := siteBody{Org: host.OrgSlug, Host: host.Name, Env: host.EnvSlug, CanAdmin: v.Scope.CanAdmin(host.OrgID), Labels: store.SiteLabels}
	found := false
	for _, site := range h.Sites {
		if site.Root == root {
			body.Site, found = site, true
		} else {
			body.Others = append(body.Others, site)
		}
	}
	if !found {
		s.notFound(w, r, v)
		return
	}
	labels, err := s.st.SiteLabelsByName(ctx)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if l, ok := labels[store.SiteLabelKey(host.OrgSlug, host.Name, root)]; ok {
		body.Label, body.LabelSet = l, true
	} else {
		body.Label = suggestSiteLabel(body.Site.ServerNames)
	}
	var fs []report.Finding
	for _, f := range h.Findings {
		if f.Site == root {
			fs = append(fs, f)
		}
	}
	base := "/hosts/" + url.PathEscape(host.OrgSlug) + "/" + url.PathEscape(host.Name) + "/site?root=" + url.QueryEscape(root)
	body.View = buildFindingsView(base, "composer", r.URL.Query(), fs, nil, kernelInfo{})
	if r.URL.Query().Get("labeled") == "1" {
		body.Notice = "Label saved."
	}
	repos, err := s.st.SiteRepos(ctx, host.ID)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body.Repo, body.CanOperate = repos[root], v.Scope.CanOperate(host.OrgID)
	rn := r.URL.Query().Get("repo")
	body.RepoNotice, body.RepoError = repoNotices[rn], rn == "invalid"
	if s.canHandoff(v, host.OrgID) && len(handoffFindings(h, root)) > 0 {
		body.HandoffURL = handoffURL(host.OrgSlug, host.Name, root, "")
	}
	hn := r.URL.Query().Get("handoff")
	body.HandoffNote, body.HandoffError = handoffNotices[hn], hn == "failed"
	body.Cloudflare = s.cloudflareCard(ctx, v, host.OrgID, host.Name, root)
	body.Surface = s.surfaceLineFor(ctx, v, host.OrgID, host.Name, root)
	name := root
	if len(body.Site.ServerNames) > 0 && body.Site.ServerNames[0] != "_" {
		name = body.Site.ServerNames[0]
	}
	s.render(w, r, http.StatusOK, "site", v, name, "sites", body)
}
