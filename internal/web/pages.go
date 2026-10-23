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

// ── Dashboard ──────────────────────────────────────────────────────────────

type hostRow struct {
	report.Host
	Stale  bool
	EOL    bool
	Reboot bool
}

type dashBody struct {
	Org      string
	Orgs     []store.Org
	ShowOrgs bool
	Tiles    tiles
	Rows     []hostRow
	Waiting  []store.Host
}

type tiles struct {
	Hosts, KEV, Critical, Fixable, EOL, Reboot, Stale, Sites int
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

// rows builds per-host rows with stale, EOL and reboot flags.
func (s *server) rows(r *http.Request, v *auth.Viewer, org string) ([]hostRow, error) {
	ctx := r.Context()
	rep, err := report.Build(ctx, s.st, report.Filter{Org: org, Scope: v.Scope}, s.now())
	if err != nil {
		return nil, err
	}
	ids := map[string]int64{}
	reported, err := s.st.HostsWithSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range reported {
		ids[h.OrgSlug+"/"+h.Name] = h.ID
	}
	now := s.now()
	rows := make([]hostRow, 0, len(rep.Hosts))
	for _, h := range rep.Hosts {
		row := hostRow{Host: h, Stale: s.cfg.StaleAfter > 0 && now.Sub(h.LastSeen) > s.cfg.StaleAfter}
		if h.OSLife != nil && h.OSLife.EOL {
			row.EOL = true
		}
		for _, rt := range h.Runtimes {
			if rt.Life != nil && rt.Life.EOL {
				row.EOL = true
			}
		}
		if id, ok := ids[h.Org+"/"+h.Name]; ok {
			sum, err := s.st.LatestSnapshot(ctx, id)
			if err != nil && !errors.Is(err, store.ErrNotFound) {
				return nil, err
			}
			row.Reboot = sum.RebootRequired != nil && *sum.RebootRequired
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (s *server) dashboard(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	rows, err := s.rows(r, v, org)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := dashBody{Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1, Rows: rows}
	for _, row := range rows {
		body.Tiles.Hosts++
		body.Tiles.KEV += row.Counts.KEV
		body.Tiles.Critical += row.Counts.Critical
		if row.Counts.Fixable > 0 {
			body.Tiles.Fixable++
		}
		if row.EOL {
			body.Tiles.EOL++
		}
		if row.Reboot {
			body.Tiles.Reboot++
		}
		if row.Stale {
			body.Tiles.Stale++
		}
		for _, site := range row.Sites {
			if needsAttention(site) {
				body.Tiles.Sites++
			}
		}
	}
	slices.SortStableFunc(body.Rows, func(a, b hostRow) int {
		for _, d := range [][2]int{
			{a.Counts.KEV, b.Counts.KEV}, {a.Counts.Critical, b.Counts.Critical},
			{a.Counts.High, b.Counts.High}, {a.Counts.Fixable, b.Counts.Fixable},
		} {
			if d[0] != d[1] {
				return d[1] - d[0]
			}
		}
		return strings.Compare(a.Org+"/"+a.Name, b.Org+"/"+b.Name)
	})

	all, err := s.visibleHosts(r, v, "")
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, h := range all {
		if h.LastSeenAt.IsZero() && (org == "" || h.OrgSlug == org) {
			body.Waiting = append(body.Waiting, h)
		}
	}
	s.render(w, r, http.StatusOK, "dashboard", v, "Dashboard", "dashboard", body)
}

// ── Hosts ──────────────────────────────────────────────────────────────────

type hostsBody struct {
	Org      string
	Orgs     []store.Org
	ShowOrgs bool
	Hosts    []hostsRow
}

type hostsRow struct {
	store.Host
	Reported bool
	Row      hostRow
}

func (s *server) hostsPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	rows, err := s.rows(r, v, org)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	byName := map[string]hostRow{}
	for _, row := range rows {
		byName[row.Org+"/"+row.Name] = row
	}
	all, err := s.visibleHosts(r, v, org)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := hostsBody{Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1}
	for _, h := range all {
		row, ok := byName[h.OrgSlug+"/"+h.Name]
		body.Hosts = append(body.Hosts, hostsRow{Host: h, Reported: ok, Row: row})
	}
	s.render(w, r, http.StatusOK, "hosts", v, "Hosts", "hosts", body)
}

// ── Host page ──────────────────────────────────────────────────────────────

type hostBody struct {
	Org, Name   string
	AutoName    bool // takes the hostname it reports first
	Tags        []string
	CanAdmin    bool   // may rename the host
	Notice      string // fixed messages only (see renameNotices)
	RenameError string
	Reported    bool
	Summary     store.SnapshotSummary
	Reboot      string
	Report      report.Host
	OSFindings  []report.Finding
	Sites       []siteSection
	Stale       bool
	Pending     []store.InventoryPackage
	Packages    []store.InventoryPackage
	Commands    []command
	Anomalies   []store.AnomalyRow
	PackageMgr  string
	ShowOrgName bool
}

type command struct {
	Label, ID, Text string
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

	rep, err := report.Build(ctx, s.st, report.Filter{Org: host.OrgSlug, Scope: v.Scope}, s.now())
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
	body.PackageMgr = packageManager(inv)
	body.Commands = upgradeCommands(body.PackageMgr, body.Pending)

	if body.Anomalies, err = s.st.Anomalies(ctx, host.ID); err != nil {
		s.fail(w, r, v, err)
		return
	}
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
}

func (s *server) sitesPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org, orgs, err := s.orgFilter(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	rep, err := report.Build(r.Context(), s.st, report.Filter{Org: org, Scope: v.Scope}, s.now())
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	body := sitesBody{Org: org, Orgs: orgs, ShowOrgs: len(orgs) > 1}
	for _, h := range rep.Hosts {
		for _, site := range h.Sites {
			body.Sites = append(body.Sites, siteRow{Site: site, Org: h.Org, Host: h.Name})
		}
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
	Findings []report.Finding
	Command  *command
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
	renameNotices = map[string]string{"1": "Host renamed.", "tags": "Tags saved."}
	renameErrors  = map[string]string{
		"invalid": "Names are letters, digits, '.', '-' or '_', starting and ending with a letter or digit.",
		"exists":  "Another host in this organization already has that name.",
		"tags":    "Tags are up to 64 lowercase letters, digits or ':._-'.",
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
