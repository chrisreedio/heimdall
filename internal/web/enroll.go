// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

// enrollTTLs are the expiry choices on the Add servers page.
var enrollTTLs = []struct {
	Value, Label string
	TTL          time.Duration
}{
	{"1h", "1 hour", time.Hour},
	{"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
}

type enrollRow struct {
	store.EnrollKey
	Status  string // active, expired, used up, revoked
	Expires string // "in 23 hours", "Oct 31, 2026"
}

type enrollBody struct {
	Orgs      []store.Org
	Envs      map[string][]store.Env
	TTLs      any
	Error     string
	IngestURL string
	Form      struct {
		Env, Tags, Label, Expires, Uses string
		Approval                        bool
	}
	Keys     []enrollRow
	Awaiting []store.AwaitingHost // enrolled hosts waiting for approval
	Notice   string
	// After creating a key:
	Created  bool
	Key      enrollRow
	Secret   string
	Version  string
	Unpinned bool
	Linux    string // paste on each server, then paste the key
	Many     string // an ssh loop from your machine: the key typed once
	Cloud    string // cloud-init user data (contains the key)
	Windows  string
}

// newEnrollBody is the page with the form's defaults: 24 hours, approval on.
func newEnrollBody() enrollBody {
	var body enrollBody
	body.Form.Expires, body.Form.Approval = "24h", true
	return body
}

func (s *server) enrollPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderEnroll(w, r, v, http.StatusOK, newEnrollBody())
}

func (s *server) renderEnroll(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, body enrollBody) {
	orgs, envs, err := s.adminOrgs(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if len(orgs) == 0 {
		s.notFound(w, r, v) // only org admins add hosts
		return
	}
	keys, err := s.st.ListEnrollKeys(r.Context(), "")
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	now := s.now()
	for _, k := range keys {
		if v.Scope.CanAdmin(k.OrgID) {
			body.Keys = append(body.Keys, enrollRow{k, k.Status(now), expiresIn(k.ExpiresAt, now)})
		}
	}
	awaiting, err := s.st.AwaitingHosts(r.Context(), "")
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	for _, h := range awaiting {
		if v.Scope.CanAdmin(h.OrgID) {
			body.Awaiting = append(body.Awaiting, h)
		}
	}
	body.Orgs, body.Envs, body.TTLs, body.IngestURL = orgs, envs, enrollTTLs, s.cfg.IngestURL
	s.render(w, r, status, "enroll", v, "Add servers", "hosts", body)
}

func (s *server) enrollSubmit(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	f := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	var body enrollBody
	body.Form.Env, body.Form.Tags, body.Form.Label, body.Form.Expires, body.Form.Uses = f("env"), f("tags"), f("label"), f("expires"), f("uses")
	body.Form.Approval = r.PostForm.Get("approval") != ""
	org, env, _ := strings.Cut(body.Form.Env, "/")
	if o, err := s.orgBySlug(r, org); err != nil || !v.Scope.CanAdmin(o.ID) {
		s.notFound(w, r, v)
		return
	}
	bad := func(msg string) {
		body.Error = msg
		s.renderEnroll(w, r, v, http.StatusBadRequest, body)
	}
	var ttl time.Duration
	for _, t := range enrollTTLs {
		if t.Value == body.Form.Expires {
			ttl = t.TTL
		}
	}
	if ttl == 0 {
		bad("Choose when the key expires.")
		return
	}
	uses := 0
	if body.Form.Uses != "" {
		n, err := strconv.Atoi(body.Form.Uses)
		if err != nil || n < 0 {
			bad("Servers must be a whole number, or blank for no limit.")
			return
		}
		uses = n
	}
	var tags []string
	for t := range strings.SplitSeq(body.Form.Tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	now := s.now()
	k, key, err := s.st.CreateEnrollKey(r.Context(), actorOf(v), org, env,
		store.NewEnrollKey{Label: body.Form.Label, Tags: tags, MaxUses: uses, TTL: ttl, Approval: body.Form.Approval}, now)
	if err != nil {
		bad(userError(err))
		return
	}
	body.Created, body.Key, body.Secret = true, enrollRow{k, k.Status(now), expiresIn(k.ExpiresAt, now)}, key
	base, hub := s.installURLs(&body.Version, &body.Unpinned)
	body.Linux = fmt.Sprintf("curl -fsSLO %s/install.sh && sudo sh install.sh --hub %s --enroll", base, hub)
	body.Many = fmt.Sprintf(`read -rs KEY   # paste the key (it isn't shown), then Enter
for h in web-01 web-02 web-03; do
  printf '%%s\n' "$KEY" | ssh "$h" 'cd "$(mktemp -d)" && curl -fsSLO %s/install.sh && sudo sh install.sh --hub %s --enroll-stdin'
done
unset KEY`, base, hub)
	body.Cloud = fmt.Sprintf("#cloud-config\nruncmd:\n  - [sh, -c, \"cd /root && curl -fsSLO %s/install.sh && printf '%%s\\\\n' '%s' | sh install.sh --hub %s --enroll-stdin\"]",
		base, key, hub)
	body.Windows = fmt.Sprintf("foreach ($f in 'install-windows.ps1','collect.ps1','SHA256SUMS') { Invoke-WebRequest -UseBasicParsing %s/$f -OutFile $f }\n.\\install-windows.ps1 -HubUrl %s -Enroll",
		base, hub)
	s.renderEnroll(w, r, v, http.StatusOK, body)
}

func (s *server) enrollRevoke(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	org := r.PostForm.Get("org")
	id, err := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
	if o, oerr := s.orgBySlug(r, org); err != nil || oerr != nil || !v.Scope.CanAdmin(o.ID) {
		s.notFound(w, r, v)
		return
	}
	if err := s.st.RevokeEnrollKey(r.Context(), actorOf(v), org, id); err != nil {
		body := newEnrollBody()
		body.Error = userError(err)
		s.renderEnroll(w, r, v, http.StatusBadRequest, body)
		return
	}
	http.Redirect(w, r, "/hosts/enroll", http.StatusSeeOther)
}

// enrollDecide approves or rejects (removes) a host waiting for approval.
func (s *server) enrollDecide(approve bool) func(http.ResponseWriter, *http.Request, *auth.Viewer) {
	return func(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
		org, host := r.PostForm.Get("org"), r.PostForm.Get("host")
		if o, err := s.orgBySlug(r, org); err != nil || !v.Scope.CanAdmin(o.ID) {
			s.notFound(w, r, v)
			return
		}
		decide, notice := s.st.RejectHost, host+" was rejected and removed."
		if approve {
			decide, notice = s.st.ApproveHost, host+" is approved. Its next report, within the hour, is stored."
		}
		body := newEnrollBody()
		if err := decide(r.Context(), actorOf(v), org, host); err != nil {
			body.Error = userError(err)
			s.renderEnroll(w, r, v, http.StatusBadRequest, body)
			return
		}
		body.Notice = notice
		s.renderEnroll(w, r, v, http.StatusOK, body)
	}
}

// expiresIn is when a key stops working, for people: "in 40 minutes",
// "in 23 hours", or a date further out (or for one already past).
func expiresIn(t, now time.Time) string {
	d := t.Sub(now)
	switch {
	case d <= 0:
		return t.Local().Format("Jan 2, 2006")
	case d < time.Hour:
		return "in " + plural(int(d.Minutes())+1, "minute", "minutes")
	case d < 48*time.Hour:
		return "in " + plural(int(d.Hours()), "hour", "hours")
	}
	return t.Local().Format("Jan 2, 2006")
}
