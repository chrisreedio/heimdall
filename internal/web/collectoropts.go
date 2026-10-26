// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"net/http"
	"strings"

	"github.com/realmwatch/heimdall/internal/auth"
	"github.com/realmwatch/heimdall/internal/store"
)

// installCmd is a Linux install command with the collector option flags
// in the middle. The template wraps Flags in a <span data-collector-flags>
// that app.js rewrites when an option checkbox changes, so the command
// changes in place and the token or key shown once is never reissued.
// Without JavaScript the command is the one rendered here.
type installCmd struct{ Pre, Flags, Post string }

func (c installCmd) String() string { return c.Pre + c.Flags + c.Post }

// collectorFlags are install.sh's flags for the options, in the order
// app.js writes them. --watch-privilege-users implies --watch-privilege.
// An option left off adds nothing (rather than --no-...), so re-running a
// command on a server that already reports keeps what it has.
func collectorFlags(d store.CollectorDefaults) string {
	var b strings.Builder
	if d.WatchPrivilegeUsers {
		b.WriteString(" --watch-privilege-users")
	}
	if d.WatchLogins {
		b.WriteString(" --watch-logins")
	}
	return b.String()
}

// collectorForm reads the collector options from a submitted form: the
// checkboxes when the form had them (opts=1), otherwise the org's
// default. remember asks to store them as the org's default.
func collectorForm(r *http.Request, def store.CollectorDefaults) (d store.CollectorDefaults, remember bool) {
	if r.PostForm.Get("opts") == "" {
		return def, false
	}
	d.WatchPrivilegeUsers = r.PostForm.Get("watch_privilege_users") != ""
	d.WatchLogins = r.PostForm.Get("watch_logins") != ""
	return d, r.PostForm.Get("remember_opts") != ""
}

// rememberCollector saves the options as the org's default (audited)
// when the form asked to, after the host or key was created. Only org
// admins reach the pages that call it. A failure here mustn't hide the
// token or key just issued, so it comes back as a message for the page.
func (s *server) rememberCollector(r *http.Request, v *auth.Viewer, org store.Org, d store.CollectorDefaults, remember bool) (saved bool, msg string) {
	if !remember {
		return false, ""
	}
	if d == org.Collector {
		return true, ""
	}
	if err := s.st.SetCollectorDefaults(r.Context(), actorOf(v), org.Slug, d); err != nil {
		s.log.Error("save collector defaults", "org", org.Slug, "err", err)
		return false, "The collector options weren't saved as " + org.Slug + "'s default: " + userError(err)
	}
	return true, ""
}

// formOrgDefaults is the collector default of the org a form's "org/env"
// value names, or of the first org.
func formOrgDefaults(orgs []store.Org, env string) store.CollectorDefaults {
	slug, _, _ := strings.Cut(env, "/")
	for _, o := range orgs {
		if o.Slug == slug {
			return o.Collector
		}
	}
	if len(orgs) > 0 {
		return orgs[0].Collector
	}
	return store.CollectorDefaults{WatchPrivilegeUsers: true, WatchLogins: true}
}
