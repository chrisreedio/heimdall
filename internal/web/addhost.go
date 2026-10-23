// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/chrisreedio/heimdall/internal/auth"
	"github.com/chrisreedio/heimdall/internal/store"
)

// Releases is where install commands download from. Never the hub: a
// compromised hub must not be able to hand servers code to run.
const Releases = "https://github.com/chrisreedio/heimdall/releases/download"

var releaseTag = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

type addHostBody struct {
	Orgs      []store.Org
	Envs      map[string][]store.Env // org slug → envs
	Error     string
	IngestURL string
	Form      struct{ Name, Tags, Env string } // kept when the form is shown again
	// After a successful add:
	Added    bool
	Host     store.Host
	Token    string
	Version  string // release tag the commands install
	Unpinned bool   // this build has no release tag; edit the version in the commands
	Linux    string
	Cloud    string
	Windows  string
}

// adminOrgs lists orgs where the viewer may add hosts.
func (s *server) adminOrgs(r *http.Request, v *auth.Viewer) ([]store.Org, map[string][]store.Env, error) {
	all, err := s.st.ListOrgs(r.Context())
	if err != nil {
		return nil, nil, err
	}
	var orgs []store.Org
	envs := map[string][]store.Env{}
	for _, o := range all {
		if !v.Scope.CanAdmin(o.ID) {
			continue
		}
		es, err := s.st.ListEnvs(r.Context(), o.Slug)
		if err != nil {
			return nil, nil, err
		}
		orgs, envs[o.Slug] = append(orgs, o), es
	}
	return orgs, envs, nil
}

func (s *server) addHostPage(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	s.renderAddHost(w, r, v, http.StatusOK, addHostBody{})
}

func (s *server) renderAddHost(w http.ResponseWriter, r *http.Request, v *auth.Viewer, status int, body addHostBody) {
	orgs, envs, err := s.adminOrgs(r, v)
	if err != nil {
		s.fail(w, r, v, err)
		return
	}
	if len(orgs) == 0 {
		s.notFound(w, r, v) // only org admins add hosts
		return
	}
	body.Orgs, body.Envs, body.IngestURL = orgs, envs, s.cfg.IngestURL
	s.render(w, r, status, "addhost", v, "Add a host", "hosts", body)
}

func (s *server) addHostSubmit(w http.ResponseWriter, r *http.Request, v *auth.Viewer) {
	f := func(k string) string { return strings.TrimSpace(r.PostForm.Get(k)) }
	org, env := f("org"), f("env")
	// The form sends "org/env"; a bare env with a separate org also works.
	if o, e, ok := strings.Cut(env, "/"); ok {
		org, env = o, e
	}
	if o, err := s.orgBySlug(r, org); err != nil || !v.Scope.CanAdmin(o.ID) {
		s.notFound(w, r, v)
		return
	}
	var tags []string
	for t := range strings.SplitSeq(f("tags"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	host, token, err := s.st.AddHost(r.Context(), actorOf(v), org, env, f("name"), tags)
	if err != nil {
		body := addHostBody{Error: userError(err)}
		body.Form.Name, body.Form.Tags, body.Form.Env = f("name"), f("tags"), org+"/"+env
		s.renderAddHost(w, r, v, http.StatusBadRequest, body)
		return
	}
	body := addHostBody{Added: true, Host: host, Token: token, Version: s.cfg.Version}
	if !releaseTag.MatchString(body.Version) {
		body.Version, body.Unpinned = "vX.Y.Z", true
	}
	hub := s.cfg.IngestURL
	if hub == "" {
		hub = "https://ingest.example.com"
	}
	base := Releases + "/" + body.Version
	body.Linux = fmt.Sprintf("curl -fsSLO %s/install.sh && sudo sh install.sh --hub %s", base, hub)
	body.Cloud = fmt.Sprintf("#cloud-config\nruncmd:\n  - [sh, -c, \"cd /root && curl -fsSLO %s/install.sh && printf '%%s\\\\n' '%s' | sh install.sh --hub %s --token-stdin\"]",
		base, token, hub)
	body.Windows = fmt.Sprintf("foreach ($f in 'install-windows.ps1','collect.ps1','SHA256SUMS') { Invoke-WebRequest -UseBasicParsing %s/$f -OutFile $f }\n.\\install-windows.ps1 -HubUrl %s",
		base, hub)
	s.renderAddHost(w, r, v, http.StatusOK, body)
}
