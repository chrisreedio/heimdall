// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// SiteReposHeader carries each site's git remote, read by the collector
// from the site's .git/config with any credentials stripped:
//
//	X-Heimdall-Site-Repos: v1 <root> <url>,<root> <url>
//
// "v1" alone means the collector looked and found none. It's a header, not
// a snapshot field, like the privilege watch's: the snapshot decoder
// rejects unknown fields, so a new field would make every older hub refuse
// a newer collector's push, while any hub ignores a header it doesn't know.
// Bad entries are dropped; they never fail the push. Without the header
// (an older collector), stored repositories are left as they are.
const SiteReposHeader = "X-Heimdall-Site-Repos"

const maxSiteReposHeader = 8 << 10

// parseSiteRepos parses a SiteReposHeader value. ok is false when the
// header is absent or malformed, so nothing should change.
func parseSiteRepos(v string) (repos map[string]string, ok bool) {
	if len(v) > maxSiteReposHeader {
		return nil, false
	}
	rest, found := strings.CutPrefix(v, "v1")
	if !found || (rest != "" && rest[0] != ' ') {
		return nil, false
	}
	repos = map[string]string{}
	for entry := range strings.SplitSeq(strings.TrimSpace(rest), ",") {
		root, u, ok := strings.Cut(strings.TrimSpace(entry), " ")
		if !ok || len(repos) == store.MaxDetectedRepos {
			continue
		}
		if _, dup := repos[root]; !dup {
			repos[root] = strings.TrimSpace(u) // normalized (or dropped) by the store
		}
	}
	return repos, true
}

func (h *Handler) recordSiteRepos(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(SiteReposHeader)
	if len(vals) != 1 {
		return
	}
	repos, ok := parseSiteRepos(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + SiteReposHeader + " header")
		return
	}
	if err := h.store.SetDetectedSiteRepos(ctx, host.ID, repos); err != nil {
		log.Warn("site repositories not recorded", "err", err)
	}
}
