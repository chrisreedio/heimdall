// SPDX-License-Identifier: AGPL-3.0-or-later

package ingest

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/realmwatch/heimdall/internal/store"
)

// SiteBranchesHeader carries each site's checked-out branch, read by the
// collector from the site's .git/HEAD only:
//
//	X-Heimdall-Site-Branches: v1 <root> branch:<name>,<root> commit:<sha>
//
// "commit:" is a detached HEAD. "v1" alone means the collector looked and
// found none, which is normal for zero-downtime deploys whose releases
// keep no .git. A header for the same reason as SiteReposHeader: the
// snapshot decoder rejects unknown fields, so a snapshot field would make
// every older hub refuse a newer collector's push. Bad entries are
// dropped; they never fail the push. Without the header (an older
// collector), stored branches are left as they are.
const SiteBranchesHeader = "X-Heimdall-Site-Branches"

// parseSiteBranches parses a SiteBranchesHeader value. ok is false when
// the header is malformed, so nothing should change. The root is
// everything before an entry's last space; the store validates each
// branch and commit.
func parseSiteBranches(v string) (refs map[string]store.DetectedRef, ok bool) {
	if len(v) > maxSiteReposHeader {
		return nil, false
	}
	rest, found := strings.CutPrefix(v, "v1")
	if !found || (rest != "" && rest[0] != ' ') {
		return nil, false
	}
	refs = map[string]store.DetectedRef{}
	for entry := range strings.SplitSeq(strings.TrimSpace(rest), ",") {
		entry = strings.TrimSpace(entry)
		i := strings.LastIndexByte(entry, ' ')
		if i <= 0 || len(refs) == store.MaxDetectedRepos {
			continue
		}
		root, ref := strings.TrimSpace(entry[:i]), entry[i+1:]
		if _, dup := refs[root]; dup {
			continue
		}
		if b, ok := strings.CutPrefix(ref, "branch:"); ok && b != "" {
			refs[root] = store.DetectedRef{Branch: b}
		} else if c, ok := strings.CutPrefix(ref, "commit:"); ok && c != "" {
			refs[root] = store.DetectedRef{Commit: c}
		}
	}
	return refs, true
}

func (h *Handler) recordSiteBranches(ctx context.Context, log *slog.Logger, host store.IngestHost, r *http.Request) {
	vals := r.Header.Values(SiteBranchesHeader)
	if len(vals) != 1 {
		return
	}
	refs, ok := parseSiteBranches(vals[0])
	if !ok {
		log.Warn("ignored a malformed " + SiteBranchesHeader + " header")
		return
	}
	if err := h.store.SetDetectedSiteBranches(ctx, host.ID, refs); err != nil {
		log.Warn("site branches not recorded", "err", err)
	}
}
