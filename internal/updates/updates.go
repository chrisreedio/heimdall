// SPDX-License-Identifier: AGPL-3.0-or-later

// Package updates checks whether a newer Heimdall release exists, so the
// UI can tell admins. It only reads the latest release's version; the hub
// never downloads or installs anything itself (upgrades are a deliberate
// root action with the verified installer).
package updates

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/realmwatch/heimdall/internal/netx"
)

// LatestURL is GitHub's "latest release" API for this repository.
const LatestURL = "https://api.github.com/repos/realmwatch/heimdall/releases/latest"

var tagRe = regexp.MustCompile(`^v(\d{1,4})\.(\d{1,4})\.(\d{1,4})$`)

// Release is a newer version admins should know about.
type Release struct {
	Version string // e.g. v0.5.0
	URL     string // release notes
}

type Checker struct {
	HTTP    *netx.Client
	URL     string // LatestURL if empty
	Current string // this build's version; checks are skipped unless it's a release tag

	mu     sync.Mutex
	latest Release
}

// Enabled reports whether this build can be compared with releases.
func (c *Checker) Enabled() bool { return tagRe.MatchString(c.Current) }

// Check fetches the latest release and remembers it if it's newer.
func (c *Checker) Check(ctx context.Context) error {
	if !c.Enabled() {
		return nil
	}
	url := c.URL
	r, err := Latest(ctx, c.HTTP, url)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Version != "" && Newer(r.Version, c.Current) {
		c.latest = r
	} else {
		c.latest = Release{}
	}
	return nil
}

// ErrNoRelease means the latest release isn't a plain release of this repo.
var ErrNoRelease = errors.New("no usable latest release")

// Latest fetches the latest release from url (LatestURL if empty). Only
// plain vX.Y.Z tags whose release page is on this repo are accepted.
func Latest(ctx context.Context, hc *netx.Client, url string) (Release, error) {
	if url == "" {
		url = LatestURL
	}
	var r struct {
		TagName string `json:"tag_name"`
		HTMLURL string `json:"html_url"`
		Draft   bool   `json:"draft"`
		Pre     bool   `json:"prerelease"`
	}
	if err := hc.GetJSON(ctx, url, 1<<20, &r); err != nil {
		return Release{}, err
	}
	if r.Draft || r.Pre || !tagRe.MatchString(r.TagName) ||
		!strings.HasPrefix(r.HTMLURL, "https://github.com/realmwatch/heimdall/releases/") {
		return Release{}, ErrNoRelease
	}
	return Release{Version: r.TagName, URL: r.HTMLURL}, nil
}

// IsTag reports whether v is a plain release tag (vX.Y.Z).
func IsTag(v string) bool { return tagRe.MatchString(v) }

// Available returns a newer release, if one was found.
func (c *Checker) Available() (Release, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.latest, c.latest.Version != ""
}

// Newer reports whether release tag a is newer than b (both vX.Y.Z).
func Newer(a, b string) bool {
	ma, mb := tagRe.FindStringSubmatch(a), tagRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x > y
		}
	}
	return false
}

// Run checks shortly after start and then daily until ctx ends.
func (c *Checker) Run(ctx context.Context, logf func(string, ...any)) {
	if !c.Enabled() {
		return
	}
	t := time.NewTimer(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Check(ctx); err != nil {
				logf("update check failed", "err", err)
			} else if r, ok := c.Available(); ok {
				logf("a newer Heimdall release is available", "version", r.Version, "running", c.Current)
			}
			t.Reset(24 * time.Hour)
		}
	}
}
