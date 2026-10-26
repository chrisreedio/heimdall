// SPDX-License-Identifier: AGPL-3.0-or-later

package snapshot

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Limits for v2 site data.
const (
	MaxSites            = 200
	MaxServerNames      = 50
	MaxComposerPackages = 3000
)

// Site is a web app the collector found on the host (format v2).
type Site struct {
	Root             string            `json:"root"`          // app root, absolute path
	DocumentRoot     string            `json:"document_root"` // as configured in the web server
	ServerNames      []string          `json:"server_names"`
	WebServer        string            `json:"web_server"`      // "nginx", "apache", or "" if listed in HEIMDALL_SITES
	PHPFPMVersion    string            `json:"php_fpm_version"` // e.g. "8.3"; "" if unknown
	Readable         bool              `json:"readable"`        // the collector could read composer.json/lock
	Framework        string            `json:"framework"`       // "laravel" or ""
	FrameworkVersion string            `json:"framework_version"`
	PHPRequirement   string            `json:"php_requirement"` // composer.json require.php, e.g. "^8.2"
	DeployedAt       *time.Time        `json:"deployed_at"`     // composer.lock mtime
	ComposerPackages []ComposerPackage `json:"composer_packages"`
	// NpmPackages is v4 only: the app root's package-lock.json. Must be
	// absent before v4; omitempty keeps older documents' inventory hashes.
	NpmPackages []NpmPackage `json:"npm_packages,omitempty"`
}

// ComposerPackage is one entry from composer.lock (packages and packages-dev).
type ComposerPackage struct {
	Name    string `json:"name"` // vendor/package
	Version string `json:"version"`
}

var (
	WebServers = []string{"", "nginx", "apache"}
	Frameworks = []string{"", "laravel"}
)

var (
	// Absolute path: conservative charset, no "..", no "//".
	sitePathRe   = regexp.MustCompile(`^/[A-Za-z0-9._@+-]+(/[A-Za-z0-9._@+-]+)*$|^/$`)
	serverNameRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)*$`)
	phpMinorRe   = regexp.MustCompile(`^[0-9]\.[0-9]{1,2}$`)
	composerName = regexp.MustCompile(`^[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*$`)
	composerVer  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,99}$`)
	phpReqRe     = regexp.MustCompile(`^[0-9A-Za-z .,|<>=^~*@-]{0,100}$`)
)

func validSitePath(p string) bool {
	if len(p) > 512 || !sitePathRe.MatchString(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == ".." || part == "." {
			return false
		}
	}
	return true
}

func validServerName(n string) bool {
	return n == "_" || n == "localhost" || serverNameRe.MatchString(n)
}

// validateSites applies the v2 rules; v1 documents must carry no sites.
func validateSites(s *Snapshot, unavailable map[string]bool, bad func(field, format string, a ...any)) {
	if s.Format == FormatV1 {
		if s.Sites != nil {
			bad("sites", "not allowed in %s", FormatV1)
		}
		if unavailable["sites"] {
			bad("unavailable", "\"sites\" is not a %s check", FormatV1)
		}
		return
	}
	switch {
	case unavailable["sites"]:
		if len(s.Sites) > 0 {
			bad("sites", "must be empty when listed in unavailable")
		}
		return
	case s.Sites == nil:
		bad("sites", "required in %s (use [] for none, or list \"sites\" as unavailable)", FormatV2)
		return
	case len(s.Sites) > MaxSites:
		bad("sites", "too many (%d > %d)", len(s.Sites), MaxSites)
		return
	}

	roots := make(map[string]bool, len(s.Sites))
	for i, site := range s.Sites {
		f := fmt.Sprintf("sites[%d]", i)
		if !validSitePath(site.Root) {
			bad(f+".root", "invalid path %s", quote(site.Root))
		} else if roots[site.Root] {
			bad(f+".root", "duplicate root %s", quote(site.Root))
		}
		roots[site.Root] = true
		if site.DocumentRoot != "" && !validSitePath(site.DocumentRoot) {
			bad(f+".document_root", "invalid path %s", quote(site.DocumentRoot))
		}
		if len(site.ServerNames) > MaxServerNames {
			bad(f+".server_names", "too many (%d > %d)", len(site.ServerNames), MaxServerNames)
		} else {
			for j, n := range site.ServerNames {
				if !validServerName(n) {
					bad(fmt.Sprintf("%s.server_names[%d]", f, j), "invalid server name %s", quote(n))
				}
			}
		}
		if !slices.Contains(WebServers, site.WebServer) {
			bad(f+".web_server", "must be nginx, apache or empty, got %s", quote(site.WebServer))
		}
		if site.PHPFPMVersion != "" && !phpMinorRe.MatchString(site.PHPFPMVersion) {
			bad(f+".php_fpm_version", "invalid value %s", quote(site.PHPFPMVersion))
		}
		if !slices.Contains(Frameworks, site.Framework) {
			bad(f+".framework", "must be laravel or empty, got %s", quote(site.Framework))
		}
		if site.FrameworkVersion != "" && !composerVer.MatchString(site.FrameworkVersion) {
			bad(f+".framework_version", "invalid value %s", quote(site.FrameworkVersion))
		}
		if !phpReqRe.MatchString(site.PHPRequirement) {
			bad(f+".php_requirement", "invalid value %s", quote(site.PHPRequirement))
		}
		if site.DeployedAt != nil {
			if y := site.DeployedAt.Year(); y < 1990 || y > 2100 {
				bad(f+".deployed_at", "implausible time")
			}
		}
		if !site.Readable && (site.Framework != "" || site.FrameworkVersion != "" ||
			site.PHPRequirement != "" || site.DeployedAt != nil || len(site.ComposerPackages) > 0) {
			bad(f, "composer data present but readable is false")
		}
		validateNpm(s, f, site, bad)
		if len(site.ComposerPackages) > MaxComposerPackages {
			bad(f+".composer_packages", "too many (%d > %d)", len(site.ComposerPackages), MaxComposerPackages)
			continue
		}
		seen := make(map[string]bool, len(site.ComposerPackages))
		for j, p := range site.ComposerPackages {
			pf := fmt.Sprintf("%s.composer_packages[%d]", f, j)
			if !composerName.MatchString(p.Name) {
				bad(pf+".name", "invalid value %s", quote(p.Name))
			}
			if !composerVer.MatchString(p.Version) {
				bad(pf+".version", "invalid value %s", quote(p.Version))
			}
			if seen[p.Name] {
				bad(pf, "duplicate package %s", quote(p.Name))
			}
			seen[p.Name] = true
		}
	}
}
