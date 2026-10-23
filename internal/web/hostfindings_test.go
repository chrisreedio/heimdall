// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/chrisreedio/heimdall/internal/report"
)

func TestFindingsView(t *testing.T) {
	var list []report.Finding
	for i := range 120 { // 120 packages x 2 findings
		sev := []string{"low", "medium", "high", "critical"}[i%4]
		fixed := ""
		if i%3 == 0 {
			fixed = "2.0"
		}
		for j := range 2 {
			list = append(list, report.Finding{Package: fmt.Sprintf("pkg-%03d", i), Version: "1.0", Severity: sev,
				CVEs: []string{fmt.Sprintf("CVE-2026-%d", i*10+j)}, Fixed: fixed, KEV: i == 7})
		}
	}
	base := "/hosts/acme/web-01"
	fv := buildFindingsView(base, "dpkg", url.Values{}, list)
	if fv.View != "packages" || fv.Total != 240 || fv.Pages != 3 || len(fv.Groups) != findingsPerPage {
		t.Fatalf("default view: %s total=%d pages=%d groups=%d", fv.View, fv.Total, fv.Pages, len(fv.Groups))
	}
	if g := fv.Groups[0]; g.Package != "pkg-007" || g.KEV != 2 || g.Total != 2 {
		t.Errorf("known-exploited package should sort first: %+v", g)
	}
	if fv.Groups[1].Worst != "critical" {
		t.Errorf("then worst severity: %+v", fv.Groups[1])
	}
	if fv.NextLink != base+"?page=2#findings" || fv.PrevLink != "" {
		t.Errorf("paging links: next=%q prev=%q", fv.NextLink, fv.PrevLink)
	}
	// Filters combine, and changing one goes back to page 1.
	fv = buildFindingsView(base, "dpkg", url.Values{"sev": {"critical"}, "fix": {"1"}, "page": {"9"}}, list)
	// The patch command covers exactly the filtered, fixable packages.
	if fv.FixCmd == nil || !strings.HasPrefix(fv.FixCmd.Text, "sudo apt-get update && sudo apt-get install --only-upgrade pkg-003 ") || strings.Contains(fv.FixCmd.Text, "pkg-000") {
		t.Errorf("fix command = %+v", fv.FixCmd)
	}
	for _, g := range fv.Groups {
		if g.Worst != "critical" || g.Fixable != g.Total {
			t.Errorf("filtered group %+v", g)
		}
	}
	if fv.Page != fv.Pages {
		t.Errorf("out-of-range page should clamp: %d of %d", fv.Page, fv.Pages)
	}
	if l := fv.SevLinks["critical"]; strings.Contains(l, "sev=") || !strings.Contains(l, "fix=1") {
		t.Errorf("the active severity chip should clear it and keep fix: %q", l)
	}
	if l := fv.SevLinks["high"]; !strings.Contains(l, "sev=high") || strings.Contains(l, "page=") {
		t.Errorf("another chip: %q", l)
	}
	// All findings, a page at a time; junk parameters are ignored.
	fv = buildFindingsView(base, "dpkg", url.Values{"view": {"all"}, "page": {"2"}, "sev": {"<x>"}}, list)
	if fv.View != "all" || len(fv.Rows) != findingsPerPage || fv.Page != 2 || fv.Sev != "" {
		t.Errorf("all view: rows=%d page=%d sev=%q", len(fv.Rows), fv.Page, fv.Sev)
	}
}

func TestFixCommandUsesBinaryNames(t *testing.T) {
	list := []report.Finding{
		{Package: "openssl", Binaries: []string{"libssl3", "openssl"}, Fixed: "3.0.2-0ubuntu1.20"},
		{Package: "glibc", Binaries: []string{"libc6"}, Fixed: "2.35-0ubuntu3.9", FixPending: true},
		{Package: "perl", Fixed: ""}, // no fix: not included
		{Package: "evil; rm -rf /", Fixed: "1"},
	}
	cmd, n, pending := fixCommand("dpkg", list)
	if cmd == nil || cmd.Text != "sudo apt-get update && sudo apt-get install --only-upgrade libc6 libssl3 openssl" || n != 3 || pending != 1 {
		t.Errorf("cmd=%+v n=%d pending=%d", cmd, n, pending)
	}
	if cmd, _, _ := fixCommand("pacman", list); cmd != nil {
		t.Error("no command for package managers without one")
	}
}
