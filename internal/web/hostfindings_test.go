// SPDX-License-Identifier: AGPL-3.0-or-later

package web

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

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
	pkgs := report.Pkgs{}
	for _, f := range list {
		pkgs[f.Package] = true // every package has an update pending
	}
	fv := buildFindingsView(base, "dpkg", url.Values{}, list, pkgs, kernelInfo{})
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
	fv = buildFindingsView(base, "dpkg", url.Values{"sev": {"critical"}, "fix": {"1"}, "page": {"9"}}, list, pkgs, kernelInfo{})
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
	fv = buildFindingsView(base, "dpkg", url.Values{"view": {"all"}, "page": {"2"}, "sev": {"<x>"}}, list, pkgs, kernelInfo{})
	if fv.View != "all" || len(fv.Rows) != findingsPerPage || fv.Page != 2 || fv.Sev != "" {
		t.Errorf("all view: rows=%d page=%d sev=%q", len(fv.Rows), fv.Page, fv.Sev)
	}
}

// planFix is the host page's patch command for findings on a host with
// these packages.
func planFix(pm string, list []report.Finding, pkgs report.Pkgs) (*command, int, int) {
	return fixCommand(pm, report.PlanUpgrade(pm, list, pkgs))
}

// pending marks every named package installed with an update pending.
func pending(names ...string) report.Pkgs {
	m := report.Pkgs{}
	for _, n := range names {
		m[n] = true
	}
	return m
}

func TestFixCommandUsesBinaryNames(t *testing.T) {
	list := []report.Finding{
		{Package: "openssl", Binaries: []string{"libssl3", "openssl"}, Fixed: "3.0.2-0ubuntu1.20"},
		{Package: "glibc", Binaries: []string{"libc6"}, Fixed: "2.35-0ubuntu3.9", FixPending: true},
		{Package: "perl", Fixed: ""}, // no fix: not included
		{Package: "evil; rm -rf /", Fixed: "1"},
	}
	pkgs := pending("libssl3", "openssl", "libc6", "perl", "evil; rm -rf /")
	cmd, n, fixPending := planFix("dpkg", list, pkgs)
	if cmd == nil || cmd.Text != "sudo apt-get update && sudo apt-get install --only-upgrade libc6 libssl3 openssl" || n != 3 || fixPending != 1 {
		t.Errorf("cmd=%+v n=%d pending=%d", cmd, n, fixPending)
	}
	if cmd, _, _ := planFix("pacman", list, pkgs); cmd != nil {
		t.Error("no command for package managers without one")
	}
}

func TestFixCommandKernel(t *testing.T) {
	set := pending
	awsKernel := report.Finding{Package: "linux-aws-6.17", Fixed: "6.17.0-1019.19~24.04.1",
		Binaries: []string{"linux-aws-6.17-headers-6.17.0-1009", "linux-headers-6.17.0-1009-aws", "linux-modules-6.17.0-1009-aws", "linux-tools-6.17.0-1009-aws"}}
	openssl := report.Finding{Package: "openssl", Fixed: "3.0.13-0ubuntu3.5", Binaries: []string{"libssl3", "openssl"}}
	aws := set("linux-aws", "linux-image-aws", "linux-headers-aws", "linux-image-6.17.0-1009-aws", "linux-modules-6.17.0-1009-aws",
		"linux-aws-6.17-headers-6.17.0-1009", "linux-headers-6.17.0-1009-aws", "linux-tools-6.17.0-1009-aws", "libssl3", "openssl")
	for _, c := range []struct {
		name, pm  string
		list      []report.Finding
		installed report.Pkgs
		want      string
		note      string
	}{
		{"ubuntu aws kernel only", "dpkg", []report.Finding{awsKernel}, aws,
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-aws linux-headers-aws linux-image-aws", "metapackage (linux-aws, linux-headers-aws, linux-image-aws)"},
		{"ubuntu aws mixed", "dpkg", []report.Finding{awsKernel, openssl}, aws,
			"sudo apt-get update && sudo apt-get install --only-upgrade libssl3 linux-aws linux-headers-aws linux-image-aws openssl", "Reboot afterwards"},
		{"ubuntu generic", "dpkg", []report.Finding{{Package: "linux", Fixed: "6.8.0-47.47", Binaries: []string{"linux-image-6.8.0-45-generic", "linux-libc-dev"}}},
			set("linux-generic", "linux-image-generic", "linux-image-6.8.0-45-generic", "linux-libc-dev"),
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-generic linux-image-generic linux-libc-dev", "Reboot afterwards"},
		{"ubuntu hwe", "dpkg", []report.Finding{{Package: "linux-hwe-6.11", Fixed: "6.11.0-31.31~24.04.1", Binaries: []string{"linux-hwe-6.11-headers-6.11.0-29"}}},
			set("linux-generic-hwe-24.04", "linux-image-generic-hwe-24.04", "linux-hwe-6.11-headers-6.11.0-29"),
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-generic-hwe-24.04 linux-image-generic-hwe-24.04", "Reboot afterwards"},
		{"debian", "dpkg", []report.Finding{{Package: "linux", Fixed: "6.1.115-1", Binaries: []string{"linux-image-6.1.0-26-amd64"}}},
			set("linux-image-amd64", "linux-image-6.1.0-26-amd64"),
			"sudo apt-get update && sudo apt-get install --only-upgrade linux-image-amd64", "linux-image-amd64"},
		{"no metapackage", "dpkg", []report.Finding{awsKernel, openssl}, set("linux-modules-6.17.0-1009-aws", "libssl3", "openssl"),
			"sudo apt-get update && sudo apt-get upgrade", "no kernel metapackage"},
		{"no kernel", "dpkg", []report.Finding{openssl}, aws, "sudo apt-get update && sudo apt-get install --only-upgrade libssl3 openssl", ""},
		{"rocky", "rpm", []report.Finding{{Package: "kernel", Fixed: "5.14.0-503.14.1.el9_5", Binaries: []string{"kernel", "kernel-core", "kernel-modules"}}},
			set("kernel", "kernel-core", "kernel-modules"), "sudo dnf upgrade --refresh kernel kernel-core kernel-modules", "Reboot afterwards"},
		{"alpine", "apk", []report.Finding{{Package: "linux-lts", Fixed: "6.6.58-r0", Binaries: []string{"linux-lts"}}},
			set("linux-lts"), "sudo apk update && sudo apk upgrade linux-lts", "Reboot afterwards"},
	} {
		cmd, _, _ := planFix(c.pm, c.list, c.installed)
		if cmd == nil || cmd.Text != c.want {
			t.Errorf("%s: %+v, want %q", c.name, cmd, c.want)
			continue
		}
		if (c.note == "") != (cmd.Note == "") || !strings.Contains(cmd.Note, c.note) {
			t.Errorf("%s: note %q, want %q", c.name, cmd.Note, c.note)
		}
	}
}

func TestDayAgo(t *testing.T) {
	now := time.Date(2026, 10, 25, 15, 0, 0, 0, time.Local)
	at := func(y int, m time.Month, d int) *time.Time {
		v := time.Date(y, m, d, 9, 0, 0, 0, time.Local)
		return &v
	}
	plain := func(y int, m time.Month, d int) *time.Time { // a date without a time
		v := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
		return &v
	}
	for _, c := range []struct {
		t    *time.Time
		want string
	}{{at(2026, 10, 25), "Today 9:00 AM (6h ago)"}, {at(2026, 10, 24), "Yesterday 9:00 AM"}, {at(2026, 10, 22), "3 days ago"},
		{plain(2026, 10, 25), "today"}, {plain(2026, 10, 24), "yesterday"},
		{at(2026, 9, 1), "Sep 1, 2026"}, {at(2026, 11, 2), "Nov 2, 2026"}, {nil, ""}} {
		if got := dayAgo(c.t, now); got != c.want {
			t.Errorf("dayAgo(%v) = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestFullDateKeepsPlainDates(t *testing.T) {
	fullDate := funcs["fullDate"].(func(*time.Time) string)
	d := time.Date(2025, 2, 4, 0, 0, 0, 0, time.UTC) // a lifecycle date
	if got := fullDate(&d); got != "Tuesday, February 4, 2025" {
		t.Errorf("plain date shifted: %q", got)
	}
}
