// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"testing"
	"time"
)

// tallyOpen counts OpenFindings the slow way, as the reference.
func tallyOpen(t *testing.T, s *Store, hostID int64) map[string]FindingCounts {
	t.Helper()
	fs, err := s.OpenFindings(t.Context(), hostID)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]FindingCounts{}
	for _, f := range fs {
		c := out[f.SiteRoot]
		c.Total++
		if f.Dev { // npm dev dependencies count nowhere else
			c.Dev++
			out[f.SiteRoot] = c
			continue
		}
		if f.KEV {
			c.KEV++
		}
		switch f.Severity {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		default:
			c.Unknown++
		}
		if f.FixedVersion != "" {
			c.Fixable++
			if f.Severity == "critical" || f.Severity == "high" {
				c.FixUrgent++
			}
		} else {
			c.NoFix++
			if f.KEV || f.InNews || f.EPSS >= WatchEPSS {
				c.Watch++
			}
		}
		if f.FixPending {
			c.FixPending++
		}
		if f.InNews {
			c.InNews++
		}
		out[f.SiteRoot] = c
	}
	return out
}

func checkCounts(t *testing.T, s *Store, hostID int64, step string) map[string]FindingCounts {
	t.Helper()
	all, err := s.OpenFindingCounts(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	got, want := all[hostID], tallyOpen(t, s, hostID)
	if len(got) != len(want) {
		t.Fatalf("%s: tally %+v, want %+v", step, got, want)
	}
	for root, w := range want {
		if got[root] != w {
			t.Errorf("%s: site %q tally %+v, want %+v", step, root, got[root], w)
		}
	}
	return got
}

func TestFindingCountsStayCurrent(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	h := addFindingHost(t, s, "acme", "web-01", "DEBIAN-CVE-2099-0001", "CVE-2099-0001")
	other := addFindingHost(t, s, "acme", "web-02", "DEBIAN-CVE-2099-0009", "CVE-2099-0009")
	for _, a := range []Advisory{
		{ID: "CVE-2099-0002", Modified: newsNow, Severity: "critical", Raw: []byte(`{}`)},
		{ID: "GHSA-aaaa-bbbb-cccc", Modified: newsNow, Severity: "low", Raw: []byte(`{}`), Aliases: []string{"CVE-2099-0003"}},
		{ID: "OLD-0001", Modified: newsNow, Severity: "medium", Raw: []byte(`{}`)},
	} {
		if err := s.PutAdvisory(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	fs := []Finding{
		{AdvisoryID: "DEBIAN-CVE-2099-0001", Ecosystem: "Debian:12", Package: "openssl", Version: "1", FixedVersion: "2", FixPending: true},
		{AdvisoryID: "CVE-2099-0002", Ecosystem: "Debian:12", Package: "linux", Version: "6"},
		{AdvisoryID: "OLD-0001", Ecosystem: "Debian:12", Package: "bash", Version: "5", FixedVersion: "5.1"},
		{AdvisoryID: "GHSA-aaaa-bbbb-cccc", Ecosystem: "Packagist", Package: "laravel/framework", Version: "11", FixedVersion: "11.1", SiteRoot: "/srv/app"},
		// A critical, fixable, soon known-exploited npm dev dependency.
		{AdvisoryID: "CVE-2099-0002", Ecosystem: "npm", Package: "vite", Version: "5.0.10", FixedVersion: "5.0.12", SiteRoot: "/srv/app", Dev: true},
	}
	if _, _, err := s.SetFindings(ctx, h.ID, fs, newsNow); err != nil {
		t.Fatal(err)
	}
	c := checkCounts(t, s, h.ID, "after SetFindings")
	if c[""].Total != 3 || c[""].FixUrgent != 1 || c[""].FixPending != 1 || c["/srv/app"].Fixable != 1 {
		t.Errorf("tally %+v", c)
	}
	if a := c["/srv/app"]; a.Total != 2 || a.Dev != 1 || a.Critical != 0 || a.FixUrgent != 0 {
		t.Errorf("site tally with a dev finding %+v", a)
	}

	// The KEV catalog names an alias of one advisory and another's own ID.
	if err := s.ReplaceKEV(ctx, []KEVEntry{{CVE: "CVE-2099-0001", DateAdded: newsNow}, {CVE: "CVE-2099-0002", DateAdded: newsNow}}); err != nil {
		t.Fatal(err)
	}
	if c := checkCounts(t, s, h.ID, "after ReplaceKEV"); c[""].KEV != 2 || c["/srv/app"].KEV != 0 {
		t.Errorf("KEV after catalog refresh: %+v", c)
	}

	// A live incident naming the site advisory's CVE alias.
	items := testNewsItems()
	items[0].CVEs = []string{"CVE-2099-0003"}
	if _, err := s.ReplaceNews(ctx, testSource, items, "", "", newsNow); err != nil {
		t.Fatal(err)
	}
	if err := s.MatchNews(ctx, 0, newsNow); err != nil {
		t.Fatal(err)
	}
	if c := checkCounts(t, s, h.ID, "after MatchNews"); c["/srv/app"].InNews != 1 {
		t.Errorf("in the news: %+v", c)
	}

	// Patching resolves findings; the other host's tally is untouched.
	if _, _, err := s.SetFindings(ctx, h.ID, fs[1:2], newsNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c := checkCounts(t, s, h.ID, "after patching"); c[""].Total != 1 || c["/srv/app"].Total != 0 {
		t.Errorf("after patching: %+v", c)
	}
	if c := checkCounts(t, s, other.ID, "other host"); c[""].Watch != 0 {
		t.Errorf("other host watches %+v", c)
	}
	// An EPSS score crossing WatchEPSS puts a finding with no fix on watch.
	if err := s.PutEPSS(ctx, []EPSSScore{{CVE: "CVE-2099-0009", Score: WatchEPSS + 0.01, Date: newsNow}}); err != nil {
		t.Fatal(err)
	}
	if c := checkCounts(t, s, other.ID, "after PutEPSS"); c[""].Watch != 1 {
		t.Errorf("EPSS watch: %+v", c)
	}
	if err := s.RemoveHost(ctx, "test", "acme", "web-01"); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.OpenFindingCounts(ctx); all[h.ID] != nil {
		t.Error("removed host keeps its tally")
	}
}
