// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"errors"
	"testing"
	"time"
)

var newsNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

const testSource = "https://news.example.test/incidents.json"

func testNewsItems() []NewsItem {
	closed := newsNow.Add(-24 * time.Hour)
	return []NewsItem{
		{Slug: "ssl-overflow", Category: "patch", Title: "SSL overflow", URL: "https://news.example.test/i/ssl",
			Severity: "critical", PatchStatus: "patched", Status: "live", CVEs: []string{"CVE-2099-0001", "CVE-2099-0002"},
			StartedAt: newsNow.Add(-48 * time.Hour), UpdatedAt: newsNow},
		{Slug: "widget-breach", Category: "breach", Title: "Widget breach", URL: "https://news.example.test/i/w",
			Severity: "high", Status: "closed", StartedAt: newsNow.Add(-72 * time.Hour), UpdatedAt: closed, ClosedAt: &closed},
	}
}

// addFindingHost adds org/host with one open finding on advisory id (whose
// aliases are given) and returns the host.
func addFindingHost(t *testing.T, s *Store, org, host, advisory string, aliases ...string) IngestHost {
	t.Helper()
	ctx := t.Context()
	s.CreateOrg(ctx, "test", org, "")
	s.CreateEnv(ctx, "test", org, "prod", "")
	if _, _, err := s.AddHost(ctx, "test", org, "prod", host, nil); err != nil {
		t.Fatal(err)
	}
	h, err := s.HostByName(ctx, org, host)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutAdvisory(ctx, Advisory{ID: advisory, Modified: newsNow, Severity: "high", Raw: []byte(`{}`), Aliases: aliases}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SetFindings(ctx, h.ID, []Finding{{AdvisoryID: advisory, Ecosystem: "Debian:12", Package: "openssl", Version: "1"}}, newsNow); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestReplaceNewsKeepsIDsAndPrunes(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	if _, err := s.ReplaceNews(ctx, testSource, testNewsItems(), `"v1"`, "", newsNow); err != nil {
		t.Fatal(err)
	}
	all, err := s.News(ctx, AllScope)
	if err != nil || len(all) != 2 {
		t.Fatalf("news %v %v", all, err)
	}
	if all[0].Slug != "ssl-overflow" || all[0].CVEs[1] != "CVE-2099-0002" || all[1].ClosedAt == nil {
		t.Errorf("newest first, fields round-trip: %+v", all)
	}
	firstID := all[0].ID
	if etag, _, _ := s.NewsValidators(ctx, testSource); etag != `"v1"` {
		t.Errorf("etag %q", etag)
	}

	// A refresh updates in place and removes what the feed dropped.
	items := testNewsItems()[:1]
	items[0].Title = "SSL overflow (updated)"
	removed, err := s.ReplaceNews(ctx, testSource, items, `"v2"`, "", newsNow)
	if err != nil || removed != 1 {
		t.Fatalf("removed %d %v", removed, err)
	}
	all, _ = s.News(ctx, AllScope)
	if len(all) != 1 || all[0].ID != firstID || all[0].Title != "SSL overflow (updated)" {
		t.Errorf("after refresh: %+v", all)
	}

	// Invalid items are refused as a whole, leaving the stored copy.
	bad := testNewsItems()
	bad[1].URL = "http://news.example.test/i/w"
	var verr *ValidationError
	if _, err := s.ReplaceNews(ctx, testSource, bad, "", "", newsNow); !errors.As(err, &verr) {
		t.Errorf("http URL: %v", err)
	}
	if all, _ = s.News(ctx, AllScope); len(all) != 1 {
		t.Errorf("failed replace changed the store: %d items", len(all))
	}

	// Closed incidents go after the retention period; live ones stay.
	s.ReplaceNews(ctx, testSource, testNewsItems(), "", "", newsNow)
	if n, err := s.PruneNews(ctx, newsNow); err != nil || n != 1 {
		t.Errorf("pruned %d %v", n, err)
	}
	// Sources no longer configured are dropped.
	if n, err := s.DeleteNewsExcept(ctx, []string{"https://other.example/x.json"}); err != nil || n != 1 {
		t.Errorf("deleted %d %v", n, err)
	}
	if etag, _, _ := s.NewsValidators(ctx, testSource); etag != "" {
		t.Errorf("validators kept for a removed source: %q", etag)
	}
}

func TestMatchNews(t *testing.T) {
	t.Parallel()
	s := newStore(t)
	ctx := t.Context()
	// acme's host has the CVE as an alias of a distro advisory; globex's
	// has the CVE itself as the advisory ID.
	web := addFindingHost(t, s, "acme", "web-01", "DEBIAN-CVE-2099-0001", "CVE-2099-0001")
	db := addFindingHost(t, s, "globex", "db-01", "CVE-2099-0002")
	if _, err := s.ReplaceNews(ctx, testSource, testNewsItems(), "", "", newsNow); err != nil {
		t.Fatal(err)
	}
	if err := s.MatchNews(ctx, 0, newsNow); err != nil {
		t.Fatal(err)
	}
	all, _ := s.News(ctx, AllScope)
	if len(all[0].Hosts) != 2 || all[0].Hosts[0].Name != "web-01" || all[0].Hosts[0].Reason != "CVE-2099-0001" ||
		all[0].Hosts[1].Name != "db-01" || len(all[1].Hosts) != 0 {
		t.Fatalf("matches: %+v", all)
	}

	// Scope: an acme viewer never sees globex's host in a badge.
	acme := Scope{Orgs: map[int64]Role{web.OrgID: RoleViewer}}
	mine, _ := s.News(ctx, acme)
	if len(mine[0].Hosts) != 1 || mine[0].Hosts[0].Name != "web-01" {
		t.Errorf("scoped hosts: %+v", mine[0].Hosts)
	}
	if hn, _ := s.HostNews(ctx, db.ID); len(hn) != 1 || hn[0].Slug != "ssl-overflow" {
		t.Errorf("host news: %+v", hn)
	}

	// The live incident boosts the finding.
	fs, err := s.OpenFindings(ctx, web.ID)
	if err != nil || len(fs) != 1 || !fs[0].InNews {
		t.Errorf("in news: %+v %v", fs, err)
	}

	// Patching web-01 resolves the finding and drops its match on the next
	// evaluation; db-01 keeps its own.
	if _, _, err := s.SetFindings(ctx, web.ID, nil, newsNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := s.MatchNews(ctx, web.ID, newsNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	all, _ = s.News(ctx, AllScope)
	if len(all[0].Hosts) != 1 || all[0].Hosts[0].Name != "db-01" {
		t.Errorf("after patch: %+v", all[0].Hosts)
	}
	if hn, _ := s.HostNews(ctx, web.ID); len(hn) != 0 {
		t.Errorf("patched host still in the news: %+v", hn)
	}
}

func TestNewsRanksFindings(t *testing.T) {
	t.Parallel()
	fs := []ReportFinding{
		{AdvisoryID: "A", Severity: "critical", FixedVersion: "2"},
		{AdvisoryID: "B", Severity: "low", InNews: true},
		{AdvisoryID: "C", Severity: "low", KEV: true},
	}
	sortFindings(fs)
	if fs[0].AdvisoryID != "C" || fs[1].AdvisoryID != "B" || fs[2].AdvisoryID != "A" {
		t.Errorf("order %v %v %v: want KEV, then in the news, then the rest", fs[0].AdvisoryID, fs[1].AdvisoryID, fs[2].AdvisoryID)
	}
}
