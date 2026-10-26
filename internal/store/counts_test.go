// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/realmwatch/heimdall/internal/snapshot"
)

// oracleCountsSQL is countsSQL as it was before the kernel sets moved to
// indexed temp tables: ?2 is the sets as JSON ({"<host id>": {"old": [...],
// "boot": [...]}}), ?3 kernel.Userland's names, ?4 WatchEPSS. It's the
// reference the faster query must agree with.
const oracleCountsSQL = `
	WITH kev AS (
		SELECT k.cve_id AS id FROM kev_entries k
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN kev_entries k ON k.cve_id = aa.alias),
	news_cve AS (
		SELECT DISTINCT c.value AS cve FROM news_items n, json_each(n.cve_ids) c WHERE n.status = 'live'),
	news AS (
		SELECT cve AS id FROM news_cve
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN news_cve ON news_cve.cve = aa.alias),
	hot AS (
		SELECT e.cve_id AS id FROM epss_scores e WHERE e.score >= ?4
		UNION SELECT aa.advisory_id FROM advisory_aliases aa JOIN epss_scores e ON e.cve_id = aa.alias WHERE e.score >= ?4),
	ks AS (
		SELECT CAST(key AS INTEGER) AS host_id, json_extract(value, '$.old') AS old, json_extract(value, '$.boot') AS boot
		FROM json_each(?2)),
	fs AS (
		SELECT f.host_id, f.site_root, a.severity AS sev, f.dev AS dev,
		       coalesce(f.fixed_version, '') != '' AS fixable, f.fix_pending AS pending,
		       f.advisory_id IN (SELECT id FROM kev) AS kev, f.advisory_id IN (SELECT id FROM news) AS news,
		       f.advisory_id IN (SELECT id FROM hot) AS hot,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND h.dpkg AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(?3))
		           AND b.value NOT LIKE 'linux-source-%'), 0) AS ku,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND ks.old IS NOT NULL AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(ks.old))), 0) AS nr0,
		       coalesce(f.site_root = '' AND json_array_length(f.binaries) > 0 AND ks.boot IS NOT NULL AND NOT EXISTS (
		           SELECT 1 FROM json_each(f.binaries) b WHERE b.value NOT IN (SELECT value FROM json_each(ks.boot))), 0) AS rb
		FROM findings f JOIN advisories a INDEXED BY advisories_tally ON a.id = f.advisory_id
		LEFT JOIN ks ON ks.host_id = f.host_id
		JOIN (SELECT h.id, coalesce(s.package_manager = 'dpkg', 0) AS dpkg FROM hosts h
		      LEFT JOIN snapshots s ON s.id = h.last_snapshot_id WHERE ?1 = 0 OR h.id = ?1) h ON h.id = f.host_id
		WHERE f.resolved_at IS NULL AND a.withdrawn IS NULL),
	fk AS (SELECT *, nr0 AND NOT ku AS nr, ku OR nr0 OR dev AS off FROM fs)
	INSERT INTO finding_counts (host_id, site_root, total, kev, critical, high, medium, low, unknown,
	                            fixable, fix_pending, fix_urgent, in_news, not_running, reboot_pending, kernel_userland, watch, dev)
	SELECT host_id, site_root, count(*),
	       sum(kev AND NOT off),
	       sum(sev = 'critical' AND NOT dev), sum(sev = 'high' AND NOT dev), sum(sev = 'medium' AND NOT dev),
	       sum(sev = 'low' AND NOT dev), sum(sev NOT IN ('critical', 'high', 'medium', 'low') AND NOT dev),
	       sum(fixable AND NOT off), sum(pending AND NOT off),
	       sum(fixable AND NOT off AND sev IN ('critical', 'high')),
	       sum(news AND NOT dev), sum(nr), sum(rb AND NOT off), sum(ku),
	       sum(NOT fixable AND NOT off AND (kev OR news OR hot)), sum(dev)
	FROM fk
	GROUP BY host_id, site_root`

// oracleCounts rewrites finding_counts for hostID (0 = all) with the old query.
func oracleCounts(tb testing.TB, s *Store, hostID int64, sets map[int64]kernelSet) {
	tb.Helper()
	js := map[string]kernelSet{}
	for id, ks := range sets {
		if ks.Old == nil {
			ks.Old = []string{}
		}
		if ks.Boot == nil {
			ks.Boot = []string{}
		}
		js[strconv.FormatInt(id, 10)] = ks
	}
	b, _ := json.Marshal(js)
	err := s.tx(tb.Context(), func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(tb.Context(), `DELETE FROM finding_counts WHERE ?1 = 0 OR host_id = ?1`, hostID); err != nil {
			return err
		}
		_, err := tx.ExecContext(tb.Context(), oracleCountsSQL, hostID, string(b), userlandJSON, WatchEPSS)
		return err
	})
	if err != nil {
		tb.Fatal(err)
	}
}

// countRows is finding_counts, one line per row, in order.
func countRows(tb testing.TB, s *Store) []string {
	tb.Helper()
	rows, err := s.db.QueryContext(tb.Context(), `
		SELECT host_id, site_root, total, kev, critical, high, medium, low, unknown,
		       fixable, fix_pending, fix_urgent, in_news, not_running, reboot_pending, kernel_userland, watch, dev
		FROM finding_counts ORDER BY host_id, site_root`)
	if err != nil {
		tb.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var root string
		v := make([]int64, 17)
		if err := rows.Scan(&v[0], &root, &v[1], &v[2], &v[3], &v[4], &v[5], &v[6], &v[7], &v[8], &v[9], &v[10], &v[11],
			&v[12], &v[13], &v[14], &v[15], &v[16]); err != nil {
			tb.Fatal(err)
		}
		out = append(out, fmt.Sprintf("%d %q %v", v[0], root, v[1:]))
	}
	if err := rows.Err(); err != nil {
		tb.Fatal(err)
	}
	return out
}

func allKernelSets(tb testing.TB, s *Store, hostID int64) map[int64]kernelSet {
	tb.Helper()
	var sets map[int64]kernelSet
	if err := s.tx(tb.Context(), func(tx *sql.Tx) (err error) {
		sets, err = kernelSets(tb.Context(), tx, hostID)
		return err
	}); err != nil {
		tb.Fatal(err)
	}
	return sets
}

func recount(tb testing.TB, s *Store, hostID int64) {
	tb.Helper()
	if err := s.tx(tb.Context(), func(tx *sql.Tx) error { return refreshFindingCounts(tb.Context(), tx, hostID) }); err != nil {
		tb.Fatal(err)
	}
}

// addSnapshotHost adds host with the snapshot in ../snapshot/testdata/file.
func addSnapshotHost(t *testing.T, s *Store, host, file string) IngestHost {
	t.Helper()
	ctx := t.Context()
	if _, _, err := s.AddHost(ctx, "test", "acme", "prod", host, nil); err != nil {
		t.Fatal(err)
	}
	h, err := s.HostByName(ctx, "acme", host)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../snapshot/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := snapshot.DecodeBytes(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveReport(ctx, NewSnapshot{Host: h, Source: "push", ReceivedAt: newsNow, PayloadSHA256: sha256.Sum256(raw),
		Snapshot: snap}, nil); err != nil {
		t.Fatal(err)
	}
	return h
}

// The indexed temp tables count exactly what the JSON sets did, for one
// host or all of them: hosts with old kernels, a pending reboot, neither,
// and no dpkg, findings on every mix of kernel, userland and other
// packages, sites, npm dev dependencies, KEV, news and EPSS.
func TestFindingCountsMatchJSONSets(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	hosts := []IngestHost{
		addSnapshotHost(t, s, "web-01", "ubuntu2404-aws-reboot-pending.json"),
		addSnapshotHost(t, s, "web-02", "ubuntu2404-aws-old-kernel.json"),
		addSnapshotHost(t, s, "web-03", "debian12.json"),
		addSnapshotHost(t, s, "web-04", "alpine320.json"),
	}
	sets := allKernelSets(t, s, 0)
	if len(sets[hosts[0].ID].Boot) == 0 || len(sets[hosts[1].ID].Old) == 0 {
		t.Fatalf("fixture kernel sets: %+v", sets)
	}

	sevs := []string{"critical", "high", "medium", "low", "unknown"}
	var advs []string
	for i := range 10 {
		id := fmt.Sprintf("TEST-%04d", i)
		cve := fmt.Sprintf("CVE-2099-%04d", i)
		a := Advisory{ID: id, Modified: newsNow, Severity: sevs[i%len(sevs)], Raw: []byte(`{}`), Aliases: []string{cve}}
		if i == 9 {
			a.ID, a.Aliases = cve, nil // matched by its own ID
		}
		if err := s.PutAdvisory(ctx, a); err != nil {
			t.Fatal(err)
		}
		advs = append(advs, a.ID)
	}
	if err := s.ReplaceKEV(ctx, []KEVEntry{{CVE: "CVE-2099-0001", DateAdded: newsNow}, {CVE: "CVE-2099-0009", DateAdded: newsNow}}); err != nil {
		t.Fatal(err)
	}
	items := testNewsItems()
	items[0].CVEs = []string{"CVE-2099-0002", "CVE-2099-0006"}
	if _, err := s.ReplaceNews(ctx, testSource, items, "", "", newsNow); err != nil {
		t.Fatal(err)
	}
	if err := s.PutEPSS(ctx, []EPSSScore{{CVE: "CVE-2099-0003", Score: 0.5, Date: newsNow}, {CVE: "CVE-2099-0008", Score: 0.01, Date: newsNow}}); err != nil {
		t.Fatal(err)
	}

	for _, h := range hosts {
		ks := sets[h.ID]
		running := []string{"linux-modules-6.17.0-1009-aws"}
		bins := [][]string{
			ks.Old, ks.Boot, append(slices.Clone(ks.Old), ks.Boot...),
			firstN(ks.Old, 2), firstN(ks.Boot, 1), append(firstN(ks.Old, 1), "linux-tools-common"),
			{"linux-tools-common", "linux-source-6.8.0"}, {"linux-libc-dev"}, append(firstN(ks.Boot, 1), "libssl3"),
			running, {"libssl3"}, {}, append(firstN(ks.Old, 1), "libssl3"),
		}
		var fs []Finding
		for i, b := range bins {
			for j, adv := range advs {
				if (i+j)%3 == 0 {
					continue
				}
				f := Finding{AdvisoryID: adv, Ecosystem: "Ubuntu:24.04:LTS", Package: fmt.Sprintf("src-%d", i), Version: "1", Binaries: b}
				if j%2 == 0 {
					f.FixedVersion, f.FixPending = "2", j%4 == 0
				}
				fs = append(fs, f)
			}
		}
		for j, adv := range advs {
			fs = append(fs,
				Finding{AdvisoryID: adv, Ecosystem: "npm", Package: "vite", Version: "5", FixedVersion: "6", SiteRoot: "/srv/app", Dev: j%2 == 0},
				Finding{AdvisoryID: adv, Ecosystem: "Packagist", Package: "linux-thing", Version: "1", SiteRoot: "/srv/app", Binaries: ks.Old})
		}
		if _, _, err := s.SetFindings(ctx, h.ID, fs, newsNow); err != nil {
			t.Fatal(err)
		}
	}

	oracleCounts(t, s, 0, sets)
	want := countRows(t, s)
	if len(want) < 8 {
		t.Fatalf("oracle rows: %v", want)
	}
	recount(t, s, 0)
	if got := countRows(t, s); !slices.Equal(got, want) {
		t.Errorf("all hosts:\n got %v\nwant %v", got, want)
	}
	// One host at a time, after the other hosts' sets were in the tables.
	for _, h := range hosts {
		recount(t, s, h.ID)
	}
	if got := countRows(t, s); !slices.Equal(got, want) {
		t.Errorf("per host:\n got %v\nwant %v", got, want)
	}
	// And they really count something.
	all, _ := s.OpenFindingCounts(ctx)
	if c := all[hosts[1].ID][""]; c.NotRunning == 0 || c.KernelUserland == 0 {
		t.Errorf("old-kernel host: %+v", c)
	}
	if c := all[hosts[0].ID][""]; c.RebootPending == 0 {
		t.Errorf("reboot-pending host: %+v", c)
	}
	if c := all[hosts[3].ID][""]; c.KernelUserland != 0 || c.NotRunning != 0 {
		t.Errorf("non-dpkg host: %+v", c)
	}
	// The connection's temp tables are left empty.
	for _, tb := range []string{"kernel_old", "kernel_boot", "kernel_userland"} {
		var n int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM temp.`+tb).Scan(&n); err != nil || n != 0 {
			t.Errorf("temp.%s: %d rows, %v", tb, n, err)
		}
	}
}

func firstN(s []string, n int) []string { return slices.Clone(s[:min(n, len(s))]) }

// scaleHost seeds a host like one seen in production: oldNames old-kernel
// package names and n open findings, most of them on old kernels.
func scaleHost(tb testing.TB, s *Store, oldNames, n int) (int64, map[int64]kernelSet) {
	tb.Helper()
	ctx := tb.Context()
	s.CreateOrg(ctx, "test", "acme", "")
	s.CreateEnv(ctx, "test", "acme", "prod", "")
	if _, _, err := s.AddHost(ctx, "test", "acme", "prod", "web-01", nil); err != nil {
		tb.Fatal(err)
	}
	h, err := s.HostByName(ctx, "acme", "web-01")
	if err != nil {
		tb.Fatal(err)
	}
	var old []string
	for i := range oldNames {
		old = append(old, fmt.Sprintf("linux-modules-6.8.0-%d-generic", i))
	}
	for i := range 50 {
		if err := s.PutAdvisory(ctx, Advisory{ID: fmt.Sprintf("TEST-%04d", i), Modified: newsNow, Severity: "high", Raw: []byte(`{}`)}); err != nil {
			tb.Fatal(err)
		}
	}
	// Straight in: SetFindings would recount with no kernel sets.
	err = s.tx(ctx, func(tx *sql.Tx) error {
		for i := range n {
			bins := []string{old[i%oldNames], old[(i*7)%oldNames], old[(i*13)%oldNames]}
			if i%10 == 0 {
				bins = append(bins, "libssl3")
			}
			b, _ := json.Marshal(bins)
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO findings (host_id, site_root, advisory_id, ecosystem, package_name, package_version, binaries)
				VALUES (?, '', ?, 'Ubuntu:24.04:LTS', ?, '1', ?)`,
				h.ID, fmt.Sprintf("TEST-%04d", i%50), fmt.Sprintf("linux-%d", i/50), string(b)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		tb.Fatal(err)
	}
	return h.ID, map[int64]kernelSet{h.ID: {Old: old}}
}

func writeCounts(tb testing.TB, s *Store, hostID int64, sets map[int64]kernelSet) {
	tb.Helper()
	if err := s.tx(tb.Context(), func(tx *sql.Tx) error { return writeFindingCounts(tb.Context(), tx, hostID, sets) }); err != nil {
		tb.Fatal(err)
	}
}

// A hundred-odd old-kernel names no longer multiply the work per binary:
// the lookups are index searches, and the counts still agree.
func TestFindingCountsScale(t *testing.T) {
	s := newStore(t)
	id, sets := scaleHost(t, s, 141, 1000)
	start := time.Now()
	writeCounts(t, s, id, sets)
	took := time.Since(start)
	got := countRows(t, s)
	oracleCounts(t, s, id, sets)
	if want := countRows(t, s); !slices.Equal(got, want) {
		t.Fatalf("counts %v, want %v", got, want)
	}
	all, _ := s.OpenFindingCounts(t.Context())
	if c := all[id][""]; c.Total != 1000 || c.NotRunning != 900 {
		t.Errorf("counts %+v", c)
	}
	t.Logf("1000 findings, 141 old-kernel names: %v", took)

	// The plan searches the sets by key rather than scanning them.
	rows, err := s.db.QueryContext(t.Context(), `EXPLAIN QUERY PLAN `+countsSQL, id, WatchEPSS)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	p := strings.Join(plan, "\n")
	for _, alias := range []string{"ko", "kb", "kl"} {
		if !strings.Contains(p, "SEARCH "+alias+" USING PRIMARY KEY") {
			t.Errorf("%s isn't searched by key:\n%s", alias, p)
		}
	}
}

// go test -run '^$' -bench FindingCounts ./internal/store
func BenchmarkFindingCounts(b *testing.B) {
	for _, n := range []int{1000, 4000} {
		b.Run(fmt.Sprintf("temp-tables/%d", n), func(b *testing.B) {
			s := newStore(b)
			id, sets := scaleHost(b, s, 141, n)
			for b.Loop() {
				writeCounts(b, s, id, sets)
			}
		})
		b.Run(fmt.Sprintf("json-sets/%d", n), func(b *testing.B) {
			s := newStore(b)
			id, sets := scaleHost(b, s, 141, n)
			for b.Loop() {
				oracleCounts(b, s, id, sets)
			}
		})
	}
}

// One host's MatchNews recounts only when its matches changed: after an
// ingest, SetFindings has just counted it against the same incidents.
func TestMatchNewsRecountsOnlyOnChange(t *testing.T) {
	s := newStore(t)
	ctx := t.Context()
	h := addFindingHost(t, s, "acme", "web-01", "DEBIAN-CVE-2099-0001", "CVE-2099-0001")
	if _, err := s.ReplaceNews(ctx, testSource, testNewsItems(), "", "", newsNow); err != nil {
		t.Fatal(err)
	}
	if err := s.MatchNews(ctx, 0, newsNow); err != nil {
		t.Fatal(err)
	}
	total := func() int {
		t.Helper()
		all, err := s.OpenFindingCounts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return all[h.ID][""].Total
	}
	if total() != 1 {
		t.Fatalf("total %d", total())
	}
	// A stale tally shows whether a recount ran.
	stale := func() {
		t.Helper()
		if _, err := s.db.ExecContext(ctx, `UPDATE finding_counts SET total = 99 WHERE host_id = ?`, h.ID); err != nil {
			t.Fatal(err)
		}
	}
	stale()
	if err := s.MatchNews(ctx, h.ID, newsNow.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if total() != 99 {
		t.Errorf("unchanged matches recounted: total %d", total())
	}
	// A match that comes back (or goes) does recount.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM news_matches WHERE host_id = ?`, h.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.MatchNews(ctx, h.ID, newsNow.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if total() != 1 {
		t.Errorf("changed matches not recounted: total %d", total())
	}
	// Every host's matching always recounts: the incidents changed.
	stale()
	if err := s.MatchNews(ctx, 0, newsNow.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if total() != 1 {
		t.Errorf("MatchNews(0) didn't recount: total %d", total())
	}
}
