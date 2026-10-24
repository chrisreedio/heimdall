// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/chrisreedio/heimdall/internal/feeds/osv"
	"github.com/chrisreedio/heimdall/internal/store"
)

// tidyDatabase runs after `heimdall migrate` applies migrations: it slims
// advisories stored before migration 0012, then compacts the file when a
// good share of it is free pages (after that conversion, or after months
// of advisory updates). The hub is stopped during an upgrade, so blocking
// writers is fine; both steps are safe to interrupt and rerun.
func tidyDatabase(a *app, s *store.Store, dbPath string) error {
	start := time.Now()
	lastReport := start
	p, err := s.SlimAdvisories(a.ctx, osv.Slim, func(p store.SlimProgress) {
		if time.Since(lastReport) >= 10*time.Second {
			lastReport = time.Now()
			fmt.Fprintf(a.stderr, "slimming stored advisories: %d converted, %s read\n", p.Converted, mib(p.BytesIn))
		}
	})
	if err != nil {
		return fmt.Errorf("slimming advisories: %w", err)
	}
	if p.Converted > 0 {
		fmt.Fprintf(a.stderr, "slimmed %d advisories in %s: %s of OSV JSON now %s\n",
			p.Converted, time.Since(start).Round(time.Second), mib(p.BytesIn), mib(p.BytesOut))
	}

	st, err := s.SpaceStats(a.ctx)
	if err != nil || !st.WorthCompacting() {
		return err
	}
	need := st.CompactNeeds()
	dirs := []string{filepath.Dir(dbPath), sqliteTempDir()}
	for _, d := range dirs {
		if free, ok := diskFree(d); ok && free < need {
			fmt.Fprintf(a.stderr, "not compacting %s (%s, %s of it free pages): it needs %s free in %s, which has %s.\n"+
				"Free some space and run `heimdall migrate` again to reclaim it.\n",
				dbPath, mib(st.Bytes()), mib(st.FreeBytes()), mib(need), d, mib(free))
			return nil
		}
	}
	fmt.Fprintf(a.stderr, "compacting %s: %s, %s of it free pages (VACUUM; safe to interrupt)\n",
		dbPath, mib(st.Bytes()), mib(st.FreeBytes()))
	start = time.Now()
	if err := s.Compact(a.ctx); err != nil {
		return fmt.Errorf("compacting: %w (the database is unchanged; rerun `heimdall migrate` to retry)", err)
	}
	after, err := s.SpaceStats(a.ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "compacted %s to %s in %s\n", mib(st.Bytes()), mib(after.Bytes()), time.Since(start).Round(time.Second))
	return nil
}

// sqliteTempDir is where SQLite puts VACUUM's temporary copy on Unix: the
// first of these that exists.
func sqliteTempDir() string {
	for _, d := range []string{os.Getenv("SQLITE_TMPDIR"), os.Getenv("TMPDIR"), "/var/tmp", "/usr/tmp", "/tmp"} {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d
		}
	}
	return "."
}

func mib(n int64) string {
	if n >= 10<<30 {
		return fmt.Sprintf("%.0f GiB", float64(n)/(1<<30))
	}
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}
