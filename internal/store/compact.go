// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"bytes"
	"compress/flate"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"
)

// maxRecordBytes caps a decompressed advisory record (osv.maxVulnBytes is
// 4 MiB for the original; a slimmed one is smaller).
const maxRecordBytes = 4 << 20

// compressRecord deflates an advisory record for the record column; an
// empty record is stored as NULL.
func compressRecord(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(b); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func decompressRecord(z []byte) ([]byte, error) {
	if len(z) == 0 {
		return nil, nil
	}
	b, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(z)), maxRecordBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxRecordBytes {
		return nil, fmt.Errorf("advisory record larger than %d bytes", maxRecordBytes)
	}
	return b, nil
}

// AdvisoryRecord returns the stored OSV record of an advisory (slimmed;
// see osv.Slim), or ErrNotFound. Rows not yet converted by SlimAdvisories
// return their original JSON.
func (s *Store) AdvisoryRecord(ctx context.Context, id string) ([]byte, error) {
	var raw string
	var z []byte
	err := s.db.QueryRowContext(ctx, `SELECT raw, record FROM advisories WHERE id = ?`, id).Scan(&raw, &z)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if raw != "" {
		return []byte(raw), nil
	}
	return decompressRecord(z)
}

// SlimProgress reports SlimAdvisories' progress.
type SlimProgress struct {
	Rows, Converted int   // rows examined, rows rewritten
	BytesIn         int64 // original JSON read
	BytesOut        int64 // compressed records written
}

// SlimAdvisories converts advisories still holding their original JSON in
// `raw` (stored before migration 0012) to a compressed slim record, using
// slim (osv.Slim). It reads one row at a time and commits every few
// megabytes, so memory stays at a few records and the WAL at a few
// megabytes however large the table is; an interrupted run loses at most
// one batch and the next run carries on. A record slim can't parse is
// kept whole, compressed. It's a no-op once every row is converted.
func (s *Store) SlimAdvisories(ctx context.Context, slim func([]byte) ([]byte, error), progress func(SlimProgress)) (SlimProgress, error) {
	const batchBytes = 16 << 20 // original JSON per transaction
	var p SlimProgress
	var last int64
	for {
		var inBatch int64
		done := false
		err := s.tx(ctx, func(tx *sql.Tx) error {
			for inBatch < batchBytes {
				var rowid int64
				var raw string
				// length(raw) on TEXT counts characters, which means reading
				// it; skip converted rows by comparing with '' instead.
				err := tx.QueryRowContext(ctx,
					`SELECT rowid, raw FROM advisories WHERE rowid > ? ORDER BY rowid LIMIT 1`, last).Scan(&rowid, &raw)
				if errors.Is(err, sql.ErrNoRows) {
					done = true
					return nil
				}
				if err != nil {
					return err
				}
				last = rowid
				p.Rows++
				if raw == "" {
					continue
				}
				rec, err := slim([]byte(raw))
				if err != nil {
					rec = []byte(raw)
				}
				z, err := compressRecord(rec)
				if err != nil {
					return err
				}
				if _, err := tx.ExecContext(ctx,
					`UPDATE advisories SET raw = '', record = ? WHERE rowid = ?`, z, rowid); err != nil {
					return err
				}
				p.Converted++
				p.BytesIn += int64(len(raw))
				p.BytesOut += int64(len(z))
				inBatch += int64(len(raw))
			}
			return nil
		})
		if err != nil {
			return p, err
		}
		if progress != nil && inBatch > 0 {
			progress(p)
		}
		if done {
			return p, nil
		}
	}
}

// PruneAdvisories deletes OSV query results not refreshed since before
// (no host has had that package version since), then advisories that no
// finding (open or resolved) and no remaining query result refers to.
// Withdrawn advisories go the same way once nothing refers to them. It
// returns the number of advisories deleted.
func (s *Store) PruneAdvisories(ctx context.Context, before time.Time) (int, error) {
	var n int64
	err := s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM osv_query_cache WHERE checked_at < ?`, before.UTC().Format(timeLayout)); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `
			DELETE FROM advisories
			WHERE id NOT IN (SELECT advisory_id FROM findings)
			  AND id NOT IN (SELECT DISTINCT v.value FROM osv_query_cache c, json_each(c.vuln_ids) v)`)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	return int(n), err
}

// SpaceStats describes the database file's pages.
type SpaceStats struct {
	PageSize, Pages, FreePages int64
}

func (st SpaceStats) Bytes() int64     { return st.PageSize * st.Pages }
func (st SpaceStats) FreeBytes() int64 { return st.PageSize * st.FreePages }
func (st SpaceStats) UsedBytes() int64 { return st.Bytes() - st.FreeBytes() }

func (s *Store) SpaceStats(ctx context.Context) (SpaceStats, error) {
	var st SpaceStats
	for _, q := range []struct {
		pragma string
		dst    *int64
	}{{"page_size", &st.PageSize}, {"page_count", &st.Pages}, {"freelist_count", &st.FreePages}} {
		if err := s.db.QueryRowContext(ctx, `PRAGMA `+q.pragma).Scan(q.dst); err != nil {
			return st, err
		}
	}
	return st, nil
}

// Compact rebuilds the database without its free pages (VACUUM) and
// truncates the WAL. VACUUM is transactional: interrupted or out of disk,
// the database is left as it was. In WAL mode it writes the compacted
// database to a temporary file and then to the WAL, so it needs about
// twice UsedBytes free (see CompactNeeds), and it blocks other writers
// while it runs. Memory use is SQLite's page cache, a few megabytes.
func (s *Store) Compact(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `VACUUM`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// CompactNeeds is the free disk space Compact needs: the compacted copy
// (in the temp directory) and the same again in the WAL, plus slack.
func (st SpaceStats) CompactNeeds() int64 { return 2*st.UsedBytes() + 64<<20 }

// WorthCompacting reports whether enough of the file is free pages to be
// worth a VACUUM: at least a quarter of it and 64 MiB.
func (st SpaceStats) WorthCompacting() bool {
	return st.FreeBytes() >= 64<<20 && st.FreePages*4 >= st.Pages
}
