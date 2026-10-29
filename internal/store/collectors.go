// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"
)

type KnownCollector struct {
	SHA256  string
	Version string
	Note    string
	AddedAt time.Time
	Hosts   int // hosts whose latest snapshot used it
}

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// TrustCollector marks a collector release checksum as known-good.
func (s *Store) TrustCollector(ctx context.Context, actor, sha, version, note string) error {
	if !sha256HexRe.MatchString(sha) {
		return &ValidationError{"sha256", "must be 64 lowercase hex characters"}
	}
	if version == "" {
		return &ValidationError{"version", "is required"}
	}
	if note != "" {
		var err error
		if note, err = normalizeName("note", note); err != nil {
			return err
		}
	}
	raw, _ := hex.DecodeString(sha)
	return s.tx(ctx, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO known_collectors (sha256, version, note) VALUES (?, ?, ?)`, raw, version, note)
		if isUnique(err) {
			return fmt.Errorf("collector %s: %w", sha[:12], ErrExists)
		}
		if err != nil {
			return err
		}
		return audit(ctx, tx, AuditEntry{Actor: actor, Action: "collector.trust", Target: sha,
			Detail: map[string]any{"version": version}})
	})
}

// ListCollectors returns trusted checksums plus any untrusted ones seen in
// hosts' latest snapshots (Version is then what the host claimed).
func (s *Store) ListCollectors(ctx context.Context) (trusted, untrusted []KnownCollector, err error) {
	rows, err := s.rd.QueryContext(ctx, `
		SELECT lower(hex(k.sha256)), k.version, k.note, k.added_at,
		       (SELECT count(*) FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id WHERE s.collector_sha256 = k.sha256)
		FROM known_collectors k ORDER BY k.added_at`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k KnownCollector
		var added string
		if err := rows.Scan(&k.SHA256, &k.Version, &k.Note, &added, &k.Hosts); err != nil {
			return nil, nil, err
		}
		k.AddedAt = parseTime(added)
		trusted = append(trusted, k)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	rows, err = s.rd.QueryContext(ctx, `
		SELECT lower(hex(s.collector_sha256)), max(s.collector_version), count(*)
		FROM hosts h JOIN snapshots s ON s.id = h.last_snapshot_id
		WHERE s.collector_sha256 IS NOT NULL
		  AND s.collector_sha256 NOT IN (SELECT sha256 FROM known_collectors)
		GROUP BY s.collector_sha256 ORDER BY count(*) DESC`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k KnownCollector
		if err := rows.Scan(&k.SHA256, &k.Version, &k.Hosts); err != nil {
			return nil, nil, err
		}
		untrusted = append(untrusted, k)
	}
	return trusted, untrusted, rows.Err()
}
