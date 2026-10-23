-- Making tampering loud: unchanged reports, fast silence alerts and the
-- collector's own trigger state.

-- ── Unchanged reports ──────────────────────────────────────────────────────
-- A report whose inventory matches the host's latest snapshot is stored as
-- a heartbeat instead of a new snapshot. inventory_sha256 is a canonical
-- hash of everything but the volatile fields (collected_at, uptime); NULL
-- for snapshots stored before this migration, so the first report after an
-- upgrade is stored in full.
ALTER TABLE snapshots ADD COLUMN inventory_sha256 BLOB CHECK (inventory_sha256 IS NULL OR length(inventory_sha256) = 32);

-- One row per unchanged report. snapshot_id is the snapshot it matched (the
-- host's latest at the time); the volatile facts are kept here because
-- snapshots are append-only.
CREATE TABLE heartbeats (
    id             INTEGER PRIMARY KEY,
    host_id        INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id    INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    source         TEXT    NOT NULL CHECK (source IN ('push', 'import')),
    received_at    TEXT    NOT NULL,
    collected_at   TEXT    NOT NULL, -- as claimed by the host
    payload_sha256 BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    uptime_seconds INTEGER
) STRICT;

CREATE INDEX heartbeats_host ON heartbeats (host_id, received_at);
CREATE INDEX heartbeats_snapshot ON heartbeats (snapshot_id);
-- Same replay rule as snapshots: a payload is only ever sent once.
CREATE UNIQUE INDEX heartbeats_no_replay ON heartbeats (host_id, payload_sha256);

CREATE TRIGGER heartbeats_no_update BEFORE UPDATE ON heartbeats
BEGIN SELECT RAISE(ABORT, 'heartbeats are append-only'); END;

-- ── Silence alerts and trigger state (per host) ────────────────────────────
-- silence_alerted_for: the last_seen_at of the silence episode an immediate
-- alert went out for (NULL when none is outstanding). A later last_seen_at
-- means the host is back, and a "back" notice is due.
ALTER TABLE hosts ADD COLUMN silence_alerted_for TEXT;
-- The collector's last reported X-Heimdall-Triggers, normalized, e.g.
-- "changes=enabled,active; timer=enabled,active". NULL if never reported.
ALTER TABLE hosts ADD COLUMN triggers TEXT;
ALTER TABLE hosts ADD COLUMN triggers_at TEXT;

-- ── New anomaly rule: trigger_disabled ─────────────────────────────────────
-- SQLite can't change a CHECK constraint in place, so rebuild the table.
CREATE TABLE anomalies_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier',
                        'trigger_disabled')),
    severity        TEXT    NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    summary         TEXT    NOT NULL,
    detail          TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    detected_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    acknowledged_at TEXT,
    acknowledged_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    ack_note        TEXT,
    CHECK ((acknowledged_at IS NULL) = (ack_note IS NULL))
) STRICT;

INSERT INTO anomalies_new (id, host_id, snapshot_id, rule, severity, summary, detail, detected_at,
    acknowledged_at, acknowledged_by, ack_note)
SELECT id, host_id, snapshot_id, rule, severity, summary, detail, detected_at,
    acknowledged_at, acknowledged_by, ack_note
FROM anomalies;

DROP TABLE anomalies;
ALTER TABLE anomalies_new RENAME TO anomalies;

CREATE INDEX anomalies_open ON anomalies (host_id, detected_at) WHERE acknowledged_at IS NULL;
