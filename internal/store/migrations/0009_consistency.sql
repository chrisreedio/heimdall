-- New anomaly rules for reports that don't add up: uptime_inconsistent,
-- inventory_reverted, package_drop, collector_downgrade, os_changed. SQLite
-- can't change a CHECK in place, so the table is rebuilt, exactly as in
-- 0008 plus the new rule names.
CREATE TABLE anomalies_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier',
                        'trigger_disabled', 'privileged_access', 'privilege_watch_disabled',
                        'uptime_inconsistent', 'inventory_reverted', 'package_drop', 'collector_downgrade',
                        'os_changed')),
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
