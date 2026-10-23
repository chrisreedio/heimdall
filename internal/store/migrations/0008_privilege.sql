-- Privilege watch (opt-in on each server, install.sh --watch-privilege):
-- when sudo, su or a root SSH login happened. Only the time and kind, plus
-- a username if the server opted in to that too. Never commands.
CREATE TABLE privilege_events (
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    at          INTEGER NOT NULL, -- unix seconds, from the server's clock
    kind        TEXT    NOT NULL CHECK (kind IN ('sudo', 'su', 'root-ssh')),
    user        TEXT    NOT NULL DEFAULT '', -- '' unless usernames are opted in
    received_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (host_id, at, kind, user)
) STRICT, WITHOUT ROWID;

-- The last privilege watch state each host reported. ever_on stays 1 once
-- the host has reported "on", so only hosts that enabled it can alert.
CREATE TABLE privilege_watch (
    host_id    INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    state      TEXT    NOT NULL CHECK (state IN ('on', 'off', 'partial')),
    ever_on    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT    NOT NULL
) STRICT;

-- New anomaly rules: privileged_access, privilege_watch_disabled. SQLite
-- can't change a CHECK in place, so the table is rebuilt. The rule list
-- includes trigger_disabled, which migration 0007 adds.
CREATE TABLE anomalies_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier',
                        'trigger_disabled', 'privileged_access', 'privilege_watch_disabled')),
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
