-- IP awareness (core): who a UI session is on the tailnet, each org's SSH
-- source policy, and the privilege watch rules that use IP verdicts.

-- The Tailscale identity `tailscale serve` passed with the sign-in (only
-- recorded with ui.behind_tailscale_serve, and only from loopback).
ALTER TABLE sessions ADD COLUMN ts_login TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN ts_name  TEXT NOT NULL DEFAULT '';

-- Per-org policy: privileged SSH sessions must come from the tailnet (or a
-- private network). allow_services exempts automation labels kept in sync
-- from a deploy service's published ranges.
CREATE TABLE ip_policies (
    org_id         INTEGER PRIMARY KEY REFERENCES organizations (id) ON DELETE CASCADE,
    tailnet_only   INTEGER NOT NULL DEFAULT 0 CHECK (tailnet_only IN (0, 1)),
    allow_services INTEGER NOT NULL DEFAULT 1 CHECK (allow_services IN (0, 1)),
    updated_by     TEXT    NOT NULL DEFAULT '',
    updated_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

-- Where an address appears (the IP page): sign-ins and other audited
-- actions, and privilege sessions.
CREATE INDEX audit_log_ip ON audit_log (ip) WHERE ip <> '';
CREATE INDEX privilege_events_source ON privilege_events (source) WHERE source NOT IN ('', '?');

-- New anomaly rules: privilege_unknown_source, privilege_off_tailnet. SQLite
-- can't change a CHECK in place, so the table is rebuilt, exactly as in
-- 0009 plus the new rule names.
CREATE TABLE anomalies_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier',
                        'trigger_disabled', 'privileged_access', 'privilege_watch_disabled',
                        'uptime_inconsistent', 'inventory_reverted', 'package_drop', 'collector_downgrade',
                        'os_changed', 'privilege_unknown_source', 'privilege_off_tailnet')),
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
