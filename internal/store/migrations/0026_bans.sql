-- Bans (docs/bans.md): addresses and networks that failed SSH logins
-- across the fleet, proposed for (or, in shadow mode, only recorded as
-- candidates for) a Cloudflare account-level IP list, which per-zone
-- custom rules challenge or block. Heimdall tracks every ban's expiry and
-- removes it itself: Cloudflare lists have no TTL.

-- One row per ban, from proposal (or shadow record) to its end.
--   shadow:   shadow mode would have proposed or banned it; never written
--   proposed: waiting for an operator to approve or reject it
--   rejected: an operator said no
--   lapsed:   a proposal nobody decided on in time
--   pending:  approved (or automatic), to be added to the list
--   active:   in the list
--   lifting:  expired or unbanned, to be removed from the list
--   ended:    removed from the list (or never written)
CREATE TABLE bans (
    id          INTEGER PRIMARY KEY,
    target      TEXT    NOT NULL,          -- canonical prefix: 203.0.113.7/32, 198.51.100.0/24, 2001:db8::/64
    kind        TEXT    NOT NULL CHECK (kind IN ('address', 'network')),
    action      TEXT    NOT NULL CHECK (action IN ('challenge', 'block')),
    status      TEXT    NOT NULL CHECK (status IN ('shadow', 'proposed', 'rejected', 'lapsed', 'pending',
                                                   'active', 'lifting', 'ended')),
    mode        TEXT    NOT NULL,          -- the [bans] mode that created it
    score       REAL    NOT NULL,
    breakdown   TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(breakdown)), -- the score's parts
    evidence    TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(evidence)),  -- hosts, failures, network, ...
    orgs        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(orgs)),      -- whose hosts it hit: who may see it
    offense     INTEGER NOT NULL DEFAULT 1, -- 1 for a first ban; each repeat doubles the duration
    duration_s  INTEGER NOT NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    decided_by  TEXT    NOT NULL DEFAULT '', -- "user:3", "cli:alice", "auto"
    decided_at  TEXT    NOT NULL DEFAULT '',
    note        TEXT    NOT NULL DEFAULT '',
    started_at  TEXT    NOT NULL DEFAULT '', -- when it went into the list
    expires_at  TEXT    NOT NULL DEFAULT '', -- shadow: when the ban would have ended
    list_id     TEXT    NOT NULL DEFAULT '',
    item_id     TEXT    NOT NULL DEFAULT '',
    attempts    INTEGER NOT NULL DEFAULT 0,  -- failed writes since the last success
    last_error  TEXT    NOT NULL DEFAULT '',
    next_try_at TEXT    NOT NULL DEFAULT '',
    ended_at    TEXT    NOT NULL DEFAULT '',
    end_reason  TEXT    NOT NULL DEFAULT ''  -- expired, unbanned, vouched, rejected, lapsed
) STRICT;

-- At most one open ban per target.
CREATE UNIQUE INDEX bans_open ON bans (target) WHERE status IN ('proposed', 'pending', 'active', 'lifting');
CREATE INDEX bans_status ON bans (status, updated_at);
CREATE INDEX bans_target ON bans (target, created_at);

-- Zones an operator turned the ban rules on for, and where their rules
-- stand. No foreign key: the opt-in outlives a zone the read token stops
-- seeing, and the rules must still be removed.
CREATE TABLE ban_zones (
    zone_id     TEXT PRIMARY KEY,
    zone        TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    -- '' (nothing written yet), ok (rules in place), error (see note),
    -- off (rules removed after opting out)
    state       TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',
    ruleset_id  TEXT NOT NULL DEFAULT '',
    rules       TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(rules)), -- action → rule ID
    updated_by  TEXT NOT NULL DEFAULT '',
    updated_at  TEXT NOT NULL,
    applied_at  TEXT NOT NULL DEFAULT ''
) STRICT;

-- Every Cloudflare write and every decision: who, what, when, result.
CREATE TABLE ban_audit (
    id      INTEGER PRIMARY KEY,
    at      TEXT    NOT NULL,
    actor   TEXT    NOT NULL,
    action  TEXT    NOT NULL,
    ban_id  INTEGER,                       -- no foreign key: kept as history
    zone_id TEXT    NOT NULL DEFAULT '',
    target  TEXT    NOT NULL DEFAULT '',
    result  TEXT    NOT NULL CHECK (result IN ('ok', 'error')),
    detail  TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail))
) STRICT;

CREATE INDEX ban_audit_at ON ban_audit (at);

-- Small named state: the pause switch, the lists' IDs, alert cursors and
-- the shadow digest's last send.
CREATE TABLE ban_state (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL CHECK (json_valid(value)),
    updated_at TEXT NOT NULL
) STRICT;

-- New anomaly rules: login_then_succeeded (an unknown address failed and
-- then logged in, same day), dns_unproxied (a name that leads to one of
-- our hosts lost Cloudflare's proxy) and cname_takeover (a name's CNAME
-- target doesn't exist). The table is rebuilt exactly as in 0022, plus
-- the new names.
CREATE TABLE anomalies_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier',
                        'trigger_disabled', 'privileged_access', 'privilege_watch_disabled',
                        'uptime_inconsistent', 'inventory_reverted', 'package_drop', 'collector_downgrade',
                        'os_changed', 'privilege_unknown_source', 'privilege_off_tailnet',
                        'silent_online', 'login_then_succeeded', 'dns_unproxied', 'cname_takeover')),
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
