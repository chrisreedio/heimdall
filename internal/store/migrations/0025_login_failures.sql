-- Failed SSH logins (docs/failed-logins.md): what each server's opt-in
-- login watch counted, per source address and UTC day. Counts only: no
-- usernames, no log lines. Kept 30 days.
CREATE TABLE login_failures (
    host_id   INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    day       TEXT    NOT NULL,                -- 2026-10-24 (UTC)
    ip        TEXT    NOT NULL,                -- canonical address
    failures  INTEGER NOT NULL CHECK (failures > 0),
    usernames INTEGER NOT NULL DEFAULT 0,      -- how many distinct usernames were tried
    first_at  INTEGER NOT NULL,                -- unix seconds
    last_at   INTEGER NOT NULL,
    succeeded INTEGER NOT NULL DEFAULT 0 CHECK (succeeded IN (0, 1)), -- a login from it then succeeded
    PRIMARY KEY (host_id, day, ip)
) STRICT;

CREATE INDEX login_failures_last ON login_failures (last_at);
CREATE INDEX login_failures_ip ON login_failures (ip);

-- Each day's totals per host, including addresses past the per-push cap
-- and clients sshd named by host name.
CREATE TABLE login_failure_days (
    host_id   INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    day       TEXT    NOT NULL,
    failures  INTEGER NOT NULL,
    addresses INTEGER NOT NULL,
    PRIMARY KEY (host_id, day)
) STRICT;

-- The last report of each host's login watch.
CREATE TABLE login_watch (
    host_id     INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    source      TEXT    NOT NULL, -- journal, auth.log, secure, messages, none, unreadable
    counted_at  INTEGER NOT NULL, -- when the server last counted (unix seconds; 0 unknown)
    reported_at TEXT    NOT NULL
) STRICT;
