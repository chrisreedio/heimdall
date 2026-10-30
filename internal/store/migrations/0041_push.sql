-- Web Push notifications (internal/push, docs/mobile.md#notifications).
--
-- push_vapid is the hub's VAPID key pair (RFC 8292): one P-256 private
-- key, made on first use. Push services see only its public half.
CREATE TABLE push_vapid (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    private_key BLOB    NOT NULL CHECK (length(private_key) = 32),
    created_at  TEXT    NOT NULL
) STRICT;

-- One browser's subscription: where to send (a push service's URL) and the
-- keys to encrypt for it (RFC 8291). It belongs to the session it was made
-- in, so signing out, revoking the device or the session ending removes it.
CREATE TABLE push_subscriptions (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_hash BLOB    NOT NULL REFERENCES sessions (id_hash) ON DELETE CASCADE,
    endpoint     TEXT    NOT NULL UNIQUE,
    p256dh       BLOB    NOT NULL CHECK (length(p256dh) = 65),
    auth         BLOB    NOT NULL CHECK (length(auth) = 16),
    label        TEXT    NOT NULL DEFAULT '', -- the session's device label ("iPhone Safari")
    created_at   TEXT    NOT NULL,
    last_ok_at   TEXT    NOT NULL DEFAULT '', -- the push service last took a message
    last_error   TEXT    NOT NULL DEFAULT ''  -- why the last send failed, '' after a success
) STRICT;

CREATE INDEX push_subscriptions_user ON push_subscriptions (user_id);
CREATE INDEX push_subscriptions_session ON push_subscriptions (session_hash);

-- Each user's choices. modes maps an event kind to immediate, digest or
-- off; a kind that isn't there has its default (internal/push). Quiet hours
-- run from quiet_start to quiet_end (hours, 0-23) in time_zone.
-- digest_day is the local date ("2026-10-30") of the last daily digest.
CREATE TABLE push_settings (
    user_id     INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    modes       TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(modes)),
    quiet       INTEGER NOT NULL DEFAULT 1 CHECK (quiet IN (0, 1)),
    quiet_start INTEGER NOT NULL DEFAULT 22 CHECK (quiet_start BETWEEN 0 AND 23),
    quiet_end   INTEGER NOT NULL DEFAULT 7 CHECK (quiet_end BETWEEN 0 AND 23),
    time_zone   TEXT    NOT NULL DEFAULT '',
    detail      TEXT    NOT NULL DEFAULT 'host' CHECK (detail IN ('host', 'hidden')),
    digest_day  TEXT    NOT NULL DEFAULT ''
) STRICT;

-- Notices waiting: held for the end of quiet hours (digest = 0) or for the
-- next daily digest (digest = 1). Only what a notification may carry: the
-- kind, the host's name and a count.
CREATE TABLE push_held (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    digest     INTEGER NOT NULL CHECK (digest IN (0, 1)),
    kind       TEXT    NOT NULL,
    org_slug   TEXT    NOT NULL DEFAULT '',
    host       TEXT    NOT NULL DEFAULT '',
    hosts      INTEGER NOT NULL DEFAULT 0, -- more than one host: how many
    count      INTEGER NOT NULL DEFAULT 1,
    ref        INTEGER NOT NULL DEFAULT 0, -- a ban's ID, for its link
    created_at TEXT    NOT NULL
) STRICT;

CREATE INDEX push_held_user ON push_held (user_id, digest);
