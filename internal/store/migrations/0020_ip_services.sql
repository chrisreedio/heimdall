-- IP awareness: each synced IP label source's last sync (a deploy service's
-- published list, ...), for `heimdall ip-services status`. feed_state's
-- CHECK lists its feeds by name, so synced sources get their own table.
CREATE TABLE ip_source_state (
    source          TEXT PRIMARY KEY,      -- 'service:forge', ...
    last_attempt_at TEXT NOT NULL,
    last_success_at TEXT,
    last_error      TEXT NOT NULL DEFAULT '',
    labels          INTEGER NOT NULL DEFAULT 0 -- ranges stored by the last good sync
) STRICT;
