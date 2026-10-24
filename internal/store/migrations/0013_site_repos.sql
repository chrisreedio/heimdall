-- Each site's git repository, for "Hand off to agent". detected comes from
-- the collector (the site's .git/config remote, credentials stripped) and
-- is replaced on every push that reports it; manual is set on the site
-- page by an operator and wins over detected. Both are normalized URLs,
-- '' when unknown. A row with both empty is deleted.
CREATE TABLE site_repos (
    host_id    INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    root       TEXT    NOT NULL,
    detected   TEXT    NOT NULL DEFAULT '',
    manual     TEXT    NOT NULL DEFAULT '',
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (host_id, root)
) STRICT;
