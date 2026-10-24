-- Threat news (phase 1): curated incidents from configured feeds, and the
-- hosts they affect. A host is affected ("confirmed") when one of an
-- incident's CVEs is an open finding on it; findings decide, never the
-- feed's free-text version ranges.

-- Feed text is untrusted: it's validated before it gets here and only ever
-- rendered as escaped text.
CREATE TABLE news_items (
    id           INTEGER PRIMARY KEY,
    source       TEXT NOT NULL,                 -- the feed URL it came from
    slug         TEXT NOT NULL,
    category     TEXT NOT NULL CHECK (category IN ('patch', 'breach', 'supply-chain')),
    title        TEXT NOT NULL,
    url          TEXT NOT NULL CHECK (url LIKE 'https://%'),
    severity     TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    patch_status TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL CHECK (status IN ('live', 'closed')),
    product      TEXT NOT NULL DEFAULT '',
    stacks       TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(stacks)),
    tags         TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(tags)),
    cve_ids      TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(cve_ids)),
    affected     TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(affected)), -- affectedVersions, shown as text only
    fixed        TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(fixed)),    -- fixedVersions, shown as text only
    summary      TEXT NOT NULL DEFAULT '',
    started_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    closed_at    TEXT,
    fetched_at   TEXT NOT NULL,
    UNIQUE (source, slug)
) STRICT;

CREATE INDEX news_items_started ON news_items (started_at);

-- Kind is always 'confirmed' in phase 1; 'possible' and 'supply' come later.
CREATE TABLE news_matches (
    item_id    INTEGER NOT NULL REFERENCES news_items (id) ON DELETE CASCADE,
    host_id    INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    kind       TEXT    NOT NULL CHECK (kind IN ('confirmed', 'possible', 'supply')),
    reason     TEXT    NOT NULL DEFAULT '', -- e.g. the matching CVE IDs
    matched_at TEXT    NOT NULL,
    PRIMARY KEY (item_id, host_id, kind)
) STRICT;

CREATE INDEX news_matches_host ON news_matches (host_id);

-- Conditional-request state per source (ETag / Last-Modified).
CREATE TABLE news_sources (
    source        TEXT PRIMARY KEY,
    etag          TEXT NOT NULL DEFAULT '',
    last_modified TEXT NOT NULL DEFAULT '',
    checked_at    TEXT NOT NULL
) STRICT;

-- feed_state's CHECK lists the feeds by name; SQLite can't alter a CHECK,
-- so rebuild it with 'news' added.
CREATE TABLE feed_state_new (
    feed            TEXT PRIMARY KEY CHECK (feed IN ('osv', 'kev', 'epss', 'endoflife', 'news')),
    last_attempt_at TEXT,
    last_success_at TEXT,
    etag            TEXT,
    last_modified   TEXT,
    last_error      TEXT
) STRICT;
INSERT INTO feed_state_new SELECT feed, last_attempt_at, last_success_at, etag, last_modified, last_error FROM feed_state;
DROP TABLE feed_state;
ALTER TABLE feed_state_new RENAME TO feed_state;
