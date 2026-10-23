-- M4: findings can belong to a site (a Composer package in one app) as
-- well as to the host's OS packages. site_root is '' for OS packages.
-- SQLite can't change a UNIQUE constraint in place, so rebuild the table.

CREATE TABLE findings_new (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    advisory_id     TEXT    NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    ecosystem       TEXT    NOT NULL,
    package_name    TEXT    NOT NULL,
    package_version TEXT    NOT NULL,
    fixed_version   TEXT,
    first_seen_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    resolved_at     TEXT,
    binaries        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(binaries)),
    fix_pending     INTEGER NOT NULL DEFAULT 0 CHECK (fix_pending IN (0, 1)),
    site_root       TEXT    NOT NULL DEFAULT '',
    UNIQUE (host_id, site_root, advisory_id, package_name)
) STRICT;

INSERT INTO findings_new (id, host_id, advisory_id, ecosystem, package_name, package_version, fixed_version,
    first_seen_at, last_seen_at, resolved_at, binaries, fix_pending)
SELECT id, host_id, advisory_id, ecosystem, package_name, package_version, fixed_version,
    first_seen_at, last_seen_at, resolved_at, binaries, fix_pending
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE INDEX findings_open ON findings (host_id) WHERE resolved_at IS NULL;
CREATE INDEX findings_advisory ON findings (advisory_id);

-- Whether the collector could read the app's composer files.
ALTER TABLE sites ADD COLUMN readable INTEGER NOT NULL DEFAULT 1 CHECK (readable IN (0, 1));
