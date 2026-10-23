-- Site labels: production, staging or development, set by an admin for a
-- site (a web root on a host). Sites without a row get a label suggested
-- from their server names.
CREATE TABLE site_labels (
    host_id    INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    root       TEXT    NOT NULL,
    label      TEXT    NOT NULL CHECK (label IN ('production', 'staging', 'development')),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (host_id, root)
) STRICT;
