-- IP labels from Cloudflare IP lists (docs/cloudflare.md#ip-lists): the
-- account-level IP lists the read-only token can see, and what each one's
-- items become. Lists start ignored; only mapped ones sync, as labels with
-- source 'cloudflare:list:<id>' for every org (Cloudflare is hub-wide).
CREATE TABLE cloudflare_ip_lists (
    id          TEXT PRIMARY KEY,               -- the list's ID at Cloudflare
    account_id  TEXT NOT NULL,
    name        TEXT NOT NULL,                  -- cached from Cloudflare: "offices"
    description TEXT NOT NULL DEFAULT '',
    items       INTEGER NOT NULL DEFAULT 0,     -- as Cloudflare counted them
    kind        TEXT NOT NULL DEFAULT 'ignore' CHECK (kind IN ('ignore', 'staff', 'office', 'automation', 'infra')),
    updated_by  TEXT NOT NULL DEFAULT '',       -- who last changed the kind
    updated_at  TEXT,                           -- when (NULL: never)
    seen_at     TEXT NOT NULL                   -- the last sync that found it
) STRICT;

-- A new label kind, office: a trusted network (an office, a VPN exit, a
-- home network), not one person. SQLite can't change a CHECK in place, so
-- the table is rebuilt, exactly as in 0019 plus the new kind.
CREATE TABLE ip_labels_new (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER REFERENCES organizations (id) ON DELETE CASCADE,
    prefix     TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('staff', 'office', 'automation', 'infra', 'tailnet', 'private', 'unknown')),
    name       TEXT    NOT NULL,
    person     TEXT    NOT NULL DEFAULT '',
    source     TEXT    NOT NULL,
    note       TEXT    NOT NULL DEFAULT '',
    created_by TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

INSERT INTO ip_labels_new (id, org_id, prefix, kind, name, person, source, note, created_by, created_at, updated_at)
SELECT id, org_id, prefix, kind, name, person, source, note, created_by, created_at, updated_at FROM ip_labels;

DROP TABLE ip_labels;
ALTER TABLE ip_labels_new RENAME TO ip_labels;
CREATE INDEX ip_labels_org ON ip_labels (org_id, source);
