-- Attack-surface map (docs/surface.md): what the Cloudflare sync learns
-- beyond zones and records. Zone settings and edge certificates (read-only,
-- each optional: a token without the permission stores 'permission'), the
-- last DNS answer for CNAME targets outside our zones, and a log of how
-- public names changed between syncs, kept 90 days.
CREATE TABLE surface_zone_settings (
    zone_id      TEXT PRIMARY KEY REFERENCES cloudflare_zones (id) ON DELETE CASCADE,
    -- '' (never read), ok, permission (no Zone Settings Read) or error.
    -- On permission or error the last good values below stay.
    state        TEXT NOT NULL DEFAULT '',
    note         TEXT NOT NULL DEFAULT '',
    ssl          TEXT NOT NULL DEFAULT '', -- off, flexible, full, strict
    always_https TEXT NOT NULL DEFAULT '', -- on, off
    min_tls      TEXT NOT NULL DEFAULT '', -- 1.0, 1.1, 1.2, 1.3
    at           TEXT NOT NULL DEFAULT '',
    -- Edge certificates (certificate packs): the same states.
    cert_state   TEXT NOT NULL DEFAULT '',
    cert_note    TEXT NOT NULL DEFAULT '',
    cert_expires TEXT NOT NULL DEFAULT '', -- the soonest active certificate's expiry
    cert_at      TEXT NOT NULL DEFAULT ''
) STRICT;

-- One row per CNAME target outside every synced zone.
CREATE TABLE surface_cname_checks (
    target     TEXT PRIMARY KEY,
    status     TEXT NOT NULL CHECK (status IN ('ok', 'nxdomain', 'error')),
    note       TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL
) STRICT;

-- How a public name changed between two syncs of its zone. No foreign key:
-- the history outlives a zone the token stops seeing.
CREATE TABLE surface_changes (
    id      INTEGER PRIMARY KEY,
    at      TEXT NOT NULL,
    zone_id TEXT NOT NULL,
    zone    TEXT NOT NULL,
    name    TEXT NOT NULL,
    kind    TEXT NOT NULL CHECK (kind IN ('added', 'removed', 'proxied', 'unproxied', 'target')),
    old     TEXT NOT NULL DEFAULT '',
    new     TEXT NOT NULL DEFAULT '',
    -- JSON array of the org IDs whose hosts or sites the name led to,
    -- before or after: who may see the change.
    orgs    TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(orgs))
) STRICT;

CREATE INDEX surface_changes_at ON surface_changes (at);
