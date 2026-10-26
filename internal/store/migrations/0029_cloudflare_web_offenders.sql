-- Web offenders (docs/cloudflare.md#web-offenders): client addresses that
-- Cloudflare blocked or challenged, per zone and UTC day, from the GraphQL
-- firewall events. Only acted-on actions, never friendly addresses (labels
-- in any org, the tailnet, private ranges, Cloudflare's edge, your hosts,
-- Heimdall sign-ins). Counts and the network only: no paths, no query
-- strings, no user agents. Kept 30 days, like failed logins.
CREATE TABLE cloudflare_web_offenders (
    zone_id  TEXT    NOT NULL REFERENCES cloudflare_zones (id) ON DELETE CASCADE,
    day      TEXT    NOT NULL,                 -- 2026-10-24 (UTC)
    ip       TEXT    NOT NULL,                 -- canonical address
    events   INTEGER NOT NULL CHECK (events > 0),
    actions  TEXT    NOT NULL DEFAULT '{}',    -- JSON: events per action, e.g. {"block": 40, "managed_challenge": 2}
    first_at INTEGER NOT NULL,                 -- unix seconds (to the hour from the aggregated dataset)
    last_at  INTEGER NOT NULL,
    asn      INTEGER NOT NULL DEFAULT 0,       -- 0 unknown
    as_name  TEXT    NOT NULL DEFAULT '',
    country  TEXT    NOT NULL DEFAULT '',      -- ISO 3166-1 alpha-2, as Cloudflare names it
    sampled  INTEGER NOT NULL DEFAULT 0 CHECK (sampled IN (0, 1)), -- from capped raw events: a floor
    PRIMARY KEY (zone_id, day, ip)
) STRICT;

CREATE INDEX cloudflare_web_offenders_last ON cloudflare_web_offenders (last_at);
CREATE INDEX cloudflare_web_offenders_ip ON cloudflare_web_offenders (ip);

-- Which zone days were fetched. A day fetched after it ended (and settled)
-- is final and never asked for again; today is refetched every sync.
CREATE TABLE cloudflare_web_days (
    zone_id    TEXT    NOT NULL REFERENCES cloudflare_zones (id) ON DELETE CASCADE,
    day        TEXT    NOT NULL,
    final      INTEGER NOT NULL DEFAULT 0 CHECK (final IN (0, 1)),
    sampled    INTEGER NOT NULL DEFAULT 0 CHECK (sampled IN (0, 1)),
    fetched_at TEXT    NOT NULL,
    PRIMARY KEY (zone_id, day)
) STRICT;

-- The orgs a zone belongs to: those whose hosts or sites its records lead
-- to (the same join as the /cloudflare page), rebuilt every sync. Zones
-- have no owner of their own.
CREATE TABLE cloudflare_zone_orgs (
    zone_id TEXT    NOT NULL REFERENCES cloudflare_zones (id) ON DELETE CASCADE,
    org_id  INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    PRIMARY KEY (zone_id, org_id)
) STRICT;
