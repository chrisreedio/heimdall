-- Cloudflare (docs/cloudflare.md): the zones a read-only API token can see,
-- their A/AAAA/CNAME records, daily security event counts (aggregates
-- only: no events, no client addresses) and a cache of Radar's ASN for
-- addresses nobody knows. Hub-wide: zones belong to no org; the UI shows a
-- record to those who can see the host or site it points at.
CREATE TABLE cloudflare_zones (
    id        TEXT PRIMARY KEY,            -- Cloudflare's zone ID
    name      TEXT NOT NULL,               -- example.com
    plan      TEXT NOT NULL DEFAULT '',    -- "Free Website", "Pro Website", ...
    status    TEXT NOT NULL DEFAULT '',    -- active, pending, ...
    synced_at TEXT NOT NULL,
    -- Security events: '' (not fetched), ok, sampled (raw events on plans
    -- without the aggregated dataset), plan (not on this plan),
    -- permission (the token can't read analytics) or error.
    security       TEXT NOT NULL DEFAULT '',
    security_note  TEXT NOT NULL DEFAULT '',
    security_at    TEXT NOT NULL DEFAULT '',
    last24         TEXT NOT NULL DEFAULT '{}' -- JSON: totals and top-N for the last 24 hours
) STRICT;

CREATE TABLE cloudflare_dns_records (
    zone_id   TEXT    NOT NULL REFERENCES cloudflare_zones (id) ON DELETE CASCADE,
    name      TEXT    NOT NULL,  -- lowercase, no trailing dot
    type      TEXT    NOT NULL CHECK (type IN ('A', 'AAAA', 'CNAME')),
    content   TEXT    NOT NULL,  -- an address, or the CNAME target
    proxied   INTEGER NOT NULL,  -- orange cloud
    ttl       INTEGER NOT NULL,  -- 1 = automatic
    synced_at TEXT    NOT NULL
) STRICT;

CREATE INDEX cloudflare_dns_records_zone ON cloudflare_dns_records (zone_id);

-- One row per zone, UTC day, dimension and key; kept 30 days.
CREATE TABLE cloudflare_security_daily (
    zone_id TEXT    NOT NULL REFERENCES cloudflare_zones (id) ON DELETE CASCADE,
    day     TEXT    NOT NULL, -- 2026-10-24 (UTC)
    dim     TEXT    NOT NULL CHECK (dim IN ('total', 'requests', 'action', 'country', 'asn', 'path')),
    key     TEXT    NOT NULL DEFAULT '',
    count   INTEGER NOT NULL,
    PRIMARY KEY (zone_id, day, dim, key)
) STRICT;

CREATE TABLE cloudflare_radar_asn (
    ip         TEXT PRIMARY KEY,
    asn        INTEGER NOT NULL DEFAULT 0,  -- 0: not found or failed
    name       TEXT    NOT NULL DEFAULT '',
    country    TEXT    NOT NULL DEFAULT '',
    fetched_at TEXT    NOT NULL
) STRICT;

-- The last run of each sync ('edge', 'zones', 'radar').
CREATE TABLE cloudflare_syncs (
    what  TEXT PRIMARY KEY,
    at    TEXT NOT NULL,
    error TEXT NOT NULL DEFAULT ''
) STRICT;
