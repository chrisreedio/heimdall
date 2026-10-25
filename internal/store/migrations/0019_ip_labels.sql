-- IP awareness: what Heimdall knows about an address or range. A label is
-- added by hand (source 'manual') or kept in sync by a source such as a
-- deploy service's published ranges or the Tailscale API, which replaces
-- its own rows wholesale on each sync. org_id NULL: applies to every org.
CREATE TABLE ip_labels (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER REFERENCES organizations (id) ON DELETE CASCADE,
    prefix     TEXT    NOT NULL, -- canonical CIDR, e.g. 203.0.113.0/24 or 100.101.102.103/32
    kind       TEXT    NOT NULL CHECK (kind IN ('staff', 'automation', 'infra', 'tailnet', 'private', 'unknown')),
    name       TEXT    NOT NULL,              -- "Office VPN", "Laravel Forge", "laptop-01"
    person     TEXT    NOT NULL DEFAULT '',   -- who, when known: an email or display name
    source     TEXT    NOT NULL,              -- 'manual', 'service:forge', 'tailscale', ...
    note       TEXT    NOT NULL DEFAULT '',
    created_by TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE INDEX ip_labels_org ON ip_labels (org_id, source);

-- The address a host's last report came from (as the ingest listener saw
-- it), so your own servers' addresses are known.
ALTER TABLE hosts ADD COLUMN report_ip TEXT NOT NULL DEFAULT '';
CREATE INDEX hosts_report_ip ON hosts (org_id, report_ip) WHERE report_ip <> '';
