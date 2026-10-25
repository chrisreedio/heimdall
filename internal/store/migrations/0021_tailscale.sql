-- Tailscale: the tailnet's devices as of the last sync with the Tailscale
-- API (read only), replaced wholesale on each sync. Each device's addresses
-- also become ip_labels rows (source 'tailscale'); this table keeps the
-- detail the host page's Tailnet card shows.
CREATE TABLE tailscale_devices (
    id                  TEXT    PRIMARY KEY,           -- the API's device id
    name                TEXT    NOT NULL,              -- MagicDNS name, e.g. web-01.tail1234.ts.net
    hostname            TEXT    NOT NULL DEFAULT '',   -- the machine's own hostname
    addresses           TEXT    NOT NULL DEFAULT '',   -- space-separated, e.g. "100.101.102.103 fd7a:115c:a1e0::1"
    user_login          TEXT    NOT NULL DEFAULT '',   -- owner's login; empty for tagged devices
    tags                TEXT    NOT NULL DEFAULT '',   -- space-separated, e.g. "tag:server"
    os                  TEXT    NOT NULL DEFAULT '',
    client_version      TEXT    NOT NULL DEFAULT '',
    update_available    INTEGER NOT NULL DEFAULT 0,
    online              INTEGER NOT NULL DEFAULT 0,    -- connectedToControl
    last_seen           TEXT    NOT NULL DEFAULT '',
    key_expiry          TEXT    NOT NULL DEFAULT '',   -- empty when key expiry is disabled
    key_expiry_disabled INTEGER NOT NULL DEFAULT 0,
    synced_at           TEXT    NOT NULL
) STRICT;

-- The one row of sync state, for `heimdall tailscale status`.
CREATE TABLE tailscale_sync (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    attempted_at TEXT    NOT NULL DEFAULT '',
    synced_at    TEXT    NOT NULL DEFAULT '',  -- last good sync
    error        TEXT    NOT NULL DEFAULT '',  -- last attempt's error, '' if it worked
    devices      INTEGER NOT NULL DEFAULT 0,
    credential   TEXT    NOT NULL DEFAULT '',  -- 'oauth' or 'api-key'
    key_expires  TEXT    NOT NULL DEFAULT ''   -- an API access token's expiry, when known
) STRICT;
