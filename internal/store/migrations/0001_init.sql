-- Heimdall initial schema.
--
-- Covers every milestone in the README so later work fills tables in rather
-- than reshaping them. Timestamps are UTC ISO-8601 text.

-- ── Tenancy ────────────────────────────────────────────────────────────────

CREATE TABLE organizations (
    id                 INTEGER PRIMARY KEY,
    slug               TEXT    NOT NULL UNIQUE,
    name               TEXT    NOT NULL,
    ingest_allow_cidrs TEXT    NOT NULL DEFAULT '[]', -- JSON array (M6)
    created_at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT;

CREATE TABLE environments (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    slug       TEXT    NOT NULL,
    name       TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    UNIQUE (org_id, slug),
    UNIQUE (id, org_id) -- target of hosts' composite key
) STRICT;

CREATE TABLE hosts (
    id               INTEGER PRIMARY KEY,
    org_id           INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    env_id           INTEGER NOT NULL,
    name             TEXT    NOT NULL,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at     TEXT,
    last_snapshot_id INTEGER REFERENCES snapshots (id) ON DELETE SET NULL,
    UNIQUE (org_id, name),
    UNIQUE (id, org_id), -- target of composite keys below
    -- A host's environment must belong to the host's own org.
    FOREIGN KEY (env_id, org_id) REFERENCES environments (id, org_id) ON DELETE CASCADE
) STRICT;

CREATE TABLE host_tags (
    host_id INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    tag     TEXT    NOT NULL,
    PRIMARY KEY (host_id, tag)
) STRICT, WITHOUT ROWID;

CREATE INDEX host_tags_tag ON host_tags (tag);

-- Bearer tokens are stored as SHA-256 hashes only.
CREATE TABLE ingest_tokens (
    id           INTEGER PRIMARY KEY,
    host_id      INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    token_hash   BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at TEXT,
    revoked_at   TEXT
) STRICT;

-- At most one live token per host; rotation revokes then inserts.
CREATE UNIQUE INDEX ingest_tokens_one_active ON ingest_tokens (host_id) WHERE revoked_at IS NULL;

-- ── Inventory (append-only) ────────────────────────────────────────────────

CREATE TABLE snapshots (
    id                INTEGER PRIMARY KEY,
    host_id           INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    source            TEXT    NOT NULL CHECK (source IN ('push', 'import')),
    received_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    collected_at      TEXT    NOT NULL, -- as claimed by the host
    collector_version TEXT    NOT NULL,
    collector_sha256  BLOB    CHECK (length(collector_sha256) = 32), -- NULL if the collector ran from stdin
    payload_sha256    BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    os_id             TEXT,             -- os-release ID, e.g. "debian"
    os_version        TEXT,             -- os-release VERSION_ID, e.g. "12"
    os_pretty         TEXT,
    kernel            TEXT,
    arch              TEXT,
    uptime_seconds    INTEGER,
    reboot_required   INTEGER CHECK (reboot_required IN (0, 1)),
    package_manager   TEXT,             -- dpkg, rpm, apk
    os_id_like        TEXT
) STRICT;

CREATE INDEX snapshots_host ON snapshots (host_id, received_at);

-- A host never sends the same payload twice (it embeds collected_at), so a
-- duplicate is a replay. The hub answers quick retries idempotently.
CREATE UNIQUE INDEX snapshots_no_replay ON snapshots (host_id, payload_sha256);

CREATE TABLE packages (
    snapshot_id      INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    ecosystem        TEXT    NOT NULL, -- OSV ecosystem, e.g. "Debian:12"
    name             TEXT    NOT NULL,
    version          TEXT    NOT NULL,
    arch             TEXT    NOT NULL DEFAULT '',
    source_name      TEXT,             -- source package, used for advisory matching
    source_version   TEXT,
    pending_version  TEXT,
    pending_security INTEGER NOT NULL DEFAULT 0 CHECK (pending_security IN (0, 1)),
    -- rpm allows several versions of one package (e.g. kernels).
    PRIMARY KEY (snapshot_id, name, arch, version)
) STRICT, WITHOUT ROWID;

CREATE INDEX packages_name ON packages (name, version);

CREATE TABLE runtimes (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN ('runtime', 'service')),
    name        TEXT    NOT NULL, -- e.g. "php", "nginx"
    version     TEXT    NOT NULL,
    path        TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, name, path)
) STRICT, WITHOUT ROWID;

CREATE TABLE containers (
    snapshot_id INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    image       TEXT    NOT NULL,
    tag         TEXT    NOT NULL DEFAULT '',
    digest      TEXT    NOT NULL DEFAULT '',
    state       TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (snapshot_id, name)
) STRICT, WITHOUT ROWID;

-- Web apps on the host (M4): one row per discovered app root.
CREATE TABLE sites (
    snapshot_id       INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    root              TEXT    NOT NULL, -- app root, e.g. /home/forge/example.com
    document_root     TEXT    NOT NULL DEFAULT '',
    server_names      TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(server_names)),
    web_server        TEXT    NOT NULL DEFAULT '' CHECK (web_server IN ('', 'nginx', 'apache')),
    php_fpm_version   TEXT    NOT NULL DEFAULT '', -- from the FastCGI socket, e.g. "8.3"
    framework         TEXT    NOT NULL DEFAULT '' CHECK (framework IN ('', 'laravel')),
    framework_version TEXT    NOT NULL DEFAULT '',
    php_requirement   TEXT    NOT NULL DEFAULT '', -- composer.json require.php
    deployed_at       TEXT,                        -- composer.lock mtime
    PRIMARY KEY (snapshot_id, root)
) STRICT, WITHOUT ROWID;

CREATE INDEX sites_framework ON sites (framework, framework_version);

CREATE TABLE app_packages (
    snapshot_id   INTEGER NOT NULL REFERENCES snapshots (id) ON DELETE CASCADE,
    manifest_path TEXT    NOT NULL, -- e.g. <site root>/composer.lock
    ecosystem     TEXT    NOT NULL, -- "npm", "Packagist", "PyPI"
    name          TEXT    NOT NULL,
    version       TEXT    NOT NULL,
    PRIMARY KEY (snapshot_id, manifest_path, name, version)
) STRICT, WITHOUT ROWID;

-- Snapshots and their contents are never edited. Retention (M7) may delete.
CREATE TRIGGER snapshots_no_update BEFORE UPDATE ON snapshots
BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TRIGGER packages_no_update BEFORE UPDATE ON packages
BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TRIGGER runtimes_no_update BEFORE UPDATE ON runtimes
BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TRIGGER containers_no_update BEFORE UPDATE ON containers
BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TRIGGER app_packages_no_update BEFORE UPDATE ON app_packages
BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;
CREATE TRIGGER sites_no_update BEFORE UPDATE ON sites
BEGIN SELECT RAISE(ABORT, 'snapshots are append-only'); END;

-- Collector releases you trust; anything else raises "collector changed".
CREATE TABLE known_collectors (
    sha256   BLOB PRIMARY KEY CHECK (length(sha256) = 32),
    version  TEXT NOT NULL,
    added_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    note     TEXT NOT NULL DEFAULT ''
) STRICT, WITHOUT ROWID;

-- ── Feeds (local cache) ────────────────────────────────────────────────────

CREATE TABLE feed_state (
    feed            TEXT PRIMARY KEY CHECK (feed IN ('osv', 'kev', 'epss', 'endoflife')),
    last_attempt_at TEXT,
    last_success_at TEXT,
    etag            TEXT,
    last_modified   TEXT,
    last_error      TEXT
) STRICT;

CREATE TABLE advisories (
    id         TEXT PRIMARY KEY, -- OSV ID, e.g. "DEBIAN-CVE-2024-1234"
    modified   TEXT NOT NULL,
    published  TEXT,
    withdrawn  TEXT,
    summary    TEXT NOT NULL DEFAULT '',
    severity   TEXT NOT NULL DEFAULT 'unknown'
               CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    cvss_score REAL,
    raw        TEXT NOT NULL -- original OSV JSON
) STRICT;

CREATE TABLE advisory_aliases (
    advisory_id TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    alias       TEXT NOT NULL, -- e.g. "CVE-2024-1234"
    PRIMARY KEY (advisory_id, alias)
) STRICT, WITHOUT ROWID;

CREATE INDEX advisory_aliases_alias ON advisory_aliases (alias);

CREATE TABLE affected_ranges (
    id            INTEGER PRIMARY KEY,
    advisory_id   TEXT NOT NULL REFERENCES advisories (id) ON DELETE CASCADE,
    ecosystem     TEXT NOT NULL,
    package       TEXT NOT NULL,
    introduced    TEXT,
    fixed         TEXT,
    last_affected TEXT
) STRICT;

CREATE INDEX affected_ranges_pkg ON affected_ranges (ecosystem, package);
CREATE INDEX affected_ranges_advisory ON affected_ranges (advisory_id);

-- OSV query results per (ecosystem, source package, version). Refreshed
-- after feeds.sync_interval; advisories are refetched only when changed.
CREATE TABLE osv_query_cache (
    ecosystem  TEXT NOT NULL,
    name       TEXT NOT NULL,
    version    TEXT NOT NULL,
    vuln_ids   TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(vuln_ids)),
    checked_at TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name, version)
) STRICT, WITHOUT ROWID;

CREATE TABLE kev_entries (
    cve_id           TEXT PRIMARY KEY,
    vendor           TEXT    NOT NULL DEFAULT '',
    product          TEXT    NOT NULL DEFAULT '',
    date_added       TEXT    NOT NULL,
    due_date         TEXT,
    known_ransomware INTEGER NOT NULL DEFAULT 0 CHECK (known_ransomware IN (0, 1))
) STRICT;

CREATE TABLE epss_scores (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL CHECK (score BETWEEN 0 AND 1),
    percentile REAL NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    scored_on  TEXT NOT NULL
) STRICT;

CREATE TABLE eol_cycles (
    product       TEXT NOT NULL, -- endoflife.date product, e.g. "ubuntu", "php"
    cycle         TEXT NOT NULL, -- e.g. "22.04", "8.1"
    release_date  TEXT,
    support_until TEXT,
    eol_date      TEXT,          -- NULL if no EOL announced
    latest        TEXT,
    PRIMARY KEY (product, cycle)
) STRICT, WITHOUT ROWID;

-- ── Findings ───────────────────────────────────────────────────────────────

CREATE TABLE findings (
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
    binaries        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(binaries)), -- binary packages built from package_name
    fix_pending     INTEGER NOT NULL DEFAULT 0 CHECK (fix_pending IN (0, 1)),  -- a pending update reaches fixed_version
    UNIQUE (host_id, advisory_id, package_name)
) STRICT;

CREATE INDEX findings_open ON findings (host_id) WHERE resolved_at IS NULL;
CREATE INDEX findings_advisory ON findings (advisory_id);

-- ── Users & access ─────────────────────────────────────────────────────────

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    kind          TEXT    NOT NULL CHECK (kind IN ('local', 'entra')),
    email         TEXT    NOT NULL,
    display_name  TEXT    NOT NULL DEFAULT '',
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)), -- all orgs, user mgmt
    password_hash TEXT,   -- local only (argon2id PHC string)
    totp_secret   BLOB,   -- local only
    totp_last_step INTEGER NOT NULL DEFAULT 0, -- last accepted TOTP time step (replay protection)
    entra_tid     TEXT,   -- entra only
    entra_oid     TEXT,   -- entra only; NULL until bound on first login
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_login_at TEXT,
    disabled_at   TEXT,
    CHECK (
        (kind = 'local' AND password_hash IS NOT NULL AND entra_tid IS NULL AND entra_oid IS NULL) OR
        (kind = 'entra' AND password_hash IS NULL AND totp_secret IS NULL AND entra_tid IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX users_local_email ON users (email) WHERE kind = 'local';
CREATE UNIQUE INDEX users_entra_identity ON users (entra_tid, entra_oid) WHERE entra_oid IS NOT NULL;
CREATE UNIQUE INDEX users_entra_pending ON users (entra_tid, email) WHERE kind = 'entra' AND entra_oid IS NULL;

CREATE TABLE memberships (
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    org_id  INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    role    TEXT    NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    source  TEXT    NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'entra_app_role')),
    PRIMARY KEY (user_id, org_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE sessions (
    id_hash      BLOB    PRIMARY KEY CHECK (length(id_hash) = 32),
    user_id      INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT    NOT NULL,
    ip           TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT ''
) STRICT, WITHOUT ROWID;

CREATE INDEX sessions_user ON sessions (user_id);

-- In-flight OIDC logins (M5): state, nonce and PKCE verifier.
CREATE TABLE auth_requests (
    state_hash    BLOB PRIMARY KEY CHECK (length(state_hash) = 32),
    nonce         TEXT NOT NULL,
    pkce_verifier TEXT NOT NULL,
    return_to     TEXT NOT NULL DEFAULT '/',
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
) STRICT, WITHOUT ROWID;

-- ── Patch plans (M6) ───────────────────────────────────────────────────────

CREATE TABLE patch_plans (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER REFERENCES organizations (id) ON DELETE CASCADE, -- NULL = cross-org
    name       TEXT    NOT NULL,
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    closed_at  TEXT
) STRICT;

CREATE TABLE patch_plan_items (
    plan_id     INTEGER NOT NULL REFERENCES patch_plans (id) ON DELETE CASCADE,
    host_id     INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    batch       INTEGER NOT NULL DEFAULT 1 CHECK (batch >= 1),
    done_at     TEXT,
    done_by     INTEGER REFERENCES users (id) ON DELETE SET NULL,
    verified_at TEXT, -- set when a later snapshot confirms the fix
    PRIMARY KEY (plan_id, host_id)
) STRICT, WITHOUT ROWID;

-- ── Anomaly signals (M1, M8) ───────────────────────────────────────────────

-- Changes and reboots inside a window don't alert. Scope is the whole org,
-- one env, or one host. A window is either one-off (starts_at/ends_at) or
-- weekly (weekdays bitmask, Sun=1 … Sat=64, local start time, duration).
CREATE TABLE maintenance_windows (
    id               INTEGER PRIMARY KEY,
    org_id           INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    env_id           INTEGER,
    host_id          INTEGER,
    name             TEXT    NOT NULL DEFAULT '',
    starts_at        TEXT,
    ends_at          TEXT,
    weekdays         INTEGER CHECK (weekdays BETWEEN 1 AND 127),
    start_time       TEXT    CHECK (start_time GLOB '[0-2][0-9]:[0-5][0-9]'),
    duration_minutes INTEGER CHECK (duration_minutes BETWEEN 1 AND 1440),
    timezone         TEXT,   -- IANA name, e.g. "America/Chicago"
    created_by       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    FOREIGN KEY (env_id, org_id) REFERENCES environments (id, org_id) ON DELETE CASCADE,
    FOREIGN KEY (host_id, org_id) REFERENCES hosts (id, org_id) ON DELETE CASCADE,
    CHECK (env_id IS NULL OR host_id IS NULL),
    CHECK (
        (starts_at IS NOT NULL AND ends_at IS NOT NULL AND ends_at > starts_at
         AND weekdays IS NULL AND start_time IS NULL AND duration_minutes IS NULL AND timezone IS NULL) OR
        (starts_at IS NULL AND ends_at IS NULL
         AND weekdays IS NOT NULL AND start_time IS NOT NULL AND duration_minutes IS NOT NULL AND timezone IS NOT NULL)
    )
) STRICT;

CREATE INDEX maintenance_windows_org ON maintenance_windows (org_id);

CREATE TABLE anomalies (
    id              INTEGER PRIMARY KEY,
    host_id         INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    snapshot_id     INTEGER REFERENCES snapshots (id) ON DELETE SET NULL, -- NULL for rejected replays, silence
    rule            TEXT    NOT NULL CHECK (rule IN (
                        'silence', 'replay', 'clock_skew', 'package_change', 'package_downgrade',
                        'kernel_no_reboot', 'unexpected_reboot', 'collector_changed', 'peer_outlier')),
    severity        TEXT    NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    summary         TEXT    NOT NULL,
    detail          TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    detected_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    acknowledged_at TEXT,
    acknowledged_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    ack_note        TEXT,
    CHECK ((acknowledged_at IS NULL) = (ack_note IS NULL))
) STRICT;

CREATE INDEX anomalies_open ON anomalies (host_id, detected_at) WHERE acknowledged_at IS NULL;

-- Mute one rule on one host. Always expires, so nothing is muted forever.
CREATE TABLE anomaly_suppressions (
    id         INTEGER PRIMARY KEY,
    host_id    INTEGER NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    rule       TEXT    NOT NULL,
    until_at   TEXT    NOT NULL,
    note       TEXT    NOT NULL CHECK (note <> ''),
    created_by INTEGER REFERENCES users (id) ON DELETE SET NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    CHECK (until_at > created_at)
) STRICT;

CREATE INDEX anomaly_suppressions_host ON anomaly_suppressions (host_id, rule);

-- ── Audit log ──────────────────────────────────────────────────────────────

-- org_id is deliberately not a foreign key: entries outlive what they describe.
CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY,
    at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    actor  TEXT    NOT NULL, -- "cli:<os user>", "user:<id>", "host:<id>"
    action TEXT    NOT NULL, -- e.g. "host.add", "token.create"
    org_id INTEGER,
    target TEXT    NOT NULL DEFAULT '',
    detail TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(detail)),
    ip     TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX audit_log_at ON audit_log (at);

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
