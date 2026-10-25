-- Enrollment keys: a short-lived secret that adds servers to one org and
-- environment, each getting its own ingest token. Only hashes are stored.
CREATE TABLE enroll_keys (
    id         INTEGER PRIMARY KEY,
    org_id     INTEGER NOT NULL,
    env_id     INTEGER NOT NULL,
    label      TEXT    NOT NULL DEFAULT '',
    tags       TEXT    NOT NULL DEFAULT '[]', -- JSON array, given to each host
    key_hash   BLOB    NOT NULL UNIQUE CHECK (length(key_hash) = 32),
    max_uses   INTEGER NOT NULL DEFAULT 0, -- 0: any number until it expires
    uses       INTEGER NOT NULL DEFAULT 0,
    -- 1: hosts it enrolls wait for an admin's approval before reporting
    require_approval INTEGER NOT NULL DEFAULT 1 CHECK (require_approval IN (0, 1)),
    created_by TEXT    NOT NULL,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at TEXT    NOT NULL,
    revoked_at TEXT,
    FOREIGN KEY (env_id, org_id) REFERENCES environments (id, org_id) ON DELETE CASCADE
) STRICT;

CREATE INDEX enroll_keys_org ON enroll_keys (org_id);

-- Which key enrolled a host, and a hash of its machine ID (as its
-- collector reports it), so the same server isn't enrolled twice. A host
-- awaiting approval has its reports answered but not stored.
ALTER TABLE hosts ADD COLUMN enroll_key_id INTEGER REFERENCES enroll_keys (id) ON DELETE SET NULL;
ALTER TABLE hosts ADD COLUMN machine TEXT NOT NULL DEFAULT '';
ALTER TABLE hosts ADD COLUMN awaiting_approval INTEGER NOT NULL DEFAULT 0 CHECK (awaiting_approval IN (0, 1));
CREATE INDEX hosts_machine ON hosts (org_id, machine) WHERE machine <> '';
