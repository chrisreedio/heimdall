-- Optional AI analysis ([ai]): the fleet brief (one per org, host_id NULL)
-- and "explain this host" (host_id set). Each row is one run against the
-- operator's own model deployment. result holds the validated,
-- advisory-only output; prompts are never stored. The last few runs per
-- org brief and per host are kept and older ones pruned.
CREATE TABLE ai_runs (
    id            INTEGER PRIMARY KEY,
    org_id        INTEGER NOT NULL REFERENCES organizations (id) ON DELETE CASCADE,
    host_id       INTEGER,
    kind          TEXT    NOT NULL CHECK (kind IN ('brief', 'host')),
    status        TEXT    NOT NULL CHECK (status IN ('running', 'ok', 'error')),
    created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    finished_at   TEXT,
    requested_by  TEXT    NOT NULL DEFAULT '', -- audit actor, e.g. "user:3" or "hub:schedule"
    deployment    TEXT    NOT NULL DEFAULT '', -- the configured deployment name
    model         TEXT    NOT NULL DEFAULT '', -- the model the API said answered
    input_tokens  INTEGER NOT NULL DEFAULT 0,
    output_tokens INTEGER NOT NULL DEFAULT 0,
    error         TEXT    NOT NULL DEFAULT '', -- a short, fixed message; never a raw response
    result        TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(result)),
    FOREIGN KEY (host_id, org_id) REFERENCES hosts (id, org_id) ON DELETE CASCADE,
    CHECK ((kind = 'brief') = (host_id IS NULL))
) STRICT;

CREATE INDEX ai_runs_latest ON ai_runs (org_id, kind, host_id, id);
