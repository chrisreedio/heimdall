-- Whether anything answers at a dangling record's address
-- (docs/cloudflare.md#dangling-records): the hub's plain TCP connect to
-- ports 443 and 80, nothing sent. state: answers (port is the one that
-- accepted), refused (something is there but both ports are closed) or
-- silent (no reply on either). No row: not checked. Rows for addresses
-- that are no longer dangling are dropped on the next probe run.
CREATE TABLE dangling_probes (
    addr       TEXT    PRIMARY KEY,
    state      TEXT    NOT NULL CHECK (state IN ('answers', 'refused', 'silent')),
    port       INTEGER NOT NULL DEFAULT 0,
    checked_at TEXT    NOT NULL
) STRICT;
