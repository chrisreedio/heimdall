-- A CNAME target whose domain isn't registered either ('unregistered').
-- The table is a cache the next zone sync refills, so it's rebuilt empty:
-- that also drops answers from before lookups told a name with no
-- addresses (a DKIM key) from one that doesn't exist.
DROP TABLE surface_cname_checks;
CREATE TABLE surface_cname_checks (
    target     TEXT PRIMARY KEY,
    status     TEXT NOT NULL CHECK (status IN ('ok', 'nxdomain', 'unregistered', 'error')),
    note       TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL
) STRICT;
