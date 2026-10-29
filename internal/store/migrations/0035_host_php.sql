-- Which PHP versions a host uses outside its sites' PHP-FPM sockets, from
-- the collector's X-Heimdall-PHP header: cli is the version the command
-- line `php` runs ('' when there's none), fpm the versions whose PHP-FPM
-- is running (a JSON array). With both and the sites' FPM versions, an
-- installed PHP version nothing uses can be suggested for removal. No row
-- means an older collector: unknown, so nothing is suggested.
CREATE TABLE host_php (
    host_id INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    cli     TEXT    NOT NULL DEFAULT '',
    fpm     TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(fpm)),
    seen_at TEXT    NOT NULL
) STRICT;
