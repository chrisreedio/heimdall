-- Each host's sshd settings, from the collector's X-Heimdall-SSH header:
-- where they came from (src: g = `sshd -G`, files = read from
-- sshd_config, unreadable, none = no sshd), its ports, the addresses
-- listening on them (JSON arrays), and password, keyboard-interactive,
-- PAM and root login ('' unknown). What sshd allows, not whether a cloud
-- firewall lets anyone reach it. No row means an older collector.
CREATE TABLE host_ssh (
    host_id  INTEGER PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    src      TEXT    NOT NULL CHECK (src IN ('g', 'files', 'unreadable', 'none')),
    ports    TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(ports)),
    listen   TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(listen)),
    password TEXT    NOT NULL DEFAULT '',
    kbd      TEXT    NOT NULL DEFAULT '',
    pam      TEXT    NOT NULL DEFAULT '',
    root     TEXT    NOT NULL DEFAULT '',
    seen_at  TEXT    NOT NULL
) STRICT;
