-- Each org's default collector options on the Add host and Add servers
-- pages: record who and from where for sudo, su and root SSH
-- (--watch-privilege-users), and count failed SSH logins (--watch-logins).
-- Both start on, for existing orgs too: they only change the install
-- command shown, never a server that already reports.
ALTER TABLE organizations ADD COLUMN watch_privilege_users INTEGER NOT NULL DEFAULT 1 CHECK (watch_privilege_users IN (0, 1));
ALTER TABLE organizations ADD COLUMN watch_logins INTEGER NOT NULL DEFAULT 1 CHECK (watch_logins IN (0, 1));
