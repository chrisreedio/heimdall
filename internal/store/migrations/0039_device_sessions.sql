-- Device sessions: "Keep me signed in on this device" at sign-in makes a
-- session that lasts 30 days from its last use (kept = 1) instead of the
-- hub's idle and absolute limits. label describes the browser, from its
-- User-Agent ("iPhone Safari"), for the Devices list. Sessions from before
-- this have no label; the list falls back to their user_agent.
ALTER TABLE sessions ADD COLUMN kept  INTEGER NOT NULL DEFAULT 0 CHECK (kept IN (0, 1));
ALTER TABLE sessions ADD COLUMN label TEXT    NOT NULL DEFAULT '';

-- A single sign-on carries the choice through Microsoft's sign-in page.
ALTER TABLE auth_requests ADD COLUMN keep INTEGER NOT NULL DEFAULT 0 CHECK (keep IN (0, 1));
