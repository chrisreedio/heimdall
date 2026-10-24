-- Privilege watch: where each session came from (an SSH login's remote
-- address, or the remote host of the terminal sudo or su ran in), recorded
-- only when the server opted in to usernames (--watch-privilege-users).
-- '' for a local session or no opt-in, '?' when the server couldn't tell.
ALTER TABLE privilege_events ADD COLUMN source TEXT NOT NULL DEFAULT '';
