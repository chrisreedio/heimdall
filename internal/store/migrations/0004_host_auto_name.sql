-- Hosts added without a name take the hostname their collector reports on
-- the first check-in (then auto_name goes back to 0). Until then their
-- name is a "pending-..." placeholder.
ALTER TABLE hosts ADD COLUMN auto_name INTEGER NOT NULL DEFAULT 0;
