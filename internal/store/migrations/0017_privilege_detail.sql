-- What each server's privilege hook records (kinds, users or sources), as
-- its collector last reported; '' until a collector that says reports.
ALTER TABLE privilege_watch ADD COLUMN detail TEXT NOT NULL DEFAULT '';
