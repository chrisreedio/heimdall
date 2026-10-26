-- Per-org: count deploy-service sessions (from a synced automation range)
-- toward privileged_access. Off by default: Forge and the like SSH in as
-- root on every deploy.
ALTER TABLE ip_policies ADD COLUMN count_services INTEGER NOT NULL DEFAULT 0 CHECK (count_services IN (0, 1));
