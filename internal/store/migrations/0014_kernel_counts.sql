-- Kernel-aware finding counts. not_running: OS findings whose packages all
-- belong to an older kernel that's installed but not running; they're left
-- out of kev, fixable, fix_pending and fix_urgent. reboot_pending: findings
-- on the running kernel while a newer one is installed (still live, and
-- counted everywhere). Telling those apart needs the running kernel and
-- the installed kernel packages compared as dpkg versions, so the store
-- recounts every host in Go right after this migration (see Migrate).
ALTER TABLE finding_counts ADD COLUMN not_running INTEGER NOT NULL DEFAULT 0;
ALTER TABLE finding_counts ADD COLUMN reboot_pending INTEGER NOT NULL DEFAULT 0;
