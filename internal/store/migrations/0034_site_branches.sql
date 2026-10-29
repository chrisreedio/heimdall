-- Each site's checked-out branch, for "Hand off to agent" (where the pull
-- request goes). detected_branch and detected_commit come from the
-- collector (the site's .git/HEAD: a branch, or the commit of a detached
-- HEAD) and are replaced on every push that reports them; manual_branch is
-- set on the site page by an operator and wins. '' when unknown. A row
-- with every column empty is deleted.
ALTER TABLE site_repos ADD COLUMN detected_branch TEXT NOT NULL DEFAULT '';
ALTER TABLE site_repos ADD COLUMN detected_commit TEXT NOT NULL DEFAULT '';
ALTER TABLE site_repos ADD COLUMN manual_branch TEXT NOT NULL DEFAULT '';
