-- Advisories kept each OSV record verbatim in `raw`, and nothing reads it:
-- findings, pages, reports and MCP use the columns, aliases and ranges
-- derived from it. Ubuntu's kernel records list every binary of every
-- kernel flavour in every release, so `raw` was nearly all of a hub's
-- database (3.8 GB for three Ubuntu hosts).
--
-- From now on `record` holds a slimmed record (see osv.Slim), deflate-
-- compressed, and `raw` is ''. `heimdall migrate` converts existing rows
-- after this migration in small batches (Store.SlimAdvisories), then
-- reclaims the space with VACUUM. Adding a column doesn't rewrite the table.
ALTER TABLE advisories ADD COLUMN record BLOB;

-- Ranges are only ever looked up by advisory (Store.FixedVersions).
DROP INDEX affected_ranges_pkg;
