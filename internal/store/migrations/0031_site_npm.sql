-- Sites' npm packages (snapshot v4) go in app_packages under
-- <site root>/package-lock.json, with npm's dev flag: needed only to build
-- or test the app. A finding on a dev package carries the flag, and
-- finding_counts counts those apart (dev): they're in total, and nowhere
-- else, so they don't raise a host's severity, known-exploited, fixable or
-- watch counts. Existing rows are all runtime packages (0), so nothing
-- needs recounting.
ALTER TABLE app_packages ADD COLUMN dev INTEGER NOT NULL DEFAULT 0 CHECK (dev IN (0, 1));
ALTER TABLE findings ADD COLUMN dev INTEGER NOT NULL DEFAULT 0 CHECK (dev IN (0, 1));
ALTER TABLE finding_counts ADD COLUMN dev INTEGER NOT NULL DEFAULT 0;
