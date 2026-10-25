-- finding_counts.watch: open findings with no fix released yet that are
-- still worth watching (known-exploited, in the news, or an EPSS score of at
-- least store.WatchEPSS), on live kernels only. The store recounts every host
-- right after this migration (see Migrate).
ALTER TABLE finding_counts ADD COLUMN watch INTEGER NOT NULL DEFAULT 0;
