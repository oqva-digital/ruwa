-- Persistent metric samples: backs the ruwa Console "Metrics" page so charts
-- survive restarts/deploys. The live `/metrics` endpoint is in-memory atomics
-- (reset to zero on every boot); a background sampler snapshots them here on a
-- fixed cadence so cumulative counters and point-in-time gauges have history.
--
-- `ts` is unix SECONDS. `value` is REAL: counters are stored as their absolute
-- cumulative reading at sample time (a restart resets the underlying counter,
-- which the chart shows as a drop to zero — honest, and distinguishable from a
-- real decrease). One row per (series, second); the sampler self-prunes by age.
CREATE TABLE metrics_samples (
    name   TEXT NOT NULL,        -- series name, e.g. 'ruwa_messages_in_total'
    ts     INTEGER NOT NULL,     -- unix seconds
    value  REAL NOT NULL,
    PRIMARY KEY (name, ts)
);

CREATE INDEX idx_metrics_samples_ts ON metrics_samples (ts);
