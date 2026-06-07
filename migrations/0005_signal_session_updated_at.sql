-- Track when each Signal session record was last written, so the retention
-- sweep can prune dead-device sessions (peers that haven't been talked to in a
-- long time). Backfill existing rows to migration time so a freshly-upgraded
-- store doesn't immediately prune live sessions.
ALTER TABLE signal_sessions ADD COLUMN updated_at INTEGER NOT NULL DEFAULT 0;
UPDATE signal_sessions SET updated_at = strftime('%s', 'now');
CREATE INDEX idx_signal_sessions_updated_at
    ON signal_sessions (updated_at);
