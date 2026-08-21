-- When this session last persisted a heavy history-sync chunk
-- (INITIAL_BOOTSTRAP / FULL / RECENT). Used to skip re-downloading the same
-- history when the phone re-pushes those chunks on reconnect. NULL = never.
ALTER TABLE sessions ADD COLUMN history_synced_at INTEGER;
