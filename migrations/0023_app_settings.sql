-- Instance-wide key/value settings (first consumer: the Console's AI text
-- assistant config, stored under key 'ai' as a JSON blob).
--
-- `value` is sealed at rest through the vault (same treatment as private keys
-- and Cloud API credentials) because it can carry third-party API keys; the
-- store layer seals on write and unseals on read, so callers only ever see
-- plaintext bytes. `updated_at` is unix seconds.
CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT    PRIMARY KEY,
    value      BLOB    NOT NULL,
    updated_at INTEGER NOT NULL
);
