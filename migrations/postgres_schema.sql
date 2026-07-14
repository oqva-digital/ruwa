-- Consolidated Postgres schema (idempotent) for the PgStore backend. Mirrors
-- the SQLite migrations 0001–0006: SQLite INTEGER -> BIGINT, BLOB -> BYTEA.
-- Integer-coded booleans (uploaded, from_me, is_group, ...) stay BIGINT so the
-- Rust read/write patterns match the SQLite backend exactly.

CREATE TABLE IF NOT EXISTS sessions (
    id                  TEXT PRIMARY KEY,
    label               TEXT,
    status              TEXT NOT NULL,
    jid                 TEXT,
    registration_id     BIGINT,
    noise_key_priv      BYTEA,
    noise_key_pub       BYTEA,
    identity_key_priv   BYTEA,
    identity_key_pub    BYTEA,
    signed_prekey_id    BIGINT,
    signed_prekey_priv  BYTEA,
    signed_prekey_pub   BYTEA,
    signed_prekey_sig   BYTEA,
    adv_secret_key      BYTEA,
    account_pb          BYTEA,
    server_token        BYTEA,
    client_token        BYTEA,
    business_name       TEXT,
    push_name           TEXT,
    platform            TEXT,
    created_at          BIGINT NOT NULL,
    updated_at          BIGINT NOT NULL,
    proxy_url           TEXT,
    api_key             TEXT,
    mark_online         INTEGER NOT NULL DEFAULT 0
);
-- Idempotent add for databases created before mark_online existed.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS mark_online INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS prekeys (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    key_id      BIGINT NOT NULL,
    private_key BYTEA NOT NULL,
    public_key  BYTEA NOT NULL,
    uploaded    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, key_id)
);

CREATE TABLE IF NOT EXISTS signal_sessions (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,
    record      BYTEA NOT NULL,
    updated_at  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, address)
);

CREATE TABLE IF NOT EXISTS lid_pn_map (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    lid_user    TEXT NOT NULL,
    pn_user     TEXT NOT NULL,
    updated_at  BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, lid_user)
);
CREATE INDEX IF NOT EXISTS idx_lid_pn_map_pn ON lid_pn_map (session_id, pn_user);

CREATE TABLE IF NOT EXISTS sender_keys (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL,
    sender      TEXT NOT NULL,
    record      BYTEA NOT NULL,
    PRIMARY KEY (session_id, group_id, sender)
);

CREATE TABLE IF NOT EXISTS remote_identities (
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    identity_key BYTEA NOT NULL,
    PRIMARY KEY (session_id, address)
);

CREATE TABLE IF NOT EXISTS app_state_versions (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    version     BIGINT NOT NULL,
    hash        BYTEA NOT NULL,
    PRIMARY KEY (session_id, name)
);

CREATE TABLE IF NOT EXISTS app_state_mac_keys (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    key_id      BYTEA NOT NULL,
    key_data    BYTEA NOT NULL,
    PRIMARY KEY (session_id, key_id)
);

CREATE TABLE IF NOT EXISTS messages (
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    chat_jid     TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    sender_jid   TEXT NOT NULL,
    from_me      BIGINT NOT NULL,
    timestamp    BIGINT NOT NULL,
    msg_type     TEXT NOT NULL,
    body_text    TEXT,
    payload_json TEXT NOT NULL,
    media_path   TEXT,
    status       TEXT NOT NULL DEFAULT 'received',
    edited       BIGINT NOT NULL DEFAULT 0,
    revoked      BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, chat_jid, message_id)
);
-- Existing deploys: add the edit/revoke flags in place (CREATE above is a no-op
-- once the table exists). Mirrors the body_tsv backfill pattern.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS edited BIGINT NOT NULL DEFAULT 0;
ALTER TABLE messages ADD COLUMN IF NOT EXISTS revoked BIGINT NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_messages_chat_ts ON messages (session_id, chat_jid, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages (session_id, sender_jid, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_messages_status ON messages (session_id, status, timestamp);
-- Full-text search index. A STORED generated tsvector keeps body_text searchable
-- with BM25-like ranking via ts_rank; the 'simple' config (no stemming/stopwords)
-- suits the mixed-language corpus. Adding the column backfills existing rows.
ALTER TABLE messages ADD COLUMN IF NOT EXISTS body_tsv tsvector
    GENERATED ALWAYS AS (to_tsvector('simple', coalesce(body_text, ''))) STORED;
CREATE INDEX IF NOT EXISTS idx_messages_tsv ON messages USING GIN (body_tsv);

CREATE TABLE IF NOT EXISTS contacts (
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    jid           TEXT NOT NULL,
    first_name    TEXT,
    full_name     TEXT,
    push_name     TEXT,
    business_name TEXT,
    PRIMARY KEY (session_id, jid)
);

CREATE TABLE IF NOT EXISTS chats (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    jid         TEXT NOT NULL,
    name        TEXT,
    is_group    BIGINT NOT NULL DEFAULT 0,
    last_msg_ts BIGINT,
    archived    BIGINT NOT NULL DEFAULT 0,
    pinned      BIGINT NOT NULL DEFAULT 0,
    muted_until BIGINT,
    PRIMARY KEY (session_id, jid)
);

CREATE TABLE IF NOT EXISTS groups (
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    jid           TEXT NOT NULL,
    subject       TEXT,
    subject_owner TEXT,
    subject_time  BIGINT,
    creator       TEXT,
    creation_ts   BIGINT,
    description   TEXT,
    is_announce   BIGINT NOT NULL DEFAULT 0,
    is_locked     BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, jid)
);

CREATE TABLE IF NOT EXISTS group_participants (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    group_jid   TEXT NOT NULL,
    user_jid    TEXT NOT NULL,
    is_admin    BIGINT NOT NULL DEFAULT 0,
    is_super    BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, group_jid, user_jid)
);

CREATE TABLE IF NOT EXISTS outbound_queue (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    msg_id      TEXT NOT NULL,
    op_json     TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (session_id, msg_id)
);

CREATE TABLE IF NOT EXISTS session_leases (
    session_id   TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    owner_id     TEXT NOT NULL,
    heartbeat_ts BIGINT NOT NULL,
    ttl          BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS egress_targets (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    events      TEXT,
    secret      TEXT,
    config      TEXT NOT NULL DEFAULT '{}',
    updated_at  BIGINT NOT NULL,
    PRIMARY KEY (session_id, kind)
);

-- Persistent session event log (mirror of SQLite migration 0011): backs the
-- dashboard "Logs" page history. `ts` is unix MILLISECONDS.
CREATE TABLE IF NOT EXISTS event_log (
    id           BIGSERIAL PRIMARY KEY,
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts           BIGINT NOT NULL,
    event_type   TEXT NOT NULL,
    payload_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_event_log_session ON event_log (session_id, id DESC);

-- Persistent metric samples (mirror of SQLite migration 0013): backs the ruwa
-- Console "Metrics" page so charts survive restarts. `ts` is unix SECONDS,
-- `value` a double. The background sampler self-prunes by age.
CREATE TABLE IF NOT EXISTS metrics_samples (
    name   TEXT NOT NULL,
    ts     BIGINT NOT NULL,
    value  DOUBLE PRECISION NOT NULL,
    PRIMARY KEY (name, ts)
);

CREATE INDEX IF NOT EXISTS idx_metrics_samples_ts ON metrics_samples (ts);

-- Persistent process log ring (mirror of SQLite migration 0014): the server's
-- own tracing output, so the Console can show diagnostics across restarts.
-- `ts` is unix MILLISECONDS, `sev` numeric severity (0 trace .. 4 error).
CREATE TABLE IF NOT EXISTS log_ring (
    id      BIGSERIAL PRIMARY KEY,
    ts      BIGINT NOT NULL,
    sev     INTEGER NOT NULL,
    level   TEXT NOT NULL,
    target  TEXT NOT NULL,
    message TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_log_ring_id ON log_ring (id DESC);
CREATE INDEX IF NOT EXISTS idx_log_ring_sev ON log_ring (sev, id DESC);

-- Per-message "message secret" (mirror of SQLite migration 0016): the 32-byte
-- `messageContextInfo.messageSecret`, needed to unseal `SecretEncryptedMessage`
-- edits (HKDF-derived AES-256-GCM key off the original message's secret).
-- Keyed by stanza id; `secret` is sealed at rest via the vault. Pruned with
-- messages.
CREATE TABLE IF NOT EXISTS message_secrets (
    session_id TEXT   NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    message_id TEXT   NOT NULL,
    chat_jid   TEXT   NOT NULL,
    sender_jid TEXT   NOT NULL,
    secret     BYTEA  NOT NULL,
    created_at BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, message_id)
);

CREATE INDEX IF NOT EXISTS idx_message_secrets_created ON message_secrets (created_at);
