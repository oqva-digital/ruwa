-- Initial schema. Tables follow whatsmeow's `store` package layout but flatten
-- to one DB across tenants (each row carries `session_id`).

CREATE TABLE sessions (
    id          TEXT PRIMARY KEY,
    label       TEXT,
    status      TEXT NOT NULL,
    jid         TEXT,
    -- Long-term identity. Populated on first connection / pairing.
    registration_id INTEGER,
    noise_key_priv  BLOB,
    noise_key_pub   BLOB,
    identity_key_priv BLOB,
    identity_key_pub  BLOB,
    signed_prekey_id  INTEGER,
    signed_prekey_priv BLOB,
    signed_prekey_pub  BLOB,
    signed_prekey_sig  BLOB,
    adv_secret_key  BLOB,
    -- Server-issued credentials retrieved during pairing.
    account_pb      BLOB,
    server_token    BLOB,
    client_token    BLOB,
    business_name   TEXT,
    push_name       TEXT,
    platform        TEXT,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

-- One-time prekeys; consumed when a peer initiates a session with us.
CREATE TABLE prekeys (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    private_key BLOB NOT NULL,
    public_key  BLOB NOT NULL,
    uploaded    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, key_id)
);

-- Signal Protocol session state (Double Ratchet) per remote address.
CREATE TABLE signal_sessions (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    address     TEXT NOT NULL,    -- "{user}.{device}" or "{user}@{server}.{device}"
    record      BLOB NOT NULL,
    PRIMARY KEY (session_id, address)
);

-- Group sender-keys.
CREATE TABLE sender_keys (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    group_id    TEXT NOT NULL,
    sender      TEXT NOT NULL,
    record      BLOB NOT NULL,
    PRIMARY KEY (session_id, group_id, sender)
);

-- Persistent identity records of remote peers (TOFU).
CREATE TABLE remote_identities (
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    address      TEXT NOT NULL,
    identity_key BLOB NOT NULL,
    PRIMARY KEY (session_id, address)
);

-- App state lthash (Hash State of contacts/chats/etc per collection).
CREATE TABLE app_state_versions (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,    -- "regular", "regular_high", "regular_low", "critical_block", "critical_unblock_low"
    version     INTEGER NOT NULL,
    hash        BLOB NOT NULL,
    PRIMARY KEY (session_id, name)
);

CREATE TABLE app_state_mac_keys (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    key_id      BLOB NOT NULL,
    key_data    BLOB NOT NULL,
    PRIMARY KEY (session_id, key_id)
);

-- Local message store (mirror of WhatsApp history).
CREATE TABLE messages (
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    chat_jid     TEXT NOT NULL,
    message_id   TEXT NOT NULL,
    sender_jid   TEXT NOT NULL,
    from_me      INTEGER NOT NULL,
    timestamp    INTEGER NOT NULL,
    msg_type     TEXT NOT NULL,         -- text|image|video|audio|document|sticker|reaction|...
    body_text    TEXT,
    payload_json TEXT NOT NULL,         -- full decoded payload
    media_path   TEXT,                  -- local path once downloaded
    PRIMARY KEY (session_id, chat_jid, message_id)
);

CREATE INDEX idx_messages_chat_ts
    ON messages (session_id, chat_jid, timestamp DESC);
CREATE INDEX idx_messages_sender
    ON messages (session_id, sender_jid, timestamp DESC);

-- Contacts / chats / groups.
CREATE TABLE contacts (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    jid         TEXT NOT NULL,
    first_name  TEXT,
    full_name   TEXT,
    push_name   TEXT,
    business_name TEXT,
    PRIMARY KEY (session_id, jid)
);

CREATE TABLE chats (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    jid         TEXT NOT NULL,
    name        TEXT,
    is_group    INTEGER NOT NULL DEFAULT 0,
    last_msg_ts INTEGER,
    archived    INTEGER NOT NULL DEFAULT 0,
    pinned      INTEGER NOT NULL DEFAULT 0,
    muted_until INTEGER,
    PRIMARY KEY (session_id, jid)
);

CREATE TABLE groups (
    session_id     TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    jid            TEXT NOT NULL,
    subject        TEXT,
    subject_owner  TEXT,
    subject_time   INTEGER,
    creator        TEXT,
    creation_ts    INTEGER,
    description    TEXT,
    is_announce    INTEGER NOT NULL DEFAULT 0,
    is_locked      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, jid)
);

CREATE TABLE group_participants (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    group_jid   TEXT NOT NULL,
    user_jid    TEXT NOT NULL,
    is_admin    INTEGER NOT NULL DEFAULT 0,
    is_super    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, group_jid, user_jid)
);
