-- Per-message "message secret" (the 32-byte `messageContextInfo.messageSecret`
-- that rides on normal messages).
--
-- Modern WhatsApp delivers message EDITS (and poll/event edits) as a
-- `SecretEncryptedMessage` whose `encPayload` is AES-256-GCM-sealed under a key
-- HKDF-derived from the ORIGINAL message's secret — NOT as the old
-- `protocolMessage{type=MESSAGE_EDIT}`. To decrypt an inbound edit we must have
-- recorded the original message's secret when it first arrived. Without this
-- table every edit decrypts at the Signal layer fine but then can't be unsealed,
-- so it lands as msg_type="unknown".
--
-- Keyed by stanza id (unique per session). `sender_jid` is retained in
-- `ToNonAD` form because it feeds the HKDF use-case info string when deriving
-- the per-edit key; `secret` is sealed at rest via the same vault as Signal
-- sessions. Pruned alongside messages.
CREATE TABLE message_secrets (
    session_id TEXT    NOT NULL,
    message_id TEXT    NOT NULL,
    chat_jid   TEXT    NOT NULL,
    sender_jid TEXT    NOT NULL,
    secret     BLOB    NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, message_id)
);

CREATE INDEX idx_message_secrets_created ON message_secrets (created_at);
