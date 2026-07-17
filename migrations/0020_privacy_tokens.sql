-- Per-peer "trusted contact" privacy token (aka tctoken). Modern WhatsApp requires
-- a <tctoken> on 1:1 messages to a peer that expects one; without it the server
-- rejects the stanza with error 463 (MissingTcToken) and it never delivers. The
-- peer issues the token to us via a <notification type="privacy_token"> and in the
-- HistorySync blob; we store it keyed by the peer's LID (canonical, no device/agent)
-- and echo it back on outbound sends. `timestamp` gates expiry (~28-day window).
CREATE TABLE IF NOT EXISTS privacy_tokens (
    session_id       TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    peer_lid         TEXT NOT NULL,
    token            BLOB NOT NULL,
    timestamp        BIGINT NOT NULL DEFAULT 0,
    sender_timestamp BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, peer_lid)
);
