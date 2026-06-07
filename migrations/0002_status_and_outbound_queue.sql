-- Outbound delivery state.
--
-- `messages.status` tracks lifecycle of an outbound row:
--   'queued'    : persisted, not yet shipped to wire
--   'sent'      : shipped; awaiting server <ack>
--   'delivered' : server acked
--   'failed'    : ship attempt errored after retries (kept for inspection)
-- Inbound rows default to 'received'.
ALTER TABLE messages ADD COLUMN status TEXT NOT NULL DEFAULT 'received';

CREATE INDEX idx_messages_status
    ON messages (session_id, status, timestamp);

-- Persistent outbound work queue. Survives reconnect: on connect, the
-- send pump drains rows whose status is 'queued' and re-attempts shipping
-- in original order. `op_json` is a JSON-serialized SendOp.
CREATE TABLE outbound_queue (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    msg_id      TEXT NOT NULL,
    op_json     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    PRIMARY KEY (session_id, msg_id)
);
