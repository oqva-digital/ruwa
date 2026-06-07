-- Egress targets: per-session event fan-out destinations. One event on a
-- session's broadcast channel (SessionEvent) is shipped to every enabled target
-- here — webhooks (HTTP POST), RabbitMQ, or SQS. This table holds only the
-- *config*; the delivery worker lives in src/egress.rs.
--
-- A session may have at most one target per kind (PK = session_id, kind), e.g.
-- one webhook + one rabbitmq + one sqs. `events` is a CSV allowlist of
-- SessionEvent type tags (empty/NULL = all). `config` is a transport-specific
-- JSON blob: { "url": ... } for webhook, { "uri","exchange","routing_key" } for
-- rabbitmq, { "queue_url","region" } for sqs. `secret` is the HMAC signing key
-- for webhooks (NULL for queues).
CREATE TABLE egress_targets (
    session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL,              -- 'webhook' | 'rabbitmq' | 'sqs'
    enabled     INTEGER NOT NULL DEFAULT 1,
    events      TEXT,                        -- CSV allowlist; NULL/empty = all
    secret      TEXT,                        -- HMAC secret (webhook); else NULL
    config      TEXT NOT NULL DEFAULT '{}',  -- transport-specific JSON
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (session_id, kind)
);
