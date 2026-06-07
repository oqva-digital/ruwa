-- Persistent process log ring: captures the app's own `tracing` output (the
-- warn/error/info lines that otherwise only reach stdout → the platform's
-- ephemeral log view) so the ruwa Console can show diagnostics that survive a
-- restart/deploy. Distinct from `event_log`, which holds per-session WhatsApp
-- events (connected/message/…); this is the server's internal log stream.
--
-- A bounded "ring": a background flusher caps it to the newest N rows plus an
-- age cutoff. `ts` is unix MILLISECONDS. `sev` is a numeric severity (0 trace ..
-- 4 error) so a min-level filter is a cheap `sev >= ?`; `level` is the text form.
CREATE TABLE log_ring (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      INTEGER NOT NULL,    -- unix milliseconds
    sev     INTEGER NOT NULL,    -- 0 trace, 1 debug, 2 info, 3 warn, 4 error
    level   TEXT NOT NULL,       -- ERROR | WARN | INFO | DEBUG | TRACE
    target  TEXT NOT NULL,       -- event target (module path)
    message TEXT NOT NULL        -- formatted message + structured fields
);

CREATE INDEX idx_log_ring_id ON log_ring (id DESC);
CREATE INDEX idx_log_ring_sev ON log_ring (sev, id DESC);
