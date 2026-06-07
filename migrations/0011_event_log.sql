-- Persistent session event log: backs the dashboard "Logs" page history.
--
-- Every SessionEvent broadcast on a session's bus is appended here by the
-- per-session egress worker (the one consumer guaranteed to run for every
-- connected session). The broadcast channel keeps nothing once an event is
-- delivered, so without this table the Logs page can only show events that
-- arrive while it happens to be open. With it, the page seeds from history and
-- survives reloads.
--
-- `ts` is unix MILLISECONDS (matches the live-stream timestamp the dashboard
-- stamps with Date.now(), so history and live rows sort/format identically).
-- Rows are pruned by the egress worker: newest-N-per-session + an age cutoff.
CREATE TABLE event_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,        -- unix milliseconds
    event_type   TEXT NOT NULL,           -- SessionEvent tag: connected|message|disconnected|...
    payload_json TEXT NOT NULL            -- full type-tagged SessionEvent JSON
);

CREATE INDEX idx_event_log_session
    ON event_log (session_id, id DESC);
