-- Cross-instance session ownership leases. When multiple API instances share
-- one database, exactly one may hold a live WhatsApp socket per session — two
-- live sockets trigger WA's replace-war (each boots the other). An instance
-- acquires a lease before connecting and renews it on a heartbeat; a lease is
-- stealable only once it goes stale (heartbeat_ts + ttl < now), so a crashed
-- instance's sessions become claimable after the TTL.
CREATE TABLE session_leases (
    session_id   TEXT PRIMARY KEY REFERENCES sessions(id) ON DELETE CASCADE,
    owner_id     TEXT NOT NULL,      -- instance id holding the lease
    heartbeat_ts INTEGER NOT NULL,   -- unix ts of the last renew/acquire
    ttl          INTEGER NOT NULL    -- seconds; lease is stale once hb+ttl < now
);
