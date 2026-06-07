-- PN <-> LID (LinkedID) identity mapping, per session.
--
-- Modern WhatsApp addresses devices by their LID (`<user>.<dev>@lid`) as well
-- as their phone number (`<user>:<dev>@s.whatsapp.net`). The two refer to the
-- same physical identity, but our Signal sessions are keyed by address string,
-- so a session opened under one addressing isn't found under the other. This
-- table records the per-user LID<->PN correspondence (learned from usync device
-- queries and inbound message `sender_lid`/`peer_recipient_pn` attrs) so the
-- inbound decrypt path can resolve a `@lid` sender to the PN session it already
-- has (mirrors whatsmeow's StoreLIDPNMapping). Keyed by the *user* part — the
-- mapping is per-account, shared across that account's devices.
CREATE TABLE lid_pn_map (
    session_id TEXT    NOT NULL,
    lid_user   TEXT    NOT NULL,
    pn_user    TEXT    NOT NULL,
    updated_at INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (session_id, lid_user)
);

CREATE INDEX idx_lid_pn_map_pn ON lid_pn_map (session_id, pn_user);
