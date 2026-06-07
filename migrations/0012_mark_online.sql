-- Per-session presence preference.
--
-- ruwa announces a `<presence>` on connect. `available` marks the companion
-- ONLINE, which WhatsApp uses to SILENCE the phone's notifications (it assumes
-- you're reading on the companion). `unavailable` keeps the phone notifying
-- (what Evolution sends; reception is unaffected).
--
-- 0 (default) = announce `unavailable` → phone keeps notifying.
-- 1           = announce `available`   → online, phone notifications silenced.
ALTER TABLE sessions ADD COLUMN mark_online INTEGER NOT NULL DEFAULT 0;
