-- Canonicalize existing LID-addressed rows onto their phone-number (PN) JID.
--
-- WhatsApp delivers the same 1:1 conversation under two addressings: a phone
-- number (`<digits>@s.whatsapp.net`) and an opaque LID
-- (`<n>[.agent][:device]@lid`). Before the ingest-time canonicalization landed,
-- messages/chats/contacts accumulated under BOTH forms, so a single contact
-- showed up as two chats. This one-time pass rewrites every LID row whose user
-- has a known PN (`lid_pn_map`) to the PN form, stripping the LID agent/device
-- suffix first. LID rows with no known PN are left untouched (we can't resolve a
-- stable phone number for them yet).
--
-- The repeated `substr(... min(instr ...))` expression extracts the bare LID
-- user — everything before the first of `.`, `:`, or `@` (e.g.
-- `64000000000001.1:50@lid` → `64000000000001`) — to join against
-- `lid_pn_map.lid_user`. `UPDATE OR IGNORE` / pre-DELETE guard against the rare
-- PK collision (a row already present under the PN form) so the migration can
-- never abort startup; at worst a stray LID row survives as a harmless leftover.

-- messages.chat_jid (PK includes chat_jid → OR IGNORE on collision)
UPDATE OR IGNORE messages
SET chat_jid = lm.pn_user || '@s.whatsapp.net'
FROM lid_pn_map AS lm
WHERE messages.session_id = lm.session_id
  AND messages.chat_jid LIKE '%@lid'
  AND lm.lid_user = substr(messages.chat_jid, 1, (min(
        CASE WHEN instr(messages.chat_jid, '.') = 0 THEN 1000000 ELSE instr(messages.chat_jid, '.') END,
        CASE WHEN instr(messages.chat_jid, ':') = 0 THEN 1000000 ELSE instr(messages.chat_jid, ':') END,
        instr(messages.chat_jid, '@')) - 1));

-- messages.sender_jid (not part of any unique key → plain UPDATE)
UPDATE messages
SET sender_jid = lm.pn_user || '@s.whatsapp.net'
FROM lid_pn_map AS lm
WHERE messages.session_id = lm.session_id
  AND messages.sender_jid LIKE '%@lid'
  AND lm.lid_user = substr(messages.sender_jid, 1, (min(
        CASE WHEN instr(messages.sender_jid, '.') = 0 THEN 1000000 ELSE instr(messages.sender_jid, '.') END,
        CASE WHEN instr(messages.sender_jid, ':') = 0 THEN 1000000 ELSE instr(messages.sender_jid, ':') END,
        instr(messages.sender_jid, '@')) - 1));

-- chats.jid (PK = session_id, jid). Drop LID rows that would collide with an
-- existing PN row (the PN row carries the canonical metadata), then rewrite the
-- rest.
DELETE FROM chats
WHERE chats.jid LIKE '%@lid'
  AND EXISTS (
    SELECT 1 FROM lid_pn_map AS lm
    WHERE lm.session_id = chats.session_id
      AND lm.lid_user = substr(chats.jid, 1, (min(
            CASE WHEN instr(chats.jid, '.') = 0 THEN 1000000 ELSE instr(chats.jid, '.') END,
            CASE WHEN instr(chats.jid, ':') = 0 THEN 1000000 ELSE instr(chats.jid, ':') END,
            instr(chats.jid, '@')) - 1))
      AND EXISTS (
        SELECT 1 FROM chats AS c2
        WHERE c2.session_id = chats.session_id
          AND c2.jid = lm.pn_user || '@s.whatsapp.net'));

UPDATE OR IGNORE chats
SET jid = lm.pn_user || '@s.whatsapp.net'
FROM lid_pn_map AS lm
WHERE chats.session_id = lm.session_id
  AND chats.jid LIKE '%@lid'
  AND lm.lid_user = substr(chats.jid, 1, (min(
        CASE WHEN instr(chats.jid, '.') = 0 THEN 1000000 ELSE instr(chats.jid, '.') END,
        CASE WHEN instr(chats.jid, ':') = 0 THEN 1000000 ELSE instr(chats.jid, ':') END,
        instr(chats.jid, '@')) - 1));

-- contacts.jid (PK = session_id, jid). Same collapse so the chat list joins the
-- contact name on the PN key.
DELETE FROM contacts
WHERE contacts.jid LIKE '%@lid'
  AND EXISTS (
    SELECT 1 FROM lid_pn_map AS lm
    WHERE lm.session_id = contacts.session_id
      AND lm.lid_user = substr(contacts.jid, 1, (min(
            CASE WHEN instr(contacts.jid, '.') = 0 THEN 1000000 ELSE instr(contacts.jid, '.') END,
            CASE WHEN instr(contacts.jid, ':') = 0 THEN 1000000 ELSE instr(contacts.jid, ':') END,
            instr(contacts.jid, '@')) - 1))
      AND EXISTS (
        SELECT 1 FROM contacts AS c2
        WHERE c2.session_id = contacts.session_id
          AND c2.jid = lm.pn_user || '@s.whatsapp.net'));

UPDATE OR IGNORE contacts
SET jid = lm.pn_user || '@s.whatsapp.net'
FROM lid_pn_map AS lm
WHERE contacts.session_id = lm.session_id
  AND contacts.jid LIKE '%@lid'
  AND lm.lid_user = substr(contacts.jid, 1, (min(
        CASE WHEN instr(contacts.jid, '.') = 0 THEN 1000000 ELSE instr(contacts.jid, '.') END,
        CASE WHEN instr(contacts.jid, ':') = 0 THEN 1000000 ELSE instr(contacts.jid, ':') END,
        instr(contacts.jid, '@')) - 1));
