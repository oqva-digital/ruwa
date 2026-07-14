-- `revoked` flag on messages, for in-place revoke (delete-for-everyone) application.
--
-- A REVOKE now UPDATES the target message — clears `body_text` and sets
-- `revoked = 1` — instead of leaving the original untouched. Before this, an
-- inbound revoke only inserted a standalone `revoked` row and an OUTBOUND
-- revoke touched nothing at all, so a message deleted for everyone still sat
-- in the chat list as if nothing had happened.
ALTER TABLE messages ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0;
