-- `edited` flag on messages, for in-place edit application.
--
-- A message EDIT (modern `SecretEncryptedMessage`, or the legacy
-- `protocolMessage{MESSAGE_EDIT}`) now UPDATES the original message's
-- `body_text` and sets `edited = 1`, instead of inserting a separate row. The
-- chat then shows the edit in place (matching WhatsApp's "Edited" affordance),
-- and the old separate edit row — which carried the edit stanza's own
-- routing/`from_me` and mislabeled the bubble — is no longer created.
ALTER TABLE messages ADD COLUMN edited INTEGER NOT NULL DEFAULT 0;
