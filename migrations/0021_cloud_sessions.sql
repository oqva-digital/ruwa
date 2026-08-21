-- Session backend discriminator + Meta WhatsApp Cloud API credentials.
--
-- `kind` = 'web' (companion device: Noise WS + Signal — the default, and what
-- every pre-existing row is) or 'cloud' (Meta Cloud API / Graph; no device
-- keys, no socket). Cloud sessions reuse the same messages/contacts/chats
-- tables and the same event bus; only the transport differs.
--
-- Secrets (`cloud_access_token`, `cloud_app_secret`) are stored SEALED via
-- `crypto::vault::seal` (AES-256-GCM when RUWA_DB_ENCRYPTION_KEY is set) —
-- same treatment as the device private keys. They are never serialized to the
-- API. `cloud_verify_token` is the low-sensitivity webhook handshake token
-- (Meta echoes it in the GET verify request) and stays plaintext.
ALTER TABLE sessions ADD COLUMN kind TEXT NOT NULL DEFAULT 'web';
ALTER TABLE sessions ADD COLUMN cloud_phone_number_id TEXT;
ALTER TABLE sessions ADD COLUMN cloud_waba_id TEXT;
ALTER TABLE sessions ADD COLUMN cloud_access_token BLOB;
ALTER TABLE sessions ADD COLUMN cloud_app_secret BLOB;
ALTER TABLE sessions ADD COLUMN cloud_verify_token TEXT;
ALTER TABLE sessions ADD COLUMN cloud_graph_version TEXT;
-- Inbound Meta webhooks resolve the session by `metadata.phone_number_id`.
CREATE INDEX IF NOT EXISTS idx_sessions_cloud_pnid ON sessions(cloud_phone_number_id);
