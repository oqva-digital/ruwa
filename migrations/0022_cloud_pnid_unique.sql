-- One cloud session per Meta phone_number_id.
--
-- Inbound webhooks resolve their session by `metadata.phone_number_id`, so two
-- rows sharing a number would make the newer one silently unreachable — and a
-- per-session key holder could re-point their session at another tenant's
-- number to capture (or starve) its inbound traffic. The partial UNIQUE index
-- makes that impossible at the storage layer (`create_cloud` /
-- `set_cloud_creds` answer 409 up front); the plain index from 0021 is
-- redundant with it and dropped.
DROP INDEX IF EXISTS idx_sessions_cloud_pnid;
CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_cloud_pnid_unique
    ON sessions(cloud_phone_number_id) WHERE cloud_phone_number_id IS NOT NULL;
