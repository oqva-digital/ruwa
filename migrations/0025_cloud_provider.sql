-- Kapso provider for kind='cloud' sessions.
--
-- A cloud session can now reach WhatsApp either directly through Meta's Graph
-- API (`cloud_provider='meta'`, the default and what every pre-0025 cloud row
-- is) or through the Kapso Business Platform (`cloud_provider='kapso'`), which
-- mirrors the Graph surface 1:1. For Kapso sessions ruwa is the platform/BSP:
-- it issues a hosted setup link, the customer completes Meta embedded signup on
-- Kapso, and a Kapso project webhook hands back the `phone_number_id`. Until
-- that callback lands the session sits in status 'pending_onboarding' with a
-- NULL `cloud_phone_number_id` (the partial UNIQUE index from 0022 ignores
-- NULLs, so many pending Kapso sessions coexist).
--
-- `cloud_webhook_secret` is the per-number HMAC key ruwa registers with Kapso
-- (`X-Webhook-Signature` on inbound message webhooks) — SEALED via
-- `crypto::vault::seal`, same as the other cloud secrets. The Kapso platform
-- `X-API-Key` is server-wide (`RUWA_KAPSO_API_KEY`) and is never stored here.
ALTER TABLE sessions ADD COLUMN cloud_provider TEXT NOT NULL DEFAULT 'meta';
ALTER TABLE sessions ADD COLUMN cloud_internal_id TEXT;   -- Kapso phone-number config UUID
ALTER TABLE sessions ADD COLUMN cloud_customer_id TEXT;   -- Kapso customer UUID
ALTER TABLE sessions ADD COLUMN cloud_base_url TEXT;      -- per-session upstream host override
ALTER TABLE sessions ADD COLUMN cloud_setup_ref TEXT;     -- our correlation id for the onboarding callback
ALTER TABLE sessions ADD COLUMN cloud_setup_link TEXT;    -- last-issued hosted setup URL (non-secret)
ALTER TABLE sessions ADD COLUMN cloud_webhook_secret BLOB; -- sealed; Kapso per-number X-Webhook-Signature key

-- The Kapso onboarding callback is matched back to its session by this ref.
CREATE INDEX IF NOT EXISTS idx_sessions_cloud_setup_ref
    ON sessions(cloud_setup_ref) WHERE cloud_setup_ref IS NOT NULL;
