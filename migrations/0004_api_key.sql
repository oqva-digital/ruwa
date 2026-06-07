-- Per-tenant API key. A request to /v1/sessions/:id/* may authenticate with
-- either the global RUWA_API_TOKEN (admin, all sessions) or this session's own
-- key. Generated + returned once at session creation; never echoed afterwards.
-- NULL = legacy session created before this column (admin-token-only access).
ALTER TABLE sessions ADD COLUMN api_key TEXT;
