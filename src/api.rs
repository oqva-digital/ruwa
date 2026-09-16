//! HTTP API surface.
//!
//! Auth: every route under `/v1` requires `Authorization: Bearer <token>`. The
//! global `RUWA_API_TOKEN` is the admin/superuser token (all routes). A
//! `/v1/sessions/:id/*` route additionally accepts that session's own per-tenant
//! `api_key` (minted + returned once at create), scoped to just that session.
//! Convention: routes return JSON; errors flow through `error::Error`.
//!
//! Sessions come in two kinds (`SessionMeta.kind`): `web` (WhatsApp Web
//! multi-device socket) and `cloud` (Meta WhatsApp Cloud API). Both share the
//! same routes; handlers that only make sense for one backend answer 501 on the
//! other (`require_web` / `require_cloud`). Cloud sends are synchronous Graph
//! calls (`cloud_dispatch`) and respond `202 {"id": wamid, "status": "sent"}`;
//! inbound cloud traffic arrives on the unauthenticated, signature-verified
//! `GET|POST /v1/cloud/webhook` (`cloud_webhook_verify` / `cloud_webhook_receive`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(not(feature = "console"))]
use tower_http::services::{ServeDir, ServeFile};

use crate::cloud;
use crate::egress::ai::{self, AiConfig, AiMode};
use crate::error::{Error, Result};
use crate::session::{
    CloudCredsPatch, SendOp, Session, SessionKind, SessionManager, SessionMeta,
};

#[derive(Clone)]
pub struct AppState {
    pub manager: Arc<SessionManager>,
    pub api_token: Arc<String>,
    /// When true (`RUWA_READONLY=1`), every mutating route returns 403.
    /// Read-only routes (GET / SSE) and `/health` still serve. Useful for
    /// running an inspection-only deployment over an existing store.
    pub readonly: bool,
    /// S3-compatible media storage config when `RUWA_MEDIA_STORE=s3`; `None` =
    /// default `db` mode (media cached on local disk). When set, lazily-downloaded
    /// inbound media is offloaded to the bucket and the row stores the object URL.
    pub media_store: Option<Arc<crate::media::S3Config>>,
}

/// Reject the call when `RUWA_READONLY=1`. Mutating routes (POST/DELETE)
/// call this just after `check_auth`.
fn check_writable(state: &AppState) -> Result<()> {
    if state.readonly {
        Err(Error::Forbidden(
            "RUWA_READONLY=1: this deployment refuses mutating requests".into(),
        ))
    } else {
        Ok(())
    }
}

/// Combo helper for mutating routes: bearer auth + readonly gate.
fn check_auth_write(headers: &HeaderMap, state: &AppState) -> Result<()> {
    check_auth(headers, &state.api_token)?;
    check_writable(state)
}

/// Auth for a specific session's routes (`/v1/sessions/:id/*`). Accepts EITHER
/// the global admin token (superuser, every session) OR that session's own
/// per-tenant `api_key`. A per-session key is scoped to just that session, so a
/// tenant holding only their key cannot list/create or touch other sessions.
fn check_session_auth(headers: &HeaderMap, state: &AppState, id: &str) -> Result<()> {
    let token = bearer_token(headers)?;
    if token == state.api_token.as_str() {
        return Ok(());
    }
    match state.manager.session_api_key(id)? {
        Some(key) if token == key => Ok(()),
        _ => Err(Error::Unauthorized),
    }
}

/// Session-scoped auth + readonly gate, for mutating per-session routes.
fn check_session_auth_write(headers: &HeaderMap, state: &AppState, id: &str) -> Result<()> {
    check_session_auth(headers, state, id)?;
    check_writable(state)
}

/// Time every served request and feed the HTTP metrics (count + duration sum →
/// average response time on `/metrics`).
async fn track_http_metrics(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let start = std::time::Instant::now();
    let resp = next.run(req).await;
    crate::session::metrics::record_http(start.elapsed().as_millis() as u64);
    resp
}

/// Max accepted `POST /v1/cloud/webhook` body (Meta caps deliveries at 3 MB).
/// Only for the direct Meta webhook — Kapso's webhook (`/v1/cloud/kapso/webhook`)
/// uses `body_limit()` instead, since Kapso batches up to 100 messages per
/// delivery (`max_buffer_size`) with no documented byte cap of its own, and a
/// batch of media/location-bearing messages routinely exceeds Meta's own limit.
const CLOUD_WEBHOOK_BODY_LIMIT: usize = 4 * 1024 * 1024;

/// Max accepted request body on every other `/v1/*` route. axum's default is
/// 2 MB, which silently 413s the multipart media upload and base64 sends for
/// anything bigger than a small photo. Overridable via `RUWA_BODY_LIMIT_MB`.
const DEFAULT_BODY_LIMIT_MB: usize = 20;

fn body_limit() -> usize {
    std::env::var("RUWA_BODY_LIMIT_MB")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|mb| *mb > 0)
        .unwrap_or(DEFAULT_BODY_LIMIT_MB)
        * 1024
        * 1024
}

pub fn router(state: AppState) -> Router {
    // Stamp process start once (this is built once per process) so
    // `ruwa_process_uptime_seconds` counts from boot.
    crate::session::metrics::mark_process_start();
    let v1 = Router::new()
        .route("/config", get(config))
        .route(
            "/settings/ai",
            get(get_ai_settings)
                .put(put_ai_settings)
                .delete(delete_ai_settings),
        )
        .route("/settings/ai/test", post(test_ai_settings))
        .route("/ai/improve-text", post(ai_improve_text))
        .route("/metrics/series", get(list_metrics_series))
        .route("/metrics/history", get(get_metrics_history))
        .route("/logs", get(get_logs))
        .route("/sessions", get(list_sessions).post(create_session))
        .route("/sessions/import", post(import_session))
        .route("/sessions/:id", get(get_session).delete(delete_session))
        .route("/sessions/:id/health", get(session_health))
        .route("/sessions/:id/qr", get(get_qr))
        .route("/sessions/:id/pair-phone", post(pair_phone_session))
        .route("/sessions/:id/connect", post(connect_session))
        .route("/sessions/:id/reconnect", post(reconnect_session))
        .route("/sessions/:id/resync-appstate", post(resync_appstate_session))
        .route("/sessions/:id/logout", post(logout_session))
        .route("/sessions/:id/proxy", get(get_session_proxy).post(set_session_proxy))
        .route("/sessions/:id/proxy/check", post(check_session_proxy))
        .route("/sessions/:id/calls", get(list_calls))
        .route("/sessions/:id/calls/dial", get(dial_call_audio_ws))
        .route("/sessions/:id/calls/:call_id/audio", get(call_audio_ws))
        .route("/sessions/:id/calls/:call_id/reject", post(reject_call))
        .route("/sessions/:id/cloud", put(set_session_cloud))
        .route("/sessions/:id/label", post(set_session_label))
        .route("/sessions/:id/mark-online", post(set_session_presence))
        .route("/sessions/:id/messages", get(list_messages).post(send_message))
        .route("/sessions/:id/messages/media", post(send_media))
        .route("/sessions/:id/messages/location", post(send_location))
        .route("/sessions/:id/messages/contact", post(send_contact))
        .route("/sessions/:id/messages/poll", post(send_poll))
        .route("/sessions/:id/messages/event", post(send_event))
        .route("/sessions/:id/messages/template", post(send_template))
        .route(
            "/sessions/:id/messages/interactive",
            post(send_interactive),
        )
        .route(
            "/sessions/:id/templates",
            get(list_templates).post(create_template),
        )
        .route(
            "/sessions/:id/templates/:name",
            axum::routing::delete(delete_template),
        )
        .route(
            "/sessions/:id/broadcasts",
            get(list_broadcasts_h).post(create_broadcast_h),
        )
        .route("/sessions/:id/broadcasts/:bid", get(get_broadcast_h))
        .route(
            "/sessions/:id/broadcasts/:bid/recipients",
            get(list_broadcast_recipients_h)
                .post(add_broadcast_recipients_h)
                .delete(clear_broadcast_recipients_h),
        )
        .route("/sessions/:id/broadcasts/:bid/send", post(send_broadcast_h))
        .route(
            "/sessions/:id/broadcasts/:bid/schedule",
            post(schedule_broadcast_h),
        )
        .route(
            "/sessions/:id/broadcasts/:bid/cancel",
            post(cancel_broadcast_h),
        )
        .route("/sessions/:id/broadcasts/:bid/stop", post(stop_broadcast_h))
        // Meta webhook: no bearer auth (Meta can't send one) — the POST is
        // authenticated by `X-Hub-Signature-256` over the raw body instead, and
        // the GET by the verify token. Exempt from the readonly gate (inbound
        // traffic, like the web socket's).
        // Meta batches up to 1000 updates / 3 MB per POST — above axum's 2 MB
        // default, which would 413 (and Meta would retry the same body forever).
        .route(
            "/cloud/webhook",
            get(cloud_webhook_verify)
                .post(cloud_webhook_receive)
                .layer(axum::extract::DefaultBodyLimit::max(CLOUD_WEBHOOK_BODY_LIMIT)),
        )
        // Kapso webhooks: same "no bearer auth" treatment as `/cloud/webhook`
        // (the handlers don't call `check_auth`; the POSTs are signature-verified).
        .route(
            "/cloud/kapso/webhook",
            get(cloud_kapso_webhook_verify)
                .post(cloud_kapso_webhook_receive)
                .layer(axum::extract::DefaultBodyLimit::max(body_limit())),
        )
        .route(
            "/cloud/kapso/project-webhook",
            get(cloud_kapso_webhook_verify).post(cloud_kapso_project_webhook_receive),
        )
        .route(
            "/sessions/:id/cloud/setup-link",
            post(regen_kapso_setup_link),
        )
        .route(
            "/sessions/:id/messages/media/multipart",
            post(send_media_multipart),
        )
        .route(
            "/sessions/:id/messages/:chat/:msgid/media",
            get(get_message_media),
        )
        .route(
            "/sessions/:id/messages/:chat/:msgid/context",
            get(get_message_context),
        )
        .route("/sessions/:id/contacts", get(list_contacts))
        .route("/sessions/:id/chats", get(list_chats))
        .route("/sessions/:id/groups", get(list_groups))
        .route("/sessions/:id/history/backfill", post(backfill_history))
        .route("/sessions/:id/onwhatsapp", post(check_on_whatsapp))
        .route(
            "/sessions/:id/contacts/:jid/picture",
            get(get_contact_picture),
        )
        .route("/sessions/:id/contacts/:jid/block", post(block_contact))
        .route("/sessions/:id/contacts/:jid/unblock", post(unblock_contact))
        .route("/sessions/:id/profile", put(set_profile))
        .route("/sessions/:id/presence", post(set_presence))
        .route("/sessions/:id/chats/:chat/typing", post(set_typing))
        .route("/sessions/:id/chats/:chat/read", post(mark_read))
        .route("/sessions/:id/messages/react", post(send_reaction))
        .route("/sessions/:id/messages/edit", post(send_edit))
        .route("/sessions/:id/messages/revoke", post(send_revoke))
        .route("/sessions/:id/events", get(stream_events))
        .route("/sessions/:id/events/history", get(get_event_history))
        .route(
            "/sessions/:id/webhook",
            get(get_webhook).put(set_webhook).delete(delete_webhook),
        )
        .route(
            "/sessions/:id/webhooks",
            get(list_webhooks).post(create_webhook),
        )
        .route(
            "/sessions/:id/webhooks/:label",
            get(get_webhook_labelled)
                .put(set_webhook_labelled)
                .delete(delete_webhook_labelled),
        )
        .route(
            "/sessions/:id/egress/redis",
            get(get_redis_egress).put(set_redis_egress).delete(delete_redis_egress),
        )
        .with_state(state.clone());

    // The ruwa Console SPA (dashboard/) is served same-origin from this binary
    // (so its `/v1` fetches need no CORS). The real API routes (`/v1`, `/health`,
    // `/metrics`) are matched first; unknown paths fall back to the SPA. With the
    // `console` feature the assets are embedded in the binary (build.rs); without
    // it they're served from `RUWA_WEB_DIR` on disk (default `dashboard/dist`;
    // the Docker image bakes them at `/srv/ruwa/web`).
    let router = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .nest("/v1", v1);

    #[cfg(feature = "console")]
    let router = router.fallback(embedded_console);
    #[cfg(not(feature = "console"))]
    let router = {
        let web_dir =
            std::env::var("RUWA_WEB_DIR").unwrap_or_else(|_| "dashboard/dist".to_string());
        let spa = ServeDir::new(&web_dir).fallback(ServeFile::new(format!("{web_dir}/index.html")));
        router.fallback_service(spa)
    };

    router
        .with_state(state)
        .layer(axum::extract::DefaultBodyLimit::max(body_limit()))
        .layer(axum::middleware::from_fn(track_http_metrics))
}

// Embedded dashboard, generated by build.rs and compiled in under `console`.
#[cfg(feature = "console")]
include!(concat!(env!("OUT_DIR"), "/dashboard_assets.rs"));

/// Serve the embedded dashboard. Exact path match wins; any unmatched path
/// falls back to `index.html` so client-side SPA routes resolve.
#[cfg(feature = "console")]
async fn embedded_console(uri: axum::http::Uri) -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;
    let path = uri.path();
    let lookup = if path == "/" { "/index.html" } else { path };
    let hit = DASHBOARD_ASSETS
        .iter()
        .find(|(p, _, _)| *p == lookup)
        .or_else(|| DASHBOARD_ASSETS.iter().find(|(p, _, _)| *p == "/index.html"));
    match hit {
        Some((_, mime, bytes)) => ([(header::CONTENT_TYPE, *mime)], *bytes).into_response(),
        None => (StatusCode::NOT_FOUND, "console not embedded").into_response(),
    }
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

/// Prometheus text-format metrics. Bearer-authed (same admin token as `/v1`)
/// so instance counters aren't exposed unauthenticated — scrape with the token
/// in an `Authorization: Bearer` header. Readonly mode still serves it.
async fn metrics(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse> {
    check_auth(&headers, &state.api_token)?;
    let body = state.manager.metrics_text();
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

/// Persisted metric series names (admin-authed). Backs the Console "Metrics"
/// page's series picker — these survive restarts, unlike the in-memory
/// `/metrics` exposition.
async fn list_metrics_series(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<String>>> {
    check_auth(&headers, &state.api_token)?;
    Ok(Json(state.manager.metrics_names()?))
}

#[derive(Deserialize)]
struct MetricsHistoryQuery {
    name: String,
    /// Window start (unix seconds). Defaults to 24h ago.
    since: Option<i64>,
    /// Max points (most-recent within the window). Defaults to 1500, capped 20k.
    limit: Option<u32>,
}

/// One persisted metric series over a time window (admin-authed), oldest-first
/// `[{ts, value}]` ready for charting in the Console.
async fn get_metrics_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<MetricsHistoryQuery>,
) -> Result<Json<serde_json::Value>> {
    check_auth(&headers, &state.api_token)?;
    let now = chrono::Utc::now().timestamp();
    let since = q.since.unwrap_or(now - 86_400);
    let limit = q.limit.unwrap_or(1_500).min(20_000);
    let points: Vec<serde_json::Value> = state
        .manager
        .metrics_history(&q.name, since, limit)?
        .into_iter()
        .map(|p| json!({ "ts": p.ts, "value": p.value }))
        .collect();
    Ok(Json(json!({ "name": q.name, "points": points })))
}

#[derive(Deserialize)]
struct LogsQuery {
    /// Minimum level to return (error|warn|info|debug). Default: all.
    level: Option<String>,
    /// Keyset cursor — return rows with id < this (for paging older).
    before: Option<i64>,
    /// Max rows (default 200, capped 2000).
    limit: Option<u32>,
}

/// Persisted process logs (admin-authed), newest-first. Backs the Console
/// "Diagnostics" log viewer — the server's own tracing output, surviving
/// restarts (distinct from per-session WhatsApp events at `/events/history`).
async fn get_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LogsQuery>,
) -> Result<Json<serde_json::Value>> {
    check_auth(&headers, &state.api_token)?;
    let min_sev = q
        .level
        .as_deref()
        .map(crate::store::log_level_sev)
        .unwrap_or(0);
    let before = q.before.unwrap_or(i64::MAX);
    let limit = q.limit.unwrap_or(200).min(2_000);
    let logs: Vec<serde_json::Value> = state
        .manager
        .store
        .log_ring_query(min_sev, before, limit)?
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id,
                "ts": r.ts,
                "level": r.level,
                "target": r.target,
                "message": r.message,
            })
        })
        .collect();
    Ok(Json(json!({ "logs": logs })))
}

/// Non-secret server config for the Console (admin-authed). Reports the
/// server-wide media-storage mode + bucket/endpoint/public URL so the UI can
/// show the live config instead of a placeholder. NEVER exposes the S3
/// access/secret keys.
async fn config(State(state): State<AppState>, headers: HeaderMap) -> Result<impl IntoResponse> {
    check_auth(&headers, &state.api_token)?;
    let media = match &state.media_store {
        Some(s3) => json!({
            "mode": "s3",
            "endpoint": s3.endpoint,
            "bucket": s3.bucket,
            "region": s3.region,
            "public_base_url": s3.public_base_url,
        }),
        None => json!({ "mode": "db" }),
    };
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "media": media,
    })))
}

/// Extract the bearer token from the `Authorization` header, or `Unauthorized`.
fn bearer_token(headers: &HeaderMap) -> Result<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)
}

fn check_auth(headers: &HeaderMap, expected: &str) -> Result<()> {
    if bearer_token(headers)? != expected {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

/// Query string for destructive routes — `?force=1` (or `true`/`yes`) bypasses
/// the body confirmation.
#[derive(Deserialize, Default)]
struct ConfirmQuery {
    force: Option<String>,
    /// Logout only: `?fresh=1` regenerates the device identity + clears stale
    /// crypto so the next pairing is a brand-new device (recovers a session
    /// WhatsApp/peers have stopped trusting). Default re-pairs the same identity.
    fresh: Option<String>,
    /// Delete only, `provider=kapso`: `?keep_remote=1` deletes the local session
    /// but leaves the Kapso number + customer in place (default offboards them).
    keep_remote: Option<String>,
}

#[derive(Deserialize)]
struct ConfirmBody {
    #[serde(default)]
    confirm: bool,
    #[serde(default)]
    fresh: bool,
}

/// Footgun guard for irreversible actions (logout, delete). The caller must
/// opt in explicitly with either `?force=1` or a JSON body `{"confirm":true}`;
/// otherwise we 400 instead of silently nuking the session. The body is parsed
/// leniently (empty/garbage simply counts as "not confirmed").
fn require_confirmation(action: &str, q: &ConfirmQuery, body: &[u8]) -> Result<()> {
    let forced = matches!(q.force.as_deref(), Some("1") | Some("true") | Some("yes"));
    let body_confirmed = (!body.is_empty())
        .then(|| serde_json::from_slice::<ConfirmBody>(body).ok())
        .flatten()
        .is_some_and(|b| b.confirm);
    if forced || body_confirmed {
        Ok(())
    } else {
        Err(Error::BadRequest(format!(
            "{action} is irreversible; resend with ?force=1 or a JSON body {{\"confirm\":true}}"
        )))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)] // a typo'd key (e.g. `url`) must 400, not silently no-op
struct CreateSessionReq {
    label: Option<String>,
    /// Optional egress proxy URL (socks5/socks5h/http). Validated on create.
    proxy: Option<String>,
    /// Backend: `"web"` (default — WhatsApp Web linked device, QR/phone
    /// pairing) or `"cloud"` (Meta WhatsApp Cloud API; needs `cloud`).
    kind: Option<String>,
    /// Cloud API credentials — required (and only accepted) with `kind: cloud`.
    cloud: Option<CloudCredsReq>,
}

/// Cloud API credentials as accepted on `POST /sessions` (`kind: cloud`).
/// Secrets are sealed at rest and never echoed by any response.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudCredsReq {
    /// Upstream: `"meta"` (default — Graph direct, needs the creds below) or
    /// `"kapso"` (onboarded through the Kapso Business Platform; the fields
    /// below are the hosted-signup options instead).
    #[serde(default)]
    provider: Option<String>,
    /// Graph node id of the business phone number (required for `meta`).
    phone_number_id: Option<String>,
    /// WhatsApp Business Account id — needed for template management.
    #[serde(default)]
    waba_id: Option<String>,
    /// System-user / business access token (required for `meta`).
    access_token: Option<String>,
    /// Meta app secret: signs inbound webhooks. Optional but strongly
    /// recommended (without it webhooks need `RUWA_CLOUD_ALLOW_UNSIGNED=1`).
    #[serde(default)]
    app_secret: Option<String>,
    /// Token echoed on the webhook subscription handshake.
    #[serde(default)]
    verify_token: Option<String>,
    /// Graph API version (default `v25.0`).
    #[serde(default)]
    graph_version: Option<String>,
    // ---- kapso (`provider = "kapso"`) hosted-signup options ----
    /// `"coexistence"` | `"dedicated"`.
    #[serde(default)]
    connection_type: Option<String>,
    /// ISO-3166-1 alpha-2 codes offered in the hosted signup.
    #[serde(default)]
    country_isos: Option<Vec<String>>,
    /// Hosted-signup UI language.
    #[serde(default)]
    language: Option<String>,
    /// Ask Kapso to provision a fresh phone number for the customer.
    #[serde(default)]
    provision_phone_number: bool,
    /// Redirect target after a successful hosted signup.
    #[serde(default)]
    success_redirect_url: Option<String>,
    /// Redirect target after a failed hosted signup.
    #[serde(default)]
    failure_redirect_url: Option<String>,
}

/// Non-empty trimmed string, or `None` (blank/absent collapse together).
fn non_blank(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// 501 for a WhatsApp-Web-only route called on a cloud session.
fn require_web(session: &Session, what: &'static str) -> Result<()> {
    if session.kind() == SessionKind::Cloud {
        return Err(Error::NotImplemented(what));
    }
    Ok(())
}

/// 501 for a Cloud-API-only route called on a web session.
fn require_cloud(session: &Session, what: &'static str) -> Result<()> {
    if session.kind() != SessionKind::Cloud {
        return Err(Error::NotImplemented(what));
    }
    Ok(())
}

/// Graph client for a cloud session: its stored (unsealed) credentials +
/// its egress proxy, so Graph traffic shares the session's IP like web media.
fn cloud_client(state: &AppState, id: &str, session: &Session) -> Result<cloud::CloudClient> {
    let creds = state.manager.cloud_creds(id)?;
    let proxy = session.meta.read().proxy_url.clone();
    cloud::CloudClient::new(creds, proxy.as_deref())
}

/// Outcome of a synchronous cloud send, for handlers that need the persisted
/// row's coordinates (e.g. to attach a media path) besides the HTTP response.
struct CloudSent {
    /// Chat the row was filed under (`<wa_id digits>@s.whatsapp.net`).
    chat_jid: String,
    wamid: String,
    timestamp: i64,
}

/// POST `graph_payload` to Graph on behalf of a cloud session and, once Meta
/// accepted it, persist the outbound row keyed by the returned `wamid`
/// (`from_me=1, status=sent`) + emit `MessageSent`. A Graph error propagates
/// (mapped by `cloud::map_graph_error`) and leaves NO row — the caller's
/// message was never sent. The row's chat is the recipient as WhatsApp sees
/// it (`contacts[0].wa_id`, e.g. Brazilian 9th digit normalized) so later
/// status webhooks and the user's replies land in the same chat.
#[allow(clippy::too_many_arguments)]
async fn cloud_send_record(
    state: &AppState,
    id: &str,
    session: &Session,
    to: &str,
    msg_type: &str,
    body_text: Option<&str>,
    payload_echo: serde_json::Value,
    graph_payload: serde_json::Value,
) -> Result<CloudSent> {
    // The Cloud API addresses phone numbers only: refuse @lid/@g.us/… ids
    // instead of letting the builders digit-strip them into a stranger's number.
    cloud::check_recipient(to)?;
    let client = cloud_client(state, id, session)?;
    let sent = client.send(graph_payload).await?;
    tracing::debug!(
        session = %id,
        phone_number_id = %client.phone_number_id(),
        wamid = %sent.wamid,
        msg_type,
        "cloud: graph accepted outbound message"
    );
    let now = chrono::Utc::now().timestamp();
    let recipient = sent.wa_id.as_deref().unwrap_or(to);
    let chat_jid = cloud::to_jid(recipient);
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());
    state.manager.cloud_record_outbound(
        id,
        &chat_jid,
        &sent.wamid,
        &sender_jid,
        msg_type,
        body_text,
        &payload_echo.to_string(),
        now,
    )?;
    Ok(CloudSent { chat_jid, wamid: sent.wamid, timestamp: now })
}

/// `cloud_send_record` + the standard `202 {"id","timestamp","status":"sent"}`.
#[allow(clippy::too_many_arguments)]
async fn cloud_dispatch(
    state: &AppState,
    id: &str,
    session: &Session,
    to: &str,
    msg_type: &str,
    body_text: Option<&str>,
    payload_echo: serde_json::Value,
    graph_payload: serde_json::Value,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    let sent = cloud_send_record(
        state, id, session, to, msg_type, body_text, payload_echo, graph_payload,
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp { id: sent.wamid, timestamp: sent.timestamp, status: "sent" }),
    ))
}

/// Cloud media kind for the public `type` string of the media routes.
fn cloud_media_kind(kind: &str) -> Option<cloud::MediaKind> {
    Some(match kind {
        "image" => cloud::MediaKind::Image,
        "video" => cloud::MediaKind::Video,
        "audio" => cloud::MediaKind::Audio,
        "ptt" | "voice" => cloud::MediaKind::Ptt,
        "document" => cloud::MediaKind::Document,
        "sticker" => cloud::MediaKind::Sticker,
        _ => return None,
    })
}

#[derive(Serialize)]
struct SessionResp {
    #[serde(flatten)]
    meta: SessionMeta,
    /// Masked proxy (credentials hidden), or null if direct. The raw URL is
    /// never returned.
    proxy: Option<String>,
    /// Per-tenant API key — present ONLY in the create response (returned once,
    /// never echoed by list/get). Omitted from the wire when absent.
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
}

impl SessionResp {
    fn new(meta: SessionMeta) -> Self {
        let proxy = meta.proxy_url.as_deref().map(mask_proxy);
        SessionResp { meta, proxy, api_key: None }
    }

    /// Variant used by the create handler: includes the freshly minted key once.
    fn with_api_key(meta: SessionMeta, api_key: Option<String>) -> Self {
        SessionResp { api_key, ..Self::new(meta) }
    }
}

/// Hide credentials in a proxy URL for display: `socks5://u:p@h:1080` →
/// `socks5://***@h:1080`; no-auth URLs pass through unchanged.
fn mask_proxy(url: &str) -> String {
    match (url.split_once("://"), url.rfind('@')) {
        (Some((scheme, rest)), Some(_)) => {
            let host = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
            format!("{scheme}://***@{host}")
        }
        _ => url.to_string(),
    }
}

#[derive(Deserialize)]
struct SetPresenceReq {
    /// `true` → announce `available` (online; phone notifications silenced);
    /// `false` → `unavailable` (phone keeps notifying).
    mark_online: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)] // reject a typo'd key (e.g. `url`) instead of a silent no-op
struct SetProxyReq {
    /// Proxy URL, or null to clear (direct connection).
    proxy: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)] // reject a typo'd key (e.g. `name`) instead of a silent no-op
struct SetLabelReq {
    /// New display label for the instance, or null/blank to clear it. This is a
    /// ruwa-side organizational name only — it has no WhatsApp protocol effect.
    label: Option<String>,
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionMeta>>> {
    check_auth(&headers, &state.api_token)?;
    Ok(Json(state.manager.list()))
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateSessionReq>,
) -> Result<(StatusCode, Json<SessionResp>)> {
    check_auth_write(&headers, &state)?;
    let kind = match req.kind.as_deref().map(str::trim) {
        None | Some("") | Some("web") => SessionKind::Web,
        Some("cloud") => SessionKind::Cloud,
        Some(other) => {
            return Err(Error::BadRequest(format!(
                "unknown session kind {other:?}: expected \"web\" or \"cloud\""
            )))
        }
    };
    let session = match kind {
        SessionKind::Web => {
            if req.cloud.is_some() {
                return Err(Error::BadRequest(
                    "cloud credentials are only accepted with \"kind\": \"cloud\"".into(),
                ));
            }
            state.manager.create(req.label)?
        }
        SessionKind::Cloud => {
            let c = req.cloud.ok_or_else(|| {
                Error::BadRequest(
                    "kind \"cloud\" requires a \"cloud\" object (provider \"meta\" needs \
                     phone_number_id + access_token; provider \"kapso\" needs neither)"
                        .into(),
                )
            })?;
            let provider = c
                .provider
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .unwrap_or_else(|| "meta".to_string());
            match provider.as_str() {
                "kapso" => {
                    state
                        .manager
                        .create_kapso(
                            req.label,
                            crate::session::KapsoCreateReq {
                                connection_type: non_blank(c.connection_type),
                                country_isos: c.country_isos.unwrap_or_default(),
                                language: non_blank(c.language),
                                provision_phone_number: c.provision_phone_number,
                                success_redirect_url: non_blank(c.success_redirect_url),
                                failure_redirect_url: non_blank(c.failure_redirect_url),
                                graph_version: non_blank(c.graph_version),
                            },
                        )
                        .await?
                }
                "meta" => {
                    let phone_number_id = non_blank(c.phone_number_id).ok_or_else(|| {
                        Error::BadRequest("cloud.phone_number_id is required".into())
                    })?;
                    let access_token = non_blank(c.access_token).ok_or_else(|| {
                        Error::BadRequest("cloud.access_token is required".into())
                    })?;
                    state.manager.create_cloud(
                        req.label,
                        cloud::CloudCreds {
                            provider: cloud::CloudProvider::Meta,
                            phone_number_id,
                            waba_id: non_blank(c.waba_id),
                            access_token,
                            api_key: None,
                            base_url: None,
                            app_secret: non_blank(c.app_secret),
                            verify_token: non_blank(c.verify_token),
                            graph_version: non_blank(c.graph_version)
                                .unwrap_or_else(|| cloud::DEFAULT_GRAPH_VERSION.to_string()),
                        },
                    )?
                }
                other => {
                    return Err(Error::BadRequest(format!(
                        "unknown cloud provider {other:?}: expected \"meta\" or \"kapso\""
                    )))
                }
            }
        }
    };
    let id = session.meta.read().id.clone();
    // Apply the proxy up-front (validates the URL; rolls back the session on a
    // bad value so we don't leave a half-configured row).
    if req.proxy.is_some() {
        if let Err(e) = state.manager.set_proxy(&id, req.proxy) {
            let _ = state.manager.delete(&id);
            return Err(e);
        }
    }
    let meta = session.meta.read().clone();
    // Hand back the per-tenant API key exactly once — the client must store it
    // now; no endpoint ever returns it again.
    let api_key = state.manager.session_api_key(&id)?;
    Ok((
        StatusCode::CREATED,
        Json(SessionResp::with_api_key(meta, api_key)),
    ))
}

/// Import an already-paired companion session (Baileys/Evolution) WITHOUT
/// re-pairing. Body is the Baileys `creds` JSON (the blob Evolution stores in
/// its `Session.creds`), optionally wrapped as `{ "label": ..., "creds": {...} }`
/// — a bare creds object is also accepted. On success the device logs in
/// directly on the next `POST /connect` (no QR). This is a MOVE: stop the source
/// client for this device first, or WhatsApp bounces one with conflict=replaced.
async fn import_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<SessionResp>)> {
    check_auth_write(&headers, &state)?;
    // Accept either {label?, creds:{...}} or a bare Baileys creds object.
    let label = body
        .get("label")
        .and_then(|l| l.as_str())
        .map(str::to_string);
    let creds_json = body.get("creds").unwrap_or(&body);
    let creds = crate::session::ImportedCreds::from_baileys_json(creds_json)?;
    let (session, api_key) = state.manager.import_session(label, creds)?;
    let meta = session.meta.read().clone();
    Ok((
        StatusCode::CREATED,
        Json(SessionResp::with_api_key(meta, Some(api_key))),
    ))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<SessionResp>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    let meta = session.meta.read().clone();
    Ok(Json(SessionResp::new(meta)))
}

async fn delete_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ConfirmQuery>,
    body: axum::body::Bytes,
) -> Result<StatusCode> {
    check_session_auth_write(&headers, &state, &id)?;
    require_confirmation("deleting a session", &q, &body)?;
    let keep_remote = matches!(q.keep_remote.as_deref(), Some("1") | Some("true") | Some("yes"));
    if !keep_remote {
        // Best-effort: offboard the number + drop the customer on Kapso. No-op
        // for non-Kapso sessions. Must run before the local rows are deleted.
        state.manager.kapso_teardown(&id).await;
    }
    state.manager.delete(&id)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Liveness/health for one session — real socket state (last rx, reconnect
/// count, prekeys), not just persisted status. For monitoring + the soak test.
async fn session_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<crate::session::SessionHealth>> {
    check_session_auth(&headers, &state, &id)?;
    Ok(Json(state.manager.health(&id)?))
}

/// Set or clear (`proxy: null`) a session's egress proxy. Validated immediately;
/// takes effect on the next connect, so reconnect to apply it to a live session.
async fn set_session_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SetProxyReq>,
) -> Result<Json<SessionResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    state.manager.set_proxy(&id, req.proxy)?;
    let meta = state.manager.get(&id)?.meta.read().clone();
    Ok(Json(SessionResp::new(meta)))
}

/// Answer an incoming call and bridge its audio over a WebSocket. On upgrade:
/// decrypt the callKey, derive the SRTP keys, ship `<preaccept>`+`<accept>`,
/// connect the relay transport, and run the media loop bridged to this socket.
/// Binary WS frames are 20 ms of s16le PCM (640 B); ruwa aggregates 3 → one
/// 60 ms WA frame and slices inbound frames back to 20 ms. Auth via bearer
/// header or `?token=` (browsers can't set WS headers). See SPEC "Calls".
async fn call_audio_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, call_id)): Path<(String, String)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Result<axum::response::Response> {
    // Bearer via header, or ?token= for browser WS clients.
    if check_session_auth(&headers, &state, &id).is_err() {
        let tok = q.get("token").map(String::as_str).unwrap_or("");
        if tok != state.api_token.as_str() {
            return Err(Error::Unauthorized);
        }
    }
    let session = state.manager.get(&id)?;
    require_web(&session, "calls are not supported on cloud sessions")?;
    let offer = session
        .pending_call_get(&call_id)
        .ok_or_else(|| Error::NotFound(format!("no ringing call {call_id}")))?;
    let keys = state
        .manager
        .load_device_keys(&id)
        .map_err(|e| Error::Internal(anyhow::anyhow!(e)))?;
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = run_call_audio_bridge(state, id, call_id, offer, keys, socket).await {
            tracing::warn!(error = %e, "call audio bridge ended with error");
        }
    }))
}

/// The post-upgrade orchestration: decrypt → derive keys → answer stanzas →
/// connect relay → run the media loop, bridging PCM to/from the WebSocket.
async fn run_call_audio_bridge(
    state: AppState,
    id: String,
    call_id: String,
    offer: crate::call::ParsedOffer,
    keys: crate::crypto::identity::DeviceKeys,
    socket: axum::extract::ws::WebSocket,
) -> anyhow::Result<()> {
    use anyhow::anyhow;

    let session = state.manager.get(&id)?;
    let store = state.manager.store.clone();

    // Our own device LID (selects our SRTP participant id); the peer is the caller.
    let own_lid = {
        let meta = session.meta.read();
        meta.jid.as_ref().and_then(|jid| {
            let user = jid.split(':').next().unwrap_or(jid).split('@').next().unwrap_or(jid);
            let device = jid.split(':').nth(1).and_then(|s| s.split('@').next()).unwrap_or("0");
            store.pn_to_lid(&id, user).ok().flatten().map(|lu| format!("{lu}:{device}@lid"))
        })
    }
    .ok_or_else(|| anyhow!("session has no LID (not paired?)"))?;
    let peer_lid = offer.call_creator.clone();

    // Decrypt the callKey (consumes a prekey — only now, at answer time).
    let call_key = crate::session::decrypt_call_key(
        &store, &id, &keys, &peer_lid, &offer.enc.enc_type, offer.enc.version, &offer.enc.ciphertext,
    )
    .ok_or_else(|| anyhow!("could not decrypt callKey"))?;

    // SRTP keys: send from our LID, recv from the peer's; audio SSRC is slot 0.
    let own_pid = crate::call::format_participant_id(&own_lid);
    let peer_pid = crate::call::format_participant_id(&peer_lid);
    let send_keys = crate::call::derive_e2e_keys(&call_key, &own_pid)
        .ok_or_else(|| anyhow!("derive send keys"))?;
    let recv_keys = crate::call::derive_e2e_keys(&call_key, &peer_pid)
        .ok_or_else(|| anyhow!("derive recv keys"))?;
    let send_ssrc = crate::call::derive_wasm_participant_ssrc(&call_id, &own_pid, 0);

    // Relay endpoint + STUN material.
    let relay = offer.relay.as_ref().ok_or_else(|| anyhow!("offer carried no <relay>"))?;
    let ep = crate::call::get_media_relay_endpoint(relay).ok_or_else(|| anyhow!("no relay endpoint"))?;
    let (relay_ip, relay_port) =
        crate::call::get_primary_ipv4_address(ep).ok_or_else(|| anyhow!("relay has no IPv4"))?;
    let token = relay
        .relay_tokens
        .get(ep.token_id as usize)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("relay token {} missing", ep.token_id))?
        .clone();
    let integrity_key = relay
        .relay_key_ascii
        .clone()
        .ok_or_else(|| anyhow!("relay <key> missing"))?;

    // Ship the answer stanzas (stop sibling ringing, then accept).
    let to = offer.from.clone();
    let rates: Vec<&str> = offer.audio_rates.iter().map(|_| "16000").take(1).collect();
    let rates = if rates.is_empty() { vec!["16000"] } else { rates };
    session.enqueue_send(crate::session::SendOp::RawNode(crate::call::build_preaccept(
        &call_id, &to, &peer_lid, &generate_message_id(), &rates,
    )))?;
    session.enqueue_send(crate::session::SendOp::RawNode(crate::call::build_accept(
        &call_id, &to, &peer_lid, &generate_message_id(), &rates,
    )))?;

    // Connect + allocate the relay transport.
    let transport = crate::call::RelayTransport::connect_and_allocate(
        &relay_ip, relay_port, &token, &integrity_key, &call_id, &own_pid,
    )
    .await?;

    session.pending_call_remove(&call_id);
    if offer.mlow {
        tracing::info!(call_id = %call_id, "answer: peer offered MLow — using MLow codec");
    }
    bridge_media_over_ws(
        &session, &call_id, &offer.from, &peer_lid, transport, send_keys, send_ssrc, recv_keys,
        offer.mlow, socket,
    )
    .await
}

/// Run the media loop and bridge its 60 ms PCM frames to/from the WebSocket as
/// 20 ms s16le frames. Shared by the answer (`run_call_audio_bridge`) and dial
/// (`run_dial_audio_bridge`) paths — the only difference between them is how the
/// transport + SRTP keys are obtained (offer decrypt vs. our own callKey). On
/// exit, if WE ended the call, ship a `<terminate reason=hangup>`.
#[allow(clippy::too_many_arguments)]
async fn bridge_media_over_ws(
    session: &Arc<crate::session::Session>,
    call_id: &str,
    peer_from: &str,
    peer_lid: &str,
    transport: crate::call::RelayTransport,
    send_keys: crate::call::E2eSrtpKeys,
    send_ssrc: u32,
    recv_keys: crate::call::E2eSrtpKeys,
    mlow: bool,
    socket: axum::extract::ws::WebSocket,
) -> anyhow::Result<()> {
    use axum::extract::ws::Message;
    use futures_util::{SinkExt, StreamExt};

    // Media loop ⇄ WS bridge channels (60 ms PCM frames). The agent→WA buffer is
    // deliberately shallow (8 × 60 ms = 480 ms max): if the browser mic outpaces
    // the 60 ms send tick (clock drift on a long call), a deep buffer would grow
    // unbounded latency, so we drop-newest past the cap rather than accumulate
    // seconds of lag. WA→agent stays roomier (the browser worklet drops its own
    // backlog past ~600 ms).
    let (to_wa_tx, to_wa_rx) = tokio::sync::mpsc::channel::<Vec<i16>>(8);
    let (from_wa_tx, mut from_wa_rx) = tokio::sync::mpsc::channel::<Vec<i16>>(64);
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());

    let media = crate::call::MediaLoop {
        transport,
        send_keys,
        send_ssrc,
        recv_keys,
        from_agent: to_wa_rx,
        to_agent: from_wa_tx,
        shutdown: shutdown.clone(),
        mlow,
    };
    let media_task = tokio::spawn(media.run());
    // Register so an inbound peer <terminate> tears down this live media loop.
    session.active_call_register(call_id, shutdown.clone());

    let (mut ws_tx, mut ws_rx) = socket.split();
    let _ = ws_tx
        .send(Message::Text(serde_json::json!({
            "event": "start", "call_id": call_id, "from": peer_from,
            "audio": {"encoding": "pcm_s16le", "rate": 16000, "channels": 1, "frame_ms": 20},
            "codec": "opus"
        }).to_string()))
        .await;

    // Inbound (WA → agent): 60 ms PCM → three 20 ms (640 B) binary frames.
    let ws_out = tokio::spawn(async move {
        while let Some(frame) = from_wa_rx.recv().await {
            for chunk in frame.chunks(320) {
                let mut bytes = Vec::with_capacity(chunk.len() * 2);
                for &s in chunk {
                    bytes.extend_from_slice(&s.to_le_bytes());
                }
                if ws_tx.send(Message::Binary(bytes)).await.is_err() {
                    return;
                }
            }
        }
        let _ = ws_tx.send(Message::Close(None)).await;
    });

    // Outbound (agent → WA): accumulate 20 ms binary frames into 60 ms (960-sample)
    // frames. Also break when the call ends from the peer side (shutdown fired by
    // the inbound <terminate> handler) — the notified future is created once, up
    // front, so a fire between iterations isn't missed.
    let mut acc: Vec<i16> = Vec::with_capacity(960);
    let ended = shutdown.notified();
    tokio::pin!(ended);
    loop {
        tokio::select! {
            _ = &mut ended => break,
            msg = ws_rx.next() => match msg {
                Some(Ok(Message::Binary(b))) => {
                    if b.len() % 2 != 0 {
                        continue;
                    }
                    for pair in b.as_chunks::<2>().0 {
                        acc.push(i16::from_le_bytes(*pair));
                    }
                    while acc.len() >= 960 {
                        let frame: Vec<i16> = acc.drain(..960).collect();
                        // Non-blocking: drop-newest when the shallow buffer is full
                        // (bounds latency); only stop when the media loop is gone.
                        match to_wa_tx.try_send(frame) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            }
        }
    }

    // Teardown. `active_call_end` removes the call and notifies the media loop,
    // returning true iff WE are ending it (the peer's <terminate> handler would
    // have already removed it → false). Only then do we tell WA we hung up.
    if session.active_call_end(call_id) {
        let node = crate::call::build_terminate(
            &generate_message_id(), peer_from, peer_lid, call_id, Some("hangup"),
        );
        let _ = session.enqueue_send(crate::session::SendOp::RawNode(node));
    }
    ws_out.abort();
    let _ = media_task.await;
    Ok(())
}

/// WS upgrade for an OUTBOUND (dial) call: `GET …/calls/dial?peer=<number>`.
/// On upgrade: place the call (offer + relay), connect the transport, wait for
/// the peer to answer, derive the recv keys for the answering device, and bridge
/// audio. Auth via bearer header or `?token=` (browser WS).
///
/// LIVE-UNVERIFIED: exercises the outbound `place_call` path end-to-end but has
/// not been validated against a live WhatsApp peer.
async fn dial_call_audio_ws(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<std::collections::HashMap<String, String>>,
    ws: axum::extract::ws::WebSocketUpgrade,
) -> Result<axum::response::Response> {
    if check_session_auth(&headers, &state, &id).is_err() {
        let tok = q.get("token").map(String::as_str).unwrap_or("");
        if tok != state.api_token.as_str() {
            return Err(Error::Unauthorized);
        }
    }
    let peer = q
        .get("peer")
        .cloned()
        .ok_or_else(|| Error::BadRequest("missing ?peer=<number>".into()))?;
    let session = state.manager.get(&id)?;
    require_web(&session, "calls are not supported on cloud sessions")?;
    let keys = state
        .manager
        .load_device_keys(&id)
        .map_err(|e| Error::Internal(anyhow::anyhow!(e)))?;
    Ok(ws.on_upgrade(move |socket| async move {
        if let Err(e) = run_dial_audio_bridge(state, id, peer, keys, socket).await {
            tracing::warn!(error = %e, "dial audio bridge ended with error");
        }
    }))
}

async fn run_dial_audio_bridge(
    state: AppState,
    id: String,
    peer: String,
    keys: crate::crypto::identity::DeviceKeys,
    socket: axum::extract::ws::WebSocket,
) -> anyhow::Result<()> {
    use anyhow::anyhow;

    let session = state.manager.get(&id)?;
    let store = state.manager.store.clone();
    let dispatcher = session
        .iq_client_clone()
        .ok_or_else(|| anyhow!("session offline — cannot place a call"))?;

    // Ship the offer + capture the relay.
    let setup = crate::session::place_call(&session, &store, &keys, &dispatcher, &peer).await?;

    // Our send keys/SSRC are known immediately (keyed on our own LID).
    let own_pid = crate::call::format_participant_id(&setup.own_lid);
    let send_keys = crate::call::derive_e2e_keys(&setup.call_key, &own_pid)
        .ok_or_else(|| anyhow!("derive send keys"))?;
    let send_ssrc = crate::call::derive_wasm_participant_ssrc(&setup.call_id, &own_pid, 0);

    // Relay endpoint + STUN material (same extraction as the answer path).
    let ep = crate::call::get_media_relay_endpoint(&setup.relay)
        .ok_or_else(|| anyhow!("no relay endpoint"))?;
    let (relay_ip, relay_port) =
        crate::call::get_primary_ipv4_address(ep).ok_or_else(|| anyhow!("relay has no IPv4"))?;
    tracing::info!(
        %relay_ip, relay_port, own_pid = %own_pid, send_ssrc,
        want_web_port = crate::call::WEB_CLIENT_RELAY_PORT,
        "dial: relay endpoint chosen (port != 3480 risks one-way audio)"
    );
    let token = setup
        .relay
        .relay_tokens
        .get(ep.token_id as usize)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| anyhow!("relay token {} missing", ep.token_id))?
        .clone();
    let integrity_key = setup
        .relay
        .relay_key_ascii
        .clone()
        .ok_or_else(|| anyhow!("relay <key> missing"))?;

    let transport = crate::call::RelayTransport::connect_and_allocate(
        &relay_ip, relay_port, &token, &integrity_key, &setup.call_id, &own_pid,
    )
    .await?;

    // Wait for the peer to pick up (which device answered decides the recv keys).
    // ~60 s ring; on timeout/decline, cancel the call.
    let answering = match tokio::time::timeout(std::time::Duration::from_secs(60), setup.accept_rx)
        .await
    {
        Ok(Ok(jid)) => jid,
        _ => {
            session.outbound_accept_cancel(&setup.call_id);
            let node = crate::call::build_terminate(
                &generate_message_id(), &setup.peer_addr, &setup.call_creator, &setup.call_id, None,
            );
            let _ = session.enqueue_send(crate::session::SendOp::RawNode(node));
            return Ok(());
        }
    };
    let peer_pid = crate::call::format_participant_id(&answering);
    let recv_keys = crate::call::derive_e2e_keys(&setup.call_key, &peer_pid)
        .ok_or_else(|| anyhow!("derive recv keys for answering device"))?;
    tracing::info!(
        answering = %answering, peer_pid = %peer_pid,
        "dial: peer answered — recv keys derived, starting media bridge"
    );

    bridge_media_over_ws(
        &session, &setup.call_id, &setup.peer_addr, &setup.call_creator, transport, send_keys,
        send_ssrc, recv_keys, false, socket,
    )
    .await
}

/// One ringing incoming call in the `GET /calls` listing. Neutral shape — no
/// protobuf, no callKey ciphertext.
#[derive(Serialize)]
struct CallResp {
    call_id: String,
    from: String,
    is_video: bool,
    audio_rates: Vec<u32>,
}

/// List the calls currently ringing on a web session (populated from inbound
/// `<offer>`s, cleared on terminate/reject). Read-only; media isn't answered here.
async fn list_calls(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<CallResp>>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    let calls = session
        .pending_calls_snapshot()
        .into_iter()
        .map(|o| CallResp {
            call_id: o.call_id,
            from: o.from,
            is_video: o.is_video,
            audio_rates: o.audio_rates,
        })
        .collect();
    Ok(Json(calls))
}

/// Non-sensitive breakdown of a proxy URL: scheme/host/port + the sticky-session
/// hints parsed out of the username (country/city/session/lifetime). Never the
/// password; the username value itself is redacted (only its parsed hints show).
fn proxy_info_json(url: &str) -> serde_json::Value {
    let scheme = url.split_once("://").map(|(s, _)| s).unwrap_or("");
    // host:port is everything after the last '@' (or after scheme:// if no auth).
    let after_scheme = url.split_once("://").map(|(_, r)| r).unwrap_or(url);
    let hostport = after_scheme.rsplit_once('@').map(|(_, h)| h).unwrap_or(after_scheme);
    let (host, port) = hostport.rsplit_once(':').unwrap_or((hostport, ""));
    // Username = between "://" and the last '@'; parse `_key-value` sticky hints.
    let user = after_scheme.rsplit_once('@').map(|(u, _)| u).unwrap_or("");
    let user = user.split_once(':').map(|(u, _)| u).unwrap_or(user); // drop password
    let mut hints = serde_json::Map::new();
    for key in ["country", "city", "session", "lifetime", "state", "region"] {
        if let Some(pos) = user.find(&format!("_{key}-")) {
            let rest = &user[pos + key.len() + 2..];
            let val = rest.split('_').next().unwrap_or("");
            if !val.is_empty() {
                // `session` is an opaque id — confirm presence, don't echo it.
                let shown = if key == "session" { "<set>".to_string() } else { val.to_string() };
                hints.insert(key.to_string(), serde_json::Value::String(shown));
            }
        }
    }
    serde_json::json!({
        "scheme": scheme,
        "host": host,
        "port": port.parse::<u16>().ok(),
        "has_auth": after_scheme.contains('@'),
        "hints": hints,
        "masked": mask_proxy(url),
    })
}

/// Show the session's configured proxy — non-sensitive fields only, so an
/// operator can verify it's being built right (host/port/country/city/…).
async fn get_session_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth(&headers, &state, &id)?;
    let proxy = state.manager.get(&id)?.meta.read().proxy_url.clone();
    Ok(Json(match proxy {
        Some(url) => serde_json::json!({ "configured": true, "proxy": proxy_info_json(&url) }),
        None => serde_json::json!({ "configured": false }),
    }))
}

/// Heartbeat the session's proxy: make a short HTTPS request THROUGH it and
/// report reachability, latency, and the exit IP WhatsApp would see. Tells you
/// whether the proxy itself is broken vs. a ruwa/account issue. No proxy → tests
/// the direct egress (the server's own IP).
async fn check_session_proxy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth(&headers, &state, &id)?;
    let proxy = state.manager.get(&id)?.meta.read().proxy_url.clone();

    let mut builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(8));
    if let Some(url) = proxy.as_deref() {
        match reqwest::Proxy::all(url) {
            Ok(p) => builder = builder.proxy(p),
            Err(e) => {
                return Ok(Json(serde_json::json!({
                    "ok": false, "via_proxy": true, "error": format!("invalid proxy url: {e}")
                })));
            }
        }
    }
    let client = builder.build().map_err(|e| Error::Internal(anyhow::anyhow!(e)))?;
    // A tiny plaintext IP echo — confirms the tunnel works AND surfaces the exit IP.
    let started = std::time::Instant::now();
    let result = client.get("https://api.ipify.org").send().await;
    let latency_ms = started.elapsed().as_millis() as u64;
    Ok(Json(match result {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let exit_ip = resp.text().await.ok().map(|s| s.trim().to_string());
            serde_json::json!({
                "ok": (200..300).contains(&status),
                "via_proxy": proxy.is_some(),
                "status": status,
                "latency_ms": latency_ms,
                "exit_ip": exit_ip,
            })
        }
        Err(e) => serde_json::json!({
            "ok": false,
            "via_proxy": proxy.is_some(),
            "latency_ms": latency_ms,
            "error": e.to_string(),
        }),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectCallReq {
    /// The caller's JID — the `from` of the `call_offer` event. Accepts bare
    /// digits or a full jid (normalized like message recipients).
    peer: String,
}

/// Decline an incoming call: ships whatsmeow's `<call><reject/></call>` so
/// the caller's phone stops ringing and shows "declined". `call_id` comes
/// from the `call_offer` event. Web sessions only.
async fn reject_call(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, call_id)): Path<(String, String)>,
    Json(req): Json<RejectCallReq>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "calls are not supported on cloud sessions")?;
    let own_jid = session
        .meta
        .read()
        .jid
        .clone()
        .ok_or_else(|| Error::BadRequest("session has no JID (not paired)".into()))?;
    let peer = normalize_recipient_jid(&req.peer);
    let node = crate::session::build_call_reject_node(
        &generate_message_id(),
        &own_jid,
        &peer,
        &call_id,
    );
    session.enqueue_send(SendOp::RawNode(node))?;
    Ok(Json(serde_json::json!({
        "call_id": call_id,
        "peer": peer,
        "rejected": true
    })))
}

/// Update a cloud session's Graph credentials (partial: only the fields present
/// replace the stored value; an empty string clears an optional one). Takes
/// effect on the next `connect`/send — `reconnect` to re-validate a new token.
/// `phone_number_id` changes need the master token and 409 if another session
/// already owns that number. 501 on web sessions.
async fn set_session_cloud(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<CloudCredsPatch>,
) -> Result<Json<SessionResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, "cloud credentials are only available on cloud sessions")?;
    // A kapso session's Meta credentials are managed by Kapso via the hosted
    // setup link — there is nothing here for an operator to patch.
    if session
        .meta
        .read()
        .cloud
        .as_ref()
        .is_some_and(|c| c.provider == "kapso")
    {
        return Err(Error::NotImplemented(
            "cloud credentials for a kapso session are managed through the setup link",
        ));
    }
    // Re-pointing a session at a different Meta number is an operator action:
    // a per-session key may rotate tokens/secrets, not claim other numbers.
    if patch.phone_number_id.is_some() && bearer_token(&headers)? != state.api_token.as_str() {
        return Err(Error::Forbidden(
            "changing phone_number_id requires the master API token".into(),
        ));
    }
    state.manager.set_cloud_creds(&id, patch)?;
    let meta = session.meta.read().clone();
    Ok(Json(SessionResp::new(meta)))
}

/// Rename an instance: set or clear (`label: null`/blank) its display label.
/// A purely organizational ruwa-side name — no WhatsApp protocol effect. Takes
/// effect immediately; no reconnect needed.
async fn set_session_label(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SetLabelReq>,
) -> Result<Json<SessionResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    state.manager.set_label(&id, req.label)?;
    let meta = state.manager.get(&id)?.meta.read().clone();
    Ok(Json(SessionResp::new(meta)))
}

/// Toggle a session's online presence. `mark_online=false` (default) keeps your
/// phone notifying; `true` marks the companion online (WhatsApp then silences
/// the phone). Applied live if connected.
async fn set_session_presence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SetPresenceReq>,
) -> Result<Json<SessionResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "mark-online (presence) is not supported on cloud sessions")?;
    state.manager.set_mark_online(&id, req.mark_online)?;
    let meta = state.manager.get(&id)?.meta.read().clone();
    Ok(Json(SessionResp::new(meta)))
}

async fn get_qr(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "QR pairing is not supported on cloud sessions")?;
    let qr = session
        .current_qr()
        .ok_or_else(|| Error::NotFound(format!("no QR available for session {id}")))?;
    let svg = render_qr_svg(&qr);
    Ok(Json(json!({
        "qr": qr,
        "svg_base64": B64.encode(svg.as_bytes()),
    })))
}

/// Render the QR string as an SVG document. Caller base64s for transport.
/// We use SVG instead of PNG because qrcode's PNG path requires the `image`
/// feature, whose transitive deps need rustc 1.88+. SVG renders pixel-
/// accurate at any size and any browser/scanner handles it.
fn render_qr_svg(data: &str) -> String {
    use qrcode::render::svg;
    use qrcode::QrCode;
    let code = QrCode::new(data.as_bytes()).expect("QR encoding accepts arbitrary input");
    code.render::<svg::Color<'_>>()
        .min_dimensions(256, 256)
        .quiet_zone(true)
        .build()
}

/// Body for `POST /sessions/:id/pair-phone`.
#[derive(Deserialize)]
struct PairPhoneReq {
    /// International phone number, digits only (e.g. `15551234567`). A leading
    /// `+` or punctuation is tolerated — non-digits are stripped server-side.
    phone: String,
    /// Display name shown on the phone, formatted `Browser (OS)`. WhatsApp
    /// validates it and 400s on an unrecognized value; defaults to
    /// `Chrome (Linux)`.
    #[serde(default)]
    client_display_name: Option<String>,
}

/// Request an 8-char phone-number pairing code ("Link with phone number"), the
/// alternative to scanning a QR. The session must already be `connect`ed (the
/// Noise socket has to be up), and the code should be entered promptly — the
/// login socket closes after ~160 s.
async fn pair_phone_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PairPhoneReq>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "phone pairing is not supported on cloud sessions")?;
    let keys = state.manager.load_device_keys(&id)?;
    let display = req
        .client_display_name
        .as_deref()
        .unwrap_or("Chrome (Linux)");
    let code = session
        .pair_phone(&keys.noise.public, &req.phone, display)
        .await?;
    Ok(Json(json!({ "code": code })))
}

async fn connect_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<SessionResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    state.manager.connect(&id)?;
    let session = state.manager.get(&id)?;
    let meta = session.meta.read().clone();
    Ok((StatusCode::ACCEPTED, Json(SessionResp::new(meta))))
}

/// Force a real reconnect ("rekey"): bounce the live socket and re-login without
/// re-pairing. Unlike `/connect` (idempotent — a no-op when already connected),
/// this always bounces, so it heals sessions stuck on undecryptable inbound
/// (e.g. imported from Baileys). Clears the in-flight retry map too.
async fn reconnect_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<SessionResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    state.manager.reconnect(&id)?;
    let session = state.manager.get(&id)?;
    let meta = session.meta.read().clone();
    Ok((StatusCode::ACCEPTED, Json(SessionResp::new(meta))))
}

/// Force a FULL app-state resync: zero every collection's stored version so the
/// next connect fetches a snapshot (not an incremental patch), then reconnect.
/// A snapshot re-carries the current SET state of every action — including
/// `nct_salt_sync`, the account NCT salt used to derive the 1:1 `<cstoken>`. This
/// repairs sessions that linked before the salt-capture code existed: an
/// incremental sync never re-delivers an old mutation, but a snapshot does.
/// Idempotent: re-applying contact/pin/mute mutations is a no-op.
async fn resync_appstate_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<SessionResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    // Verify the session exists (and is a web one) before touching its rows.
    let session = state.manager.get(&id)?;
    require_web(&session, "app-state resync is not supported on cloud sessions")?;
    for col in crate::session::AppStateCollection::all() {
        state
            .manager
            .store
            .app_state_version_set(&id, col.name(), 0, &[])
            .map_err(crate::error::Error::from)?;
    }
    // Reconnect re-ships the app-state fetch IQs; version 0 → want_snapshot=true.
    state.manager.reconnect(&id)?;
    let session = state.manager.get(&id)?;
    let meta = session.meta.read().clone();
    Ok((StatusCode::ACCEPTED, Json(SessionResp::new(meta))))
}

async fn logout_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ConfirmQuery>,
    body: axum::body::Bytes,
) -> Result<Json<SessionResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    require_confirmation("logging out a session", &q, &body)?;
    // `?fresh=1` or body `{"fresh":true}` → regenerate the device identity.
    let fresh = matches!(q.fresh.as_deref(), Some("1") | Some("true") | Some("yes"))
        || (!body.is_empty())
            .then(|| serde_json::from_slice::<ConfirmBody>(&body).ok())
            .flatten()
            .is_some_and(|b| b.fresh);
    state.manager.logout(&id, fresh)?;
    let session = state.manager.get(&id)?;
    let meta = session.meta.read().clone();
    Ok(Json(SessionResp::new(meta)))
}

/// A reference to the message being replied to (quoted).
#[derive(Deserialize)]
struct QuotedRef {
    /// Stanza id of the quoted message.
    id: String,
    /// Author JID of the quoted message. Required for group replies (the
    /// participant who sent the quoted message); optional in 1:1 chats.
    #[serde(default)]
    participant: Option<String>,
}

#[derive(Deserialize)]
struct SendTextReq {
    /// Recipient — bare phone (`5511...`), full JID (`...@s.whatsapp.net`), or group JID.
    to: String,
    /// Message body. Required. When mentioning, include the `@<number>` tokens here.
    text: String,
    /// JIDs mentioned in the body (`["5511...@s.whatsapp.net"]`). Each should have
    /// a matching `@<number>` in `text`. Empty = no mentions.
    #[serde(default)]
    mentions: Vec<String>,
    /// Reply to (quote) a message. Renders as a reply in the recipient's client.
    #[serde(default)]
    quoted: Option<QuotedRef>,
    /// Deprecated shorthand for `quoted` with no participant (1:1 replies).
    #[serde(default)]
    reply_to: Option<String>,
}

#[derive(Serialize)]
struct SendTextResp {
    id: String,
    timestamp: i64,
    /// "queued" once the message row is persisted and the SendOp has been
    /// pushed onto the connection task's outbound queue. The send pump
    /// (in `session::run_send_pump`) drains the queue, runs X3DH-on-demand
    /// for unknown peers, encrypts via Signal, and ships the `<message>`
    /// node — at which point a `MessageSent` event lands on the SSE bus.
    /// Server-ack confirmation (`<ack>` round-trip) is a follow-up.
    ///
    /// Cloud sessions send synchronously (Graph POST inside the handler), so
    /// they answer `"sent"` with `id` = Meta's `wamid` and a row already at
    /// `status=sent`; delivery/read/failed arrive later via the Meta webhook.
    status: &'static str,
}

async fn send_message(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendTextReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.text.is_empty() {
        return Err(Error::BadRequest("text must be non-empty".into()));
    }
    let session = state.manager.get(&id)?;
    if session.kind() == SessionKind::Cloud {
        // Cloud: synchronous Graph text send. `quoted.id`/`reply_to` becomes the
        // Graph `context.message_id`; `mentions` have no Cloud API equivalent
        // and are ignored (the `@number` tokens stay in the text).
        let reply_to = req
            .quoted
            .as_ref()
            .map(|q| q.id.as_str())
            .or(req.reply_to.as_deref());
        let payload = cloud::text_payload(&req.to, &req.text, reply_to);
        let echo = json!({ "type": "text", "text": req.text });
        return cloud_dispatch(&state, &id, &session, &req.to, "text", Some(&req.text), echo, payload)
            .await;
    }
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session
        .meta
        .read()
        .jid
        .clone()
        .unwrap_or_else(|| "self".into());

    state.manager.persist_outgoing_text(
        &id,
        &chat_jid,
        &msg_id,
        &sender_jid,
        &req.text,
        now,
    )?;

    // Push onto the per-session send queue. If the connection task is
    // offline (no receiver), the persisted row stays as a record of
    // intent — caller can reconnect and re-drive. The enqueue itself is
    // best-effort: we still 202 even if the queue is shut down so the
    // POST is idempotent against a transient disconnect.
    //
    // Mentions and/or a reply promote the send to an `ExtendedTextMessage`
    // (carrying a contextInfo); a plain text stays a lean `conversation`.
    let quoted = req
        .quoted
        .as_ref()
        .map(|q| (q.id.as_str(), q.participant.as_deref()))
        .or_else(|| req.reply_to.as_deref().map(|id| (id, None)));
    let op = if req.mentions.is_empty() && quoted.is_none() {
        SendOp::Text {
            chat_jid: chat_jid.clone(),
            msg_id: msg_id.clone(),
            text: req.text.clone(),
            timestamp: now,
        }
    } else {
        let inner = crate::session::build_extended_text_message(&req.text, &req.mentions, quoted);
        SendOp::EncryptedInner {
            chat_jid: chat_jid.clone(),
            msg_id: msg_id.clone(),
            inner_proto: inner,
            timestamp: now,
        }
    };
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, op);

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
}

#[derive(Deserialize)]
struct SendLocationReq {
    /// Recipient — bare phone, full JID, or group JID.
    to: String,
    latitude: f64,
    longitude: f64,
    /// Optional place name shown on the pin.
    #[serde(default)]
    name: Option<String>,
    /// Optional street address shown under the name.
    #[serde(default)]
    address: Option<String>,
}

async fn send_location(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendLocationReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if !(-90.0..=90.0).contains(&req.latitude) || !(-180.0..=180.0).contains(&req.longitude) {
        return Err(Error::BadRequest(
            "latitude must be in [-90,90] and longitude in [-180,180]".into(),
        ));
    }
    let session = state.manager.get(&id)?;
    let body = req.name.as_deref().or(req.address.as_deref()).unwrap_or("location");
    let payload = serde_json::json!({
        "type": "location",
        "latitude": req.latitude,
        "longitude": req.longitude,
        "name": req.name,
        "address": req.address,
    });
    if session.kind() == SessionKind::Cloud {
        let graph = cloud::location_payload(
            &req.to,
            req.latitude,
            req.longitude,
            req.name.as_deref(),
            req.address.as_deref(),
            None,
        );
        return cloud_dispatch(&state, &id, &session, &req.to, "location", Some(body), payload, graph)
            .await;
    }
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    state.manager.persist_outgoing(
        &id, &chat_jid, &msg_id, &sender_jid, "location", Some(body), &payload.to_string(), now,
    )?;

    let inner = crate::session::build_location_message(
        req.latitude,
        req.longitude,
        req.name.as_deref(),
        req.address.as_deref(),
    );
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp { id: msg_id, timestamp: now, status: "queued" }),
    ))
}

#[derive(Deserialize)]
struct SendContactReq {
    /// Recipient — bare phone, full JID, or group JID.
    to: String,
    /// Contact's display name (shown in the chat list).
    display_name: String,
    /// Contact's phone number. Used to build the vCard when `vcard` is omitted.
    #[serde(default)]
    phone: Option<String>,
    /// Raw vCard text. If present, used verbatim; otherwise one is built from
    /// `display_name` + `phone`.
    #[serde(default)]
    vcard: Option<String>,
}

/// Assemble a minimal vCard 3.0 from a name + phone, embedding the WhatsApp id
/// (`waid`, digits only) so the recipient's client links it to a WA contact.
fn build_vcard(name: &str, phone: &str) -> String {
    let waid: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    format!(
        "BEGIN:VCARD\nVERSION:3.0\nN:;{name};;;\nFN:{name}\nTEL;type=CELL;type=VOICE;waid={waid}:{phone}\nEND:VCARD"
    )
}

/// Best-effort vCard → neutral contact card for the Cloud API (which takes
/// structured contacts, not vCard text): `FN:` (else `fallback_name`) becomes
/// the name; every `TEL…:` line contributes a phone. Never fails — an unusable
/// vCard yields a card with no phones (the caller rejects that).
fn contact_card_from_vcard(vcard: &str, fallback_name: &str) -> cloud::ContactCard {
    let mut name: Option<String> = None;
    let mut phones = Vec::new();
    for line in vcard.lines() {
        let line = line.trim();
        let (key, value) = match line.split_once(':') {
            Some(kv) => kv,
            None => continue,
        };
        // `TEL;type=CELL;waid=…:+55 11 …` — the property name is before the
        // first `;`; the value is everything after the LAST `:` of the params.
        let prop = key.split(';').next().unwrap_or("").trim().to_ascii_uppercase();
        let value = value.trim();
        match prop.as_str() {
            "FN" if !value.is_empty() && name.is_none() => name = Some(value.to_string()),
            "TEL" if !value.is_empty() => phones.push(value.to_string()),
            _ => {}
        }
    }
    cloud::ContactCard {
        name: name.unwrap_or_else(|| fallback_name.to_string()),
        phones,
    }
}

async fn send_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendContactReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.display_name.trim().is_empty() {
        return Err(Error::BadRequest("display_name must be non-empty".into()));
    }
    let vcard = match (req.vcard.as_deref(), req.phone.as_deref()) {
        (Some(v), _) if !v.trim().is_empty() => v.to_string(),
        (_, Some(p)) if !p.trim().is_empty() => build_vcard(&req.display_name, p),
        _ => {
            return Err(Error::BadRequest(
                "provide either a vcard or a phone to build one".into(),
            ))
        }
    };

    let session = state.manager.get(&id)?;
    let payload = serde_json::json!({
        "type": "contact",
        "display_name": req.display_name,
        "vcard": vcard,
    });
    if session.kind() == SessionKind::Cloud {
        // Cloud sends structured contact cards, not vCards: use the explicit
        // phone when given, else pull FN/TEL out of the vCard best-effort.
        let card = match req.phone.as_deref().map(str::trim).filter(|p| !p.is_empty()) {
            Some(p) => cloud::ContactCard { name: req.display_name.clone(), phones: vec![p.to_string()] },
            None => contact_card_from_vcard(&vcard, &req.display_name),
        };
        if card.phones.is_empty() {
            return Err(Error::BadRequest(
                "cloud contact cards need a phone (provide `phone` or a vCard with a TEL line)".into(),
            ));
        }
        let graph = cloud::contacts_payload(&req.to, std::slice::from_ref(&card), None);
        return cloud_dispatch(
            &state, &id, &session, &req.to, "contact", Some(&req.display_name), payload, graph,
        )
        .await;
    }
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    state.manager.persist_outgoing(
        &id, &chat_jid, &msg_id, &sender_jid, "contact",
        Some(&req.display_name), &payload.to_string(), now,
    )?;

    let inner = crate::session::build_contact_message(&req.display_name, &vcard);
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp { id: msg_id, timestamp: now, status: "queued" }),
    ))
}

fn default_selectable() -> u32 {
    1
}

#[derive(Deserialize)]
struct SendPollReq {
    /// Recipient — bare phone, full JID, or group JID.
    to: String,
    /// The poll question.
    name: String,
    /// The answer options (2+).
    options: Vec<String>,
    /// How many options a voter may select. Default 1 (single-choice).
    #[serde(default = "default_selectable")]
    selectable_count: u32,
    /// Optional poll end time, unix seconds. Voting closes on the phones at
    /// that time ("Ends in …"); must be in the future.
    #[serde(default)]
    end_time: Option<i64>,
    /// Makes the poll a quiz with this option as the correct answer. Must be
    /// one of `options`; a quiz is single-choice.
    #[serde(default)]
    quiz_answer: Option<String>,
    /// Message field carrying the poll: `v1` (default), `v3`, `v5` or `v6`.
    #[serde(default)]
    wire_version: Option<String>,
}

async fn send_poll(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendPollReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.name.trim().is_empty() {
        return Err(Error::BadRequest("poll name must be non-empty".into()));
    }
    if req.options.len() < 2 {
        return Err(Error::BadRequest("a poll needs at least 2 options".into()));
    }
    if req.selectable_count < 1 || req.selectable_count as usize > req.options.len() {
        return Err(Error::BadRequest(
            "selectable_count must be between 1 and the number of options".into(),
        ));
    }
    if let Some(a) = &req.quiz_answer {
        if !req.options.contains(a) {
            return Err(Error::BadRequest("quiz_answer must be one of the options".into()));
        }
        if req.selectable_count != 1 {
            return Err(Error::BadRequest("a quiz must have selectable_count 1".into()));
        }
    }
    let wire_version = match req.wire_version.as_deref() {
        None => crate::session::PollWireVersion::default(),
        Some(v) => crate::session::PollWireVersion::parse(v).ok_or_else(|| {
            Error::BadRequest("wire_version must be one of v1, v3, v5, v6".into())
        })?,
    };

    let session = state.manager.get(&id)?;
    require_web(&session, "polls are not supported on cloud sessions")?;
    let now = chrono::Utc::now().timestamp();
    if req.end_time.is_some_and(|t| t <= now) {
        return Err(Error::BadRequest("end_time must be a future unix timestamp (seconds)".into()));
    }
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    // Fresh 32-byte poll secret (WA encrypts vote payloads under it).
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let payload = serde_json::json!({
        "type": "poll",
        "text": req.name,
        "poll": {
            "name": req.name,
            "options": req.options,
            "selectable_count": req.selectable_count,
            "end_time": req.end_time,
            "quiz_answer": req.quiz_answer,
        },
    });
    state.manager.persist_outgoing(
        &id, &chat_jid, &msg_id, &sender_jid, "poll",
        Some(&req.name), &payload.to_string(), now,
    )?;
    // Keep the secret: every vote on this poll comes back sealed under a key
    // derived from it, and without it the votes can't be read.
    if sender_jid != "self" {
        let _ = state.manager.store.message_secret_put(
            &id,
            &msg_id,
            &chat_jid,
            &crate::session::to_non_ad_jid(&sender_jid),
            &secret,
            now,
        );
    }

    let inner = crate::session::build_poll_message_ext(
        &req.name,
        &req.options,
        req.selectable_count,
        &secret,
        &crate::session::PollExtras {
            // WhatsApp's `endTime` is milliseconds: a seconds value reads as
            // 1970 and the poll arrives already ended (verified live).
            end_time: req.end_time.map(|t| t * 1000),
            quiz_answer: req.quiz_answer.clone(),
            wire_version,
        },
    );
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp { id: msg_id, timestamp: now, status: "queued" }),
    ))
}

#[derive(Deserialize)]
struct SendEventReq {
    /// Recipient — bare phone, full JID, or group JID.
    to: String,
    /// Event title (shown on the calendar card).
    name: String,
    /// Optional longer description.
    #[serde(default)]
    description: Option<String>,
    /// Optional free-text place (mapped to the event's location name).
    #[serde(default)]
    location: Option<String>,
    /// Event start, unix seconds.
    start_time: i64,
    /// Optional event end, unix seconds. Must be after `start_time` if given.
    #[serde(default)]
    end_time: Option<i64>,
    /// Optional join link (e.g. a video-call URL).
    #[serde(default)]
    join_link: Option<String>,
}

/// Send a native WhatsApp event / calendar invite. In-house equivalent of
/// Evolution's `/message/sendCalendar` — booked-appointment / calendar invites.
async fn send_event(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendEventReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.name.trim().is_empty() {
        return Err(Error::BadRequest("event name must be non-empty".into()));
    }
    if let Some(end) = req.end_time {
        if end < req.start_time {
            return Err(Error::BadRequest(
                "end_time must not be before start_time".into(),
            ));
        }
    }

    let session = state.manager.get(&id)?;
    require_web(&session, "calendar events are not supported on cloud sessions")?;
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    let payload = serde_json::json!({
        "type": "event",
        "name": req.name,
        "description": req.description,
        "location": req.location,
        "start_time": req.start_time,
        "end_time": req.end_time,
        "join_link": req.join_link,
    });
    state.manager.persist_outgoing(
        &id, &chat_jid, &msg_id, &sender_jid, "event",
        Some(&req.name), &payload.to_string(), now,
    )?;

    let inner = crate::session::build_event_message(
        &req.name,
        req.description.as_deref(),
        req.location.as_deref(),
        req.start_time,
        req.end_time,
        req.join_link.as_deref(),
    );
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp { id: msg_id, timestamp: now, status: "queued" }),
    ))
}

/// Bare phone numbers get the s.whatsapp.net server appended; otherwise
/// the caller's JID is used verbatim.
fn normalize_recipient_jid(input: &str) -> String {
    if input.contains('@') {
        input.to_string()
    } else {
        format!("{input}@s.whatsapp.net")
    }
}

/// Whatsmeow-style 16-byte hex message id (32 hex chars). The server is
/// fairly tolerant of the format; uniqueness within a session is what
/// matters.
pub(crate) fn generate_message_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode_upper(buf)
}

#[derive(Deserialize)]
struct ListMessagesQuery {
    chat: Option<String>,
    q: Option<String>,
    limit: Option<u32>,
    /// Optional Unix timestamp; only messages strictly older are returned.
    before: Option<i64>,
}


async fn list_messages(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ListMessagesQuery>,
) -> Result<Json<Vec<crate::store::MessageListRow>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let limit = q.limit.unwrap_or(50).min(500);
    let before = q.before.unwrap_or(i64::MAX);
    let rows = state
        .manager
        .store
        .messages_list(&id, q.chat.as_deref(), q.q.as_deref(), before, limit)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct EventHistoryQuery {
    /// Keyset cursor: only events with a smaller row id are returned (for
    /// paging older). Omit for the newest page.
    before: Option<i64>,
    limit: Option<u32>,
    /// Restrict to a single `SessionEvent` type tag, e.g. `message`.
    #[serde(rename = "type")]
    type_filter: Option<String>,
}

/// Persisted event history for a session — the durable backing for the live SSE
/// stream so the dashboard Logs page can seed past events and survive reloads.
/// Returns oldest-first `{ id, ts, ev }` objects, where `ev` is the same
/// type-tagged `SessionEvent` shape the SSE stream emits and `ts` is unix ms.
async fn get_event_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<EventHistoryQuery>,
) -> Result<Json<Vec<serde_json::Value>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let limit = q.limit.unwrap_or(200).min(1000);
    let before = q.before.unwrap_or(i64::MAX);
    let rows =
        state
            .manager
            .store
            .event_log_list(&id, before, q.type_filter.as_deref(), limit)?;
    // DB returns newest-first; reverse to chronological so the page can append
    // it above the live tail.
    let evs = rows
        .into_iter()
        .rev()
        .map(|r| {
            let ev: serde_json::Value = serde_json::from_str(&r.payload_json)
                .unwrap_or_else(|_| serde_json::json!({ "type": r.event_type }));
            serde_json::json!({ "id": r.id, "ts": r.ts, "ev": ev })
        })
        .collect();
    Ok(Json(evs))
}

#[derive(Deserialize)]
struct SendMediaReq {
    to: String,
    /// "image" | "video" | "audio" | "ptt" (alias "voice") | "document" | "sticker".
    /// "ptt"/"voice" sends as a WhatsApp voice note (AudioMessage ptt=true).
    #[serde(rename = "type")]
    kind: String,
    /// Local filesystem path the server can read.
    file_path: String,
    /// MIME type — best caller-provided.
    mime: String,
    caption: Option<String>,
    /// Optional display filename (Document messages).
    filename: Option<String>,
    /// @-mentioned JIDs (image/video/document carry them in contextInfo).
    #[serde(default)]
    mentions: Vec<String>,
}

/// Confine a caller-supplied media `file_path`. Reading an arbitrary server path
/// is a path-traversal / data-exfiltration risk (CWE-22) — acute on the
/// agent/MCP surface under prompt injection (a hijacked agent could "send"
/// `/data/ruwa.db` or a secrets file to an attacker). When `RUWA_MEDIA_BASE_DIR`
/// is set, the resolved path MUST live within it; unset = unchanged behaviour
/// (the operator opted into full-filesystem access). Agent deployments should
/// set it. The server-spooled multipart path is trusted and not checked here.
fn check_media_path(p: &str) -> Result<()> {
    let Some(base) = std::env::var("RUWA_MEDIA_BASE_DIR").ok().filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let base = std::fs::canonicalize(&base)
        .map_err(|e| Error::Internal(anyhow::anyhow!("RUWA_MEDIA_BASE_DIR {base}: {e}")))?;
    let real = std::fs::canonicalize(p)
        .map_err(|_| Error::BadRequest(format!("file_path not found or unreadable: {p}")))?;
    if !real.starts_with(&base) {
        return Err(Error::BadRequest(
            "file_path is outside RUWA_MEDIA_BASE_DIR".into(),
        ));
    }
    Ok(())
}

async fn send_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendMediaReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    use crate::media::MediaType;
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    let kind = match req.kind.as_str() {
        "image" => MediaType::Image,
        "video" => MediaType::Video,
        "audio" => MediaType::Audio,
        "ptt" | "voice" => MediaType::Ptt,
        "document" => MediaType::Document,
        "sticker" => MediaType::Sticker,
        _ => return Err(Error::BadRequest(format!("unknown media type {}", req.kind))),
    };
    // Reject paths outside RUWA_MEDIA_BASE_DIR (when set) before touching disk.
    check_media_path(&req.file_path)?;
    // Verify the file is readable up-front so the API returns a clean
    // 400 instead of failing silently inside the send pump. Bytes
    // themselves are re-read by the pump (avoids a second copy in memory).
    if let Err(e) = std::fs::metadata(&req.file_path) {
        return Err(Error::BadRequest(format!(
            "cannot stat file_path {}: {e}",
            req.file_path
        )));
    }

    if session.kind() == SessionKind::Cloud {
        let bytes = std::fs::read(&req.file_path)
            .map_err(|e| Error::BadRequest(format!("cannot read file_path {}: {e}", req.file_path)))?;
        let upload_name = req.filename.clone().unwrap_or_else(|| {
            std::path::Path::new(&req.file_path)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "file".into())
        });
        return cloud_send_media(
            &state,
            &id,
            &session,
            CloudMediaSend {
                to: &req.to,
                kind: &req.kind,
                mime: &req.mime,
                caption: req.caption.as_deref(),
                filename: req.filename.as_deref(),
                upload_name: &upload_name,
                bytes,
                local_path: Some(&req.file_path),
            },
        )
        .await;
    }

    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session
        .meta
        .read()
        .jid
        .clone()
        .unwrap_or_else(|| "self".into());

    // Persist message row with media_path pointing at the source file
    // so GET /media can stream the original bytes back to the caller
    // immediately (the wire upload happens async in the pump).
    let payload = serde_json::json!({
        "type": req.kind,
        "mime": req.mime,
        "caption": req.caption,
        "filename": req.filename,
        "file_path": req.file_path,
    });
    state.manager.store.message_insert_media(
        &id,
        &chat_jid,
        &msg_id,
        &sender_jid,
        now,
        &req.kind,
        req.caption.as_deref(),
        &payload.to_string(),
        Some(&req.file_path),
    )?;
    offload_outbound_media(&state, &id, &chat_jid, &msg_id, &req.file_path, &req.mime);

    // Enqueue the live upload + send. The pump runs the mediaconn IQ +
    // upload + Signal encrypt + ship pipeline.
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::Media {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        kind,
        file_path: req.file_path.clone(),
        mime: req.mime.clone(),
        caption: req.caption.clone(),
        filename: req.filename.clone(),
        mentions: req.mentions.clone(),
        timestamp: now,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
}

/// Inputs of a cloud media send (shared by the JSON and multipart routes).
struct CloudMediaSend<'a> {
    to: &'a str,
    /// Public media type string (`image|video|audio|ptt|voice|document|sticker`).
    kind: &'a str,
    mime: &'a str,
    caption: Option<&'a str>,
    /// Display filename (documents).
    filename: Option<&'a str>,
    /// Filename used for the Graph multipart upload part.
    upload_name: &'a str,
    bytes: Vec<u8>,
    /// Local file the bytes came from (JSON route) — cached as the row's
    /// `media_path` so `GET …/media` streams it without a Graph round-trip.
    local_path: Option<&'a str>,
}

/// Cloud media send: upload the bytes to Graph (`POST /{pnid}/media`), send a
/// message referencing the returned media id, persist the row (`msg_type` =
/// the public kind, `payload_json` carries `media_id` + `mimetype` so the media
/// route can re-fetch it lazily).
async fn cloud_send_media(
    state: &AppState,
    id: &str,
    session: &Session,
    m: CloudMediaSend<'_>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    let kind = cloud_media_kind(m.kind)
        .ok_or_else(|| Error::BadRequest(format!("unknown media type {}", m.kind)))?;
    // Validate the recipient BEFORE spending an upload round-trip.
    cloud::check_recipient(m.to)?;
    let client = cloud_client(state, id, session)?;
    let media_id = client.upload_media(m.bytes, m.mime, m.upload_name).await?;
    let graph = cloud::media_payload(m.to, kind, &media_id, m.caption, m.filename, None);
    // Persist under the canonical kind (`voice` → `ptt`), like the web path.
    let msg_type = match kind {
        cloud::MediaKind::Ptt => "ptt",
        _ => kind.graph_type(),
    };
    let echo = json!({
        "type": msg_type,
        "mimetype": m.mime,
        "caption": m.caption,
        "filename": m.filename,
        "media_id": media_id,
        "file_path": m.local_path,
    });
    let sent = cloud_send_record(state, id, session, m.to, msg_type, m.caption, echo, graph).await?;
    if let Some(path) = m.local_path {
        state
            .manager
            .store
            .message_set_media_path(id, &sent.chat_jid, &sent.wamid, path)?;
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp { id: sent.wamid, timestamp: sent.timestamp, status: "sent" }),
    ))
}

/// Map a multipart extractor error to ours. axum reports the body-limit
/// overflow (see `RUWA_BODY_LIMIT_MB`) as a 413 `MultipartError`; surface it
/// as such instead of a generic 400 so clients can tell "too big" from
/// "malformed".
fn multipart_err(e: axum::extract::multipart::MultipartError) -> Error {
    if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
        Error::PayloadTooLarge(format!(
            "multipart body exceeds RUWA_BODY_LIMIT_MB ({} MB)",
            body_limit() / (1024 * 1024)
        ))
    } else {
        Error::BadRequest(format!("multipart parse: {e}"))
    }
}

/// Multipart variant of `POST /messages/media` for clients that can't
/// write files server-side. Form fields:
///   `file`     : the binary content (required)
///   `metadata` : JSON `{ "to":"...", "type":"image|video|audio|document|sticker",
///                        "mime":"...", "caption":"...", "filename":"..." }`
/// The handler streams the upload to a temp file under `data/uploads/<session>/`,
/// then enqueues a `SendOp::Media` against that path. The send pump
/// re-reads, encrypts, and ships exactly the same as the JSON variant.
async fn send_media_multipart(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    mut multipart: axum::extract::Multipart,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    use crate::media::MediaType;
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;

    let mut file_bytes: Option<Vec<u8>> = None;
    let mut meta_json: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(multipart_err)?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(multipart_err)?;
                file_bytes = Some(bytes.to_vec());
            }
            "metadata" => {
                let txt = field
                    .text()
                    .await
                    .map_err(|e| Error::BadRequest(format!("read metadata: {e}")))?;
                meta_json = Some(txt);
            }
            _ => {
                tracing::debug!(field=%name, "ignoring unknown multipart field");
            }
        }
    }

    let bytes =
        file_bytes.ok_or_else(|| Error::BadRequest("multipart: missing 'file' field".into()))?;
    let meta_str =
        meta_json.ok_or_else(|| Error::BadRequest("multipart: missing 'metadata' field".into()))?;
    #[derive(Deserialize)]
    struct MultipartMeta {
        to: String,
        #[serde(rename = "type")]
        kind: String,
        mime: String,
        #[serde(default)]
        caption: Option<String>,
        #[serde(default)]
        filename: Option<String>,
        #[serde(default)]
        mentions: Vec<String>,
    }
    let meta: MultipartMeta = serde_json::from_str(&meta_str)
        .map_err(|e| Error::BadRequest(format!("metadata JSON: {e}")))?;

    let kind = match meta.kind.as_str() {
        "image" => MediaType::Image,
        "video" => MediaType::Video,
        "audio" => MediaType::Audio,
        "ptt" | "voice" => MediaType::Ptt,
        "document" => MediaType::Document,
        "sticker" => MediaType::Sticker,
        _ => return Err(Error::BadRequest(format!("unknown media type {}", meta.kind))),
    };

    if session.kind() == SessionKind::Cloud {
        // Cloud: the bytes go to the provider's media upload. Also spool a local
        // copy and record it as the row's media_path, so `GET …/media` streams
        // it back directly — the provider's media-read API (Graph `GET /{id}`)
        // isn't reliably reachable (Kapso returns 401), so without this the
        // dashboard can't render an outbound image it just sent.
        let dir = std::path::PathBuf::from("data/uploads").join(&id);
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::Internal(anyhow::anyhow!("mkdir uploads: {e}")))?;
        let spool_path = dir.join(format!("{}.bin", generate_message_id()));
        std::fs::write(&spool_path, &bytes)
            .map_err(|e| Error::Internal(anyhow::anyhow!("spool: {e}")))?;
        let spool_path_str = spool_path.to_string_lossy().into_owned();
        let upload_name = meta.filename.clone().unwrap_or_else(|| "file".into());
        return cloud_send_media(
            &state,
            &id,
            &session,
            CloudMediaSend {
                to: &meta.to,
                kind: &meta.kind,
                mime: &meta.mime,
                caption: meta.caption.as_deref(),
                filename: meta.filename.as_deref(),
                upload_name: &upload_name,
                bytes,
                local_path: Some(&spool_path_str),
            },
        )
        .await;
    }

    // Spool to disk so the send pump (which re-reads in send_media_op)
    // doesn't have to keep the bytes in memory across the await tree.
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&meta.to);
    let msg_id = generate_message_id();
    let dir = std::path::PathBuf::from("data/uploads").join(&id);
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Internal(anyhow::anyhow!("mkdir uploads: {e}")))?;
    let spool_path = dir.join(format!("{msg_id}.bin"));
    std::fs::write(&spool_path, &bytes)
        .map_err(|e| Error::Internal(anyhow::anyhow!("spool: {e}")))?;
    let spool_path_str = spool_path.to_string_lossy().into_owned();

    let sender_jid = session
        .meta
        .read()
        .jid
        .clone()
        .unwrap_or_else(|| "self".into());
    let payload = serde_json::json!({
        "type": meta.kind,
        "mime": meta.mime,
        "caption": meta.caption,
        "filename": meta.filename,
        "file_path": spool_path_str,
    });
    state.manager.store.message_insert_media(
        &id,
        &chat_jid,
        &msg_id,
        &sender_jid,
        now,
        &meta.kind,
        meta.caption.as_deref(),
        &payload.to_string(),
        Some(&spool_path_str),
    )?;
    offload_outbound_media(&state, &id, &chat_jid, &msg_id, &spool_path_str, &meta.mime);

    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::Media {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        kind,
        file_path: spool_path_str,
        mime: meta.mime.clone(),
        caption: meta.caption.clone(),
        filename: meta.filename.clone(),
        mentions: meta.mentions.clone(),
        timestamp: now,
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
}

/// Best-effort durable copy of an OUTBOUND media file: when an S3 store is
/// configured, upload the plaintext now and point `media_path` at the object
/// URL, so `GET …/media` keeps working after the ephemeral spool file is gone
/// (a redeploy wipes `data/uploads`). Spawned off the request; failures are
/// logged and leave the local path in place (the WhatsApp-CDN re-download
/// fallback still covers it once the upload descriptor lands).
fn offload_outbound_media(state: &AppState, id: &str, chat: &str, msg_id: &str, path: &str, mime: &str) {
    let Some(s3) = state.media_store.clone() else { return };
    let store = Arc::clone(&state.manager.store);
    let (id, chat, msg_id, path, mime) =
        (id.to_string(), chat.to_string(), msg_id.to_string(), path.to_string(), mime.to_string());
    tokio::spawn(async move {
        let bytes = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(id = %msg_id, error = %e, "outbound media offload: read failed");
                return;
            }
        };
        let key = format!("{id}/{chat}/{msg_id}");
        match crate::media::put_object(&s3, &key, &bytes, &mime).await {
            Ok(object_url) => {
                let _ = store.message_set_media_path(&id, &chat, &msg_id, &object_url);
                tracing::info!(id = %msg_id, "outbound media offloaded to object store");
            }
            Err(e) => tracing::warn!(id = %msg_id, error = ?e, "outbound media offload failed"),
        }
    });
}

/// Stream the decrypted media bytes for a stored message. If `media_path`
/// is already populated (outbound message we sent, or a previous lazy
/// download), the file is streamed directly. For inbound messages where
/// the row carries url + media_key but no local copy, this triggers a
/// just-in-time download + decrypt + cache to a per-session media dir,
/// then streams. 404 only when neither path exists.
#[derive(Deserialize)]
struct MessageContextQuery {
    /// How many messages before/after the target to include (default 5, max 50).
    before: Option<u32>,
    after: Option<u32>,
}

/// GET /sessions/:id/messages/:chat/:msgid/context — the target message plus N
/// before and N after, in chronological order. Empty if the id isn't in the chat.
async fn get_message_context(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, chat, msgid)): Path<(String, String, String)>,
    axum::extract::Query(q): axum::extract::Query<MessageContextQuery>,
) -> Result<Json<Vec<crate::store::MessageListRow>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let before = q.before.unwrap_or(5).min(50);
    let after = q.after.unwrap_or(5).min(50);
    let rows = state
        .manager
        .store
        .message_context(&id, &chat, &msgid, before, after)?;
    Ok(Json(rows))
}

async fn get_message_media(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, chat, msgid)): Path<(String, String, String)>,
) -> Result<axum::response::Response> {
    use axum::http::header;
    use axum::response::IntoResponse;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;

    let row = state.manager.store.message_media_lookup(&id, &chat, &msgid)?;
    let (media_path, msg_type, payload_json) = row.ok_or_else(|| {
        Error::NotFound("no message with that id in this session/chat".into())
    })?;

    // Decoded payload (carries the original `mimetype`). Used to serve the right
    // Content-Type so the browser can render <img>/<audio>/<video> inline
    // instead of treating every blob as a download.
    let payload: serde_json::Value =
        serde_json::from_str(&payload_json).unwrap_or(serde_json::Value::Null);
    let content_type = media_content_type(&payload, &msg_type);

    if let Some(path) = media_path {
        // A remote URL (s3 offload) → redirect; a local path → stream the file.
        if is_remote_url(&path) {
            return Ok(axum::response::Redirect::temporary(&path).into_response());
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                return Ok(([(header::CONTENT_TYPE, content_type)], bytes).into_response());
            }
            // The local cache/spool is ephemeral (wiped on redeploy). Fall
            // through to a fresh download from WhatsApp's CDN when the row
            // carries the descriptor; only a row with no way to re-fetch is a
            // real miss (404 below, not a 500).
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(session = %id, id = %msgid, path = %path, "cached media file gone — re-downloading");
            }
            Err(e) => return Err(Error::Internal(anyhow::anyhow!("read: {e}"))),
        }
    }

    // Cloud: an inbound row carries `media_id` (Meta) and/or a ready `url`
    // (Kapso re-hosts inbound media and hands back `media_url`). Prefer the
    // ready URL — Meta's `GET /{media_id}` lookup isn't reliably proxied by
    // Kapso (401) — and only fall back to the id→media_info round-trip.
    if session.kind() == SessionKind::Cloud {
        let client = cloud_client(&state, &id, &session)?;
        let ready_url = payload
            .get("url")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let media_id = payload
            .get("media_id")
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let (bytes, content_type) = if let Some(u) = ready_url {
            match client.download(u).await {
                Ok(bytes) => (bytes, content_type),
                // A Kapso webhook can carry Meta's direct URL in `media_url`.
                // It is not readable with Kapso's project key, but the media-id
                // lookup returns Kapso's short-lived signed `download_url`.
                // Meta URLs can expire too, so this fallback is safe for both.
                Err(e) if media_id.is_some() => {
                    tracing::debug!(session = %id, id = %msgid, error = %e, "cloud ready media url failed; retrying via media id");
                    cloud_download_media_by_id(
                        &client,
                        media_id.expect("guarded above"),
                        &content_type,
                    )
                    .await?
                }
                Err(e) => return Err(e),
            }
        } else if let Some(mid) = media_id {
            cloud_download_media_by_id(&client, mid, &content_type).await?
        } else {
            return Err(Error::NotFound(
                "media not downloaded and neither url nor media_id present".into(),
            ));
        };
        return cache_media_and_respond(&state, &id, &chat, &msgid, bytes, &content_type).await;
    }

    // Lazy inbound download. Pull url+media_key out of payload_json,
    // map the media kind, fetch+decrypt, cache to disk, return bytes.
    let url = payload
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            Error::NotFound(
                "media bytes are no longer cached and the message carries no download url (sent before the upload descriptor was persisted)".into(),
            )
        })?;
    let media_key_b64 = payload
        .get("media_key_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::NotFound("media_key missing from payload".into()))?;
    let media_key_bytes = B64
        .decode(media_key_b64)
        .map_err(|e| Error::Internal(anyhow::anyhow!("decode media_key: {e}")))?;
    if media_key_bytes.len() != 32 {
        return Err(Error::Internal(anyhow::anyhow!(
            "media_key wrong length"
        )));
    }
    let mut media_key = [0u8; 32];
    media_key.copy_from_slice(&media_key_bytes);

    use crate::media::MediaType;
    let kind = match msg_type.as_str() {
        "image" => MediaType::Image,
        "video" => MediaType::Video,
        "audio" => MediaType::Audio,
        "ptt" | "voice" => MediaType::Ptt,
        "document" => MediaType::Document,
        "sticker" => MediaType::Sticker,
        other => {
            return Err(Error::BadRequest(format!(
                "stored msg_type '{other}' is not a media type"
            )));
        }
    };

    // Download via the session proxy (or direct if RUWA_PROXY_DOWNLOADS=0, to
    // save the metered proxy's bandwidth — CDN fetches work from any IP).
    let proxy = state.manager.get(&id)?.meta.read().proxy_url.clone();
    let blob = crate::media::download_encrypted(url, crate::session::download_proxy(proxy.as_deref()))
        .await
        .map_err(|e| Error::Internal(anyhow::anyhow!("download: {e:?}")))?;
    let plaintext = crate::media::decrypt(&blob, &media_key, kind)
        .map_err(|e| Error::Internal(anyhow::anyhow!("decrypt: {e:?}")))?;

    cache_media_and_respond(&state, &id, &chat, &msgid, plaintext, &content_type).await
}

/// Resolve a cloud media id to a fresh download URL, then fetch its bytes.
/// Kapso's lookup returns its short-lived signed URL, unlike Meta's direct URL
/// that may appear in a webhook payload.
async fn cloud_download_media_by_id(
    client: &cloud::CloudClient,
    media_id: &str,
    fallback_content_type: &str,
) -> Result<(Vec<u8>, String)> {
    let info = client.media_info(media_id).await?;
    let bytes = client.download(&info.url).await?;
    let content_type = info
        .mime_type
        .filter(|m| !m.trim().is_empty())
        .unwrap_or_else(|| fallback_content_type.to_string());
    Ok((bytes, content_type))
}

/// Cache freshly fetched media bytes and serve them. s3 mode: offload to the
/// bucket, persist the object URL as `media_path` (so the next GET redirects)
/// and redirect now. db mode (default): write `data/media/<session>/<msgid>`,
/// persist the path so the next call is a direct fs read, and stream the bytes.
async fn cache_media_and_respond(
    state: &AppState,
    id: &str,
    chat: &str,
    msgid: &str,
    plaintext: Vec<u8>,
    content_type: &str,
) -> Result<axum::response::Response> {
    use axum::http::header;
    if let Some(s3) = &state.media_store {
        let key = format!("{id}/{chat}/{msgid}");
        let object_url = crate::media::put_object(s3, &key, &plaintext, content_type)
            .await
            .map_err(|e| Error::Internal(anyhow::anyhow!("s3 upload: {e:?}")))?;
        state
            .manager
            .store
            .message_set_media_path(id, chat, msgid, &object_url)?;
        return Ok(axum::response::Redirect::temporary(&object_url).into_response());
    }

    let cache_dir = std::path::PathBuf::from("data/media").join(id);
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| Error::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    let cache_path = cache_dir.join(msgid);
    std::fs::write(&cache_path, &plaintext)
        .map_err(|e| Error::Internal(anyhow::anyhow!("write cache: {e}")))?;
    let cache_path_str = cache_path.to_string_lossy().into_owned();
    state
        .manager
        .store
        .message_set_media_path(id, chat, msgid, &cache_path_str)?;

    Ok((
        [(header::CONTENT_TYPE, content_type.to_string())],
        plaintext,
    )
        .into_response())
}

/// Whether a stored `media_path` is a remote URL (s3 offload) vs a local file.
fn is_remote_url(p: &str) -> bool {
    p.starts_with("http://") || p.starts_with("https://")
}

/// Best Content-Type for a stored media message: the original `mimetype` from
/// the decoded payload when present (it may carry codec params, e.g.
/// `audio/ogg; codecs=opus` — kept verbatim), else a sane default per msg_type
/// so the browser still renders the bubble inline.
fn media_content_type(payload: &serde_json::Value, msg_type: &str) -> String {
    if let Some(m) = payload
        .get("mimetype")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return m.to_string();
    }
    match msg_type {
        "image" => "image/jpeg",
        "video" => "video/mp4",
        "audio" | "ptt" | "voice" => "audio/ogg",
        "sticker" => "image/webp",
        _ => "application/octet-stream",
    }
    .to_string()
}

async fn stream_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<axum::response::sse::Sse<
    impl futures_util::Stream<Item = std::result::Result<axum::response::sse::Event, std::convert::Infallible>>,
>> {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use futures_util::stream::unfold;

    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    let rx = session.events.subscribe();

    // Pump SessionEvents → SSE Events. On Lagged we drop and continue;
    // on Closed we end the stream.
    let stream = unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    // Shared serializer (single source of truth with egress) —
                    // emits the bare, type-tagged event; SSE wire shape unchanged.
                    let json = crate::egress::event_to_sse_json(&ev);
                    return Some((Ok::<_, std::convert::Infallible>(Event::default().data(json)), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

// ===== Webhooks (egress kind = "webhook") ===================================

/// Set/replace a session's webhook. `events` is an allowlist of `SessionEvent`
/// type tags (`["message","message_sent",…]`); empty = deliver all. `secret`,
/// when set, signs each delivery (HMAC-SHA256, item A5).
#[derive(serde::Deserialize)]
struct WebhookConfigReq {
    /// Destination URL. Each event is POSTed here.
    url: String,
    /// Event-type allowlist; empty/omitted = all events.
    #[serde(default)]
    events: Vec<String>,
    /// HMAC signing secret (optional). Never echoed back.
    #[serde(default)]
    secret: Option<String>,
    /// Whether delivery is active. Defaults to true.
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Webhook config as returned by GET (the secret is redacted to `has_secret`).
#[derive(serde::Serialize)]
struct WebhookConfigResp {
    /// "" for the primary webhook (`/webhook`); otherwise the label of an
    /// additional webhook (`/webhooks/:label`).
    label: String,
    url: String,
    events: Vec<String>,
    enabled: bool,
    /// Whether a signing secret is configured (the value itself is never echoed).
    has_secret: bool,
    updated_at: i64,
}

/// A session's webhooks live in `egress_targets` under kind `"webhook"` (the
/// primary) and `"webhook:<label>"` (additional ones). These two helpers map
/// between a label and the stored `kind`, so the existing single-row store API
/// supports many webhooks per session with no schema change.
fn webhook_kind(label: &str) -> String {
    if label.is_empty() {
        "webhook".into()
    } else {
        format!("webhook:{label}")
    }
}
fn webhook_label_of(kind: &str) -> String {
    kind.strip_prefix("webhook:").unwrap_or("").to_string()
}
/// A webhook label must be 1–64 chars of `[A-Za-z0-9_-]` (it becomes part of the
/// `kind` discriminant and a URL path segment).
fn validate_webhook_label(label: &str) -> Result<()> {
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(Error::BadRequest(
            "label must be 1–64 chars of [A-Za-z0-9_-]".into(),
        ));
    }
    Ok(())
}

/// Build a `webhook`/`webhook:<label>` egress target from a request, validating
/// the URL. Shared by every webhook write endpoint (primary + labelled).
fn build_webhook_target(
    session_id: &str,
    label: &str,
    req: &WebhookConfigReq,
) -> Result<crate::store::EgressTarget> {
    let url = req.url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(Error::BadRequest("url must be an http(s) URL".into()));
    }
    let events_csv = if req.events.is_empty() {
        None
    } else {
        Some(req.events.join(","))
    };
    Ok(crate::store::EgressTarget {
        session_id: session_id.to_string(),
        kind: webhook_kind(label),
        enabled: req.enabled,
        events: events_csv,
        secret: req.secret.clone().filter(|s| !s.is_empty()),
        config: serde_json::json!({ "url": url }).to_string(),
        updated_at: chrono::Utc::now().timestamp(),
    })
}

/// Map a stored `webhook` egress target to the neutral response shape.
fn webhook_resp(t: &crate::store::EgressTarget) -> WebhookConfigResp {
    let url = serde_json::from_str::<serde_json::Value>(&t.config)
        .ok()
        .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(str::to_string))
        .unwrap_or_default();
    let events = t
        .events
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    WebhookConfigResp {
        label: webhook_label_of(&t.kind),
        url,
        events,
        enabled: t.enabled,
        has_secret: t.secret.is_some(),
        updated_at: t.updated_at,
    }
}

async fn set_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<WebhookConfigReq>,
) -> Result<Json<WebhookConfigResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    // Ensure the session exists (and 404 cleanly if not).
    let _ = state.manager.get(&id)?;
    let target = build_webhook_target(&id, "", &req)?;
    state.manager.store.egress_set(&target)?;
    Ok(Json(webhook_resp(&target)))
}

async fn get_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<WebhookConfigResp>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    match state.manager.store.egress_get(&id, "webhook")? {
        Some(t) => Ok(Json(webhook_resp(&t))),
        None => Err(Error::NotFound("no webhook configured".into())),
    }
}

async fn delete_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    check_session_auth_write(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    state.manager.store.egress_delete(&id, "webhook")?;
    Ok(StatusCode::NO_CONTENT)
}

// ----- Multiple webhooks per session (the primary above + N labelled) --------
//
// A session may register many webhook destinations. Each event fans out to all
// of them independently (see `egress::deliver_event`). The primary lives at
// `/webhook`; additional ones at `/webhooks/:label`. Listing returns both.

#[derive(serde::Deserialize)]
struct WebhookCreateReq {
    /// Unique label for this webhook within the session (1–64 of [A-Za-z0-9_-]).
    label: String,
    #[serde(flatten)]
    cfg: WebhookConfigReq,
}

/// GET /sessions/:id/webhooks — every webhook for the session (primary + labelled).
async fn list_webhooks(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<WebhookConfigResp>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let mut out: Vec<WebhookConfigResp> = state
        .manager
        .store
        .egress_list_for_session(&id)?
        .iter()
        .filter(|t| t.kind == "webhook" || t.kind.starts_with("webhook:"))
        .map(webhook_resp)
        .collect();
    // Primary first, then labelled in a stable order.
    out.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(Json(out))
}

/// POST /sessions/:id/webhooks — create/replace a labelled webhook.
async fn create_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<WebhookCreateReq>,
) -> Result<(StatusCode, Json<WebhookConfigResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    validate_webhook_label(&req.label)?;
    let target = build_webhook_target(&id, &req.label, &req.cfg)?;
    state.manager.store.egress_set(&target)?;
    Ok((StatusCode::CREATED, Json(webhook_resp(&target))))
}

/// GET /sessions/:id/webhooks/:label — one labelled webhook.
async fn get_webhook_labelled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, label)): Path<(String, String)>,
) -> Result<Json<WebhookConfigResp>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    validate_webhook_label(&label)?;
    match state.manager.store.egress_get(&id, &webhook_kind(&label))? {
        Some(t) => Ok(Json(webhook_resp(&t))),
        None => Err(Error::NotFound(format!("no webhook labelled '{label}'"))),
    }
}

/// PUT /sessions/:id/webhooks/:label — create/update one labelled webhook.
async fn set_webhook_labelled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, label)): Path<(String, String)>,
    Json(req): Json<WebhookConfigReq>,
) -> Result<Json<WebhookConfigResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    validate_webhook_label(&label)?;
    let target = build_webhook_target(&id, &label, &req)?;
    state.manager.store.egress_set(&target)?;
    Ok(Json(webhook_resp(&target)))
}

/// DELETE /sessions/:id/webhooks/:label — remove one labelled webhook.
async fn delete_webhook_labelled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, label)): Path<(String, String)>,
) -> Result<StatusCode> {
    check_session_auth_write(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    validate_webhook_label(&label)?;
    state
        .manager
        .store
        .egress_delete(&id, &webhook_kind(&label))?;
    Ok(StatusCode::NO_CONTENT)
}

// ===== Redis egress (egress kind = "redis") =================================

#[derive(serde::Deserialize)]
struct RedisEgressReq {
    /// `redis://[:password@]host:port[/db]`. Password (if any) is redacted on GET.
    url: String,
    /// Delivery mode: `"list"` (RPUSH, durable) or `"pubsub"` (PUBLISH, fan-out).
    #[serde(default = "default_redis_mode")]
    mode: String,
    /// List key (RPUSH) or channel name (PUBLISH).
    key: String,
    /// Event-type allowlist; empty/omitted = all.
    #[serde(default)]
    events: Vec<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_redis_mode() -> String {
    "list".into()
}

#[derive(serde::Serialize)]
struct RedisEgressResp {
    /// URL with any password replaced by `***`.
    url: String,
    mode: String,
    key: String,
    events: Vec<String>,
    enabled: bool,
    updated_at: i64,
}

/// Replace a redis URL's password with `***` for display.
fn redact_redis_url(url: &str) -> String {
    match url::Url::parse(url) {
        Ok(mut u) if u.password().is_some() => {
            let _ = u.set_password(Some("***"));
            u.to_string()
        }
        _ => url.to_string(),
    }
}

fn redis_resp(t: &crate::store::EgressTarget) -> RedisEgressResp {
    let v: serde_json::Value = serde_json::from_str(&t.config).unwrap_or_default();
    let url = v.get("url").and_then(|u| u.as_str()).unwrap_or_default();
    let mode = v.get("mode").and_then(|m| m.as_str()).unwrap_or("list").to_string();
    let key = v.get("key").and_then(|k| k.as_str()).unwrap_or_default().to_string();
    let events = t
        .events
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    RedisEgressResp {
        url: redact_redis_url(url),
        mode,
        key,
        events,
        enabled: t.enabled,
        updated_at: t.updated_at,
    }
}

async fn set_redis_egress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RedisEgressReq>,
) -> Result<Json<RedisEgressResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let parsed = url::Url::parse(req.url.trim())
        .map_err(|_| Error::BadRequest("url must be a valid redis:// URL".into()))?;
    if parsed.scheme() != "redis" && parsed.scheme() != "rediss" {
        return Err(Error::BadRequest("url scheme must be redis:// or rediss://".into()));
    }
    let mode = match req.mode.as_str() {
        "list" | "pubsub" => req.mode.as_str(),
        _ => return Err(Error::BadRequest("mode must be 'list' or 'pubsub'".into())),
    };
    if req.key.trim().is_empty() {
        return Err(Error::BadRequest("key (list/channel) must be non-empty".into()));
    }
    let events_csv = if req.events.is_empty() {
        None
    } else {
        Some(req.events.join(","))
    };
    let target = crate::store::EgressTarget {
        session_id: id.clone(),
        kind: "redis".into(),
        enabled: req.enabled,
        events: events_csv,
        secret: None,
        config: serde_json::json!({ "url": req.url.trim(), "mode": mode, "key": req.key.trim() })
            .to_string(),
        updated_at: chrono::Utc::now().timestamp(),
    };
    state.manager.store.egress_set(&target)?;
    Ok(Json(redis_resp(&target)))
}

async fn get_redis_egress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<RedisEgressResp>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    match state.manager.store.egress_get(&id, "redis")? {
        Some(t) => Ok(Json(redis_resp(&t))),
        None => Err(Error::NotFound("no redis egress configured".into())),
    }
}

async fn delete_redis_egress(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode> {
    check_session_auth_write(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    state.manager.store.egress_delete(&id, "redis")?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct ListContactsQuery {
    /// Optional case-insensitive substring over name/jid. Omitted = all.
    q: Option<String>,
}

async fn list_contacts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    axum::extract::Query(query): axum::extract::Query<ListContactsQuery>,
) -> Result<Json<Vec<crate::store::ContactRow>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let mut rows = state.manager.store.contacts_list(&id)?;
    if let Some(needle) = query.q.map(|s| s.to_lowercase()).filter(|s| !s.is_empty()) {
        let hit = |o: &Option<String>| {
            o.as_deref()
                .is_some_and(|s| s.to_lowercase().contains(&needle))
        };
        rows.retain(|c| {
            c.jid.to_lowercase().contains(&needle)
                || hit(&c.full_name)
                || hit(&c.push_name)
                || hit(&c.business_name)
        });
    }
    Ok(Json(rows))
}

async fn list_chats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::store::ChatRow>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let rows = state.manager.store.chats_list(&id)?;
    Ok(Json(rows))
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Vec<crate::store::GroupRow>>> {
    check_session_auth(&headers, &state, &id)?;
    let _ = state.manager.get(&id)?;
    let rows = state.manager.store.groups_list(&id)?;
    Ok(Json(rows))
}

#[derive(Deserialize)]
struct BackfillReq {
    chat: String,
    count: Option<u32>,
}

async fn backfill_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<BackfillReq>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "history backfill is not supported on cloud sessions")?;
    let count = req.count.unwrap_or(50).min(500);
    // Anchor the pull at the oldest message we already hold for this chat; the
    // phone resends `count` messages immediately before it. Without an anchor
    // there's nothing to request "before", so 404 the caller.
    let anchor = state
        .manager
        .store
        .message_oldest_for_chat(&id, &req.chat)
        .ok()
        .flatten();
    let Some((oldest_id, oldest_from_me, oldest_ts)) = anchor else {
        return Err(Error::NotFound(format!(
            "no stored messages for chat {} to anchor a history pull",
            req.chat
        )));
    };
    let _ = session.enqueue_send(SendOp::PeerHistoryRequest {
        chat: req.chat.clone(),
        oldest_id: oldest_id.clone(),
        oldest_from_me,
        oldest_ts,
        count,
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "status": "queued",
            "count": count,
            "anchor": { "oldest_id": oldest_id, "oldest_ts": oldest_ts },
        })),
    ))
}

#[derive(Deserialize)]
struct SetProfileReq {
    /// New display (push) name. Sent as a presence update.
    #[serde(default)]
    name: Option<String>,
    /// New "about"/status text.
    #[serde(default)]
    status: Option<String>,
    /// New profile picture as base64-encoded JPEG bytes.
    #[serde(default)]
    picture: Option<String>,
}

/// Update our own profile: any combination of display name, status text, and
/// picture. Requires a live connection (status/picture issue IQs). Returns the
/// set of fields that were applied.
async fn set_profile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SetProfileReq>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.name.is_none() && req.status.is_none() && req.picture.is_none() {
        return Err(Error::BadRequest(
            "provide at least one of name, status, picture".into(),
        ));
    }
    let session = state.manager.get(&id)?;
    require_web(&session, "profile updates are not supported on cloud sessions")?;
    let mut applied = Vec::new();

    if let Some(status) = req.status.as_deref() {
        let iq = crate::session::build_set_status_iq(&crate::session::uuid_v4(), status);
        let reply = session.iq_request(iq).await?;
        if crate::session::iq_is_error(&reply) {
            return Err(Error::Internal(anyhow::anyhow!("server rejected status update")));
        }
        applied.push("status");
    }

    if let Some(b64) = req.picture.as_deref() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let jpeg = B64
            .decode(b64.trim())
            .map_err(|_| Error::BadRequest("picture must be base64-encoded JPEG".into()))?;
        let own_jid = session
            .meta
            .read()
            .jid
            .clone()
            .ok_or_else(|| Error::BadRequest("session has no JID (not paired)".into()))?;
        let iq = crate::session::build_set_picture_iq(
            &crate::session::uuid_v4(),
            &own_jid,
            &jpeg,
        );
        let reply = session.iq_request(iq).await?;
        if crate::session::iq_is_error(&reply) {
            return Err(Error::Internal(anyhow::anyhow!("server rejected picture update")));
        }
        applied.push("picture");
    }

    if let Some(name) = req.name.as_deref() {
        // The push name is the source of truth for the `name` attr WA stamps on
        // every presence broadcast (reconnect, keepalive, mark-online). Persist
        // it first so later presence rebroadcasts don't revert to the old name —
        // then ship one presence update now so peers see the change immediately.
        state
            .manager
            .store
            .session_set_push_name(&id, name)
            .map_err(|e| Error::Internal(anyhow::anyhow!(e)))?;
        let node = crate::session::build_global_presence_node("available", Some(name));
        let _ = session.enqueue_send(SendOp::RawNode(node));
        applied.push("name");
    }

    Ok(Json(serde_json::json!({ "applied": applied })))
}

/// Block (or unblock) a contact via a blocklist IQ. Requires a live connection.
async fn set_block(state: &AppState, headers: &HeaderMap, id: &str, jid: &str, block: bool) -> Result<Json<serde_json::Value>> {
    check_session_auth_write(headers, state, id)?;
    let session = state.manager.get(id)?;
    require_web(&session, "block/unblock is not supported on cloud sessions")?;
    let target = normalize_recipient_jid(jid);
    let iq_id = crate::session::uuid_v4();
    let iq = crate::session::build_block_iq(&iq_id, &target, block);
    let reply = session.iq_request(iq).await?;
    if crate::session::iq_is_error(&reply) {
        return Err(Error::Internal(anyhow::anyhow!(
            "server rejected the blocklist update"
        )));
    }
    Ok(Json(serde_json::json!({ "jid": target, "blocked": block })))
}

async fn block_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, jid)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    set_block(&state, &headers, &id, &jid, true).await
}

async fn unblock_contact(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, jid)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    set_block(&state, &headers, &id, &jid, false).await
}

#[derive(Deserialize)]
struct PictureQuery {
    /// When true, fetch the small preview thumbnail instead of the full image.
    #[serde(default)]
    preview: bool,
}

/// Deadline for the profile-picture IQ. The server answers in well under a
/// second when it answers at all; a silent drop must surface fast (504), not
/// after the generic 30 s, because avatar consumers poll many contacts.
const PICTURE_IQ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Normalize + validate the `:jid` of a profile-picture lookup into the bare
/// form the `target` attribute wants: device/agent suffixes stripped, `c.us`
/// mapped to `s.whatsapp.net`, digits-only user (or `digits-digits` for
/// groups). Anything else is a 400 — a bogus target would otherwise be
/// silently dropped by the server and burn the whole timeout.
fn picture_target_jid(input: &str) -> Result<String> {
    let full = normalize_recipient_jid(input.trim());
    let (head, server) = full
        .rsplit_once('@')
        .ok_or_else(|| Error::BadRequest("invalid jid".into()))?;
    // Strip `:device` and `.agent` — the picture belongs to the account.
    let user = &head[..head.find([':', '.']).unwrap_or(head.len())];
    let server = match server {
        "c.us" => "s.whatsapp.net",
        s @ ("s.whatsapp.net" | "lid" | "g.us") => s,
        other => {
            return Err(Error::BadRequest(format!(
                "unsupported jid server '{other}' (expected s.whatsapp.net, lid or g.us)"
            )))
        }
    };
    let digits_or_dash = |c: char| c.is_ascii_digit() || (server == "g.us" && c == '-');
    if user.is_empty() || !user.chars().all(digits_or_dash) || user.len() > 32 {
        return Err(Error::BadRequest(format!("invalid jid user '{user}'")));
    }
    Ok(format!("{user}@{server}"))
}

/// Fetch a contact's (or group's) profile picture URL. Requires a live
/// connection. Returns `{ jid, url }`; `url` is null when there's no picture or
/// it's hidden from us. 400 for a malformed jid, 504 when WhatsApp doesn't
/// answer within [`PICTURE_IQ_TIMEOUT`].
async fn get_contact_picture(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, jid)): Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<PictureQuery>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth(&headers, &state, &id)?;
    let target = picture_target_jid(&jid)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "profile pictures are not supported on cloud sessions")?;
    // The peer's privacy token (if we hold a fresh one) — lets the query
    // through "my contacts"-style profile-photo privacy, like whatsmeow.
    let tctoken = crate::session::peer_tctoken_for_jid(&state.manager.store, &id, &target);
    let iq_id = crate::session::uuid_v4();
    let iq = crate::session::build_picture_iq(&iq_id, &target, q.preview, tctoken.as_deref());
    let reply = session.iq_request_timeout(iq, PICTURE_IQ_TIMEOUT).await?;
    let url = crate::session::parse_picture_response(&reply);
    Ok(Json(serde_json::json!({ "jid": target, "url": url })))
}

#[derive(Deserialize)]
struct OnWhatsAppReq {
    /// Phone numbers to check (E.164, with or without a leading `+`).
    numbers: Vec<String>,
}

/// Check which of the given numbers are registered on WhatsApp. Requires a live
/// connection (issues a usync IQ); returns `[{ query, jid, exists }]`.
async fn check_on_whatsapp(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<OnWhatsAppReq>,
) -> Result<Json<Vec<crate::session::OnWhatsAppResult>>> {
    check_session_auth(&headers, &state, &id)?;
    if req.numbers.is_empty() {
        return Err(Error::BadRequest("numbers must be non-empty".into()));
    }
    let session = state.manager.get(&id)?;
    require_web(&session, "onwhatsapp lookup is not supported on cloud sessions")?;
    let iq_id = crate::session::uuid_v4();
    let iq = crate::session::build_usync_contact_iq(&iq_id, &req.numbers);
    let reply = session.iq_request(iq).await?;
    Ok(Json(crate::session::parse_usync_contact_response(
        &reply,
        &req.numbers,
    )))
}

#[derive(Deserialize)]
struct PresenceReq {
    /// `"available"` or `"unavailable"`.
    state: String,
}

async fn set_presence(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<PresenceReq>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.state != "available" && req.state != "unavailable" {
        return Err(Error::BadRequest(
            "presence state must be 'available' or 'unavailable'".into(),
        ));
    }
    let session = state.manager.get(&id)?;
    require_web(&session, "presence is not supported on cloud sessions")?;
    // Server uses the push name to populate the contact card other peers
    // see; pulled from the persisted session row (pair-success populates).
    let push_name: Option<String> = state.manager.store.session_push_name(&id).ok().flatten();
    let node = crate::session::build_global_presence_node(&req.state, push_name.as_deref());
    let _ = session.enqueue_send(SendOp::RawNode(node));
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status": "queued"})),
    ))
}

#[derive(Deserialize)]
struct TypingReq {
    /// `"composing"` (typing) or `"paused"` (stopped).
    state: String,
}

/// WhatsApp only relays a `composing` indicator while the session is marked
/// `available`. So when the user starts typing on a session that's running
/// `unavailable` (the default), we announce `available` first. Not needed for
/// `paused`, nor when the session is already online.
fn typing_should_announce_available(state: &str, mark_online: bool) -> bool {
    state == "composing" && !mark_online
}

async fn set_typing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, chat)): Path<(String, String)>,
    Json(req): Json<TypingReq>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.state != "composing" && req.state != "paused" {
        return Err(Error::BadRequest(
            "typing state must be 'composing' or 'paused'".into(),
        ));
    }
    let session = state.manager.get(&id)?;
    let chat_jid = normalize_recipient_jid(&chat);
    if session.kind() == SessionKind::Cloud {
        // Cloud has no free-standing presence: the typing indicator rides on a
        // mark-as-read of the user's latest inbound message (and expires on
        // its own after ~25 s or when we reply), so `paused` is a no-op.
        if req.state != "composing" {
            return Ok((
                StatusCode::ACCEPTED,
                Json(serde_json::json!({"status": "ignored"})),
            ));
        }
        let cloud_chat = cloud::to_jid(&chat_jid);
        let target = state
            .manager
            .store
            .latest_inbound_message_id(&id, &cloud_chat)?
            .ok_or_else(|| {
                Error::BadRequest(
                    "no inbound message in this chat to attach a typing indicator to".into(),
                )
            })?;
        cloud_client(&state, &id, &session)?
            .mark_read(&target, true)
            .await?;
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status": "sent"})),
        ));
    }
    let own_jid = session
        .meta
        .read()
        .jid
        .clone()
        .ok_or_else(|| Error::BadRequest("not paired".into()))?;
    // WhatsApp only relays a typing indicator while we're marked `available`.
    // Sessions default to `unavailable` (to keep the phone notifying), so a bare
    // `composing` is silently dropped. When the user starts typing and the
    // session isn't already online, announce `available` first so it actually
    // shows. Side effect (the cost of appearing online): WhatsApp silences the
    // phone's notifications for this connection.
    let online = state.manager.store.session_mark_online(&id).unwrap_or(false);
    if typing_should_announce_available(&req.state, online) {
        let push_name: Option<String> = state.manager.store.session_push_name(&id).ok().flatten();
        let presence = crate::session::build_global_presence_node("available", push_name.as_deref());
        let _ = session.enqueue_send(SendOp::RawNode(presence));
    }
    let node = crate::session::build_chat_presence_node(&own_jid, &chat_jid, &req.state);
    let _ = session.enqueue_send(SendOp::RawNode(node));
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status": "queued"})),
    ))
}

#[derive(Deserialize)]
struct MarkReadReq {
    /// One or more message ids to ack as read.
    ids: Vec<String>,
    /// In group chats, the original sender's user JID (so the server
    /// routes the receipt to them). Omit / null in 1:1 chats.
    #[serde(default)]
    participant: Option<String>,
}

async fn mark_read(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, chat)): Path<(String, String)>,
    Json(req): Json<MarkReadReq>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.ids.is_empty() {
        return Err(Error::BadRequest("ids must be non-empty".into()));
    }
    let session = state.manager.get(&id)?;
    let chat_jid = normalize_recipient_jid(&chat);
    if session.kind() == SessionKind::Cloud {
        // Cloud: one Graph `{"status":"read","message_id":…}` per id.
        let client = cloud_client(&state, &id, &session)?;
        for mid in &req.ids {
            client.mark_read(mid, false).await?;
        }
        return Ok((
            StatusCode::ACCEPTED,
            Json(serde_json::json!({"status": "sent", "count": req.ids.len()})),
        ));
    }
    let now = chrono::Utc::now().timestamp();
    let id_refs: Vec<&str> = req.ids.iter().map(String::as_str).collect();
    let node = crate::session::build_read_receipt_node(
        &chat_jid,
        req.participant.as_deref(),
        &id_refs,
        now,
    );
    let _ = session.enqueue_send(SendOp::RawNode(node));
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status": "queued", "count": req.ids.len()})),
    ))
}

#[derive(Deserialize)]
struct ReactReq {
    /// Chat the target message lives in.
    to: String,
    /// Target message id.
    msg_id: String,
    /// True if the target was sent by us, false if by a peer/group member.
    #[serde(default)]
    from_me: bool,
    /// In groups, the user JID that sent the target message.
    #[serde(default)]
    participant: Option<String>,
    /// Emoji string. Empty string removes the previous reaction.
    emoji: String,
}

async fn send_reaction(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<ReactReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    if session.kind() == SessionKind::Cloud {
        let graph = cloud::reaction_payload(&req.to, &req.msg_id, &req.emoji);
        let echo = json!({ "type": "reaction", "message_id": req.msg_id, "emoji": req.emoji });
        let body = if req.emoji.is_empty() { None } else { Some(req.emoji.as_str()) };
        return cloud_dispatch(&state, &id, &session, &req.to, "reaction", body, echo, graph).await;
    }
    let chat_jid = normalize_recipient_jid(&req.to);
    let now = chrono::Utc::now().timestamp();
    let now_ms = now * 1000;
    let inner = crate::session::build_reaction_message(
        &chat_jid,
        &req.msg_id,
        req.from_me,
        req.participant.as_deref(),
        &req.emoji,
        now_ms,
    );
    let msg_id = generate_message_id();
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });
    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
}

#[derive(Deserialize)]
struct EditReq {
    to: String,
    msg_id: String,
    #[serde(default)]
    from_me: bool,
    #[serde(default)]
    participant: Option<String>,
    /// Replacement body.
    text: String,
}

/// How long after sending WhatsApp still accepts an edit. Past this the stanza
/// is ignored — the official app hides the "Edit" option once it lapses.
const EDIT_WINDOW_SECS: i64 = 15 * 60;

async fn send_edit(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<EditReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    if req.text.is_empty() {
        return Err(Error::BadRequest("text must be non-empty".into()));
    }
    let session = state.manager.get(&id)?;
    require_web(&session, "message edits are not supported on cloud sessions")?;
    let chat_jid = normalize_recipient_jid(&req.to);
    let now = chrono::Utc::now().timestamp();
    let now_ms = now * 1000;

    // Same deal as the revoke window, just far tighter: WhatsApp only accepts an
    // edit within 15 minutes of sending. Past that the stanza is ignored, so
    // refuse it rather than returning a 202 that reads as success.
    if let Ok(Some(ts)) = state.manager.store.message_timestamp(&id, &req.msg_id) {
        let age = now.saturating_sub(ts);
        if age > EDIT_WINDOW_SECS {
            return Err(Error::BadRequest(format!(
                "message is {} minutes old; WhatsApp only allows editing within \
                 {} minutes of sending",
                age / 60,
                EDIT_WINDOW_SECS / 60,
            )));
        }
    }

    let inner = crate::session::build_edit_message(
        &chat_jid,
        &req.msg_id,
        req.from_me,
        req.participant.as_deref(),
        &req.text,
        now_ms,
    );
    let msg_id = generate_message_id();
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });

    // Apply the new text to our own copy too. The peer's devices learn it from
    // the stanza; without this our chat keeps showing the text we just replaced
    // (the same gap the revoke path had).
    if let Ok(true) = state
        .manager
        .store
        .message_mark_edited(&id, &req.msg_id, Some(&req.text))
    {
        let _ = session.events.send(crate::session::SessionEvent::Message {
            id: msg_id.clone(),
            chat: chat_jid.clone(),
            from: chat_jid.clone(),
            body: serde_json::json!({
                "type": "edited",
                "text": req.text,
                "edits": req.msg_id,
                "from_me": true,
            }),
        });
    }

    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
}

#[derive(Deserialize)]
struct RevokeReq {
    to: String,
    msg_id: String,
    #[serde(default)]
    from_me: bool,
    #[serde(default)]
    participant: Option<String>,
}

/// How long after sending WhatsApp still honours a "delete for everyone".
/// Past this the server ignores the revoke and no client deletes anything — not
/// even the official app, which greys the option out. We reject up front instead
/// of queueing a stanza that provably does nothing.
const REVOKE_WINDOW_SECS: i64 = 60 * 60 * 60; // 2 days 12 hours

async fn send_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RevokeReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_web(&session, "message revokes are not supported on cloud sessions")?;
    let chat_jid = normalize_recipient_jid(&req.to);
    let now = chrono::Utc::now().timestamp();

    // Refuse a revoke WhatsApp will silently drop. Only when we actually have
    // the target row: if we don't know the message, we can't judge its age, so
    // let it through and let the server decide.
    if let Ok(Some(ts)) = state.manager.store.message_timestamp(&id, &req.msg_id) {
        let age = now.saturating_sub(ts);
        if age > REVOKE_WINDOW_SECS {
            return Err(crate::error::Error::BadRequest(format!(
                "message is {} hours old; WhatsApp only allows delete-for-everyone \
                 within {} hours of sending",
                age / 3600,
                REVOKE_WINDOW_SECS / 3600,
            )));
        }
    }

    let inner = crate::session::build_revoke_message(
        &chat_jid,
        &req.msg_id,
        req.from_me,
        req.participant.as_deref(),
    );
    let msg_id = generate_message_id();
    let _ = session.enqueue_send_persistent(&state.manager.store, &id, SendOp::EncryptedInner {
        chat_jid: chat_jid.clone(),
        msg_id: msg_id.clone(),
        inner_proto: inner,
        timestamp: now,
    });

    // Tombstone the target on our side too, so the chat stops showing a message
    // we just deleted for everyone. The peer's own devices learn it from the
    // stanza; our copy would otherwise sit there untouched forever.
    if let Ok(true) = state.manager.store.message_mark_revoked(&id, &req.msg_id) {
        let _ = session.events.send(crate::session::SessionEvent::Message {
            id: msg_id.clone(),
            chat: chat_jid.clone(),
            from: chat_jid.clone(),
            body: serde_json::json!({
                "type": "revoked",
                "revokes": req.msg_id,
                "from_me": true,
            }),
        });
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
}

// ===== Cloud API: templates, interactive messages, Meta webhook ============

/// Body of `POST /messages/template`: `to` + the neutral template spec (name,
/// language, body_params, header, buttons, components, reply_to).
#[derive(Deserialize)]
struct SendTemplateReq {
    /// Recipient — bare phone or `…@s.whatsapp.net` JID.
    to: String,
    #[serde(flatten)]
    tpl: cloud::TemplateSend,
}

/// Send an approved message template (the only way to open a conversation on
/// the Cloud API outside the 24 h customer-service window). Cloud only.
async fn send_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendTemplateReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, "template messages are only available on cloud sessions")?;
    if req.tpl.name.trim().is_empty() || req.tpl.language.trim().is_empty() {
        return Err(Error::BadRequest("template name and language are required".into()));
    }
    let graph = cloud::template_payload(&req.to, &req.tpl)?;
    let components = graph
        .get("template")
        .and_then(|t| t.get("components"))
        .cloned()
        .unwrap_or_else(|| json!([]));
    let echo = json!({
        "type": "template",
        "name": req.tpl.name,
        "language": req.tpl.language,
        "components": components,
    });
    let body_text = format!("<template:{}>", req.tpl.name);
    cloud_dispatch(&state, &id, &session, &req.to, "template", Some(&body_text), echo, graph).await
}

/// Body of `POST /messages/interactive`: `to` + the neutral interactive spec
/// (`type` ∈ button|list|cta_url, body, header, footer, buttons|button+sections|cta).
#[derive(Deserialize)]
struct SendInteractiveReq {
    to: String,
    #[serde(flatten)]
    msg: cloud::InteractiveSend,
}

/// Send an interactive message (reply buttons, list, or call-to-action URL).
/// Cloud only; the recipient's tap comes back as an inbound `interactive` message.
async fn send_interactive(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<SendInteractiveReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, "interactive messages are only available on cloud sessions")?;
    let graph = cloud::interactive_payload(&req.to, &req.msg)?;
    let m = &req.msg;
    // Neutral echo of the request (no Graph shape) for the stored row.
    let mut echo = serde_json::Map::new();
    echo.insert("type".into(), json!("interactive"));
    echo.insert("interactive_type".into(), json!(m.kind));
    echo.insert("body".into(), json!(m.body));
    if let Some(h) = &m.header {
        echo.insert("header".into(), json!(h));
    }
    if let Some(f) = &m.footer {
        echo.insert("footer".into(), json!(f));
    }
    if !m.buttons.is_empty() {
        echo.insert("buttons".into(), json!(m.buttons));
    }
    if let Some(b) = &m.button {
        echo.insert("button".into(), json!(b));
    }
    if !m.sections.is_empty() {
        echo.insert("sections".into(), json!(m.sections));
    }
    if let Some(c) = &m.cta {
        echo.insert("cta".into(), json!(c));
    }
    cloud_dispatch(
        &state,
        &id,
        &session,
        &req.to,
        "interactive",
        Some(&m.body),
        serde_json::Value::Object(echo),
        graph,
    )
    .await
}

#[derive(Deserialize)]
struct ListTemplatesQuery {
    /// Filter by review status (`APPROVED`, `PENDING`, `REJECTED`, …).
    status: Option<String>,
    limit: Option<u32>,
    /// Cursor from a previous page's `next`.
    after: Option<String>,
}

/// List the WABA's message templates → `{templates: [{id,name,language,status,
/// category,components}], next}`. Cloud only; needs `waba_id`.
async fn list_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ListTemplatesQuery>,
) -> Result<Json<cloud::TemplatePage>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, "message templates are only available on cloud sessions")?;
    let client = cloud_client(&state, &id, &session)?;
    let page = client
        .list_templates(q.status.as_deref(), q.limit, q.after.as_deref())
        .await?;
    Ok(Json(page))
}

/// Submit a new template for review: body `{name, language, category,
/// components, allow_category_change?}` → 201 `{id, status, category}`.
async fn create_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<serde_json::Value>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, "message templates are only available on cloud sessions")?;
    for key in ["name", "language", "category"] {
        if body.get(key).and_then(|v| v.as_str()).map(str::trim).filter(|s| !s.is_empty()).is_none() {
            return Err(Error::BadRequest(format!("template {key} is required")));
        }
    }
    if !body.get("components").is_some_and(|c| c.is_array()) {
        return Err(Error::BadRequest("template components must be an array".into()));
    }
    let client = cloud_client(&state, &id, &session)?;
    let created = client.create_template(body).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "id": created.get("id").cloned().unwrap_or(serde_json::Value::Null),
            "status": created.get("status").cloned().unwrap_or(serde_json::Value::Null),
            "category": created.get("category").cloned().unwrap_or(serde_json::Value::Null),
        })),
    ))
}

#[derive(Deserialize)]
struct DeleteTemplateQuery {
    /// Delete only this template id (one language) instead of every language
    /// of `name`.
    hsm_id: Option<String>,
}

/// Delete a template by name (all languages) or a single `hsm_id`.
async fn delete_template(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, name)): Path<(String, String)>,
    Query(q): Query<DeleteTemplateQuery>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, "message templates are only available on cloud sessions")?;
    let client = cloud_client(&state, &id, &session)?;
    client.delete_template(&name, q.hsm_id.as_deref()).await?;
    Ok(Json(json!({ "success": true })))
}

// ---------------------------------------------------------------------------
// Kapso Broadcasts (bulk-template campaigns) — pure proxy, kapso-only
// ---------------------------------------------------------------------------

/// Body of `POST /v1/sessions/:id/broadcasts`. Fields are optional at the serde
/// layer so a missing one is a clean 400 (not axum's 422) from the handler.
#[derive(Deserialize)]
struct CreateBroadcastReq {
    #[serde(default)]
    name: Option<String>,
    /// Meta template id (the `id` returned by `GET/POST /v1/sessions/:id/templates`).
    #[serde(default)]
    template_id: Option<String>,
}

/// Body of `POST /v1/sessions/:id/broadcasts/:bid/schedule`.
#[derive(Deserialize)]
struct ScheduleBroadcastReq {
    /// ISO-8601 instant in the future.
    #[serde(default)]
    scheduled_at: Option<String>,
}

/// Query for `GET /v1/sessions/:id/broadcasts`.
#[derive(Deserialize)]
struct ListBroadcastsQuery {
    status: Option<String>,
    page: Option<u32>,
    per_page: Option<u32>,
}

/// Query for `GET /v1/sessions/:id/broadcasts/:bid/recipients`.
#[derive(Deserialize)]
struct BroadcastPageQuery {
    page: Option<u32>,
    per_page: Option<u32>,
}

const BROADCASTS_NOT_CLOUD: &str = "broadcasts are only available on cloud sessions";

/// `GET /v1/sessions/:id/broadcasts` → `BroadcastList`.
async fn list_broadcasts_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ListBroadcastsQuery>,
) -> Result<Json<cloud::BroadcastList>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    let list = state
        .manager
        .broadcast_list(&id, q.status.as_deref(), q.page, q.per_page)
        .await?;
    Ok(Json(list))
}

/// `POST /v1/sessions/:id/broadcasts` → 201 `BroadcastView`.
async fn create_broadcast_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<CreateBroadcastReq>,
) -> Result<(StatusCode, Json<cloud::BroadcastView>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    let name = body.name.as_deref().unwrap_or_default().trim();
    let template_id = body.template_id.as_deref().unwrap_or_default().trim();
    if name.is_empty() {
        return Err(Error::BadRequest("broadcast name is required".into()));
    }
    if template_id.is_empty() {
        return Err(Error::BadRequest("broadcast template_id is required".into()));
    }
    let bc = state.manager.broadcast_create(&id, name, template_id).await?;
    Ok((StatusCode::CREATED, Json(bc)))
}

/// `GET /v1/sessions/:id/broadcasts/:bid` → `BroadcastView`.
async fn get_broadcast_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
) -> Result<Json<cloud::BroadcastView>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    Ok(Json(state.manager.broadcast_get(&id, &bid).await?))
}

/// Pull the recipient array out of `{recipients:[…]}` or a bare `[…]`; enforce
/// `1..=1000`.
fn extract_recipients(body: serde_json::Value) -> Result<serde_json::Value> {
    let arr = match body {
        serde_json::Value::Array(_) => body,
        serde_json::Value::Object(mut m) => m
            .remove("recipients")
            .ok_or_else(|| Error::BadRequest("recipients array is required".into()))?,
        _ => return Err(Error::BadRequest("recipients must be an array".into())),
    };
    let n = arr
        .as_array()
        .ok_or_else(|| Error::BadRequest("recipients must be an array".into()))?
        .len();
    if n == 0 {
        return Err(Error::BadRequest("recipients must not be empty".into()));
    }
    if n > 1000 {
        return Err(Error::BadRequest(
            "at most 1000 recipients per request".into(),
        ));
    }
    Ok(arr)
}

/// `POST /v1/sessions/:id/broadcasts/:bid/recipients` → 201 `AddRecipientsResult`.
async fn add_broadcast_recipients_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
    Json(body): Json<serde_json::Value>,
) -> Result<(StatusCode, Json<cloud::AddRecipientsResult>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    let recipients = extract_recipients(body)?;
    let res = state
        .manager
        .broadcast_add_recipients(&id, &bid, recipients)
        .await?;
    Ok((StatusCode::CREATED, Json(res)))
}

/// `DELETE /v1/sessions/:id/broadcasts/:bid/recipients` → `BroadcastView`.
async fn clear_broadcast_recipients_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
) -> Result<Json<cloud::BroadcastView>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    Ok(Json(
        state.manager.broadcast_clear_recipients(&id, &bid).await?,
    ))
}

/// `GET /v1/sessions/:id/broadcasts/:bid/recipients` → `BroadcastRecipientList`.
async fn list_broadcast_recipients_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
    Query(q): Query<BroadcastPageQuery>,
) -> Result<Json<cloud::BroadcastRecipientList>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    let list = state
        .manager
        .broadcast_list_recipients(&id, &bid, q.page, q.per_page)
        .await?;
    Ok(Json(list))
}

/// `POST /v1/sessions/:id/broadcasts/:bid/send` → 202 `BroadcastView`.
async fn send_broadcast_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
) -> Result<(StatusCode, Json<cloud::BroadcastView>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    let bc = state.manager.broadcast_send(&id, &bid).await?;
    Ok((StatusCode::ACCEPTED, Json(bc)))
}

/// `POST /v1/sessions/:id/broadcasts/:bid/schedule` → 202 `BroadcastView`.
async fn schedule_broadcast_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
    Json(body): Json<ScheduleBroadcastReq>,
) -> Result<(StatusCode, Json<cloud::BroadcastView>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    let scheduled_at = body.scheduled_at.as_deref().unwrap_or_default().trim();
    if scheduled_at.is_empty() {
        return Err(Error::BadRequest("scheduled_at is required".into()));
    }
    let bc = state
        .manager
        .broadcast_schedule(&id, &bid, scheduled_at)
        .await?;
    Ok((StatusCode::ACCEPTED, Json(bc)))
}

/// `POST /v1/sessions/:id/broadcasts/:bid/cancel` → `BroadcastView`.
async fn cancel_broadcast_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
) -> Result<Json<cloud::BroadcastView>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    Ok(Json(state.manager.broadcast_cancel(&id, &bid).await?))
}

/// `POST /v1/sessions/:id/broadcasts/:bid/stop` → `BroadcastView`.
async fn stop_broadcast_h(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, bid)): Path<(String, String)>,
) -> Result<Json<cloud::BroadcastView>> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    require_cloud(&session, BROADCASTS_NOT_CLOUD)?;
    Ok(Json(state.manager.broadcast_stop(&id, &bid).await?))
}

/// Query string of Meta's webhook subscription handshake.
#[derive(Deserialize)]
struct WebhookVerifyQuery {
    #[serde(rename = "hub.mode")]
    mode: Option<String>,
    #[serde(rename = "hub.verify_token")]
    verify_token: Option<String>,
    #[serde(rename = "hub.challenge")]
    challenge: Option<String>,
}

/// `GET /v1/cloud/webhook` — Meta's subscription verification. Echoes
/// `hub.challenge` as text/plain when `hub.verify_token` matches
/// `RUWA_CLOUD_VERIFY_TOKEN` (if set) or any cloud session's `verify_token`;
/// 403 otherwise. No bearer auth (Meta can't send one).
async fn cloud_webhook_verify(
    State(state): State<AppState>,
    Query(q): Query<WebhookVerifyQuery>,
) -> Result<axum::response::Response> {
    let token = q.verify_token.as_deref().map(str::trim).unwrap_or("");
    let challenge = q.challenge.clone().unwrap_or_default();
    let mode_ok = !matches!(q.mode.as_deref(), Some(m) if m != "subscribe");
    let env_token = std::env::var("RUWA_CLOUD_VERIFY_TOKEN")
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty());
    let matches = !token.is_empty()
        && mode_ok
        && match env_token {
            Some(expected) => constant_time_eq(expected.as_bytes(), token.as_bytes()),
            None => state.manager.store.cloud_verify_token_matches(token)?,
        };
    if !matches {
        return Err(Error::Forbidden("webhook verify token mismatch".into()));
    }
    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        challenge,
    )
        .into_response())
}

/// Constant-time byte comparison (verify-token check).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Whether unsigned webhook deliveries are accepted for sessions created
/// without an `app_secret` (`RUWA_CLOUD_ALLOW_UNSIGNED=1|true`). Off by default.
fn cloud_allow_unsigned() -> bool {
    std::env::var("RUWA_CLOUD_ALLOW_UNSIGNED")
        .map(|v| matches!(v.trim(), "1" | "true" | "yes"))
        .unwrap_or(false)
}

/// `POST /v1/cloud/webhook` — inbound Meta events. Authenticated by
/// `X-Hub-Signature-256` (HMAC-SHA256 of the RAW body under the app secret of
/// the cloud session that owns `metadata.phone_number_id`). The check runs
/// PER BATCH: every batch that maps to a session must verify under THAT
/// session's own secret before anything is ingested — a genuine Meta POST is
/// single-app so all its batches share one secret, while a forged body mixing
/// a tenant's own number with someone else's must not be able to piggy-back
/// on the caller's signature. Any mapped batch failing → 401, nothing stored.
/// Unknown phone number ids are acked (200) and ignored, and per-batch ingest
/// errors are logged, never surfaced — Meta retries (and eventually disables)
/// webhooks that don't 200. Credentials are read straight from the shared
/// store (a session created on another instance is still authenticated here).
async fn cloud_webhook_receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>> {
    let batches = cloud::parse_webhook(&body)?;
    let signature = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());

    // Verify every batch that maps to a session under that session's secret.
    let mut mapped = 0usize;
    for b in &batches {
        let Some(sid) = state
            .manager
            .store
            .cloud_session_id_by_phone_number_id(&b.phone_number_id)?
        else {
            continue;
        };
        mapped += 1;
        let creds = match state.manager.store.session_cloud_creds(&sid) {
            Ok(Some(c)) => c,
            Ok(None) => {
                tracing::warn!(session = %sid, "cloud webhook: session has no cloud creds row");
                return Err(Error::Unauthorized);
            }
            Err(e) => {
                tracing::warn!(session = %sid, error = %e, "cloud webhook: creds unreadable");
                return Err(Error::Unauthorized);
            }
        };
        match creds.app_secret.as_deref() {
            Some(secret) => {
                if !cloud::verify_signature(secret, &body, signature) {
                    tracing::warn!(session = %sid, "cloud webhook: X-Hub-Signature-256 mismatch");
                    return Err(Error::Unauthorized);
                }
            }
            None if cloud_allow_unsigned() => {
                tracing::debug!(session = %sid, "cloud webhook: accepted unsigned (RUWA_CLOUD_ALLOW_UNSIGNED)");
            }
            None => {
                tracing::warn!(
                    session = %sid,
                    "cloud webhook: session has no app_secret and RUWA_CLOUD_ALLOW_UNSIGNED is not set"
                );
                return Err(Error::Unauthorized);
            }
        }
    }
    if mapped == 0 {
        tracing::debug!(
            batches = batches.len(),
            "cloud webhook: no batch maps to a cloud session — acked and ignored"
        );
        return Ok(Json(json!({})));
    }

    for batch in batches {
        let pnid = batch.phone_number_id.clone();
        let display_number = batch.display_phone_number.clone().unwrap_or_default();
        if let Err(e) = state.manager.cloud_ingest(batch).await {
            match e {
                Error::NotFound(_) => {
                    tracing::debug!(
                        phone_number_id = %pnid,
                        display_phone_number = %display_number,
                        "cloud webhook: unknown phone_number_id ignored"
                    )
                }
                other => {
                    tracing::warn!(phone_number_id = %pnid, error = %other, "cloud webhook: ingest failed")
                }
            }
        }
    }
    Ok(Json(json!({})))
}

// ---------------------------------------------------------------------------
// Kapso webhooks — `GET|POST /v1/cloud/kapso/{webhook,project-webhook}`
// ---------------------------------------------------------------------------
//
// Distinct routes from the Meta `/v1/cloud/webhook` so the two envelope
// formats + verification schemes never mix in one handler. Like the Meta
// webhook, these carry no bearer auth (the handlers do not call `check_auth`);
// the message webhook is authenticated per-batch by `X-Webhook-Signature` under
// the session's per-number secret, the project webhook by
// `RUWA_KAPSO_PROJECT_WEBHOOK_SECRET`.

/// `GET /v1/cloud/kapso/{webhook,project-webhook}` — Kapso has no verification
/// handshake, so this just stays permissive: echoes `hub.challenge` if a prober
/// sends one, else `200 "ok"`.
async fn cloud_kapso_webhook_verify(
    Query(q): Query<WebhookVerifyQuery>,
) -> impl IntoResponse {
    let body = q
        .challenge
        .clone()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ok".to_string());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
}

/// `POST /v1/cloud/kapso/webhook` — inbound Kapso message events (native
/// envelope). Mirrors `cloud_webhook_receive`: resolve each batch's session by
/// `phone_number_id`, verify `X-Webhook-Signature` under that session's
/// per-number secret (`RUWA_CLOUD_ALLOW_UNSIGNED` for a secret-less session),
/// then hand the batches to the shared `cloud_ingest`. Any mapped batch failing
/// verification → 401, nothing stored; unmapped numbers are acked and ignored.
async fn cloud_kapso_webhook_receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>> {
    let batches = cloud::parse_kapso_webhook(&body)?;
    let signature = headers.get("x-webhook-signature").and_then(|v| v.to_str().ok());

    let mut mapped = 0usize;
    for b in &batches {
        let Some(sid) = state
            .manager
            .store
            .cloud_session_id_by_phone_number_id(&b.phone_number_id)?
        else {
            continue;
        };
        mapped += 1;
        let creds = match state.manager.store.session_cloud_creds(&sid) {
            Ok(Some(c)) => c,
            Ok(None) => {
                tracing::warn!(session = %sid, "kapso webhook: session has no cloud creds row");
                return Err(Error::Unauthorized);
            }
            Err(e) => {
                tracing::warn!(session = %sid, error = %e, "kapso webhook: creds unreadable");
                return Err(Error::Unauthorized);
            }
        };
        match creds.webhook_secret.as_deref() {
            Some(secret) => {
                if !cloud::verify_kapso_signature(secret, &body, signature) {
                    tracing::warn!(session = %sid, "kapso webhook: X-Webhook-Signature mismatch");
                    return Err(Error::Unauthorized);
                }
            }
            None if cloud_allow_unsigned() => {
                tracing::debug!(session = %sid, "kapso webhook: accepted unsigned (RUWA_CLOUD_ALLOW_UNSIGNED)");
            }
            None => {
                tracing::warn!(
                    session = %sid,
                    "kapso webhook: session has no webhook secret and RUWA_CLOUD_ALLOW_UNSIGNED is not set"
                );
                return Err(Error::Unauthorized);
            }
        }
    }
    if mapped == 0 {
        tracing::debug!(
            batches = batches.len(),
            "kapso webhook: no batch maps to a cloud session — acked and ignored"
        );
        return Ok(Json(json!({})));
    }

    for batch in batches {
        let pnid = batch.phone_number_id.clone();
        if let Err(e) = state.manager.cloud_ingest(batch).await {
            match e {
                Error::NotFound(_) => {
                    tracing::debug!(phone_number_id = %pnid, "kapso webhook: unknown phone_number_id ignored")
                }
                other => {
                    tracing::warn!(phone_number_id = %pnid, error = %other, "kapso webhook: ingest failed")
                }
            }
        }
    }
    Ok(Json(json!({})))
}

/// `POST /v1/cloud/kapso/project-webhook` — Kapso project-level lifecycle
/// events (`whatsapp.phone_number.*`). Verified against
/// `RUWA_KAPSO_PROJECT_WEBHOOK_SECRET` (or `RUWA_CLOUD_ALLOW_UNSIGNED` when that
/// is unset); on a good signature the event drives `kapso_onboarding_complete`.
/// Always 200 once authenticated — handler errors are logged, not surfaced.
async fn cloud_kapso_project_webhook_receive(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>> {
    let event_header = headers.get("x-webhook-event").and_then(|v| v.to_str().ok());
    let ev = cloud::parse_kapso_project_event(&body, event_header)?;
    let signature = headers.get("x-webhook-signature").and_then(|v| v.to_str().ok());
    let secret = std::env::var("RUWA_KAPSO_PROJECT_WEBHOOK_SECRET")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    match secret {
        Some(sec) => {
            if !cloud::verify_kapso_signature(&sec, &body, signature) {
                tracing::warn!("kapso project webhook: X-Webhook-Signature mismatch");
                return Err(Error::Unauthorized);
            }
        }
        None if cloud_allow_unsigned() => {
            tracing::debug!("kapso project webhook: accepted unsigned (RUWA_CLOUD_ALLOW_UNSIGNED)");
        }
        None => {
            tracing::warn!(
                "kapso project webhook: RUWA_KAPSO_PROJECT_WEBHOOK_SECRET unset and \
                 RUWA_CLOUD_ALLOW_UNSIGNED not set — refusing"
            );
            return Err(Error::Unauthorized);
        }
    }
    if let Err(e) = state.manager.kapso_onboarding_complete(&ev).await {
        tracing::warn!(event = %ev.event, error = %e, "kapso project webhook: handler failed");
    }
    Ok(Json(json!({})))
}

/// `POST /v1/sessions/:id/cloud/setup-link` — re-issue a kapso session's hosted
/// setup link. `501` on a non-kapso session, `409` once onboarded.
async fn regen_kapso_setup_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth_write(&headers, &state, &id)?;
    let url = state.manager.regenerate_kapso_setup_link(&id).await?;
    Ok(Json(json!({ "setup_link": url })))
}

// ---------------------------------------------------------------------------
// AI text assistant — `/v1/settings/ai*` + `/v1/ai/improve-text`
// ---------------------------------------------------------------------------
//
// Instance-wide (not per-session) and ADMIN-token only: the config carries a
// third-party API key and the rewrite endpoint spends the operator's money.
// The key is stored sealed (`app_settings['ai']`, see `store::setting_set`)
// and is never returned — `GET` exposes only a `••••abcd` hint. Provider calls
// live in `egress::ai`.

/// Load the stored assistant config, if any. A row that no longer parses
/// (schema drift) is reported as an internal error rather than silently
/// "unconfigured", so the operator notices.
fn ai_config_load(state: &AppState) -> Result<Option<AiConfig>> {
    match state.manager.store.setting_get(ai::SETTING_KEY)? {
        None => Ok(None),
        Some(raw) => serde_json::from_slice::<AiConfig>(&raw)
            .map(Some)
            .map_err(|e| Error::Internal(anyhow::anyhow!("stored ai settings unreadable: {e}"))),
    }
}

/// The `GET /v1/settings/ai` shape (also returned by `PUT`). Never the key.
fn ai_settings_view(cfg: Option<&AiConfig>) -> serde_json::Value {
    match cfg {
        None => json!({
            "configured": false,
            "provider": null,
            "model": null,
            "base_url": null,
            "system_prompt": null,
            "api_key_hint": null,
        }),
        Some(c) => json!({
            "configured": true,
            "provider": c.provider.as_str(),
            "model": c.model,
            "base_url": c.effective_base_url(),
            "system_prompt": c.system_prompt,
            "api_key_hint": c.api_key_hint(),
        }),
    }
}

/// `GET /v1/settings/ai` — admin only.
async fn get_ai_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    check_auth(&headers, &state.api_token)?;
    let cfg = ai_config_load(&state)?;
    Ok(Json(ai_settings_view(cfg.as_ref())))
}

/// Body of `PUT /v1/settings/ai`. `api_key` may be omitted (or blank) to keep
/// the stored key when the provider is unchanged; `base_url` /
/// `system_prompt` are full replacements (omitted or `null` → provider
/// default / built-in prompt).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PutAiSettingsReq {
    provider: ai::Provider,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    model: Option<String>,
    #[serde(default)]
    base_url: Option<String>,
    #[serde(default)]
    system_prompt: Option<String>,
}

/// Trim an optional string, mapping blank to `None`.
fn opt_trimmed(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Merge a `PUT` body with the currently stored config into the config to
/// persist. Pure (testable without the store): `Err` is a 400 message.
fn ai_settings_merge(
    req: PutAiSettingsReq,
    current: Option<&AiConfig>,
) -> std::result::Result<AiConfig, String> {
    let provider = req.provider;
    let api_key = match opt_trimmed(req.api_key) {
        Some(k) => {
            // The key travels in an HTTP header: reject anything that can't be
            // a header value up front (a pasted key with a stray newline would
            // otherwise fail every call with an opaque "builder error").
            if k.chars().any(|c| c.is_control() || c.is_whitespace()) {
                return Err("\"api_key\" must not contain whitespace or control characters".into());
            }
            k
        }
        None => match current {
            Some(c) if c.provider == provider => c.api_key.clone(),
            Some(_) => {
                return Err("\"api_key\" is required when changing provider".to_string())
            }
            None => return Err("\"api_key\" is required".to_string()),
        },
    };
    let model = match opt_trimmed(req.model).or_else(|| provider.default_model().map(str::to_string)) {
        Some(m) => m,
        None => {
            return Err(format!(
                "\"model\" is required for provider \"{}\"",
                provider.as_str()
            ))
        }
    };
    let base_url = opt_trimmed(req.base_url).map(|u| u.trim_end_matches('/').to_string());
    if let Some(u) = &base_url {
        if !(u.starts_with("http://") || u.starts_with("https://")) {
            return Err("\"base_url\" must start with http:// or https://".to_string());
        }
        // Must be a parseable absolute URL with a host (localhost / private
        // ranges are deliberately allowed: Ollama et al. are local, and only
        // the admin token can set this).
        match reqwest::Url::parse(u) {
            Ok(p) if p.host_str().is_some() && p.query().is_none() && p.fragment().is_none() => {}
            _ => return Err("\"base_url\" must be a valid http(s) URL without query or fragment".to_string()),
        }
    }
    let system_prompt = opt_trimmed(req.system_prompt);
    Ok(AiConfig {
        provider,
        api_key,
        model,
        base_url,
        system_prompt,
    })
}

/// `PUT /v1/settings/ai` — admin only, readonly-gated. Responds with the GET
/// shape (200).
async fn put_ai_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PutAiSettingsReq>,
) -> Result<impl IntoResponse> {
    check_auth_write(&headers, &state)?;
    let current = ai_config_load(&state)?;
    let cfg = ai_settings_merge(req, current.as_ref()).map_err(Error::BadRequest)?;
    let raw = serde_json::to_vec(&cfg)
        .map_err(|e| Error::Internal(anyhow::anyhow!("encode ai settings: {e}")))?;
    state
        .manager
        .store
        .setting_set(ai::SETTING_KEY, &raw, chrono::Utc::now().timestamp())?;
    tracing::info!(provider = cfg.provider.as_str(), model = %cfg.model, "ai settings updated");
    Ok(Json(ai_settings_view(Some(&cfg))))
}

/// `DELETE /v1/settings/ai` — admin only, readonly-gated. 204 (idempotent).
async fn delete_ai_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse> {
    check_auth_write(&headers, &state)?;
    state.manager.store.setting_delete(ai::SETTING_KEY)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Map a provider failure onto the HTTP surface: refusal → 422, everything
/// else → 502 `{"error": "ai upstream: …"}`. The key is never in the message.
fn ai_error_response(e: &ai::AiError) -> axum::response::Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::BAD_GATEWAY);
    (status, Json(json!({ "error": e.to_string() }))).into_response()
}

/// The 400 the rewrite/test routes answer when nothing is configured. Built
/// by hand (not `Error::BadRequest`) so the message is the exact, unprefixed
/// contract string the Console keys off.
fn ai_unconfigured_response() -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "error": "ai assistant not configured — set it via PUT /v1/settings/ai" })),
    )
        .into_response()
}

/// `POST /v1/settings/ai/test` — admin only. One tiny round-trip to the
/// configured provider; reports latency + the model's reply.
async fn test_ai_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<axum::response::Response> {
    check_auth(&headers, &state.api_token)?;
    let Some(cfg) = ai_config_load(&state)? else {
        return Ok(ai_unconfigured_response());
    };
    match ai::AiClient::new().test(&cfg).await {
        Ok(out) => Ok(Json(json!({
            "ok": true,
            "provider": cfg.provider.as_str(),
            "model": cfg.model,
            "latency_ms": out.latency_ms,
            "reply": out.reply,
        }))
        .into_response()),
        Err(e) => {
            tracing::warn!(provider = cfg.provider.as_str(), error = %e, "ai settings test failed");
            Ok(ai_error_response(&e))
        }
    }
}

/// Body of `POST /v1/ai/improve-text`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImproveTextReq {
    text: String,
    #[serde(default)]
    mode: AiMode,
    /// Target language for `mode=translate` (e.g. `"en"`, `"pt-BR"`).
    #[serde(default)]
    language: Option<String>,
    /// Free-form instruction for `mode=custom` (≤ 500 chars).
    #[serde(default)]
    instruction: Option<String>,
}

/// `POST /v1/ai/improve-text` — admin only. Rewrites a draft per `mode`.
/// 400 when unconfigured / bad input, 422 when the model declines, 502 on
/// upstream failure.
async fn ai_improve_text(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ImproveTextReq>,
) -> Result<axum::response::Response> {
    check_auth(&headers, &state.api_token)?;
    let Some(cfg) = ai_config_load(&state)? else {
        return Ok(ai_unconfigured_response());
    };
    let text = req.text.trim();
    if text.is_empty() {
        return Err(Error::BadRequest("\"text\" must not be empty".into()));
    }
    if text.chars().count() > ai::MAX_TEXT_CHARS {
        return Err(Error::BadRequest(format!(
            "\"text\" must be at most {} characters",
            ai::MAX_TEXT_CHARS
        )));
    }
    let outcome = ai::AiClient::new()
        .improve(
            &cfg,
            req.mode,
            req.language.as_deref(),
            req.instruction.as_deref(),
            text,
        )
        .await
        .map_err(Error::BadRequest)?;
    match outcome {
        Ok(rewritten) => Ok(Json(json!({
            "text": rewritten,
            "provider": cfg.provider.as_str(),
            "model": cfg.model,
        }))
        .into_response()),
        Err(e) => {
            tracing::warn!(provider = cfg.provider.as_str(), error = %e, "ai improve-text failed");
            Ok(ai_error_response(&e))
        }
    }
}

#[cfg(test)]
pub(crate) fn test_state() -> AppState {
    test_state_with_readonly(false)
}

#[cfg(test)]
pub(crate) fn test_state_with_readonly(readonly: bool) -> AppState {
    use crate::store::Store;
    let store = Arc::new(Store::open(":memory:").expect("in-memory store"));
    let manager = Arc::new(SessionManager::new(store));
    AppState {
        manager,
        api_token: Arc::new("test-token".to_string()),
        readonly,
        media_store: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tower::ServiceExt;

    /// The reported footgun: `POST /proxy {"url": "..."}` used to deserialize to
    /// `proxy = None` and silently clear the proxy (200, no-op). `deny_unknown_fields`
    /// turns a typo'd key into a loud deserialization error instead.
    #[test]
    fn proxy_body_rejects_unknown_field_no_silent_noop() {
        assert!(serde_json::from_str::<SetProxyReq>(r#"{"url":"socks5://x"}"#).is_err());
        assert!(serde_json::from_str::<SetProxyReq>(r#"{"proxy":"socks5://x"}"#).is_ok());
        // Explicit clear (null) still works.
        assert!(serde_json::from_str::<SetProxyReq>(r#"{"proxy":null}"#).is_ok());
        // The create path takes a proxy too — hardened the same way.
        assert!(serde_json::from_str::<CreateSessionReq>(r#"{"label":"x","url":"y"}"#).is_err());
        assert!(serde_json::from_str::<CreateSessionReq>(r#"{"label":"x","proxy":"y"}"#).is_ok());
    }

    /// Typing only reaches the peer while we're `available`. A `composing` on an
    /// offline (default) session must first announce `available`; a session
    /// that's already online, or a `paused`, must not.
    #[test]
    fn typing_announces_available_only_when_composing_and_offline() {
        assert!(typing_should_announce_available("composing", false));
        assert!(!typing_should_announce_available("composing", true)); // already online
        assert!(!typing_should_announce_available("paused", false)); // stop typing
        assert!(!typing_should_announce_available("paused", true));
    }

    #[test]
    fn proxy_info_parses_non_sensitive_fields_only() {
        let url = "http://user_country-br_city-riodejaneiro_session-abc123_lifetime-168h:SECRETPW@proxy.example.com:12321";
        let v = proxy_info_json(url);
        assert_eq!(v["scheme"], "http");
        assert_eq!(v["host"], "proxy.example.com");
        assert_eq!(v["port"], 12321);
        assert_eq!(v["has_auth"], true);
        assert_eq!(v["hints"]["country"], "br");
        assert_eq!(v["hints"]["city"], "riodejaneiro");
        assert_eq!(v["hints"]["lifetime"], "168h");
        assert_eq!(v["hints"]["session"], "<set>", "opaque session id must not be echoed");
        // No password anywhere in the output.
        assert!(!serde_json::to_string(&v).unwrap().contains("SECRETPW"));
        assert!(!serde_json::to_string(&v).unwrap().contains("abc123"));
    }

    #[test]
    fn mask_proxy_hides_credentials() {
        assert_eq!(
            mask_proxy("socks5://user:secret@1.2.3.4:1080"),
            "socks5://***@1.2.3.4:1080"
        );
        // No credentials → unchanged.
        assert_eq!(mask_proxy("http://10.0.0.1:8080"), "http://10.0.0.1:8080");
        // Garbage passes through (never panics).
        assert_eq!(mask_proxy("weird"), "weird");
    }

    async fn send(
        app: axum::Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut req = Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            req = req.header("authorization", format!("Bearer {t}"));
        }
        let req = match body {
            Some(b) => req
                .header("content-type", "application/json")
                .body(Body::from(b.to_string()))
                .unwrap(),
            None => req.body(Body::empty()).unwrap(),
        };
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, v)
    }

    #[tokio::test]
    async fn reject_call_guards_auth_session_and_offline() {
        let state = test_state();
        let app = router(state.clone());

        // No bearer → 401.
        let (status, _) = send(
            app.clone(), "POST", "/v1/sessions/nope/calls/CALL1/reject",
            None, Some(serde_json::json!({"peer": "5511900000000"})),
        ).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Unknown session → 404.
        let (status, _) = send(
            app.clone(), "POST", "/v1/sessions/nope/calls/CALL1/reject",
            Some("test-token"), Some(serde_json::json!({"peer": "5511900000000"})),
        ).await;
        assert_eq!(status, StatusCode::NOT_FOUND);

        // Real session but unpaired (no JID) → 400, before any send attempt.
        let sid = state.manager.create(None).unwrap().meta.read().id.clone();
        let (status, body) = send(
            app, "POST", &format!("/v1/sessions/{sid}/calls/CALL1/reject"),
            Some("test-token"), Some(serde_json::json!({"peer": "5511900000000"})),
        ).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "unpaired session: {body}");
    }

    #[tokio::test]
    async fn list_calls_reflects_pending_and_guards_auth() {
        let state = test_state();
        let sid = state.manager.create(None).unwrap().meta.read().id.clone();
        let app = router(state.clone());

        // No bearer → 401.
        let (status, _) =
            send(app.clone(), "GET", &format!("/v1/sessions/{sid}/calls"), None, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // Authed but nothing ringing → empty array.
        let (status, body) = send(
            app.clone(), "GET", &format!("/v1/sessions/{sid}/calls"), Some("test-token"), None,
        ).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!([]));

        // Stash a pending call directly, then it appears in the listing.
        let session = state.manager.get(&sid).unwrap();
        session.pending_call_insert(crate::call::ParsedOffer {
            call_id: "C9".into(),
            call_creator: "111@lid".into(),
            from: "111@lid".into(),
            is_video: false,
            audio_rates: vec![16000],
            enc: crate::call::OfferEnc { enc_type: "pkmsg".into(), version: 2, ciphertext: vec![1] },
            relay: None,
            mlow: false,
        });
        let (status, body) = send(
            app, "GET", &format!("/v1/sessions/{sid}/calls"), Some("test-token"), None,
        ).await;
        assert_eq!(status, StatusCode::OK);
        let arr = body.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["call_id"], "C9");
        assert_eq!(arr[0]["audio_rates"], serde_json::json!([16000]));
        // The callKey ciphertext must NOT leak into the listing.
        assert!(arr[0].get("enc").is_none());
    }

    #[tokio::test]
    async fn metrics_history_endpoint_serves_persisted_series() {
        let state = test_state();
        let now = chrono::Utc::now().timestamp();
        state
            .manager
            .store
            .metrics_sample_insert_batch(&[
                ("ruwa_messages_in_total", now - 60, 3.0),
                ("ruwa_messages_in_total", now, 7.0),
            ])
            .unwrap();
        let app = router(state);

        // Series listing (admin-authed) includes the inserted series.
        let (st, body) =
            send(app.clone(), "GET", "/v1/metrics/series", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(body
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "ruwa_messages_in_total"));

        // History is oldest-first within the window.
        let uri = format!(
            "/v1/metrics/history?name=ruwa_messages_in_total&since={}",
            now - 3_600
        );
        let (st, body) = send(app, "GET", &uri, Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        let pts = body["points"].as_array().unwrap();
        assert_eq!(pts.len(), 2);
        assert_eq!(pts[0]["value"], 3.0);
        assert_eq!(pts[1]["value"], 7.0);

        // No token → 401.
        let (st, _) = send(
            router(test_state()),
            "GET",
            "/v1/metrics/series",
            None,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn logs_endpoint_serves_persisted_ring_with_level_filter() {
        let state = test_state();
        state
            .manager
            .store
            .log_ring_insert_batch(&[
                (1_000, 2, "INFO", "ruwa::session", "connected"),
                (2_000, 3, "WARN", "ruwa::session", "lease lost"),
                (3_000, 4, "ERROR", "ruwa::store", "db write failed"),
            ])
            .unwrap();
        let app = router(state);

        // No filter → newest-first, all three.
        let (st, body) = send(app.clone(), "GET", "/v1/logs", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        let logs = body["logs"].as_array().unwrap();
        assert_eq!(logs.len(), 3);
        assert_eq!(logs[0]["message"], "db write failed");

        // Min-level warn drops the info line.
        let (st, body) = send(
            app.clone(),
            "GET",
            "/v1/logs?level=warn",
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["logs"].as_array().unwrap().len(), 2);

        // Unauthed → 401.
        let (st, _) = send(app, "GET", "/v1/logs", None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = to_bytes(resp.into_body(), 1024).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["version"], env!("CARGO_PKG_VERSION"));
    }

    #[tokio::test]
    async fn send_location_validates_and_queues() {
        let app = router(test_state());
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "loc"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let id = body["id"].as_str().unwrap().to_string();

        // Out-of-range latitude → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/location"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999999999", "latitude": 200.0, "longitude": 0.0})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Valid → 202 queued.
        let (st, resp) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/location"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999",
                "latitude": -23.55,
                "longitude": -46.63,
                "name": "Sé"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        assert_eq!(resp["status"], "queued");
        let mid = resp["id"].as_str().unwrap();

        // Shows in the message list as a location row.
        let (st, msgs) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/messages"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let row = msgs
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["message_id"] == mid)
            .expect("location message in list");
        assert_eq!(row["msg_type"], "location");
    }

    #[test]
    fn vcard_embeds_waid_digits_only() {
        let v = build_vcard("Bob", "+55 (11) 99999-9999");
        assert!(v.contains("FN:Bob"));
        assert!(v.contains("waid=5511999999999:"));
        assert!(v.starts_with("BEGIN:VCARD"));
        assert!(v.trim_end().ends_with("END:VCARD"));
    }

    #[tokio::test]
    async fn send_contact_builds_vcard_and_queues() {
        let app = router(test_state());
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "c"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let id = body["id"].as_str().unwrap().to_string();

        // Neither vcard nor phone → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/contact"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999999999", "display_name": "Alice"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // display_name + phone → 202, vcard built.
        let (st, resp) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/contact"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999",
                "display_name": "Alice",
                "phone": "+5511888888888"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        assert_eq!(resp["status"], "queued");
        let mid = resp["id"].as_str().unwrap();

        let (_st, msgs) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/messages"),
            Some("test-token"),
            None,
        )
        .await;
        let row = msgs
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["message_id"] == mid)
            .expect("contact message in list");
        assert_eq!(row["msg_type"], "contact");
    }

    #[tokio::test]
    async fn send_poll_validates_and_queues() {
        let app = router(test_state());
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "p"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let id = body["id"].as_str().unwrap().to_string();

        // Fewer than 2 options → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/poll"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999999999", "name": "Q", "options": ["only one"]})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // selectable_count > options → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/poll"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "name": "Q",
                "options": ["a", "b"], "selectable_count": 3
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Valid → 202.
        let (st, resp) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/poll"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999",
                "name": "Dinner?",
                "options": ["Pizza", "Sushi"]
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        let mid = resp["id"].as_str().unwrap();

        let (_st, msgs) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/messages"),
            Some("test-token"),
            None,
        )
        .await;
        let row = msgs
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["message_id"] == mid)
            .expect("poll message in list");
        assert_eq!(row["msg_type"], "poll");
        assert_eq!(row["poll"]["options"], serde_json::json!(["Pizza", "Sushi"]));
        assert_eq!(row["poll"]["votes"], serde_json::json!({}));

        // end_time in the past, a quiz answer that isn't an option, or an
        // unknown wire version → 400.
        for bad in [
            serde_json::json!({"to": "5511999999999", "name": "Q", "options": ["a", "b"], "end_time": 1000}),
            serde_json::json!({"to": "5511999999999", "name": "Q", "options": ["a", "b"], "quiz_answer": "z"}),
            serde_json::json!({"to": "5511999999999", "name": "Q", "options": ["a", "b"], "wire_version": "v9"}),
        ] {
            let (st, _) = send(
                app.clone(),
                "POST",
                &format!("/v1/sessions/{id}/messages/poll"),
                Some("test-token"),
                Some(bad),
            )
            .await;
            assert_eq!(st, StatusCode::BAD_REQUEST);
        }
    }

    #[tokio::test]
    async fn send_event_validates_and_queues() {
        let app = router(test_state());
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "ev"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let id = body["id"].as_str().unwrap().to_string();

        // Empty name → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/event"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999999999", "name": "  ", "start_time": 1000})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // end_time before start_time → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/event"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "name": "Corte",
                "start_time": 2000, "end_time": 1000
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Valid → 202.
        let (st, resp) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/event"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999",
                "name": "Corte às 14h",
                "description": "Acme Inc",
                "location": "Rua Augusta, 123",
                "start_time": 1_900_000_000,
                "end_time": 1_900_003_600
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        let mid = resp["id"].as_str().unwrap();

        let (_st, msgs) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/messages"),
            Some("test-token"),
            None,
        )
        .await;
        let row = msgs
            .as_array()
            .unwrap()
            .iter()
            .find(|m| m["message_id"] == mid)
            .expect("event message in list");
        assert_eq!(row["msg_type"], "event");
    }

    #[tokio::test]
    async fn onwhatsapp_validates_and_requires_connection() {
        let app = router(test_state());
        let (_st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "ow"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // Empty numbers → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/onwhatsapp"),
            Some("test-token"),
            Some(serde_json::json!({"numbers": []})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Not connected → 400 (no live socket for the IQ).
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/onwhatsapp"),
            Some("test-token"),
            Some(serde_json::json!({"numbers": ["5511999999999"]})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    /// Profile-picture lookup: malformed jids are a 400 before any IQ is
    /// attempted (a bogus `target` would be silently dropped by the server and
    /// burn the whole timeout), valid ones are normalized to the bare account
    /// jid, and an unconnected session answers 400 immediately.
    #[tokio::test]
    async fn contact_picture_validates_jid_and_fails_fast_when_offline() {
        assert_eq!(picture_target_jid("5511999999999").unwrap(), "5511999999999@s.whatsapp.net");
        assert_eq!(picture_target_jid("5511999999999@c.us").unwrap(), "5511999999999@s.whatsapp.net");
        // Device / agent suffixes are stripped — the picture belongs to the account.
        assert_eq!(picture_target_jid("550000000002:1@s.whatsapp.net").unwrap(), "550000000002@s.whatsapp.net");
        assert_eq!(picture_target_jid("64000000000001.1@lid").unwrap(), "64000000000001@lid");
        assert_eq!(picture_target_jid("120363001234-5678@g.us").unwrap(), "120363001234-5678@g.us");
        for bad in ["abc", "foo@bar.com", "@s.whatsapp.net", "55 11@s.whatsapp.net", "x-y@s.whatsapp.net"] {
            assert!(
                matches!(picture_target_jid(bad), Err(Error::BadRequest(_))),
                "{bad} must be rejected"
            );
        }

        let app = router(test_state());
        let (_st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "pic"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        let started = std::time::Instant::now();
        let (st, body) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/contacts/not-a-jid/picture?preview=true"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");

        // Valid jid, no live socket → 400 right away, no timeout.
        let (st, body) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/contacts/5511999999999/picture"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
    }

    #[tokio::test]
    async fn set_profile_rejects_empty_and_bad_base64() {
        let app = router(test_state());
        let (_st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "pr"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // No fields → 400.
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/profile"),
            Some("test-token"),
            Some(serde_json::json!({})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Bad base64 picture → 400 (caught before needing a connection).
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/profile"),
            Some("test-token"),
            Some(serde_json::json!({"picture": "not!!base64"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // status-only with no connection → 400 (no live socket for the IQ).
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/profile"),
            Some("test-token"),
            Some(serde_json::json!({"status": "hi"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    /// Renaming the account (display name) must persist `push_name` so later
    /// presence rebroadcasts carry the new name instead of reverting. The name
    /// branch only enqueues a presence node (no IQ), so it succeeds offline.
    #[tokio::test]
    async fn set_profile_name_persists_push_name() {
        let state = test_state();
        let app = router(state.clone());
        let (_st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "pn"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        let (st, out) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/profile"),
            Some("test-token"),
            Some(serde_json::json!({"name": "New Name"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(out["applied"], serde_json::json!(["name"]));
        assert_eq!(
            state.manager.store.session_push_name(&id).unwrap().as_deref(),
            Some("New Name"),
        );
    }

    /// Renaming an instance persists the new label and surfaces it on GET.
    /// A blank label clears it back to null.
    #[tokio::test]
    async fn set_label_renames_instance() {
        let app = router(test_state());
        let (_st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "old"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // Rename → 200, label reflected in the response.
        let (st, out) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/label"),
            Some("test-token"),
            Some(serde_json::json!({"label": "  New Name  "})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(out["label"], "New Name"); // trimmed

        // Persisted: GET returns the new label.
        let (_st, got) = send(app.clone(), "GET", &format!("/v1/sessions/{id}"), Some("test-token"), None).await;
        assert_eq!(got["label"], "New Name");

        // Blank clears it to null.
        let (st, out) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/label"),
            Some("test-token"),
            Some(serde_json::json!({"label": "   "})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(out["label"].is_null());

        // Typo'd key is rejected (deny_unknown_fields → 422), not a silent no-op.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/label"),
            Some("test-token"),
            Some(serde_json::json!({"name": "x"})),
        )
        .await;
        assert!(st.is_client_error(), "unknown field must be rejected, got {st}");
    }

    /// `POST /reconnect` on a live (Connected) session returns 202 and echoes the
    /// session — the real-bounce path (request_reconnect), distinct from `/connect`
    /// which would no-op. We pre-set Connected so the handler takes the in-place
    /// bounce branch instead of spawning a real WhatsApp connection.
    #[tokio::test]
    async fn reconnect_route_accepts_live_session() {
        let state = test_state();
        let id = state.manager.create(None).unwrap().meta.read().id.clone();
        state
            .manager
            .get(&id)
            .unwrap()
            .set_status(crate::session::SessionStatus::Connected);
        let app = router(state);

        let (st, body) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/reconnect"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        assert_eq!(body["id"], id);
    }

    #[tokio::test]
    async fn redis_egress_round_trip_redacts_password() {
        let app = router(test_state());
        let (_st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "rd"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // None yet → 404.
        let (st, _) = send(app.clone(), "GET", &format!("/v1/sessions/{id}/egress/redis"), Some("test-token"), None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Bad scheme → 400.
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/egress/redis"),
            Some("test-token"),
            Some(serde_json::json!({"url": "http://x", "key": "k"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Set with a password in the URL.
        let (st, set) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/egress/redis"),
            Some("test-token"),
            Some(serde_json::json!({
                "url": "redis://:hunter2@redis:6379",
                "mode": "pubsub",
                "key": "wa",
                "events": ["message"]
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(set["mode"], "pubsub");
        assert_eq!(set["key"], "wa");
        // Password redacted on the way out.
        assert_eq!(set["url"], "redis://:***@redis:6379");
        assert!(!set["url"].as_str().unwrap().contains("hunter2"));

        // GET still redacted.
        let (st, got) = send(app.clone(), "GET", &format!("/v1/sessions/{id}/egress/redis"), Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(got["url"], "redis://:***@redis:6379");

        // DELETE → 204 then 404.
        let (st, _) = send(app.clone(), "DELETE", &format!("/v1/sessions/{id}/egress/redis"), Some("test-token"), None).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, _) = send(app.clone(), "GET", &format!("/v1/sessions/{id}/egress/redis"), Some("test-token"), None).await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[test]
    fn is_remote_url_distinguishes_s3_from_local() {
        assert!(is_remote_url("https://minio:9000/wa/a/b"));
        assert!(is_remote_url("http://cdn.example.com/x"));
        assert!(!is_remote_url("data/media/sess/m1"));
        assert!(!is_remote_url("/var/lib/ruwa/m1"));
    }

    #[tokio::test]
    async fn webhook_config_round_trip() {
        let app = router(test_state());

        // Seed a session.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "wh"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let id = body["id"].as_str().unwrap().to_string();

        // No webhook yet → 404.
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Non-http URL → 400.
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            Some(serde_json::json!({"url": "ftp://nope"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Set a webhook with a secret + event filter.
        let (st, set) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            Some(serde_json::json!({
                "url": "https://example.test/hook",
                "events": ["message", "message_sent"],
                "secret": "shh",
            })),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(set["url"], "https://example.test/hook");
        assert_eq!(set["events"], serde_json::json!(["message", "message_sent"]));
        assert_eq!(set["enabled"], true);
        // Secret is redacted — only its presence is reported.
        assert_eq!(set["has_secret"], true);
        assert!(set.get("secret").is_none());

        // GET reflects it (still redacted).
        let (st, got) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(got["url"], "https://example.test/hook");
        assert_eq!(got["has_secret"], true);

        // Unauthorized without a token.
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhook"),
            None,
            None,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // DELETE → 204, then GET → 404 again.
        let (st, _) = send(
            app.clone(),
            "DELETE",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn multiple_webhooks_round_trip() {
        let app = router(test_state());
        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "wh"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // Primary webhook via the singular endpoint (label "").
        let (st, p) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            Some(serde_json::json!({"url": "https://example.test/primary"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(p["label"], "");

        // Two additional, labelled webhooks.
        let (st, a) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/webhooks"),
            Some("test-token"),
            Some(serde_json::json!({"label": "alerts", "url": "https://example.test/a"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(a["label"], "alerts");
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/webhooks"),
            Some("test-token"),
            Some(serde_json::json!({
                "label": "crm", "url": "https://example.test/b", "events": ["message"]
            })),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);

        // Invalid label → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/webhooks"),
            Some("test-token"),
            Some(serde_json::json!({"label": "no spaces!", "url": "https://example.test/x"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // List = primary + the two labelled (3 total).
        let (st, list) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhooks"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        let labels: Vec<&str> = arr.iter().map(|w| w["label"].as_str().unwrap()).collect();
        assert!(labels.contains(&"") && labels.contains(&"alerts") && labels.contains(&"crm"));

        // Get one, then delete it → list drops to 2, and it 404s.
        let (st, got) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhooks/alerts"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(got["url"], "https://example.test/a");

        let (st, _) = send(
            app.clone(),
            "DELETE",
            &format!("/v1/sessions/{id}/webhooks/alerts"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        let (st, list) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhooks"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(list.as_array().unwrap().len(), 2);

        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhooks/alerts"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // The primary singular endpoint is unaffected by the labelled ones.
        let (st, prim) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/webhook"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(prim["url"], "https://example.test/primary");
    }

    #[tokio::test]
    async fn sessions_crud_round_trip() {
        let state = test_state();
        let app = router(state);

        // POST /v1/sessions creates.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone-a"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(body["label"], "phone-a");
        assert_eq!(body["status"], "pending");
        let id = body["id"].as_str().unwrap().to_string();

        // GET /v1/sessions lists.
        let (st, list) = send(app.clone(), "GET", "/v1/sessions", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        let arr = list.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["id"], id);

        // GET /v1/sessions/:id.
        let (st, one) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(one["id"], id);

        // DELETE without confirmation is a 400 footgun guard.
        let (st, _) = send(
            app.clone(),
            "DELETE",
            &format!("/v1/sessions/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // DELETE /v1/sessions/:id with ?force=1 succeeds.
        let (st, _) = send(
            app.clone(),
            "DELETE",
            &format!("/v1/sessions/{id}?force=1"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);

        // GET /v1/sessions now empty.
        let (_, list) = send(app, "GET", "/v1/sessions", Some("test-token"), None).await;
        assert_eq!(list.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn auth_rejects_missing_and_wrong_token() {
        let app = router(test_state());

        let (st, _) = send(app.clone(), "GET", "/v1/sessions", None, None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        let (st, _) = send(app.clone(), "GET", "/v1/sessions", Some("wrong"), None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // /health stays unauthenticated.
        let (st, _) = send(app, "GET", "/health", None, None).await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn per_tenant_api_key_scopes_session_routes() {
        let app = router(test_state());

        // Create returns the per-tenant key exactly once.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "tenant"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let id = body["id"].as_str().unwrap().to_string();
        let key = body["api_key"].as_str().expect("create returns api_key").to_string();
        assert!(!key.is_empty());

        // The session's own key authorizes its own routes.
        let (st, one) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(one["id"], id);
        // The key is returned ONCE — never echoed by a subsequent GET.
        assert!(one.get("api_key").is_none(), "api_key must not be echoed by GET");

        // A wrong token is rejected.
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}"),
            Some("nope"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // A per-session key is scoped: it cannot list/create across tenants.
        let (st, _) = send(app.clone(), "GET", "/v1/sessions", Some(&key), None).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // The key of session A does not unlock a different session B.
        let (_, b) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "other"})),
        )
        .await;
        let other_id = b["id"].as_str().unwrap().to_string();
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{other_id}"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // The global admin token still works on every session.
        let (st, _) = send(
            app,
            "GET",
            &format!("/v1/sessions/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
    }

    #[tokio::test]
    async fn footgun_guards_require_confirmation_on_logout_and_delete() {
        let app = router(test_state());
        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "guarded"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // logout without confirmation → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/logout"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // logout with body {"confirm":true} → ok.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/logout"),
            Some("test-token"),
            Some(serde_json::json!({"confirm": true})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // delete without confirmation → 400; with ?force=1 → 204.
        let (st, _) = send(
            app.clone(),
            "DELETE",
            &format!("/v1/sessions/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        let (st, _) = send(
            app,
            "DELETE",
            &format!("/v1/sessions/{id}?force=1"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT);
    }

    /// POST /v1/sessions/:id/connect synchronously transitions status to
    /// `connecting` and returns 202; the spawned task then races to do the
    /// actual WS work (and gets aborted when the test runtime is dropped).
    #[tokio::test]
    async fn connect_starts_background_task_and_returns_202() {
        let state = test_state();
        let app = router(state);

        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();
        assert_eq!(body["status"], "pending");

        let (st, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/connect"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        // Synchronously, before the task touches WS, status is "connecting".
        // The task may race ahead to "disconnected" if connect_wa fails fast;
        // either way it's no longer "pending".
        let status = body["status"].as_str().unwrap();
        assert_ne!(status, "pending", "expected status to advance, got {status}");
    }

    /// QR endpoint returns 404 when no codes are stashed yet, and a JSON body
    /// with `qr` (the canonical "<ref>,<noise>,<ident>,<adv>" string) plus
    /// `svg_base64` (a base64-encoded SVG QR rendering) once codes are set.
    #[tokio::test]
    async fn qr_endpoint_returns_404_then_qr_after_population() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

        let state = test_state();
        let app = router(state.clone());

        // Create session.
        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // No QR yet → 404.
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}/qr"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);

        // Inject canned QR codes (simulates what the connection task does on
        // pair-device IQ).
        let canned = "ABC123,bm9pc2U=,aWRlbnRpdHk=,YWR2c2VjcmV0".to_string();
        state.manager.get(&id).unwrap().set_qr_codes(vec![canned.clone()]);

        let (st, body) = send(
            app,
            "GET",
            &format!("/v1/sessions/{id}/qr"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["qr"], canned);
        let svg_b64 = body["svg_base64"].as_str().unwrap();
        let svg = String::from_utf8(B64.decode(svg_b64).unwrap()).unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
        assert!(svg.contains("svg"));
    }

    /// POST /v1/sessions/:id/messages with `{to, text}` accepts the request,
    /// returns 202 with `{id, timestamp, status="queued"}`, and persists a
    /// row to `messages` with from_me=1, msg_type=text, body_text=<text>.
    /// Live wire-send is M3 follow-up.
    #[tokio::test]
    async fn send_text_persists_and_returns_queued() {
        let state = test_state();
        let app = router(state.clone());

        // Create session, then send.
        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone"})),
        )
        .await;
        let session_id = body["id"].as_str().unwrap().to_string();

        let (st, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{session_id}/messages"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999",
                "text": "hello world"
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "queued");
        let msg_id = body["id"].as_str().unwrap().to_string();
        assert_eq!(msg_id.len(), 32, "16-byte hex == 32 chars");
        assert!(body["timestamp"].as_i64().unwrap() > 0);

        // Persisted row matches.
        state
            .manager
            .store
            .with_conn(|conn| {
                let (chat, body_text, from_me, msg_type): (String, String, i64, String) = conn
                    .query_row(
                        "SELECT chat_jid, body_text, from_me, msg_type \
                         FROM messages WHERE session_id = ? AND message_id = ?",
                        rusqlite::params![session_id, msg_id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )?;
                assert_eq!(chat, "5511999999999@s.whatsapp.net"); // bare phone normalized
                assert_eq!(body_text, "hello world");
                assert_eq!(from_me, 1);
                assert_eq!(msg_type, "text");
                Ok(())
            })
            .unwrap();
    }

    /// Editing applies the new text to our own copy (otherwise the chat keeps
    /// showing the text we just replaced), and a message past WhatsApp's 15-minute
    /// edit window is refused instead of queueing a stanza the server ignores.
    #[tokio::test]
    async fn edit_applies_to_own_row_and_rejects_stale_targets() {
        let state = test_state();
        let app = router(state.clone());

        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone"})),
        )
        .await;
        let sid = body["id"].as_str().unwrap().to_string();

        let (_, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999999999", "text": "teh cat"})),
        )
        .await;
        let fresh_id = body["id"].as_str().unwrap().to_string();

        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages/edit"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "msg_id": fresh_id, "text": "the cat", "from_me": true
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);

        let rows = state
            .manager
            .store
            .messages_list(&sid, Some("5511999999999@s.whatsapp.net"), None, i64::MAX, 50)
            .unwrap();
        let row = rows.iter().find(|r| r.message_id == fresh_id).unwrap();
        assert_eq!(row.body_text.as_deref(), Some("the cat"), "our copy carries the new text");
        assert!(row.edited);

        // Older than the 15-minute window → refused, with the reason.
        let stale_ts = chrono::Utc::now().timestamp() - (30 * 60);
        state
            .manager
            .store
            .message_insert(
                &crate::store::NewMessage {
                    session_id: &sid,
                    chat_jid: "5511999999999@s.whatsapp.net",
                    message_id: "STALE_EDIT",
                    sender_jid: "5511999999999@s.whatsapp.net",
                    from_me: true,
                    timestamp: stale_ts,
                    msg_type: "text",
                    body_text: Some("too late"),
                    payload_json: "{}",
                    status: None,
                },
                true,
            )
            .unwrap();

        let (st, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages/edit"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "msg_id": "STALE_EDIT", "text": "nope", "from_me": true
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(
            body.to_string().contains("15 minutes"),
            "the error must say WHY: {body}"
        );
    }

    /// Revoking tombstones our own copy (so the chat stops showing a message we
    /// just deleted for everyone), and a message past WhatsApp's revoke window is
    /// rejected up front instead of queueing a stanza that provably does nothing.
    #[tokio::test]
    async fn revoke_tombstones_own_row_and_rejects_stale_targets() {
        let state = test_state();
        let app = router(state.clone());

        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone"})),
        )
        .await;
        let sid = body["id"].as_str().unwrap().to_string();

        // A fresh outbound message → revoke is accepted and marks our row.
        let (_, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999999999", "text": "oops"})),
        )
        .await;
        let fresh_id = body["id"].as_str().unwrap().to_string();

        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages/revoke"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "msg_id": fresh_id, "from_me": true
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);

        let rows = state
            .manager
            .store
            .messages_list(&sid, Some("5511999999999@s.whatsapp.net"), None, i64::MAX, 50)
            .unwrap();
        let row = rows.iter().find(|r| r.message_id == fresh_id).unwrap();
        assert!(row.revoked, "our own copy must be tombstoned");
        assert_eq!(row.body_text, None, "revoked content must be gone");

        // A message older than the window: WhatsApp would ignore the revoke, so
        // we refuse it instead of returning a lying 202.
        let stale_ts = chrono::Utc::now().timestamp() - (72 * 3600);
        state
            .manager
            .store
            .message_insert(
                &crate::store::NewMessage {
                    session_id: &sid,
                    chat_jid: "5511999999999@s.whatsapp.net",
                    message_id: "STALE1",
                    sender_jid: "5511999999999@s.whatsapp.net",
                    from_me: true,
                    timestamp: stale_ts,
                    msg_type: "text",
                    body_text: Some("ancient"),
                    payload_json: "{}",
                    status: None,
                },
                true,
            )
            .unwrap();

        let (st, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages/revoke"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "msg_id": "STALE1", "from_me": true
            })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(
            body["error"].as_str().unwrap_or_default().contains("delete-for-everyone")
                || body.to_string().contains("delete-for-everyone"),
            "the error must say WHY, not just fail: {body}"
        );

        // An unknown target is still allowed through — we can't judge its age.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{sid}/messages/revoke"),
            Some("test-token"),
            Some(serde_json::json!({
                "to": "5511999999999", "msg_id": "UNKNOWN1", "from_me": true
            })),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn send_text_rejects_empty_body() {
        let state = test_state();
        let app = router(state);

        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        let (st, _) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/messages"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511999", "text": ""})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    /// `RUWA_READONLY=1` causes every mutating route to return 403,
    /// while read-only routes (GET) and `/health` keep serving. We
    /// don't enumerate every mutating route, just spot-check a few.
    #[tokio::test]
    async fn readonly_mode_blocks_writes_and_allows_reads() {
        // Bootstrap a session in writable mode (so the row exists).
        let writable = test_state();
        let mgr = writable.manager.clone();
        let session = mgr.create(Some("alice".into())).unwrap();
        let id = session.meta.read().id.clone();

        // Now wrap the same store in a readonly state.
        let ro = AppState {
            manager: mgr,
            api_token: Arc::new("test-token".into()),
            readonly: true,
            media_store: None,
        };
        let app = router(ro);

        // GET still works.
        let (st, _) = send(app.clone(), "GET", "/v1/sessions", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        let (st, _) = send(
            app.clone(),
            "GET",
            &format!("/v1/sessions/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // POST is blocked.
        let (st, _) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "x"})),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages"),
            Some("test-token"),
            Some(serde_json::json!({"to": "5511", "text": "hi"})),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // DELETE is blocked.
        let (st, _) = send(
            app.clone(),
            "DELETE",
            &format!("/v1/sessions/{id}"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);

        // /health is open.
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Multipart variant: a `file` part + a `metadata` JSON part are
    /// accepted, the file is spooled under data/uploads/<session>/, and
    /// a `messages` row is persisted with media_path pointing at the
    /// spool. Live wire-send is best-effort (no real WS in test) — we
    /// only assert the API side.
    #[tokio::test]
    async fn send_media_multipart_spools_and_persists() {
        let state = test_state();
        let app = router(state.clone());

        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        // Hand-roll a multipart body. Boundary, file part, metadata part.
        let boundary = "------------test-boundary";
        let metadata = serde_json::json!({
            "to": "5511999999999",
            "type": "image",
            "mime": "image/jpeg",
            "caption": "hi",
            "filename": null,
        })
        .to_string();
        let file_bytes: &[u8] = b"\xFF\xD8\xFFhello-image-bytes";
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            b"Content-Disposition: form-data; name=\"file\"; filename=\"x.jpg\"\r\n",
        );
        body.extend_from_slice(b"Content-Type: image/jpeg\r\n\r\n");
        body.extend_from_slice(file_bytes);
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(b"Content-Disposition: form-data; name=\"metadata\"\r\n\r\n");
        body.extend_from_slice(metadata.as_bytes());
        body.extend_from_slice(b"\r\n");
        body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/sessions/{id}/messages/media/multipart"))
            .header("authorization", "Bearer test-token")
            .header(
                "content-type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        assert_eq!(status, StatusCode::ACCEPTED, "body: {v}");
        assert_eq!(v["status"], "queued");

        // Spooled bytes must equal what we uploaded.
        let msg_id = v["id"].as_str().unwrap().to_string();
        let path: String = state
            .manager
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT media_path FROM messages \
                       WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![id, msg_id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        let spooled = std::fs::read(&path).unwrap();
        assert_eq!(spooled, file_bytes);
        // Cleanup spool dir to keep CI tidy.
        let _ = std::fs::remove_file(&path);
    }

    /// Bodies above axum's 2 MB default used to 413 on the multipart upload.
    /// The router now applies `RUWA_BODY_LIMIT_MB` (default 20 MB) to /v1/*,
    /// so a ~5 MB file must be accepted; one past the cap must still 413.
    #[tokio::test]
    async fn multipart_body_limit_is_raised_above_axum_default() {
        let state = test_state();
        let app = router(state.clone());
        let (_, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "phone"})),
        )
        .await;
        let id = body["id"].as_str().unwrap().to_string();

        let build = |file_len: usize| {
            let boundary = "------------big-boundary";
            let metadata = serde_json::json!({
                "to": "5511999999999",
                "type": "document",
                "mime": "application/octet-stream",
                "filename": "big.bin",
            })
            .to_string();
            let mut body: Vec<u8> = Vec::with_capacity(file_len + 512);
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(
                b"Content-Disposition: form-data; name=\"file\"; filename=\"big.bin\"\r\n",
            );
            body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
            body.extend(std::iter::repeat_n(0xABu8, file_len));
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
            body.extend_from_slice(b"Content-Disposition: form-data; name=\"metadata\"\r\n\r\n");
            body.extend_from_slice(metadata.as_bytes());
            body.extend_from_slice(b"\r\n");
            body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
            Request::builder()
                .method("POST")
                .uri(format!("/v1/sessions/{id}/messages/media/multipart"))
                .header("authorization", "Bearer test-token")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap()
        };

        // 5 MB: over axum's old 2 MB default, under our 20 MB cap.
        let resp = app.clone().oneshot(build(5 * 1024 * 1024)).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
        assert_eq!(status, StatusCode::ACCEPTED, "body: {v}");
        if let Some(msg_id) = v["id"].as_str() {
            let path: Option<String> = state
                .manager
                .store
                .with_conn(|conn| {
                    conn.query_row(
                        "SELECT media_path FROM messages \
                           WHERE session_id = ? AND message_id = ?",
                        rusqlite::params![id, msg_id],
                        |r| r.get(0),
                    )
                })
                .ok();
            if let Some(p) = path {
                let _ = std::fs::remove_file(p);
            }
        }

        // 21 MB: past the cap → 413, not a spooled file.
        let resp = app.oneshot(build(21 * 1024 * 1024)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ===== Cloud API sessions + Meta webhook ================================

    /// Fixture ids: an obviously fake Graph phone-number id + recipient.
    const CLOUD_PNID: &str = "106540352242922";
    const CLOUD_USER: &str = "5511999999999";
    const CLOUD_APP_SECRET: &str = "fake-app-secret";
    /// A second tenant's number (cross-tenant webhook tests).
    const CLOUD_PNID_B: &str = "106540352242999";

    /// Raw-body request helper (headers as given, no implicit auth); returns
    /// status + raw body bytes.
    async fn send_raw(
        app: axum::Router,
        method: &str,
        uri: &str,
        headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> (StatusCode, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            req = req.header(*k, *v);
        }
        let resp = app.oneshot(req.body(Body::from(body)).unwrap()).await.unwrap();
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        (status, bytes.to_vec())
    }

    fn cloud_create_body(app_secret: Option<&str>) -> serde_json::Value {
        let mut cloud = json!({
            "phone_number_id": CLOUD_PNID,
            "waba_id": "102300000000000",
            "access_token": "EAAG-fake-access-token",
            "verify_token": "my-verify",
        });
        if let Some(sec) = app_secret {
            cloud["app_secret"] = json!(sec);
        }
        json!({ "label": "acme cloud", "kind": "cloud", "cloud": cloud })
    }

    /// Create a cloud session via the API; returns `(id, api_key)`.
    async fn create_cloud_session(app: axum::Router, app_secret: Option<&str>) -> (String, String) {
        let (st, body) = send(
            app,
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(cloud_create_body(app_secret)),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "body: {body}");
        (
            body["id"].as_str().unwrap().to_string(),
            body["api_key"].as_str().unwrap().to_string(),
        )
    }

    /// Meta webhook body carrying one inbound text from `CLOUD_USER`.
    fn webhook_text_fixture(wamid: &str, text: &str) -> Vec<u8> {
        json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "102300000000000",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": { "display_phone_number": "15550000000", "phone_number_id": CLOUD_PNID },
                        "contacts": [{ "profile": { "name": "Test User" }, "wa_id": CLOUD_USER }],
                        "messages": [{
                            "from": CLOUD_USER,
                            "id": wamid,
                            "timestamp": "1700000000",
                            "type": "text",
                            "text": { "body": text }
                        }]
                    }
                }]
            }]
        })
        .to_string()
        .into_bytes()
    }

    /// Meta webhook body carrying one delivery status for `wamid`.
    fn webhook_status_fixture(wamid: &str, status: &str) -> Vec<u8> {
        json!({
            "object": "whatsapp_business_account",
            "entry": [{
                "id": "102300000000000",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": { "display_phone_number": "15550000000", "phone_number_id": CLOUD_PNID },
                        "statuses": [{
                            "id": wamid,
                            "status": status,
                            "timestamp": "1700000100",
                            "recipient_id": CLOUD_USER
                        }]
                    }
                }]
            }]
        })
        .to_string()
        .into_bytes()
    }

    fn signature_for(secret: &str, body: &[u8]) -> String {
        format!("sha256={}", cloud::hmac_sha256_hex(secret.as_bytes(), body))
    }

    /// POST a webhook body signed with `secret` (or unsigned when `None`).
    async fn post_webhook(app: axum::Router, secret: Option<&str>, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
        let sig = secret.map(|s| signature_for(s, &body));
        let mut headers: Vec<(&str, &str)> = vec![("content-type", "application/json")];
        if let Some(sig) = sig.as_deref() {
            headers.push(("x-hub-signature-256", sig));
        }
        send_raw(app, "POST", "/v1/cloud/webhook", &headers, body).await
    }

    #[tokio::test]
    async fn create_cloud_session_echoes_public_fields_and_never_secrets() {
        let state = test_state();
        let app = router(state.clone());
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(cloud_create_body(Some(CLOUD_APP_SECRET))),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED, "body: {body}");
        assert_eq!(body["kind"], "cloud");
        assert_eq!(body["status"], "pending");
        assert_eq!(body["cloud"]["phone_number_id"], CLOUD_PNID);
        assert_eq!(body["cloud"]["waba_id"], "102300000000000");
        assert_eq!(body["cloud"]["graph_version"], "v25.0");
        assert!(body["api_key"].as_str().is_some_and(|k| !k.is_empty()));
        let raw = body.to_string();
        assert!(!raw.contains("EAAG-fake-access-token"), "access token leaked: {raw}");
        assert!(!raw.contains(CLOUD_APP_SECRET), "app secret leaked: {raw}");
        assert!(!raw.contains("access_token"), "{raw}");
        assert!(!raw.contains("app_secret"), "{raw}");
        let id = body["id"].as_str().unwrap().to_string();

        // GET /sessions/:id + the list both carry the kind (and no secrets).
        let (st, one) = send(app.clone(), "GET", &format!("/v1/sessions/{id}"), Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(one["kind"], "cloud");
        assert!(one.get("api_key").is_none());
        let (st, list) = send(app.clone(), "GET", "/v1/sessions", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        let me = list.as_array().unwrap().iter().find(|s| s["id"] == id).unwrap();
        assert_eq!(me["kind"], "cloud");
        assert_eq!(me["cloud"]["phone_number_id"], CLOUD_PNID);
        assert!(!list.to_string().contains("EAAG-fake-access-token"));

        // A plain web session reports kind=web and no cloud block.
        let (st, web) = send(app, "POST", "/v1/sessions", Some("test-token"), Some(json!({"label": "w"}))).await;
        assert_eq!(st, StatusCode::CREATED);
        assert_eq!(web["kind"], "web");
        assert!(web.get("cloud").is_none(), "{web}");
    }

    #[tokio::test]
    async fn create_session_rejects_bad_kind_and_incomplete_cloud_creds() {
        let app = router(test_state());
        // Missing access_token → 400.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(json!({"kind": "cloud", "cloud": {"phone_number_id": CLOUD_PNID}})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"].as_str().unwrap().contains("access_token"));
        // Missing cloud block entirely → 400.
        let (st, _) = send(app.clone(), "POST", "/v1/sessions", Some("test-token"), Some(json!({"kind": "cloud"}))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Unknown kind → 400.
        let (st, body) = send(app.clone(), "POST", "/v1/sessions", Some("test-token"), Some(json!({"kind": "sms"}))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        // kind=web (explicit) with cloud creds → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(json!({"kind": "web", "cloud": {"phone_number_id": CLOUD_PNID, "access_token": "x"}})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // No cloud session got created by any of the rejects.
        let (_, list) = send(app, "GET", "/v1/sessions", Some("test-token"), None).await;
        assert!(list.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn web_only_routes_answer_501_on_cloud_sessions() {
        let app = router(test_state());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let (st, body) = send(app.clone(), "GET", &format!("/v1/sessions/{id}/qr"), Some(&key), None).await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED, "{body}");
        assert!(body["error"].as_str().unwrap().contains("cloud"));
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/poll"),
            Some(&key),
            Some(json!({"to": CLOUD_USER, "name": "q?", "options": ["a", "b"]})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/edit"),
            Some(&key),
            Some(json!({"to": CLOUD_USER, "msg_id": "x", "text": "y"})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/mark-online"),
            Some(&key),
            Some(json!({"mark_online": true})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(app.clone(), "POST", &format!("/v1/sessions/{id}/resync-appstate"), Some(&key), None).await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/onwhatsapp"),
            Some(&key),
            Some(json!({"numbers": [CLOUD_USER]})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/presence"),
            Some(&key),
            Some(json!({"state": "available"})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn cloud_only_routes_answer_501_on_web_sessions() {
        let app = router(test_state());
        let (st, web) = send(app.clone(), "POST", "/v1/sessions", Some("test-token"), Some(json!({}))).await;
        assert_eq!(st, StatusCode::CREATED);
        let id = web["id"].as_str().unwrap().to_string();
        let (st, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/template"),
            Some("test-token"),
            Some(json!({"to": CLOUD_USER, "name": "order_update", "language": "pt_BR"})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED, "{body}");
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/interactive"),
            Some("test-token"),
            Some(json!({"to": CLOUD_USER, "type": "button", "body": "hi", "buttons": [{"id": "y", "title": "Yes"}]})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(app.clone(), "GET", &format!("/v1/sessions/{id}/templates"), Some("test-token"), None).await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
        let (st, _) = send(
            app,
            "PUT",
            &format!("/v1/sessions/{id}/cloud"),
            Some("test-token"),
            Some(json!({"waba_id": "1"})),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn put_cloud_updates_public_fields_on_cloud_session() {
        let state = test_state();
        let app = router(state.clone());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let (st, body) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/cloud"),
            Some(&key),
            Some(json!({"waba_id": "999900000000000", "access_token": "EAAG-rotated", "graph_version": "26.0"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["kind"], "cloud");
        assert_eq!(body["cloud"]["waba_id"], "999900000000000");
        assert_eq!(body["cloud"]["graph_version"], "v26.0");
        assert!(!body.to_string().contains("EAAG-rotated"));
        // The new token is what the Graph client will use.
        assert_eq!(state.manager.cloud_creds(&id).unwrap().access_token, "EAAG-rotated");
        // Blank phone_number_id is refused (master token: 400).
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/cloud"),
            Some("test-token"),
            Some(json!({"phone_number_id": "  "})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // A per-session key may rotate secrets but not re-point the number.
        let (st, body) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/cloud"),
            Some(&key),
            Some(json!({"phone_number_id": "106540352242999"})),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(state.manager.cloud_creds(&id).unwrap().phone_number_id, CLOUD_PNID);
        // Non-numeric ids / malformed graph versions are refused.
        let (st, _) = send(
            app.clone(),
            "PUT",
            &format!("/v1/sessions/{id}/cloud"),
            Some("test-token"),
            Some(json!({"phone_number_id": "../me"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = send(
            app,
            "PUT",
            &format!("/v1/sessions/{id}/cloud"),
            Some(&key),
            Some(json!({"graph_version": "v25.0/../x"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cloud_phone_number_id_cannot_be_claimed_twice() {
        let state = test_state();
        let app = router(state.clone());
        let (a_id, _) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        // Same number again → 409, and no second session exists.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(cloud_create_body(Some(CLOUD_APP_SECRET))),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT, "{body}");
        let (_, list) = send(app.clone(), "GET", "/v1/sessions", Some("test-token"), None).await;
        assert_eq!(list.as_array().unwrap().len(), 1);
        // A session on another number can't be re-pointed at A's (even by the
        // master token) — webhooks would otherwise route A's traffic to it.
        let mut other = cloud_create_body(Some("other-secret"));
        other["cloud"]["phone_number_id"] = json!(CLOUD_PNID_B);
        let (st, b) = send(app.clone(), "POST", "/v1/sessions", Some("test-token"), Some(other)).await;
        assert_eq!(st, StatusCode::CREATED, "{b}");
        let b_id = b["id"].as_str().unwrap().to_string();
        let (st, body) = send(
            app,
            "PUT",
            &format!("/v1/sessions/{b_id}/cloud"),
            Some("test-token"),
            Some(json!({"phone_number_id": CLOUD_PNID})),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT, "{body}");
        assert_eq!(
            state.manager.store.cloud_session_id_by_phone_number_id(CLOUD_PNID).unwrap().as_deref(),
            Some(a_id.as_str())
        );
    }

    #[tokio::test]
    async fn cloud_webhook_verify_echoes_challenge_for_matching_token() {
        // Relies on RUWA_CLOUD_VERIFY_TOKEN being unset (the session's own
        // verify_token is consulted then).
        let app = router(test_state());
        let _ = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let (st, body) = send_raw(
            app.clone(),
            "GET",
            "/v1/cloud/webhook?hub.mode=subscribe&hub.verify_token=my-verify&hub.challenge=1158201444",
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"1158201444");
        let (st, _) = send_raw(
            app.clone(),
            "GET",
            "/v1/cloud/webhook?hub.mode=subscribe&hub.verify_token=wrong&hub.challenge=1158201444",
            &[],
            Vec::new(),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        // Missing token → 403 too (never echo the challenge blindly).
        let (st, _) = send_raw(app, "GET", "/v1/cloud/webhook?hub.mode=subscribe&hub.challenge=1", &[], Vec::new()).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn cloud_webhook_signed_text_message_is_stored_once_and_listed() {
        let state = test_state();
        let app = router(state.clone());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let body = webhook_text_fixture("wamid.HBgLNTUxMTk5OTk5OTk5ORUCABIYFjNFQjBDMDAwMDAwMDAwMDAwMDAwMDAA", "olá");

        let (st, resp) = post_webhook(app.clone(), Some(CLOUD_APP_SECRET), body.clone()).await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));
        assert_eq!(resp, b"{}");

        let chat = format!("{CLOUD_USER}@s.whatsapp.net");
        let rows = state.manager.store.messages_list(&id, Some(&chat), None, i64::MAX, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, "wamid.HBgLNTUxMTk5OTk5OTk5ORUCABIYFjNFQjBDMDAwMDAwMDAwMDAwMDAwMDAA");
        assert!(!rows[0].from_me);
        assert_eq!(rows[0].body_text.as_deref(), Some("olá"));

        // Visible through the normal messages route (same table as web).
        let (st, listed) = send(app.clone(), "GET", &format!("/v1/sessions/{id}/messages"), Some(&key), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["chat_jid"], chat);

        // Meta retries → the same body again is acked but not duplicated.
        let (st, _) = post_webhook(app.clone(), Some(CLOUD_APP_SECRET), body).await;
        assert_eq!(st, StatusCode::OK);
        let rows = state.manager.store.messages_list(&id, Some(&chat), None, i64::MAX, 10).unwrap();
        assert_eq!(rows.len(), 1);
        // The contact + chat got created from the webhook's profile name.
        assert!(state.manager.store.chats_list(&id).unwrap().iter().any(|c| c.jid == chat));
        // Health reflects the inbound webhook as last_rx.
        let (st, health) = send(app, "GET", &format!("/v1/sessions/{id}/health"), Some(&key), None).await;
        assert_eq!(st, StatusCode::OK);
        assert!(health["last_rx"].as_i64().is_some(), "{health}");
    }

    #[tokio::test]
    async fn cloud_webhook_rejects_bad_signature_and_acks_unknown_numbers() {
        let state = test_state();
        let app = router(state.clone());
        let (id, _) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let body = webhook_text_fixture("wamid.HBgLBAD0000000000000000000000001", "x");

        // Wrong secret → 401, nothing stored.
        let (st, _) = post_webhook(app.clone(), Some("not-the-secret"), body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // No signature at all → 401.
        let (st, _) = post_webhook(app.clone(), None, body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(state.manager.store.messages_list(&id, None, None, i64::MAX, 10).unwrap().is_empty());

        // Unknown phone_number_id → 200 (acked, ignored) even without a signature.
        let unknown = String::from_utf8(body).unwrap().replace(CLOUD_PNID, "999999999999999").into_bytes();
        let (st, resp) = post_webhook(app.clone(), None, unknown).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(resp, b"{}");
        assert!(state.manager.store.messages_list(&id, None, None, i64::MAX, 10).unwrap().is_empty());

        // Garbage body → 400 (not JSON).
        let (st, _) = post_webhook(app, None, b"not json".to_vec()).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cloud_webhook_verifies_every_batch_under_its_own_session_secret() {
        // Tenant A (knows secret A) forges a POST carrying a batch for A's
        // number AND one for tenant B's number, signed with A's secret. Nothing
        // may land in B (or A): the whole POST is refused.
        let state = test_state();
        let app = router(state.clone());
        let (a_id, _) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let mut other = cloud_create_body(Some("secret-of-b"));
        other["cloud"]["phone_number_id"] = json!(CLOUD_PNID_B);
        let (st, b) = send(app.clone(), "POST", "/v1/sessions", Some("test-token"), Some(other)).await;
        assert_eq!(st, StatusCode::CREATED, "{b}");
        let b_id = b["id"].as_str().unwrap().to_string();

        let entry = |pnid: &str, wamid: &str| {
            json!({
                "id": "102300000000000",
                "changes": [{
                    "field": "messages",
                    "value": {
                        "messaging_product": "whatsapp",
                        "metadata": { "display_phone_number": "15550000000", "phone_number_id": pnid },
                        "contacts": [{ "profile": { "name": "Test User" }, "wa_id": CLOUD_USER }],
                        "messages": [{
                            "from": CLOUD_USER, "id": wamid, "timestamp": "1700000000",
                            "type": "text", "text": { "body": "forged" }
                        }]
                    }
                }]
            })
        };
        let body = json!({
            "object": "whatsapp_business_account",
            "entry": [entry(CLOUD_PNID, "wamid.HBgLFORGEA1"), entry(CLOUD_PNID_B, "wamid.HBgLFORGEB1")]
        })
        .to_string()
        .into_bytes();
        let (st, _) = post_webhook(app.clone(), Some(CLOUD_APP_SECRET), body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(state.manager.store.messages_list(&a_id, None, None, i64::MAX, 10).unwrap().is_empty());
        assert!(state.manager.store.messages_list(&b_id, None, None, i64::MAX, 10).unwrap().is_empty());
        // Signed with B's secret it fails the same way (A's batch doesn't verify).
        let (st, _) = post_webhook(app.clone(), Some("secret-of-b"), body).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        assert!(state.manager.store.messages_list(&b_id, None, None, i64::MAX, 10).unwrap().is_empty());

        // A batch for B alone, signed with B's own secret, is ingested into B only.
        let only_b = json!({ "object": "whatsapp_business_account", "entry": [entry(CLOUD_PNID_B, "wamid.HBgLREALB1")] })
            .to_string()
            .into_bytes();
        let (st, _) = post_webhook(app.clone(), Some("secret-of-b"), only_b).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(state.manager.store.messages_list(&b_id, None, None, i64::MAX, 10).unwrap().len(), 1);
        assert!(state.manager.store.messages_list(&a_id, None, None, i64::MAX, 10).unwrap().is_empty());
        // Unknown numbers alongside a verified batch are still ignored (200).
        let mixed = json!({ "object": "whatsapp_business_account",
            "entry": [entry(CLOUD_PNID_B, "wamid.HBgLREALB2"), entry("999999999999999", "wamid.HBgLNOBODY")] })
            .to_string()
            .into_bytes();
        let (st, _) = post_webhook(app, Some("secret-of-b"), mixed).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(state.manager.store.messages_list(&b_id, None, None, i64::MAX, 10).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn cloud_webhook_status_updates_are_monotonic_and_deduped() {
        let state = test_state();
        let app = router(state.clone());
        let (id, _) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let chat = format!("{CLOUD_USER}@s.whatsapp.net");
        let wamid = "wamid.HBgLOUT00000000000000000000000000002";
        state
            .manager
            .cloud_record_outbound(&id, &chat, wamid, "self", "text", Some("hello"), r#"{"type":"text","text":"hello"}"#, 1_700_000_000)
            .unwrap();
        let mut rx = state.manager.get(&id).unwrap().events.subscribe();
        let status_of = || -> String {
            state
                .manager
                .store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT status FROM messages WHERE session_id=? AND message_id=?",
                        rusqlite::params![id, wamid],
                        |r| r.get(0),
                    )
                })
                .unwrap()
        };
        // read first (Meta doesn't guarantee order)…
        let (st, _) = post_webhook(app.clone(), Some(CLOUD_APP_SECRET), webhook_status_fixture(wamid, "read")).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(status_of(), "read");
        assert!(matches!(rx.try_recv(), Ok(crate::session::SessionEvent::MessageRead { .. })));
        // …then a late `delivered` and a retried `read`: row stays `read`, no events.
        for late in ["delivered", "sent", "read"] {
            let (st, _) = post_webhook(app.clone(), Some(CLOUD_APP_SECRET), webhook_status_fixture(wamid, late)).await;
            assert_eq!(st, StatusCode::OK);
            assert_eq!(status_of(), "read", "after late {late}");
        }
        assert!(rx.try_recv().is_err(), "stale statuses must not re-emit events");
        // A status for a wamid this session never sent emits nothing either.
        let (st, _) = post_webhook(app, Some(CLOUD_APP_SECRET), webhook_status_fixture("wamid.HBgLNOTOURS", "delivered")).await;
        assert_eq!(st, StatusCode::OK);
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn cloud_sends_refuse_non_phone_recipients_before_any_graph_call() {
        let app = router(test_state());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        for to in ["123456789012345@lid", "120363123456789012@g.us", "status@broadcast"] {
            let (st, body) = send(
                app.clone(),
                "POST",
                &format!("/v1/sessions/{id}/messages"),
                Some(&key),
                Some(json!({"to": to, "text": "hi"})),
            )
            .await;
            assert_eq!(st, StatusCode::BAD_REQUEST, "{to}: {body}");
            assert!(body["error"].as_str().unwrap().contains("phone number"), "{body}");
        }
        // Reactions / templates / interactive go through the same gate.
        let (st, _) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/messages/react"),
            Some(&key),
            Some(json!({"to": "123456789012345@lid", "msg_id": "wamid.HBgLX", "emoji": "👍"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        let (st, _) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/messages/template"),
            Some(&key),
            Some(json!({"to": "120363123456789012@g.us", "name": "hello_world", "language": "en_US"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cloud_webhook_unsigned_delivery_needs_opt_in_when_session_has_no_secret() {
        // Relies on RUWA_CLOUD_ALLOW_UNSIGNED being unset in the test env.
        let app = router(test_state());
        let _ = create_cloud_session(app.clone(), None).await;
        let body = webhook_text_fixture("wamid.HBgLUNSIGNED000000000000000000001", "x");
        let (st, _) = post_webhook(app.clone(), None, body.clone()).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        // Even a "signature" can't help: there's no secret to verify against.
        let (st, _) = post_webhook(app, Some("whatever"), body).await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn cloud_webhook_statuses_update_outbound_rows() {
        let state = test_state();
        let app = router(state.clone());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let chat = format!("{CLOUD_USER}@s.whatsapp.net");
        let wamid = "wamid.HBgLOUT00000000000000000000000000001";
        state
            .manager
            .cloud_record_outbound(
                &id,
                &chat,
                wamid,
                "15550000000@s.whatsapp.net",
                "text",
                Some("hello"),
                r#"{"type":"text","text":"hello"}"#,
                1_700_000_000,
            )
            .unwrap();
        let status_of = |sid: &str, mid: &str| -> String {
            state
                .manager
                .store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT status FROM messages WHERE session_id=? AND message_id=?",
                        rusqlite::params![sid, mid],
                        |r| r.get(0),
                    )
                })
                .unwrap()
        };
        assert_eq!(status_of(&id, wamid), "sent");
        for (incoming, expect) in [("delivered", "delivered"), ("played", "read"), ("failed", "failed")] {
            let (st, _) = post_webhook(app.clone(), Some(CLOUD_APP_SECRET), webhook_status_fixture(wamid, incoming)).await;
            assert_eq!(st, StatusCode::OK);
            assert_eq!(status_of(&id, wamid), expect, "after {incoming}");
        }
        // Still exactly one row, listed as ours.
        let (_, listed) = send(app, "GET", &format!("/v1/sessions/{id}/messages"), Some(&key), None).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["from_me"], true);
    }

    // ===== Kapso provider ==================================================

    const KAPSO_PNID: &str = "123456789012345";
    const KAPSO_SECRET: &str = "kapso-hook-secret-000000000000000";
    const KAPSO_CUSTOMER: &str = "cust-abc-123";

    /// Seed a `provider = kapso`, connected cloud session straight into the
    /// store (no network), returning its id. `webhook_secret` = `KAPSO_SECRET`.
    fn seed_kapso_session(state: &AppState) -> String {
        let id = crate::session::uuid_v4();
        let now = 1_700_000_000;
        state
            .manager
            .store
            .create_kapso_session(&crate::store::NewKapsoSession {
                id: &id,
                label: Some("kapso tenant"),
                status: "connected",
                api_key: "kapsotenantkey0000000000000000000",
                proxy_url: None,
                created_at: now,
                updated_at: now,
                customer_id: KAPSO_CUSTOMER,
                setup_ref: &id,
                setup_link: Some("https://app.kapso.ai/setup/x"),
                base_url: None,
                graph_version: "v25.0",
                webhook_secret: KAPSO_SECRET,
            })
            .unwrap();
        state
            .manager
            .store
            .session_set_cloud_phone_number(&id, KAPSO_PNID, Some("int-uuid-1"), Some("waba-kapso-1"), now)
            .unwrap();
        id
    }

    /// Kapso native message-webhook body: one inbound text from `CLOUD_USER`.
    fn kapso_text_fixture(wamid: &str, text: &str) -> Vec<u8> {
        json!({
            "message": {
                "id": wamid, "timestamp": "1730092800", "type": "text",
                "from": CLOUD_USER, "text": { "body": text },
                "kapso": { "direction": "inbound" }
            },
            "conversation": {
                "contact_name": "Kapso User", "phone_number": CLOUD_USER,
                "phone_number_id": KAPSO_PNID
            },
            "is_new_conversation": true,
            "phone_number_id": KAPSO_PNID
        })
        .to_string()
        .into_bytes()
    }

    #[tokio::test]
    async fn kapso_create_without_config_is_clean_400() {
        std::env::remove_var("RUWA_KAPSO_API_KEY");
        let app = router(test_state());
        let (st, body) = send(
            app,
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(json!({ "kind": "cloud", "cloud": { "provider": "kapso" } })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    }

    #[tokio::test]
    async fn kapso_webhook_get_is_permissive() {
        let app = router(test_state());
        let (st, body) =
            send_raw(app, "GET", "/v1/cloud/kapso/webhook", &[], Vec::new()).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, b"ok");
    }

    #[tokio::test]
    async fn kapso_webhook_signed_text_message_is_stored_and_bad_signature_401s() {
        let state = test_state();
        let app = router(state.clone());
        let id = seed_kapso_session(&state);
        state.manager.restore_all().await.unwrap();

        let body = kapso_text_fixture("wamid.kapso.1", "olá via kapso");
        let sig = cloud::hmac_sha256_hex(KAPSO_SECRET.as_bytes(), &body);
        let (st, resp) = send_raw(
            app.clone(),
            "POST",
            "/v1/cloud/kapso/webhook",
            &[("content-type", "application/json"), ("x-webhook-signature", &sig)],
            body.clone(),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{}", String::from_utf8_lossy(&resp));

        let chat = format!("{CLOUD_USER}@s.whatsapp.net");
        let rows = state
            .manager
            .store
            .messages_list(&id, Some(&chat), None, i64::MAX, 10)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].message_id, "wamid.kapso.1");
        assert!(!rows[0].from_me);
        assert_eq!(rows[0].body_text.as_deref(), Some("olá via kapso"));

        // Bad signature → 401, nothing more stored.
        let (st, _) = send_raw(
            app,
            "POST",
            "/v1/cloud/kapso/webhook",
            &[("content-type", "application/json"), ("x-webhook-signature", "deadbeef")],
            body,
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
        let rows = state
            .manager
            .store
            .messages_list(&id, Some(&chat), None, i64::MAX, 10)
            .unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn web_only_route_on_kapso_session_is_501() {
        let state = test_state();
        let app = router(state.clone());
        let id = seed_kapso_session(&state);
        state.manager.restore_all().await.unwrap();
        let (st, _) = send(
            app,
            "GET",
            &format!("/v1/sessions/{id}/qr"),
            Some("test-token"),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
    }

    // ---- Kapso Broadcasts (bulk-template campaigns) ------------------------

    /// Like [`seed_kapso_session`] but leaves the session in the pending-
    /// onboarding state: no `cloud_phone_number_id` yet.
    fn seed_kapso_session_onboarding(state: &AppState) -> String {
        let id = crate::session::uuid_v4();
        let now = 1_700_000_000;
        state
            .manager
            .store
            .create_kapso_session(&crate::store::NewKapsoSession {
                id: &id,
                label: Some("kapso onboarding"),
                status: "connected",
                api_key: "kapsotenantkey0000000000000000001",
                proxy_url: None,
                created_at: now,
                updated_at: now,
                customer_id: KAPSO_CUSTOMER,
                setup_ref: &id,
                setup_link: Some("https://app.kapso.ai/setup/y"),
                base_url: None,
                graph_version: "v25.0",
                webhook_secret: KAPSO_SECRET,
            })
            .unwrap();
        id
    }

    #[tokio::test]
    async fn broadcasts_on_web_session_are_501() {
        let state = test_state();
        let app = router(state.clone());
        let id = state.manager.create(None).unwrap().meta.read().id.clone();
        let (st, _) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/broadcasts"),
            Some("test-token"),
            Some(json!({ "name": "Promo", "template_id": "123456" })),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED);
    }

    #[tokio::test]
    async fn broadcasts_on_meta_cloud_session_are_501() {
        let state = test_state();
        let app = router(state.clone());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let (st, body) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/broadcasts"),
            Some(&key),
            Some(json!({ "name": "Promo", "template_id": "123456" })),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_IMPLEMENTED, "{body}");
    }

    #[tokio::test]
    async fn broadcasts_on_onboarding_kapso_session_are_400() {
        let state = test_state();
        let app = router(state.clone());
        let id = seed_kapso_session_onboarding(&state);
        state.manager.restore_all().await.unwrap();
        let (st, body) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/broadcasts"),
            Some("test-token"),
            Some(json!({ "name": "Promo", "template_id": "123456" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"].as_str().unwrap_or_default().contains("onboarding"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn broadcast_create_validates_body_before_network() {
        let state = test_state();
        let app = router(state.clone());
        let id = seed_kapso_session(&state);
        state.manager.restore_all().await.unwrap();
        // Missing / blank template_id → 400, no Kapso round-trip.
        let (st, body) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/broadcasts"),
            Some("test-token"),
            Some(json!({ "name": "" })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    }

    #[tokio::test]
    async fn broadcast_recipients_rejects_oversized_list() {
        let state = test_state();
        let app = router(state.clone());
        let id = seed_kapso_session(&state);
        state.manager.restore_all().await.unwrap();
        let recipients: Vec<serde_json::Value> = (0..1001)
            .map(|i| json!({ "phone_number": format!("+155500{i:05}"), "components": [] }))
            .collect();
        let (st, body) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/broadcasts/{}/recipients", "b-1"),
            Some("test-token"),
            Some(json!({ "recipients": recipients })),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(
            body["error"].as_str().unwrap_or_default().contains("1000"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn cloud_typing_without_inbound_message_is_400_before_any_graph_call() {
        let app = router(test_state());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let (st, body) = send(
            app.clone(),
            "POST",
            &format!("/v1/sessions/{id}/chats/{CLOUD_USER}/typing"),
            Some(&key),
            Some(json!({"state": "composing"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        // `paused` is a no-op on cloud (indicators expire by themselves).
        let (st, body) = send(
            app,
            "POST",
            &format!("/v1/sessions/{id}/chats/{CLOUD_USER}/typing"),
            Some(&key),
            Some(json!({"state": "paused"})),
        )
        .await;
        assert_eq!(st, StatusCode::ACCEPTED);
        assert_eq!(body["status"], "ignored");
    }

    #[tokio::test]
    async fn cloud_media_route_404s_without_media_id_before_any_graph_call() {
        let state = test_state();
        let app = router(state.clone());
        let (id, key) = create_cloud_session(app.clone(), Some(CLOUD_APP_SECRET)).await;
        let chat = format!("{CLOUD_USER}@s.whatsapp.net");
        // A text row has no media_id → 404, no Graph round-trip.
        state
            .manager
            .cloud_record_outbound(&id, &chat, "wamid.HBgLTXT1", "self", "text", Some("x"), r#"{"type":"text","text":"x"}"#, 1)
            .unwrap();
        let (st, _) = send(
            app,
            "GET",
            &format!("/v1/sessions/{id}/messages/{CLOUD_USER}%40s.whatsapp.net/wamid.HBgLTXT1/media"),
            Some(&key),
            None,
        )
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND);
    }

    #[test]
    fn contact_card_from_vcard_pulls_fn_and_tel() {
        let v = build_vcard("Ada Lovelace", "+55 11 99999-9999");
        let card = contact_card_from_vcard(&v, "fallback");
        assert_eq!(card.name, "Ada Lovelace");
        assert_eq!(card.phones, vec!["+55 11 99999-9999".to_string()]);
        // Multiple TELs, no FN → fallback name, all phones.
        let card = contact_card_from_vcard(
            "BEGIN:VCARD\nTEL;type=CELL:+1 555 000 0001\nTEL:+1 555 000 0002\nEND:VCARD",
            "fallback",
        );
        assert_eq!(card.name, "fallback");
        assert_eq!(card.phones.len(), 2);
        // Garbage → no phones (caller 400s).
        assert!(contact_card_from_vcard("nope", "n").phones.is_empty());
    }

    #[test]
    fn template_and_interactive_request_bodies_flatten_to_and_spec() {
        let t: SendTemplateReq = serde_json::from_value(json!({
            "to": CLOUD_USER, "name": "order_update", "language": "pt_BR",
            "body_params": ["Ada", "1234"], "reply_to": "wamid.X"
        }))
        .unwrap();
        assert_eq!(t.to, CLOUD_USER);
        assert_eq!(t.tpl.name, "order_update");
        assert_eq!(t.tpl.body_params.len(), 2);
        assert_eq!(t.tpl.reply_to.as_deref(), Some("wamid.X"));
        let i: SendInteractiveReq = serde_json::from_value(json!({
            "to": CLOUD_USER, "type": "list", "body": "Pick one", "button": "Menu",
            "sections": [{"title": "A", "rows": [{"id": "r1", "title": "One"}]}]
        }))
        .unwrap();
        assert_eq!(i.msg.kind, "list");
        assert_eq!(i.msg.sections[0].rows[0].id, "r1");
        // Missing `to` is a deserialization error (not a silent default).
        assert!(serde_json::from_value::<SendTemplateReq>(json!({"name": "x", "language": "en"})).is_err());
    }

    // ---- AI text assistant ----

    #[test]
    fn ai_settings_merge_applies_defaults_and_requires_key_and_model() {
        let parse = |s: &str| serde_json::from_str::<PutAiSettingsReq>(s).unwrap();
        // Fresh anthropic config: key required, model + base_url defaulted.
        let cfg = ai_settings_merge(
            parse(r#"{"provider":"anthropic","api_key":"sk-ant-test-0000abcd"}"#),
            None,
        )
        .unwrap();
        assert_eq!(cfg.model, "claude-opus-5");
        assert!(cfg.base_url.is_none());
        assert_eq!(cfg.effective_base_url(), "https://api.anthropic.com");
        assert!(cfg.system_prompt.is_none());
        // No key, nothing stored → 400.
        assert!(ai_settings_merge(parse(r#"{"provider":"anthropic"}"#), None).is_err());
        // Blank key counts as omitted → keeps the stored one (same provider).
        let kept = ai_settings_merge(
            parse(r#"{"provider":"anthropic","api_key":"  ","model":"claude-sonnet-4-6"}"#),
            Some(&cfg),
        )
        .unwrap();
        assert_eq!(kept.api_key, "sk-ant-test-0000abcd");
        assert_eq!(kept.model, "claude-sonnet-4-6");
        // Changing provider without a key → 400.
        assert!(ai_settings_merge(
            parse(r#"{"provider":"openai","model":"gpt-4o-mini"}"#),
            Some(&cfg)
        )
        .is_err());
        // OpenAI requires a model.
        assert!(ai_settings_merge(
            parse(r#"{"provider":"openai","api_key":"sk-test-0000wxyz"}"#),
            None
        )
        .is_err());
        // base_url is normalized (trailing slash) and validated.
        let o = ai_settings_merge(
            parse(
                r#"{"provider":"openai","api_key":"sk-test-0000wxyz","model":"llama3",
                     "base_url":"http://localhost:11434/v1/","system_prompt":" be brief "}"#,
            ),
            None,
        )
        .unwrap();
        assert_eq!(o.base_url.as_deref(), Some("http://localhost:11434/v1"));
        assert_eq!(o.system_prompt.as_deref(), Some("be brief"));
        assert!(ai_settings_merge(
            parse(r#"{"provider":"openai","api_key":"k-0000wxyz","model":"m","base_url":"localhost"}"#),
            None
        )
        .is_err());
        for bad in ["http://", "https://ex ample.com/v1", "http://host/v1?x=1", "http://host/v1#f"] {
            assert!(
                ai_settings_merge(
                    parse(&format!(
                        r#"{{"provider":"openai","api_key":"k-0000wxyz","model":"m","base_url":"{bad}"}}"#
                    )),
                    None
                )
                .is_err(),
                "{bad} must be rejected"
            );
        }
        // Keys with whitespace / control chars can't be sent as a header → 400.
        for bad in ["sk-ant 0000abcd", "sk-ant\n0000abcd", "sk\tkey-0000abcd"] {
            assert!(
                ai_settings_merge(
                    parse(&serde_json::json!({"provider":"anthropic","api_key":bad}).to_string()),
                    None
                )
                .is_err(),
                "{bad:?} must be rejected"
            );
        }
        // Unknown fields are rejected (no silent typos).
        assert!(serde_json::from_str::<PutAiSettingsReq>(
            r#"{"provider":"anthropic","apikey":"x"}"#
        )
        .is_err());
    }

    #[tokio::test]
    async fn ai_settings_roundtrip_hides_key_and_applies_defaults() {
        let app = router(test_state());

        // Unconfigured GET.
        let (st, body) = send(app.clone(), "GET", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["configured"], false);
        assert!(body["provider"].is_null());
        assert!(body["api_key_hint"].is_null());

        // PUT anthropic with just provider + key → defaults applied, key hidden.
        let (st, body) = send(
            app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"anthropic","api_key":"sk-ant-test-0000abcd"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["configured"], true);
        assert_eq!(body["provider"], "anthropic");
        assert_eq!(body["model"], "claude-opus-5");
        assert_eq!(body["base_url"], "https://api.anthropic.com");
        assert!(body["system_prompt"].is_null());
        assert_eq!(body["api_key_hint"], "••••abcd");
        assert!(body.get("api_key").is_none(), "key must never be returned");
        assert!(!body.to_string().contains("sk-ant-test"));

        // GET reflects it; the key is not in the payload.
        let (st, body) = send(app.clone(), "GET", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["configured"], true);
        assert_eq!(body["api_key_hint"], "••••abcd");
        assert!(!body.to_string().contains("sk-ant-test"));

        // PUT without api_key (same provider) keeps the key, updates model.
        let (st, body) = send(
            app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"anthropic","model":"claude-sonnet-4-6","system_prompt":"Be terse."})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["model"], "claude-sonnet-4-6");
        assert_eq!(body["system_prompt"], "Be terse.");
        assert_eq!(body["api_key_hint"], "••••abcd");

        // Switching to openai without a model → 400.
        let (st, body) = send(
            app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"openai","api_key":"sk-test-0000wxyz"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
        assert!(body["error"].as_str().unwrap().contains("model"));
        // Switching provider without a key → 400.
        let (st, _) = send(
            app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"openai","model":"gpt-4o-mini"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Valid openai config with a custom base URL.
        let (st, body) = send(
            app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"openai","api_key":"sk-test-0000wxyz","model":"gpt-4o-mini","base_url":"https://openrouter.ai/api/v1/"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK, "{body}");
        assert_eq!(body["provider"], "openai");
        assert_eq!(body["base_url"], "https://openrouter.ai/api/v1");
        assert_eq!(body["api_key_hint"], "••••wxyz");

        // DELETE → 204, then unconfigured again (idempotent).
        let (st, _) = send(app.clone(), "DELETE", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, _) = send(app.clone(), "DELETE", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::NO_CONTENT);
        let (st, body) = send(app.clone(), "GET", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["configured"], false);
    }

    #[tokio::test]
    async fn ai_improve_text_validates_before_any_upstream_call() {
        let app = router(test_state());

        // Unconfigured → 400 with the pointer to the settings route.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/ai/improve-text",
            Some("test-token"),
            Some(serde_json::json!({"text":"hello"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert_eq!(
            body["error"],
            "ai assistant not configured — set it via PUT /v1/settings/ai"
        );
        // Same for the connectivity test.
        let (st, _) = send(app.clone(), "POST", "/v1/settings/ai/test", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Configure (no network is ever hit below: every call fails validation).
        let (st, _) = send(
            app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"anthropic","api_key":"sk-ant-test-0000abcd"})),
        )
        .await;
        assert_eq!(st, StatusCode::OK);

        // Empty text → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            "/v1/ai/improve-text",
            Some("test-token"),
            Some(serde_json::json!({"text":"   "})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Over-long text → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            "/v1/ai/improve-text",
            Some("test-token"),
            Some(serde_json::json!({"text": "x".repeat(8001)})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // translate without language → 400.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/ai/improve-text",
            Some("test-token"),
            Some(serde_json::json!({"text":"oi","mode":"translate"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        assert!(body["error"].as_str().unwrap().contains("language"));
        // custom without instruction → 400.
        let (st, _) = send(
            app.clone(),
            "POST",
            "/v1/ai/improve-text",
            Some("test-token"),
            Some(serde_json::json!({"text":"oi","mode":"custom"})),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);
        // Unknown mode → 400 (serde rejection).
        let (st, _) = send(
            app.clone(),
            "POST",
            "/v1/ai/improve-text",
            Some("test-token"),
            Some(serde_json::json!({"text":"oi","mode":"poetic"})),
        )
        .await;
        assert!(st.is_client_error());
    }

    #[tokio::test]
    async fn ai_routes_are_admin_only_and_readonly_gated() {
        let state = test_state();
        let mgr = state.manager.clone();
        let app = router(state);

        // Mint a per-session key: it must NOT open the instance-wide AI routes.
        let (st, body) = send(
            app.clone(),
            "POST",
            "/v1/sessions",
            Some("test-token"),
            Some(serde_json::json!({"label": "tenant"})),
        )
        .await;
        assert_eq!(st, StatusCode::CREATED);
        let key = body["api_key"].as_str().unwrap().to_string();

        for (method, uri, body) in [
            ("GET", "/v1/settings/ai", None),
            (
                "PUT",
                "/v1/settings/ai",
                Some(serde_json::json!({"provider":"anthropic","api_key":"sk-ant-test-0000abcd"})),
            ),
            ("DELETE", "/v1/settings/ai", None),
            ("POST", "/v1/settings/ai/test", None),
            (
                "POST",
                "/v1/ai/improve-text",
                Some(serde_json::json!({"text":"hello"})),
            ),
        ] {
            let (st, _) = send(app.clone(), method, uri, Some(&key), body.clone()).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{method} {uri} with session key");
            let (st, _) = send(app.clone(), method, uri, None, body.clone()).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{method} {uri} without token");
            let (st, _) = send(app.clone(), method, uri, Some("wrong"), body).await;
            assert_eq!(st, StatusCode::UNAUTHORIZED, "{method} {uri} with wrong token");
        }

        // Admin token works (GET unconfigured).
        let (st, _) = send(app.clone(), "GET", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);

        // Readonly deployment: writes blocked, reads fine.
        let ro = AppState {
            manager: mgr,
            api_token: Arc::new("test-token".into()),
            readonly: true,
            media_store: None,
        };
        let ro_app = router(ro);
        let (st, _) = send(
            ro_app.clone(),
            "PUT",
            "/v1/settings/ai",
            Some("test-token"),
            Some(serde_json::json!({"provider":"anthropic","api_key":"sk-ant-test-0000abcd"})),
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (st, _) = send(ro_app.clone(), "DELETE", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::FORBIDDEN);
        let (st, body) = send(ro_app, "GET", "/v1/settings/ai", Some("test-token"), None).await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body["configured"], false);
    }
}
