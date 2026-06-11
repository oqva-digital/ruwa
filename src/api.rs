//! HTTP API surface.
//!
//! Auth: every route under `/v1` requires `Authorization: Bearer <token>`. The
//! global `RUWA_API_TOKEN` is the admin/superuser token (all routes). A
//! `/v1/sessions/:id/*` route additionally accepts that session's own per-tenant
//! `api_key` (minted + returned once at create), scoped to just that session.
//! Convention: routes return JSON; errors flow through `error::Error`.

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

use crate::error::{Error, Result};
use crate::session::{SendOp, SessionManager, SessionMeta};

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

pub fn router(state: AppState) -> Router {
    // Stamp process start once (this is built once per process) so
    // `ruwa_process_uptime_seconds` counts from boot.
    crate::session::metrics::mark_process_start();
    let v1 = Router::new()
        .route("/config", get(config))
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
        .route("/sessions/:id/logout", post(logout_session))
        .route("/sessions/:id/proxy", post(set_session_proxy))
        .route("/sessions/:id/label", post(set_session_label))
        .route("/sessions/:id/mark-online", post(set_session_presence))
        .route("/sessions/:id/messages", get(list_messages).post(send_message))
        .route("/sessions/:id/messages/media", post(send_media))
        .route("/sessions/:id/messages/location", post(send_location))
        .route("/sessions/:id/messages/contact", post(send_contact))
        .route("/sessions/:id/messages/poll", post(send_poll))
        .route("/sessions/:id/messages/event", post(send_event))
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
}

#[derive(Deserialize)]
struct ConfirmBody {
    #[serde(default)]
    confirm: bool,
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
    let session = state.manager.create(req.label)?;
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

async fn logout_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ConfirmQuery>,
    body: axum::body::Bytes,
) -> Result<Json<SessionResp>> {
    check_session_auth_write(&headers, &state, &id)?;
    require_confirmation("logging out a session", &q, &body)?;
    state.manager.logout(&id)?;
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
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    let body = req.name.as_deref().or(req.address.as_deref()).unwrap_or("location");
    let payload = serde_json::json!({
        "type": "location",
        "latitude": req.latitude,
        "longitude": req.longitude,
        "name": req.name,
        "address": req.address,
    });
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
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    let payload = serde_json::json!({
        "type": "contact",
        "display_name": req.display_name,
        "vcard": vcard,
    });
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

    let session = state.manager.get(&id)?;
    let now = chrono::Utc::now().timestamp();
    let chat_jid = normalize_recipient_jid(&req.to);
    let msg_id = generate_message_id();
    let sender_jid = session.meta.read().jid.clone().unwrap_or_else(|| "self".into());

    // Fresh 32-byte poll secret (WA encrypts vote payloads under it).
    use rand::RngCore;
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);

    let payload = serde_json::json!({
        "type": "poll",
        "name": req.name,
        "options": req.options,
        "selectable_count": req.selectable_count,
    });
    state.manager.persist_outgoing(
        &id, &chat_jid, &msg_id, &sender_jid, "poll",
        Some(&req.name), &payload.to_string(), now,
    )?;

    let inner = crate::session::build_poll_message(
        &req.name,
        &req.options,
        req.selectable_count,
        &secret,
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
fn generate_message_id() -> String {
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
        .map_err(|e| Error::BadRequest(format!("multipart parse: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| Error::BadRequest(format!("read file field: {e}")))?;
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
    let _ = state.manager.get(&id)?;

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
        let bytes =
            std::fs::read(&path).map_err(|e| Error::Internal(anyhow::anyhow!("read: {e}")))?;
        return Ok(([(header::CONTENT_TYPE, content_type)], bytes).into_response());
    }

    // Lazy inbound download. Pull url+media_key out of payload_json,
    // map the media kind, fetch+decrypt, cache to disk, return bytes.
    let url = payload
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::NotFound("media not downloaded and url missing".into()))?;
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

    // Download through the session's proxy so media shares its egress IP.
    let proxy = state.manager.get(&id)?.meta.read().proxy_url.clone();
    let blob = crate::media::download_encrypted(url, proxy.as_deref())
        .await
        .map_err(|e| Error::Internal(anyhow::anyhow!("download: {e:?}")))?;
    let plaintext = crate::media::decrypt(&blob, &media_key, kind)
        .map_err(|e| Error::Internal(anyhow::anyhow!("decrypt: {e:?}")))?;

    // s3 mode: offload the decrypted bytes to the bucket, persist the object URL
    // (so the next GET redirects), and redirect now.
    if let Some(s3) = &state.media_store {
        let key = format!("{id}/{chat}/{msgid}");
        let object_url = crate::media::put_object(s3, &key, &plaintext, &content_type)
            .await
            .map_err(|e| Error::Internal(anyhow::anyhow!("s3 upload: {e:?}")))?;
        state
            .manager
            .store
            .message_set_media_path(&id, &chat, &msgid, &object_url)?;
        return Ok(axum::response::Redirect::temporary(&object_url).into_response());
    }

    // db mode (default): cache to data/media/<session>/<msgid>; update the row so
    // the next call is a direct fs read.
    let cache_dir = std::path::PathBuf::from("data/media").join(&id);
    std::fs::create_dir_all(&cache_dir)
        .map_err(|e| Error::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    let cache_path = cache_dir.join(&msgid);
    std::fs::write(&cache_path, &plaintext)
        .map_err(|e| Error::Internal(anyhow::anyhow!("write cache: {e}")))?;
    let cache_path_str = cache_path.to_string_lossy().into_owned();
    state
        .manager
        .store
        .message_set_media_path(&id, &chat, &msgid, &cache_path_str)?;

    Ok(([(header::CONTENT_TYPE, content_type)], plaintext).into_response())
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

/// Fetch a contact's (or group's) profile picture URL. Requires a live
/// connection. Returns `{ jid, url }`; `url` is null when there's no picture or
/// it's hidden from us.
async fn get_contact_picture(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((id, jid)): Path<(String, String)>,
    axum::extract::Query(q): axum::extract::Query<PictureQuery>,
) -> Result<Json<serde_json::Value>> {
    check_session_auth(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    let target = normalize_recipient_jid(&jid);
    let iq_id = crate::session::uuid_v4();
    let iq = crate::session::build_picture_iq(&iq_id, &target, q.preview);
    let reply = session.iq_request(iq).await?;
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
    let own_jid = session
        .meta
        .read()
        .jid
        .clone()
        .ok_or_else(|| Error::BadRequest("not paired".into()))?;
    let chat_jid = normalize_recipient_jid(&chat);
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
    let chat_jid = normalize_recipient_jid(&req.to);
    let now = chrono::Utc::now().timestamp();
    let now_ms = now * 1000;
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

async fn send_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<RevokeReq>,
) -> Result<(StatusCode, Json<SendTextResp>)> {
    check_session_auth_write(&headers, &state, &id)?;
    let session = state.manager.get(&id)?;
    let chat_jid = normalize_recipient_jid(&req.to);
    let now = chrono::Utc::now().timestamp();
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
    Ok((
        StatusCode::ACCEPTED,
        Json(SendTextResp {
            id: msg_id,
            timestamp: now,
            status: "queued",
        }),
    ))
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
}
