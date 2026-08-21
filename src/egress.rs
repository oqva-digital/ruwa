//! Event egress — the fan-out layer that ships a session's `SessionEvent`s to
//! external destinations (webhooks, Redis). This is the single source of
//! truth for turning a `SessionEvent` into JSON, so the SSE stream
//! (`GET /v1/sessions/:id/events`) and every egress transport never drift on
//! field names.
//!
//! Two shapes are produced from the same `SessionEvent::Serialize` impl:
//!
//! - **SSE** keeps emitting the *bare* tagged event, exactly as before:
//!   `{"type":"message","id":…,"chat":…,…}` — see [`event_to_sse_json`]. The SSE
//!   wire shape MUST NOT change (the dashboard reads `ev.type` + flat fields).
//! - **Egress** (webhooks/queues) wraps that same data in a delivery envelope:
//!   `{"session":…,"event":"<type>","data":{…},"ts":<unix>}` — see
//!   [`event_to_payload`]. The `data` object is the event's fields minus the
//!   relocated `type` tag.
//!
//! Also home to [`ai`] — the Console's AI text assistant (outbound LLM HTTP
//! calls to Anthropic / OpenAI-compatible endpoints), kept here because it is
//! another outbound third-party HTTP integration.
//!
//! Item A2 lands the serializer + the SSE seam; the delivery worker, signing,
//! retry, and the queue transports arrive in A4–B (hence the `#[allow(dead_code)]`
//! on the egress-only helpers until their callers exist).

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::broadcast;

use crate::session::SessionEvent;
use crate::store::{EgressTarget, Store};

/// Hard per-request timeout for a webhook POST. A slow/hanging receiver must not
/// stall the per-session delivery loop.
const WEBHOOK_TIMEOUT_SECS: u64 = 10;

/// Why a single webhook POST didn't succeed. A6 uses the distinction to decide
/// what to retry; A4 just surfaces it.
#[derive(Debug)]
pub enum DeliverError {
    /// The egress config JSON had no usable `url`.
    BadConfig,
    /// Network/timeout error issuing the request.
    Http(reqwest::Error),
    /// The receiver answered with a non-2xx status.
    Status(u16),
    /// Reading the target config from the store failed.
    Store(String),
    /// A non-HTTP transport (Redis, …) failed (connect/io/protocol).
    Transport(String),
}

impl std::fmt::Display for DeliverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliverError::BadConfig => write!(f, "webhook target has no url"),
            DeliverError::Http(e) => write!(f, "http error: {e}"),
            DeliverError::Status(c) => write!(f, "non-2xx status: {c}"),
            DeliverError::Store(e) => write!(f, "store error: {e}"),
            DeliverError::Transport(e) => write!(f, "transport error: {e}"),
        }
    }
}

/// Build the reqwest client used for webhook delivery: a direct connection
/// (NOT through the WhatsApp egress proxy — the webhook goes to the customer's
/// own server) with a hard timeout.
pub fn webhook_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(WEBHOOK_TIMEOUT_SECS))
        .build()
        .unwrap_or_default()
}

/// Extract the destination URL from a webhook target's `config` JSON.
fn target_url(t: &EgressTarget) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(&t.config)
        .ok()
        .and_then(|v| v.get("url").and_then(|u| u.as_str()).map(str::to_string))
}

/// Hex-encoded HMAC-SHA256 of `msg` under `key` (shared with the Cloud API
/// webhook signature check — one implementation for both directions).
fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    crate::cloud::hmac_sha256_hex(key, msg)
}

/// POST one payload to a webhook target. Returns `Ok(())` on a 2xx response.
///
/// The body is the exact UTF-8 of the envelope, sent raw (so signature and bytes
/// match). Every delivery carries:
/// - `X-Ruwa-Event`: the event type tag.
/// - `X-Ruwa-Delivery`: a unique id for this attempt (receiver dedup/logging).
/// - `X-Ruwa-Signature: sha256=<hex>`: HMAC-SHA256 of the body under the target
///   secret — present only when a secret is configured. (Retry/backoff: A6.)
pub async fn deliver_webhook(
    client: &reqwest::Client,
    target: &EgressTarget,
    payload: &serde_json::Value,
) -> Result<(), DeliverError> {
    let url = target_url(target).ok_or(DeliverError::BadConfig)?;
    let body = serde_json::to_vec(payload).unwrap_or_default();
    let event_type = payload
        .get("event")
        .and_then(|e| e.as_str())
        .unwrap_or("")
        .to_string();
    let delivery_id = crate::session::uuid_v4();

    let mut req = client
        .post(&url)
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header("X-Ruwa-Event", event_type)
        .header("X-Ruwa-Delivery", delivery_id)
        .body(body.clone());
    if let Some(secret) = target.secret.as_deref().filter(|s| !s.is_empty()) {
        let sig = hmac_sha256_hex(secret.as_bytes(), &body);
        req = req.header("X-Ruwa-Signature", format!("sha256={sig}"));
    }

    let resp = req.send().await.map_err(DeliverError::Http)?;
    let code = resp.status().as_u16();
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(DeliverError::Status(code))
    }
}

/// Default retry budget for a webhook delivery: the first attempt plus up to
/// `MAX_RETRIES` more, with an equal-jittered exponential backoff starting at
/// `RETRY_BASE`. Kept small so a dead receiver doesn't wedge the delivery loop.
const MAX_RETRIES: u32 = 3;
const RETRY_BASE: Duration = Duration::from_millis(500);

/// Equal-jitter a backoff: keep half the delay, randomize the other half.
fn jittered(base: Duration) -> Duration {
    use rand::Rng;
    let half = base.as_millis() as u64 / 2;
    let extra = rand::thread_rng().gen_range(0..=half.max(1));
    Duration::from_millis(half + extra)
}

/// Deliver one envelope with retries: on a non-2xx/network error, back off
/// (jittered, doubling) and retry up to `max_retries` more times. A `BadConfig`
/// error is terminal (retrying won't fix a missing URL). On final outcome it
/// bumps the `ruwa_webhook_{delivered,failed}_total` counters.
pub async fn deliver_with_retry(
    client: &reqwest::Client,
    target: &EgressTarget,
    payload: &serde_json::Value,
    max_retries: u32,
    base: Duration,
) -> Result<(), DeliverError> {
    use crate::session::metrics;
    let mut backoff = base;
    let mut attempt = 0;
    loop {
        match deliver_webhook(client, target, payload).await {
            Ok(()) => {
                metrics::incr(&metrics::WEBHOOK_DELIVERED_TOTAL);
                return Ok(());
            }
            Err(DeliverError::BadConfig) => {
                // Misconfiguration — no point retrying or counting as a transient
                // failure; the worker logs nothing for this case.
                return Err(DeliverError::BadConfig);
            }
            Err(e) => {
                if attempt >= max_retries {
                    metrics::incr(&metrics::WEBHOOK_FAILED_TOTAL);
                    return Err(e);
                }
                tokio::time::sleep(jittered(backoff)).await;
                backoff = backoff.saturating_mul(2);
                attempt += 1;
            }
        }
    }
}

/// Whether an event type passes a target's CSV allowlist. An empty/absent filter
/// means "all events"; otherwise the type must appear in the comma-separated set
/// (surrounding whitespace ignored).
fn event_allowed(filter: &Option<String>, etype: &str) -> bool {
    match filter.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        None => true,
        Some(csv) => csv.split(',').map(str::trim).any(|t| t == etype),
    }
}

/// Whether a target should fire for this event type: enabled + passes its
/// allowlist. (Pure — the fan-out selection decision.)
fn should_fire(target: &EgressTarget, etype: &str) -> bool {
    target.enabled && event_allowed(&target.events, etype)
}

/// Publish one envelope to a Redis target (open conn → AUTH → RPUSH/PUBLISH).
async fn deliver_redis(target: &EgressTarget, body: &[u8]) -> Result<(), DeliverError> {
    let cfg = RedisConfig::from_target(target)?;
    let transport = RedisTransport::new(cfg)?;
    transport.publish(body).await
}

/// Fan one event out to **every** enabled egress target for the session
/// (webhook + redis), each independently event-filtered and **error-isolated** —
/// a failing/misconfigured target never blocks the others. Only a failure to
/// *list* the targets propagates. Config is read per-event so edits take effect
/// live.
pub async fn deliver_event(
    store: &Store,
    client: &reqwest::Client,
    session_id: &str,
    ev: &SessionEvent,
    ts: i64,
) -> Result<(), DeliverError> {
    let targets = store
        .egress_list_for_session(session_id)
        .map_err(|e| DeliverError::Store(e.to_string()))?;
    if targets.is_empty() {
        return Ok(());
    }
    let etype = event_type(ev);
    let payload = event_to_payload(session_id, ev, ts);
    let body = serde_json::to_vec(&payload).unwrap_or_default();
    // Message id, when this is a chat message — logged on delivery so a
    // "did this message reach the webhook?" question is answerable by grep
    // instead of deduced from the absence of a failure.
    let msg_id = match ev {
        SessionEvent::Message { id, .. } => Some(id.as_str()),
        _ => None,
    };

    for target in targets {
        if !should_fire(&target, &etype) {
            continue;
        }
        let result = match target.kind.as_str() {
            // "webhook" is the primary; "webhook:<label>" are additional ones.
            // A session may register many — each is delivered independently.
            k if k == "webhook" || k.starts_with("webhook:") => {
                deliver_with_retry(client, &target, &payload, MAX_RETRIES, RETRY_BASE).await
            }
            "redis" => deliver_redis(&target, &body).await,
            other => {
                tracing::debug!(kind = other, "unknown egress kind; skipping");
                Ok(())
            }
        };
        match result {
            Ok(()) => {
                // Log SUCCESSFUL delivery (previously only a metric counter, so
                // "was it delivered?" was invisible in the logs). INFO so it lands
                // in the persisted ring.
                tracing::info!(
                    session = %session_id, kind = %target.kind, event = %etype, msg_id = ?msg_id,
                    "egress delivered"
                );
            }
            Err(DeliverError::BadConfig) => {}
            Err(e) => {
                tracing::warn!(
                    session = %session_id, kind = %target.kind, event = %etype, msg_id = ?msg_id, error = %e,
                    "egress delivery failed (isolated)"
                );
            }
        }
    }
    Ok(())
}

/// Spawn the per-session egress delivery task. It subscribes to the session's
/// event bus and fans each event out to every configured target (webhook + redis),
/// looked up per event so config changes take effect live. The task ends naturally
/// when the session is dropped (the broadcast sender closes). Spawn it exactly once
/// per session — `Session::ensure_egress_worker` guards that.
pub fn spawn_egress_worker(
    store: Arc<Store>,
    session_id: String,
    mut rx: broadcast::Receiver<SessionEvent>,
) -> tokio::task::JoinHandle<()> {
    let client = webhook_client();
    tokio::spawn(async move {
        // Persisted-log retention: keep at most this many events per session and
        // drop anything older than the age window. Pruned every N inserts so the
        // DELETE cost is amortised, not paid per event.
        const LOG_KEEP_MAX: i64 = 5_000;
        const LOG_MAX_AGE_MS: i64 = 14 * 24 * 60 * 60 * 1_000;
        const PRUNE_EVERY: u32 = 256;
        let mut since_prune: u32 = 0;
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let ts = chrono::Utc::now().timestamp();

                    // Persist to the event log first — this is the one consumer
                    // guaranteed to run for every connected session, so it's where
                    // the dashboard Logs history is recorded. Best-effort: a log
                    // write failure must never block egress delivery.
                    let ts_ms = ts * 1_000;
                    let etype = event_type(&ev);
                    let payload = event_to_sse_json(&ev);
                    if let Err(e) = store.event_log_insert(&session_id, ts_ms, &etype, &payload) {
                        tracing::warn!(session = %session_id, error = %e, "event-log insert failed");
                    } else {
                        since_prune += 1;
                        if since_prune >= PRUNE_EVERY {
                            since_prune = 0;
                            let cutoff = ts_ms - LOG_MAX_AGE_MS;
                            if let Err(e) =
                                store.event_log_prune(&session_id, LOG_KEEP_MAX, cutoff)
                            {
                                tracing::warn!(session = %session_id, error = %e, "event-log prune failed");
                            }
                        }
                    }

                    // Per-target errors are isolated + logged inside deliver_event;
                    // only a failure to list targets surfaces here.
                    if let Err(e) = deliver_event(&store, &client, &session_id, &ev, ts).await {
                        tracing::warn!(session = %session_id, error = %e, "egress target lookup failed");
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // The worker fell behind and the channel dropped `n` events
                    // before this one — those were NEVER delivered to any target.
                    // Was silent; now surfaced so a webhook gap traces to a real
                    // cause instead of a mystery.
                    tracing::warn!(
                        session = %session_id, dropped = n,
                        "egress broadcast lagged — events DROPPED (not delivered to webhook/redis)"
                    );
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            }
        }
    })
}

/// The exact JSON bytes the SSE stream emits for one event: the bare,
/// `type`-tagged `SessionEvent`. Falls back to `{}` if serialization ever fails
/// (it can't, for these plain variants).
pub fn event_to_sse_json(ev: &SessionEvent) -> String {
    serde_json::to_string(ev).unwrap_or_else(|_| "{}".into())
}

/// The event's type tag (the `#[serde(tag = "type")]` discriminant), e.g.
/// `"message"`, `"connected"`, `"qr"`. Used by egress event-type filtering.
pub fn event_type(ev: &SessionEvent) -> String {
    serde_json::to_value(ev)
        .ok()
        .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

/// Build the egress delivery envelope for one event:
/// `{ "session": <id>, "event": <type>, "data": { …event fields… }, "ts": <unix> }`.
///
/// Reuses `SessionEvent`'s own `Serialize` impl as the single source of truth:
/// the event is serialized once, its `type` tag is lifted into `event`, and the
/// remaining fields become `data`. This is the payload POSTed to webhooks and
/// published to RabbitMQ/SQS.
pub fn event_to_payload(session_id: &str, ev: &SessionEvent, ts: i64) -> serde_json::Value {
    let mut v = serde_json::to_value(ev).unwrap_or_else(|_| serde_json::json!({}));
    let event_type = v
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("unknown")
        .to_string();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("type");
    }
    serde_json::json!({
        "session": session_id,
        "event": event_type,
        "data": v,
        "ts": ts,
    })
}

// ===== Redis (RESP) — in-house wire codec ===================================
//
// We hand-roll the Redis serialization protocol (RESP) rather than pull the
// `redis` crate — RESP is a tiny text protocol and keeping it in-house fits the
// lean-codebase rule. B1 is the pure codec (encode a command, parse a reply);
// B2 wires it to a TCP connection (`RedisTransport`). Hence `#[allow(dead_code)]`
// until B2.

/// A parsed RESP reply value.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RespValue {
    /// `+OK\r\n`
    Simple(String),
    /// `-ERR ...\r\n`
    Error(String),
    /// `:123\r\n`
    Int(i64),
    /// `$len\r\n<bytes>\r\n`, or `$-1\r\n` (null) → `None`.
    Bulk(Option<Vec<u8>>),
    /// `*N\r\n…`, or `*-1\r\n` (null) → `None`.
    Array(Option<Vec<RespValue>>),
}

/// RESP parse outcome distinguishing "need more bytes" from a protocol error.
#[allow(dead_code)]
#[derive(Debug)]
pub enum RespError {
    /// The buffer holds a partial reply — read more and retry.
    Incomplete,
    /// Malformed RESP.
    Protocol(String),
}

/// Encode a command as a RESP array of bulk strings:
/// `*N\r\n$len\r\n<arg>\r\n…`. e.g. `["RPUSH", key, payload]`.
#[allow(dead_code)]
pub fn encode_command(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("*{}\r\n", args.len()).as_bytes());
    for a in args {
        out.extend_from_slice(format!("${}\r\n", a.len()).as_bytes());
        out.extend_from_slice(a);
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Find the CRLF-terminated line starting at `pos`; return (line-without-CRLF,
/// index-after-CRLF).
fn resp_line(buf: &[u8], pos: usize) -> Result<(&[u8], usize), RespError> {
    if pos > buf.len() {
        return Err(RespError::Incomplete);
    }
    let rest = &buf[pos..];
    match rest.windows(2).position(|w| w == b"\r\n") {
        Some(i) => Ok((&rest[..i], pos + i + 2)),
        None => Err(RespError::Incomplete),
    }
}

fn resp_int(line: &[u8]) -> Result<i64, RespError> {
    std::str::from_utf8(line)
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .ok_or_else(|| RespError::Protocol(format!("bad integer: {line:?}")))
}

fn resp_parse_at(buf: &[u8], pos: usize) -> Result<(RespValue, usize), RespError> {
    if pos >= buf.len() {
        return Err(RespError::Incomplete);
    }
    let kind = buf[pos];
    let (line, next) = resp_line(buf, pos + 1)?;
    match kind {
        b'+' => Ok((RespValue::Simple(String::from_utf8_lossy(line).into_owned()), next)),
        b'-' => Ok((RespValue::Error(String::from_utf8_lossy(line).into_owned()), next)),
        b':' => Ok((RespValue::Int(resp_int(line)?), next)),
        b'$' => {
            let len = resp_int(line)?;
            if len < 0 {
                return Ok((RespValue::Bulk(None), next));
            }
            let len = len as usize;
            let end = next + len;
            if end + 2 > buf.len() {
                return Err(RespError::Incomplete);
            }
            Ok((RespValue::Bulk(Some(buf[next..end].to_vec())), end + 2))
        }
        b'*' => {
            let count = resp_int(line)?;
            if count < 0 {
                return Ok((RespValue::Array(None), next));
            }
            let mut items = Vec::with_capacity(count as usize);
            let mut p = next;
            for _ in 0..count {
                let (v, np) = resp_parse_at(buf, p)?;
                items.push(v);
                p = np;
            }
            Ok((RespValue::Array(Some(items)), p))
        }
        other => Err(RespError::Protocol(format!("unknown RESP type byte: {other:#x}"))),
    }
}

/// Parse one RESP reply from the front of `buf`. Returns the value and the number
/// of bytes consumed, or `Incomplete` if more bytes are needed.
#[allow(dead_code)]
pub fn parse_reply(buf: &[u8]) -> Result<(RespValue, usize), RespError> {
    resp_parse_at(buf, 0)
}

/// A queue/stream egress transport (Redis today; the seam keeps the fan-out
/// worker transport-agnostic). `publish` ships one serialized event envelope.
#[allow(dead_code)]
#[async_trait::async_trait]
pub trait EgressTransport: Send + Sync {
    async fn publish(&self, body: &[u8]) -> Result<(), DeliverError>;
}

/// How a Redis target delivers events: append to a durable list (`RPUSH`, drained
/// by `BLPOP` consumers) or fan out on a channel (`PUBLISH`).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedisMode {
    List,
    PubSub,
}

/// Parsed Redis egress config (from the `egress_targets.config` JSON).
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedisConfig {
    /// `redis://[:password@]host:port[/db]`.
    pub url: String,
    pub mode: RedisMode,
    /// List key (RPUSH) or channel name (PUBLISH).
    pub key: String,
}

#[allow(dead_code)]
impl RedisConfig {
    /// Parse `{ "url":…, "mode":"list"|"pubsub", "key":… }` from a target.
    pub fn from_target(t: &EgressTarget) -> Result<Self, DeliverError> {
        let v: serde_json::Value =
            serde_json::from_str(&t.config).map_err(|_| DeliverError::BadConfig)?;
        let url = v.get("url").and_then(|u| u.as_str()).ok_or(DeliverError::BadConfig)?;
        let key = v.get("key").and_then(|k| k.as_str()).ok_or(DeliverError::BadConfig)?;
        let mode = match v.get("mode").and_then(|m| m.as_str()).unwrap_or("list") {
            "pubsub" | "publish" => RedisMode::PubSub,
            _ => RedisMode::List,
        };
        Ok(Self { url: url.to_string(), mode, key: key.to_string() })
    }
}

/// Split a `redis://[:password@]host:port[/db]` URL into (host, port, password).
#[allow(dead_code)]
fn parse_redis_url(url: &str) -> Result<(String, u16, Option<String>), DeliverError> {
    let parsed = url::Url::parse(url).map_err(|_| DeliverError::BadConfig)?;
    let host = parsed.host_str().ok_or(DeliverError::BadConfig)?.to_string();
    let port = parsed.port().unwrap_or(6379);
    let password = parsed.password().filter(|p| !p.is_empty()).map(str::to_string);
    Ok((host, port, password))
}

/// The RESP commands to publish one `body`: an optional `AUTH`, then the
/// `RPUSH key body` (list) or `PUBLISH channel body` (pubsub). Pure — the
/// unit-testable core of the Redis transport.
#[allow(dead_code)]
fn redis_publish_commands(cfg: &RedisConfig, password: Option<&str>, body: &[u8]) -> Vec<Vec<u8>> {
    let mut cmds = Vec::new();
    if let Some(pw) = password {
        cmds.push(encode_command(&[b"AUTH", pw.as_bytes()]));
    }
    let verb: &[u8] = match cfg.mode {
        RedisMode::List => b"RPUSH",
        RedisMode::PubSub => b"PUBLISH",
    };
    cmds.push(encode_command(&[verb, cfg.key.as_bytes(), body]));
    cmds
}

/// Redis egress transport. Opens a fresh TCP connection per publish (events are
/// low-frequency; pooling is a future optimization), AUTHs if the URL carries a
/// password, then RPUSH/PUBLISH the envelope. The live connection is exercised by
/// the B-live (`[human-gate]`) test, not in-loop.
#[allow(dead_code)]
pub struct RedisTransport {
    cfg: RedisConfig,
    host: String,
    port: u16,
    password: Option<String>,
}

#[allow(dead_code)]
impl RedisTransport {
    pub fn new(cfg: RedisConfig) -> Result<Self, DeliverError> {
        let (host, port, password) = parse_redis_url(&cfg.url)?;
        Ok(Self { cfg, host, port, password })
    }
}

/// Read one full RESP reply from `stream`, buffering across reads until a
/// complete reply parses.
#[allow(dead_code)]
async fn read_one_reply<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut Vec<u8>,
) -> Result<RespValue, DeliverError> {
    use tokio::io::AsyncReadExt;
    loop {
        match parse_reply(buf) {
            Ok((v, consumed)) => {
                buf.drain(..consumed);
                return Ok(v);
            }
            Err(RespError::Incomplete) => {
                let mut tmp = [0u8; 1024];
                let n = stream
                    .read(&mut tmp)
                    .await
                    .map_err(|e| DeliverError::Transport(e.to_string()))?;
                if n == 0 {
                    return Err(DeliverError::Transport("redis closed the connection".into()));
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Err(RespError::Protocol(e)) => return Err(DeliverError::Transport(e)),
        }
    }
}

#[async_trait::async_trait]
impl EgressTransport for RedisTransport {
    async fn publish(&self, body: &[u8]) -> Result<(), DeliverError> {
        use tokio::io::AsyncWriteExt;
        let mut stream = tokio::net::TcpStream::connect((self.host.as_str(), self.port))
            .await
            .map_err(|e| DeliverError::Transport(format!("connect {}:{}: {e}", self.host, self.port)))?;
        let cmds = redis_publish_commands(&self.cfg, self.password.as_deref(), body);
        let mut rbuf = Vec::new();
        for cmd in &cmds {
            stream
                .write_all(cmd)
                .await
                .map_err(|e| DeliverError::Transport(e.to_string()))?;
            // Each command yields exactly one reply; a -ERR (e.g. bad AUTH) fails.
            if let RespValue::Error(e) = read_one_reply(&mut stream, &mut rbuf).await? {
                return Err(DeliverError::Transport(format!("redis error: {e}")));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AI text assistant — outbound third-party LLM HTTP integration
// ---------------------------------------------------------------------------

/// The Console's AI text assistant: rewrites a draft WhatsApp message
/// ("improve", "more formal", "translate to …") by calling an LLM provider over
/// raw HTTP — Anthropic's Messages API or any OpenAI-compatible
/// `/chat/completions` endpoint (OpenAI, OpenRouter, Groq, Ollama, …).
///
/// Lives in `egress` because, like webhooks and Redis, it is an *outbound*
/// third-party HTTP integration (and `src/` is capped at ten files). The
/// instance-wide config (`AiConfig`) is stored sealed under the `app_settings`
/// key [`SETTING_KEY`]; the HTTP surface (`/v1/settings/ai`,
/// `/v1/ai/improve-text`) lives in `api.rs`. No SDK: request bodies and
/// response parsing are hand-rolled and unit-tested against fixtures here.
pub mod ai {
    use std::time::{Duration, Instant};

    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};

    /// `app_settings.key` under which the JSON-encoded [`AiConfig`] lives.
    pub const SETTING_KEY: &str = "ai";
    /// Default model for the Anthropic provider (the OpenAI-compatible provider
    /// has no sensible default — gateways differ — so its model is required).
    pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5";
    pub const DEFAULT_ANTHROPIC_BASE_URL: &str = "https://api.anthropic.com";
    pub const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
    /// Hard cap on the draft passed to `improve-text` (chars).
    pub const MAX_TEXT_CHARS: usize = 8000;
    /// Hard cap on a `custom` mode instruction (chars).
    pub const MAX_INSTRUCTION_CHARS: usize = 500;
    /// Hard cap on a `translate` mode target language (chars).
    pub const MAX_LANGUAGE_CHARS: usize = 64;
    /// Per-request upstream timeout. A timed-out attempt is NOT retried: the
    /// model already spent ~a minute on it, a second pass would just double
    /// the bill and the wait.
    const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
    /// Retries on 429 / 5xx / connection failures (in addition to the first
    /// attempt).
    const MAX_RETRIES: u32 = 2;
    /// Backoff before retry `n` (1-based): 500 ms, 1 s.
    const RETRY_BASE: Duration = Duration::from_millis(500);
    /// Anthropic API version header value.
    const ANTHROPIC_VERSION: &str = "2023-06-01";
    /// Beta header enabling server-side refusal fallbacks (`"fallbacks":
    /// "default"`) on the Opus 5 / Fable 5 family.
    const ANTHROPIC_FALLBACK_BETA: &str = "server-side-fallback-2026-07-01";
    /// Max output tokens requested from the model. A ceiling, not a target:
    /// on Opus 5 adaptive thinking is always on and its tokens count against
    /// `max_tokens`, so a tight cap would truncate long rewrites (the draft is
    /// up to 8000 chars). Truncation is detected and reported, never returned
    /// as if it were the full rewrite.
    const MAX_OUTPUT_TOKENS: u32 = 16000;
    /// Max chars of an upstream error message echoed back to the client.
    const ERROR_EXCERPT_CHARS: usize = 200;

    /// Default system prompt when `AiConfig.system_prompt` is unset.
    pub const DEFAULT_SYSTEM_PROMPT: &str = "You are a writing assistant for WhatsApp messages \
sent by a business or person. Rewrite the user's draft according to the instruction. Keep the \
original meaning, language and tone register unless the instruction says otherwise; preserve \
names, numbers, dates, prices, links, emojis and line breaks that carry meaning. Keep it natural \
for WhatsApp (short paragraphs, no markdown headings). Output ONLY the rewritten message — no \
preamble, no quotes, no explanations.";

    /// Which upstream API dialect to speak.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum Provider {
        Anthropic,
        Openai,
    }

    impl Provider {
        pub fn as_str(self) -> &'static str {
            match self {
                Provider::Anthropic => "anthropic",
                Provider::Openai => "openai",
            }
        }

        pub fn default_base_url(self) -> &'static str {
            match self {
                Provider::Anthropic => DEFAULT_ANTHROPIC_BASE_URL,
                Provider::Openai => DEFAULT_OPENAI_BASE_URL,
            }
        }

        /// Default model, when the provider has one.
        pub fn default_model(self) -> Option<&'static str> {
            match self {
                Provider::Anthropic => Some(DEFAULT_ANTHROPIC_MODEL),
                Provider::Openai => None,
            }
        }
    }

    /// Instance-wide assistant configuration, JSON-encoded under
    /// `app_settings['ai']` (sealed at rest — it carries the API key).
    #[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct AiConfig {
        pub provider: Provider,
        pub api_key: String,
        pub model: String,
        /// `None` → the provider default.
        #[serde(default)]
        pub base_url: Option<String>,
        /// `None` → [`DEFAULT_SYSTEM_PROMPT`].
        #[serde(default)]
        pub system_prompt: Option<String>,
    }

    /// Hand-rolled so a stray `{:?}` (log line, `assert_eq!` failure, panic
    /// message) can never print the key — only its masked hint.
    impl std::fmt::Debug for AiConfig {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AiConfig")
                .field("provider", &self.provider)
                .field("api_key", &self.api_key_hint())
                .field("model", &self.model)
                .field("base_url", &self.base_url)
                .field("system_prompt", &self.system_prompt)
                .finish()
        }
    }

    impl AiConfig {
        /// Base URL actually used for requests (explicit or provider default),
        /// with any trailing slash removed so path joins are predictable.
        pub fn effective_base_url(&self) -> String {
            let raw = self
                .base_url
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| self.provider.default_base_url());
            raw.trim_end_matches('/').to_string()
        }

        /// The system prompt in force (custom or default).
        pub fn effective_system_prompt(&self) -> &str {
            self.system_prompt
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or(DEFAULT_SYSTEM_PROMPT)
        }

        /// `••••abcd` — the last four chars of the key, never more. Keys shorter
        /// than eight chars are fully masked (a 4-char tail would be the key).
        pub fn api_key_hint(&self) -> String {
            api_key_hint(&self.api_key)
        }
    }

    /// Mask an API key for display: `••••` + last four chars (or all dots when
    /// the key is too short for a tail to be safe).
    pub fn api_key_hint(key: &str) -> String {
        let chars: Vec<char> = key.chars().collect();
        if chars.len() < 8 {
            return "••••".to_string();
        }
        let tail: String = chars[chars.len() - 4..].iter().collect();
        format!("••••{tail}")
    }

    /// What to do with the draft.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "lowercase")]
    pub enum AiMode {
        #[default]
        Improve,
        Formal,
        Casual,
        Shorter,
        Grammar,
        Translate,
        Custom,
    }

    /// Turn a mode (+ its optional argument) into the instruction line of the
    /// user prompt. `Err(msg)` is a caller error (400): `translate` needs a
    /// `language`, `custom` needs a non-empty `instruction` ≤ 500 chars.
    pub fn mode_instruction(
        mode: AiMode,
        language: Option<&str>,
        instruction: Option<&str>,
    ) -> Result<String, String> {
        Ok(match mode {
            AiMode::Improve => {
                "Improve clarity, flow and correctness while keeping the same length and tone."
                    .to_string()
            }
            AiMode::Formal => "Make it more formal and professional.".to_string(),
            AiMode::Casual => "Make it more casual and friendly.".to_string(),
            AiMode::Shorter => {
                "Make it significantly shorter without losing key information.".to_string()
            }
            AiMode::Grammar => {
                "Fix spelling, grammar and punctuation only; change nothing else.".to_string()
            }
            AiMode::Translate => {
                let lang = language
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "mode=translate requires \"language\"".to_string())?;
                if lang.chars().count() > MAX_LANGUAGE_CHARS {
                    return Err(format!(
                        "\"language\" must be at most {MAX_LANGUAGE_CHARS} characters"
                    ));
                }
                format!("Translate it to {lang}.")
            }
            AiMode::Custom => {
                let ins = instruction
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| "mode=custom requires \"instruction\"".to_string())?;
                if ins.chars().count() > MAX_INSTRUCTION_CHARS {
                    return Err(format!(
                        "\"instruction\" must be at most {MAX_INSTRUCTION_CHARS} characters"
                    ));
                }
                ins.to_string()
            }
        })
    }

    /// The user turn sent to the model.
    pub fn build_user_prompt(instruction: &str, text: &str) -> String {
        format!("Instruction: {instruction}\n\nDraft:\n{text}")
    }

    /// Normalize the model's answer: trim whitespace and strip one layer of
    /// surrounding quotes (models sometimes quote the rewrite despite the
    /// "no quotes" instruction).
    pub fn clean_reply(raw: &str) -> String {
        let stripped = strip_reasoning_blocks(raw);
        let mut s = stripped.trim();
        const PAIRS: &[(char, char)] = &[('"', '"'), ('“', '”'), ('\'', '\''), ('«', '»')];
        for (open, close) in PAIRS {
            if s.chars().count() >= 2 && s.starts_with(*open) && s.ends_with(*close) {
                let inner = &s[open.len_utf8()..s.len() - close.len_utf8()];
                // Only strip when the quotes wrap the WHOLE reply (no unbalanced
                // inner quote of the same kind at the edges, e.g. `"a" and "b"`).
                if !inner.contains(*close) || open == close && !inner.contains(*open) {
                    s = inner.trim();
                }
                break;
            }
        }
        s.to_string()
    }

    /// Token the model must answer with when it will not rewrite the draft.
    /// Appended to EVERY system prompt (default or custom) via
    /// [`system_prompt_with_protocol`]; [`finalize_reply`] turns it into
    /// [`AiError::Refusal`] (→ 422) so a refusal never reaches the composer
    /// looking like a rewrite. Providers that signal refusals out-of-band
    /// (Anthropic `stop_reason`, OpenAI `content_filter`) are still caught
    /// earlier in the parsers; this covers models that refuse in prose.
    pub const REFUSAL_SENTINEL: &str = "[[REFUSED]]";

    /// Fixed protocol paragraph appended after the (default or custom) system
    /// prompt. Kept out of the user-editable prompt so it can't be lost.
    pub const SYSTEM_PROTOCOL_SUFFIX: &str = "\n\nResponse protocol (always applies): \
        output only the final message text — no preamble, no quotes, no commentary, \
        and never include your reasoning or <think> tags. If for any reason you will \
        not rewrite the draft, reply with exactly [[REFUSED]] and nothing else.";

    /// The system prompt actually sent: `effective_system_prompt()` +
    /// [`SYSTEM_PROTOCOL_SUFFIX`].
    pub fn system_prompt_with_protocol(cfg: &AiConfig) -> String {
        format!("{}{}", cfg.effective_system_prompt(), SYSTEM_PROTOCOL_SUFFIX)
    }

    /// [`clean_reply`] + refusal-sentinel detection. A reply that is (or
    /// contains) [`REFUSAL_SENTINEL`], or that is empty after cleaning, is a
    /// refusal — never hand that back as a rewrite.
    pub fn finalize_reply(raw: &str) -> Result<String, AiError> {
        let cleaned = clean_reply(raw);
        if cleaned.is_empty() || cleaned.contains(REFUSAL_SENTINEL) {
            return Err(AiError::Refusal);
        }
        Ok(cleaned)
    }

    /// Tags some OpenAI-compatible reasoning models (DeepSeek-R1, Qwen3, …)
    /// use to inline their chain of thought in `message.content`.
    const REASONING_TAGS: &[&str] = &["think", "thinking", "reasoning", "thought"];

    /// Drop inlined chain-of-thought from a reply: `<think>…</think>` blocks
    /// (any of `REASONING_TAGS`, case-insensitive) are removed wherever they
    /// appear; an unterminated opening tag drops everything after it; a stray
    /// closing tag with no opener drops everything before it (the model started
    /// mid-thought). Anthropic never puts thinking in text blocks, so this only
    /// matters for the OpenAI-compatible path — but it is harmless there.
    pub fn strip_reasoning_blocks(raw: &str) -> String {
        let mut out = raw.to_string();
        for tag in REASONING_TAGS {
            let open = format!("<{tag}>");
            let close = format!("</{tag}>");
            loop {
                let lower = out.to_ascii_lowercase();
                match (lower.find(&open), lower.find(&close)) {
                    (Some(o), Some(c)) if c > o => {
                        out.replace_range(o..c + close.len(), "");
                    }
                    (Some(o), Some(_)) | (Some(o), None) => {
                        // Closing tag before the opener (or none at all): the
                        // opener starts an unterminated thought → cut the tail.
                        out.truncate(o);
                        break;
                    }
                    (None, Some(c)) => {
                        // Stray closer: everything before it was thought.
                        out.replace_range(..c + close.len(), "");
                    }
                    (None, None) => break,
                }
            }
        }
        out
    }

    /// Why a provider call failed. `api.rs` maps `Refusal` → 422 and everything
    /// else → 502 (`"ai upstream: …"`). Never carries the API key.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum AiError {
        /// Non-2xx from the provider (after retries), with an excerpt of its
        /// error message.
        Upstream { status: u16, message: String },
        /// The model declined to rewrite (Anthropic `stop_reason: "refusal"`,
        /// or an OpenAI `finish_reason: "content_filter"`).
        Refusal,
        /// Network / TLS failure talking to the provider (retried).
        Transport(String),
        /// The provider didn't answer within [`REQUEST_TIMEOUT`] (not retried).
        Timeout,
        /// The model hit `max_tokens` before finishing (Anthropic `stop_reason:
        /// "max_tokens"`, OpenAI `finish_reason: "length"`). The partial text
        /// is discarded rather than handed back as a "rewrite".
        Truncated,
        /// 2xx but the body wasn't in the expected shape (or was empty).
        BadResponse(String),
    }

    impl std::fmt::Display for AiError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                AiError::Upstream { status, message } => {
                    write!(f, "ai upstream: {status} {message}")
                }
                AiError::Refusal => write!(f, "ai declined to rewrite this text"),
                AiError::Transport(m) => write!(f, "ai upstream: request failed: {m}"),
                AiError::Timeout => write!(f, "ai upstream: request timed out"),
                AiError::Truncated => {
                    write!(f, "ai upstream: reply was cut off (max_tokens); try a shorter draft")
                }
                AiError::BadResponse(m) => write!(f, "ai upstream: unexpected response: {m}"),
            }
        }
    }

    impl AiError {
        /// HTTP status the API surfaces this error as.
        pub fn http_status(&self) -> u16 {
            match self {
                AiError::Refusal => 422,
                _ => 502,
            }
        }
    }

    /// Should the Anthropic request opt into server-side refusal fallbacks?
    /// Only the Opus 5 / Fable 5 family supports (and needs) them.
    pub fn anthropic_uses_fallbacks(model: &str) -> bool {
        model.starts_with("claude-opus-5") || model.starts_with("claude-fable-5")
    }

    /// Anthropic Messages API request body. No `temperature`/`top_p`/`thinking`
    /// — Opus 5 runs adaptive thinking by default and rejects sampling params.
    pub fn anthropic_request_body(model: &str, system: &str, user: &str) -> Value {
        let mut body = json!({
            "model": model,
            "max_tokens": MAX_OUTPUT_TOKENS,
            "system": system,
            "messages": [{ "role": "user", "content": user }],
        });
        if anthropic_uses_fallbacks(model) {
            body["fallbacks"] = json!("default");
        }
        body
    }

    /// OpenAI-compatible `/chat/completions` request body.
    pub fn openai_request_body(model: &str, system: &str, user: &str) -> Value {
        json!({
            "model": model,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
        })
    }

    /// Extract the reply text from an Anthropic Messages response: the
    /// concatenation of every `content[].text` where `type == "text"`.
    /// `stop_reason: "refusal"` → [`AiError::Refusal`].
    pub fn parse_anthropic_response(v: &Value) -> Result<String, AiError> {
        match v.get("stop_reason").and_then(Value::as_str) {
            Some("refusal") => return Err(AiError::Refusal),
            Some("max_tokens") => return Err(AiError::Truncated),
            _ => {}
        }
        let content = v
            .get("content")
            .and_then(Value::as_array)
            .ok_or_else(|| AiError::BadResponse("missing content[]".into()))?;
        let text: String = content
            .iter()
            .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
            .filter_map(|b| b.get("text").and_then(Value::as_str))
            .collect();
        if text.trim().is_empty() {
            return Err(AiError::BadResponse("empty reply".into()));
        }
        Ok(text)
    }

    /// Extract `choices[0].message.content` from an OpenAI-compatible response.
    /// `finish_reason: "content_filter"` → [`AiError::Refusal`].
    pub fn parse_openai_response(v: &Value) -> Result<String, AiError> {
        let choice = v
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|c| c.first())
            .ok_or_else(|| AiError::BadResponse("missing choices[0]".into()))?;
        match choice.get("finish_reason").and_then(Value::as_str) {
            Some("content_filter") => return Err(AiError::Refusal),
            Some("length") => return Err(AiError::Truncated),
            _ => {}
        }
        let content = choice.get("message").and_then(|m| m.get("content"));
        let text = match content {
            Some(Value::String(s)) => s.clone(),
            // Some gateways return content as an array of typed parts.
            Some(Value::Array(parts)) => parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect(),
            _ => String::new(),
        };
        if text.trim().is_empty() {
            return Err(AiError::BadResponse("empty reply".into()));
        }
        Ok(text)
    }

    /// Distil a non-2xx provider body into a short, safe error excerpt:
    /// `error.message` (Anthropic + OpenAI both nest it there) when present,
    /// else the raw body, capped at [`ERROR_EXCERPT_CHARS`] and flattened to one
    /// line. The API key never appears in provider error bodies, but we cap and
    /// flatten regardless.
    pub fn upstream_error_message(body: &str) -> String {
        let msg = serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| {
                v.get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .unwrap_or_else(|| body.to_string());
        let flat: String = msg.split_whitespace().collect::<Vec<_>>().join(" ");
        if flat.chars().count() > ERROR_EXCERPT_CHARS {
            let cut: String = flat.chars().take(ERROR_EXCERPT_CHARS).collect();
            format!("{cut}…")
        } else {
            flat
        }
    }

    /// Outcome of [`AiClient::test`]: the model's reply + round-trip latency.
    #[derive(Debug, Clone)]
    pub struct TestOutcome {
        pub reply: String,
        pub latency_ms: u64,
    }

    /// HTTP client for the configured provider. Cheap to build; the API builds
    /// one per request (a `reqwest::Client` is an `Arc` internally).
    #[derive(Clone)]
    pub struct AiClient {
        http: reqwest::Client,
    }

    impl Default for AiClient {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AiClient {
        pub fn new() -> Self {
            let http = reqwest::Client::builder()
                .timeout(REQUEST_TIMEOUT)
                .build()
                .unwrap_or_default();
            Self { http }
        }

        /// Rewrite `text` per `mode` (+ `language` / `instruction`). `Err(String)`
        /// from the instruction builder is a caller error (400) and is surfaced
        /// by the API before any network call.
        pub async fn improve(
            &self,
            cfg: &AiConfig,
            mode: AiMode,
            language: Option<&str>,
            instruction: Option<&str>,
            text: &str,
        ) -> Result<Result<String, AiError>, String> {
            let ins = mode_instruction(mode, language, instruction)?;
            let user = build_user_prompt(&ins, text);
            let system = system_prompt_with_protocol(cfg);
            Ok(self
                .complete(cfg, &system, &user)
                .await
                .and_then(|r| finalize_reply(&r)))
        }

        /// Connectivity check: a tiny "Reply with OK" round-trip.
        pub async fn test(&self, cfg: &AiConfig) -> Result<TestOutcome, AiError> {
            let start = Instant::now();
            let reply = self
                .complete(
                    cfg,
                    "You are a connectivity check. Reply with exactly: OK",
                    "Reply with OK",
                )
                .await?;
            Ok(TestOutcome {
                reply: clean_reply(&reply),
                latency_ms: start.elapsed().as_millis() as u64,
            })
        }

        /// One system+user completion against the configured provider, with
        /// retries on 429 / 5xx / transport errors. Returns the raw reply text.
        pub async fn complete(
            &self,
            cfg: &AiConfig,
            system: &str,
            user: &str,
        ) -> Result<String, AiError> {
            let mut attempt = 0u32;
            loop {
                let res = self.complete_once(cfg, system, user).await;
                let retryable = match &res {
                    Err(AiError::Upstream { status, .. }) => {
                        *status == 429 || (500..600).contains(status)
                    }
                    Err(AiError::Transport(_)) => true,
                    _ => false,
                };
                if !retryable || attempt >= MAX_RETRIES {
                    return res;
                }
                attempt += 1;
                tokio::time::sleep(RETRY_BASE * attempt).await;
            }
        }

        async fn complete_once(
            &self,
            cfg: &AiConfig,
            system: &str,
            user: &str,
        ) -> Result<String, AiError> {
            let base = cfg.effective_base_url();
            let req = match cfg.provider {
                Provider::Anthropic => {
                    let mut r = self
                        .http
                        .post(format!("{base}/v1/messages"))
                        .header("x-api-key", cfg.api_key.as_str())
                        .header("anthropic-version", ANTHROPIC_VERSION)
                        .header(reqwest::header::CONTENT_TYPE, "application/json");
                    if anthropic_uses_fallbacks(&cfg.model) {
                        r = r.header("anthropic-beta", ANTHROPIC_FALLBACK_BETA);
                    }
                    r.json(&anthropic_request_body(&cfg.model, system, user))
                }
                Provider::Openai => self
                    .http
                    .post(format!("{base}/chat/completions"))
                    .header(
                        reqwest::header::AUTHORIZATION,
                        format!("Bearer {}", cfg.api_key),
                    )
                    .header(reqwest::header::CONTENT_TYPE, "application/json")
                    .json(&openai_request_body(&cfg.model, system, user)),
            };
            let resp = req.send().await.map_err(transport_error)?;
            let status = resp.status().as_u16();
            let body = resp.text().await.map_err(transport_error)?;
            if !(200..300).contains(&status) {
                return Err(AiError::Upstream {
                    status,
                    message: upstream_error_message(&body),
                });
            }
            let v: Value = serde_json::from_str(&body)
                .map_err(|e| AiError::BadResponse(format!("invalid JSON: {e}")))?;
            match cfg.provider {
                Provider::Anthropic => parse_anthropic_response(&v),
                Provider::Openai => parse_openai_response(&v),
            }
        }
    }

    /// Map a reqwest error: timeouts get their own (non-retried) variant; the
    /// rest becomes a short, URL-free `Transport` description (the URL could
    /// carry a gateway path the operator considers private; the key is never
    /// in it, but keep the excerpt minimal regardless).
    fn transport_error(e: reqwest::Error) -> AiError {
        if e.is_timeout() {
            AiError::Timeout
        } else if e.is_connect() {
            AiError::Transport("connection failed".to_string())
        } else {
            let mut s = e.without_url().to_string();
            if s.chars().count() > ERROR_EXCERPT_CHARS {
                s = s.chars().take(ERROR_EXCERPT_CHARS).collect::<String>() + "…";
            }
            AiError::Transport(s)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn cfg(provider: Provider, model: &str) -> AiConfig {
            AiConfig {
                provider,
                api_key: "sk-test-not-a-real-key-1234".into(),
                model: model.into(),
                base_url: None,
                system_prompt: None,
            }
        }

        #[test]
        fn config_defaults_and_hint() {
            let c = cfg(Provider::Anthropic, DEFAULT_ANTHROPIC_MODEL);
            assert_eq!(c.effective_base_url(), "https://api.anthropic.com");
            assert_eq!(c.effective_system_prompt(), DEFAULT_SYSTEM_PROMPT);
            assert_eq!(c.api_key_hint(), "••••1234");
            let mut o = cfg(Provider::Openai, "gpt-4o-mini");
            assert_eq!(o.effective_base_url(), "https://api.openai.com/v1");
            o.base_url = Some("https://openrouter.ai/api/v1/".into());
            assert_eq!(o.effective_base_url(), "https://openrouter.ai/api/v1");
            o.system_prompt = Some("  custom  ".into());
            assert_eq!(o.effective_system_prompt(), "custom");
            // Blank base_url/system_prompt fall back to defaults.
            o.base_url = Some("   ".into());
            o.system_prompt = Some("".into());
            assert_eq!(o.effective_base_url(), "https://api.openai.com/v1");
            assert_eq!(o.effective_system_prompt(), DEFAULT_SYSTEM_PROMPT);
            // Short keys are fully masked.
            assert_eq!(api_key_hint("abc"), "••••");
            assert_eq!(api_key_hint("abcdefg"), "••••");
            assert_eq!(api_key_hint("abcdefgh"), "••••efgh");
        }

        #[test]
        fn config_json_roundtrip_and_lenient_optional_fields() {
            let c = AiConfig {
                provider: Provider::Openai,
                api_key: "k".into(),
                model: "m".into(),
                base_url: Some("https://x/v1".into()),
                system_prompt: Some("sp".into()),
            };
            let s = serde_json::to_string(&c).unwrap();
            assert!(s.contains("\"provider\":\"openai\""));
            assert_eq!(serde_json::from_str::<AiConfig>(&s).unwrap(), c);
            // Minimal stored shape (older rows without optional keys) parses.
            let min: AiConfig =
                serde_json::from_str(r#"{"provider":"anthropic","api_key":"k","model":"m"}"#)
                    .unwrap();
            assert_eq!(min.provider, Provider::Anthropic);
            assert!(min.base_url.is_none() && min.system_prompt.is_none());
            assert!(serde_json::from_str::<AiConfig>(
                r#"{"provider":"gemini","api_key":"k","model":"m"}"#
            )
            .is_err());
        }

        #[test]
        fn mode_instructions_and_user_prompt() {
            assert_eq!(
                mode_instruction(AiMode::Improve, None, None).unwrap(),
                "Improve clarity, flow and correctness while keeping the same length and tone."
            );
            assert_eq!(
                mode_instruction(AiMode::Formal, None, None).unwrap(),
                "Make it more formal and professional."
            );
            assert_eq!(
                mode_instruction(AiMode::Casual, None, None).unwrap(),
                "Make it more casual and friendly."
            );
            assert_eq!(
                mode_instruction(AiMode::Shorter, None, None).unwrap(),
                "Make it significantly shorter without losing key information."
            );
            assert_eq!(
                mode_instruction(AiMode::Grammar, None, None).unwrap(),
                "Fix spelling, grammar and punctuation only; change nothing else."
            );
            assert_eq!(
                mode_instruction(AiMode::Translate, Some("pt-BR"), None).unwrap(),
                "Translate it to pt-BR."
            );
            assert!(mode_instruction(AiMode::Translate, None, None).is_err());
            assert!(mode_instruction(AiMode::Translate, Some("  "), None).is_err());
            let long_lang = "x".repeat(MAX_LANGUAGE_CHARS + 1);
            assert!(mode_instruction(AiMode::Translate, Some(&long_lang), None).is_err());
            assert_eq!(
                mode_instruction(AiMode::Custom, None, Some(" add a greeting ")).unwrap(),
                "add a greeting"
            );
            assert!(mode_instruction(AiMode::Custom, None, None).is_err());
            let long = "x".repeat(MAX_INSTRUCTION_CHARS + 1);
            assert!(mode_instruction(AiMode::Custom, None, Some(&long)).is_err());
            assert_eq!(
                build_user_prompt("Make it shorter.", "hello there\nfriend"),
                "Instruction: Make it shorter.\n\nDraft:\nhello there\nfriend"
            );
            // Mode deserializes from its lowercase wire name; default is improve.
            assert_eq!(serde_json::from_str::<AiMode>("\"shorter\"").unwrap(), AiMode::Shorter);
            assert_eq!(AiMode::default(), AiMode::Improve);
        }

        #[test]
        fn finalize_reply_maps_sentinel_and_empty_to_refusal() {
            assert_eq!(finalize_reply("[[REFUSED]]"), Err(AiError::Refusal));
            assert_eq!(finalize_reply("<think>no</think>\n[[REFUSED]]"), Err(AiError::Refusal));
            assert_eq!(finalize_reply("  Sorry. [[REFUSED]]"), Err(AiError::Refusal));
            assert_eq!(finalize_reply("<think>only thought</think>"), Err(AiError::Refusal));
            assert_eq!(finalize_reply("\"Olá!\""), Ok("Olá!".to_string()));
            let cfg = AiConfig {
                provider: Provider::Anthropic,
                api_key: "k".into(),
                model: "m".into(),
                base_url: None,
                system_prompt: Some("custom".into()),
            };
            let sys = system_prompt_with_protocol(&cfg);
            assert!(sys.starts_with("custom"));
            assert!(sys.contains(REFUSAL_SENTINEL));
        }

        #[test]
        fn clean_reply_strips_inlined_reasoning_blocks() {
            // Closed block before the answer (DeepSeek/Qwen style).
            assert_eq!(
                clean_reply("<think>\nI should fix the accent.\n</think>\n\nOlá, tudo bem?"),
                "Olá, tudo bem?"
            );
            // Case-insensitive + other tag names + block in the middle.
            assert_eq!(clean_reply("Oi <THINKING>hmm</THINKING> tudo bem"), "Oi  tudo bem");
            assert_eq!(clean_reply("<reasoning>x</reasoning><thought>y</thought>ok"), "ok");
            // Unterminated opener: drop the tail.
            assert_eq!(clean_reply("Olá!<think>and then I"), "Olá!");
            // Stray closer (model started mid-thought): keep what follows.
            assert_eq!(clean_reply("…so the fix is\n</think>\nOlá!"), "Olá!");
            // Wrapping quotes are still stripped after the block is removed.
            assert_eq!(clean_reply("<think>q</think>\"Olá\""), "Olá");
            // Untagged text is untouched.
            assert_eq!(clean_reply("I think so <thinks>"), "I think so <thinks>");
        }

        #[test]
        fn clean_reply_strips_wrapping_quotes_only() {
            assert_eq!(clean_reply("  \"Hi there!\" \n"), "Hi there!");
            assert_eq!(clean_reply("“Olá, tudo bem?”"), "Olá, tudo bem?");
            assert_eq!(clean_reply("'ok'"), "ok");
            // Quotes that are part of the text (not wrapping it) survive.
            assert_eq!(clean_reply("\"a\" and \"b\""), "\"a\" and \"b\"");
            assert_eq!(clean_reply("plain"), "plain");
            assert_eq!(clean_reply("\""), "\"");
            assert_eq!(clean_reply(""), "");
        }

        #[test]
        fn anthropic_request_shape() {
            let b = anthropic_request_body("claude-opus-5", "SYS", "USER");
            assert_eq!(b["model"], "claude-opus-5");
            assert_eq!(b["max_tokens"], MAX_OUTPUT_TOKENS);
            assert_eq!(b["system"], "SYS");
            assert_eq!(b["messages"][0]["role"], "user");
            assert_eq!(b["messages"][0]["content"], "USER");
            assert_eq!(b["fallbacks"], "default");
            // No sampling / thinking params (rejected by Opus 5).
            for k in ["temperature", "top_p", "top_k", "thinking"] {
                assert!(b.get(k).is_none(), "{k} must not be sent");
            }
            // Fallbacks only on the Opus 5 / Fable 5 family.
            assert!(anthropic_uses_fallbacks("claude-fable-5"));
            assert!(anthropic_uses_fallbacks("claude-opus-5-20260701"));
            assert!(!anthropic_uses_fallbacks("claude-sonnet-4-6"));
            let b = anthropic_request_body("claude-sonnet-4-6", "S", "U");
            assert!(b.get("fallbacks").is_none());
        }

        #[test]
        fn openai_request_shape() {
            let b = openai_request_body("gpt-4o-mini", "SYS", "USER");
            assert_eq!(b["model"], "gpt-4o-mini");
            assert_eq!(b["messages"][0]["role"], "system");
            assert_eq!(b["messages"][0]["content"], "SYS");
            assert_eq!(b["messages"][1]["role"], "user");
            assert_eq!(b["messages"][1]["content"], "USER");
        }

        #[test]
        fn anthropic_response_parsing() {
            let ok = json!({
                "id": "msg_01", "type": "message", "role": "assistant",
                "model": "claude-opus-5",
                "content": [
                    {"type": "thinking", "thinking": "", "signature": "x"},
                    {"type": "text", "text": "Hello "},
                    {"type": "text", "text": "world"}
                ],
                "stop_reason": "end_turn", "stop_details": null,
                "usage": {"input_tokens": 10, "output_tokens": 3}
            });
            assert_eq!(parse_anthropic_response(&ok).unwrap(), "Hello world");

            let refusal = json!({
                "id": "msg_02", "type": "message", "role": "assistant",
                "content": [],
                "stop_reason": "refusal",
                "stop_details": {"type": "refusal", "category": "other", "explanation": "…"}
            });
            assert_eq!(parse_anthropic_response(&refusal), Err(AiError::Refusal));
            assert_eq!(AiError::Refusal.http_status(), 422);

            let empty = json!({"content": [], "stop_reason": "end_turn"});
            assert!(matches!(
                parse_anthropic_response(&empty),
                Err(AiError::BadResponse(_))
            ));
            // Hitting max_tokens is reported, not returned as a half rewrite.
            let cut = json!({
                "content": [{"type": "text", "text": "Hello wor"}],
                "stop_reason": "max_tokens"
            });
            assert_eq!(parse_anthropic_response(&cut), Err(AiError::Truncated));
            assert_eq!(AiError::Truncated.http_status(), 502);
            assert!(matches!(
                parse_anthropic_response(&json!({"type": "error"})),
                Err(AiError::BadResponse(_))
            ));
        }

        #[test]
        fn openai_response_parsing() {
            let ok = json!({
                "id": "chatcmpl-1", "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {"role": "assistant", "content": "Olá!"},
                    "finish_reason": "stop"
                }]
            });
            assert_eq!(parse_openai_response(&ok).unwrap(), "Olá!");
            // Array-of-parts content (some gateways).
            let parts = json!({
                "choices": [{"message": {"role": "assistant",
                    "content": [{"type": "text", "text": "A"}, {"type": "text", "text": "B"}]}}]
            });
            assert_eq!(parse_openai_response(&parts).unwrap(), "AB");
            let filtered = json!({
                "choices": [{"message": {"role": "assistant", "content": null},
                             "finish_reason": "content_filter"}]
            });
            assert_eq!(parse_openai_response(&filtered), Err(AiError::Refusal));
            let cut = json!({
                "choices": [{"message": {"role": "assistant", "content": "Hello wor"},
                             "finish_reason": "length"}]
            });
            assert_eq!(parse_openai_response(&cut), Err(AiError::Truncated));
            assert!(matches!(
                parse_openai_response(&json!({"choices": []})),
                Err(AiError::BadResponse(_))
            ));
            assert!(matches!(
                parse_openai_response(&json!({
                    "choices": [{"message": {"role": "assistant", "content": "  "}}]
                })),
                Err(AiError::BadResponse(_))
            ));
        }

        #[test]
        fn upstream_error_excerpt_and_display() {
            // Anthropic-style error envelope.
            let m = upstream_error_message(
                r#"{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}"#,
            );
            assert_eq!(m, "invalid x-api-key");
            // OpenAI-style.
            let m = upstream_error_message(
                r#"{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}"#,
            );
            assert_eq!(m, "Incorrect API key provided");
            // Non-JSON body is flattened + capped.
            let m = upstream_error_message(&format!("<html>\n {} </html>", "x".repeat(500)));
            assert!(m.starts_with("<html> xxx"));
            assert!(!m.contains('\n'));
            assert_eq!(m.chars().count(), ERROR_EXCERPT_CHARS + 1); // + ellipsis
            let e = AiError::Upstream { status: 401, message: "invalid x-api-key".into() };
            assert_eq!(e.to_string(), "ai upstream: 401 invalid x-api-key");
            assert_eq!(e.http_status(), 502);
            assert_eq!(
                AiError::Transport("connection failed".into()).to_string(),
                "ai upstream: request failed: connection failed"
            );
            assert_eq!(AiError::Timeout.to_string(), "ai upstream: request timed out");
            assert_eq!(AiError::Timeout.http_status(), 502);
        }

        #[test]
        fn debug_never_prints_the_key() {
            let c = cfg(Provider::Anthropic, DEFAULT_ANTHROPIC_MODEL);
            let dbg = format!("{c:?}");
            assert!(!dbg.contains("sk-test-not-a-real-key"), "{dbg}");
            assert!(dbg.contains("••••1234"), "{dbg}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resp_encodes_command_as_bulk_array() {
        let cmd = encode_command(&[b"RPUSH", b"events", b"hi"]);
        assert_eq!(
            cmd,
            b"*3\r\n$5\r\nRPUSH\r\n$6\r\nevents\r\n$2\r\nhi\r\n".to_vec()
        );
    }

    #[test]
    fn resp_parses_each_reply_kind() {
        // Simple string.
        assert_eq!(parse_reply(b"+OK\r\n").unwrap(), (RespValue::Simple("OK".into()), 5));
        // Error.
        let (v, _) = parse_reply(b"-ERR nope\r\n").unwrap();
        assert_eq!(v, RespValue::Error("ERR nope".into()));
        // Integer (RPUSH returns the new list length).
        assert_eq!(parse_reply(b":7\r\n").unwrap().0, RespValue::Int(7));
        // Bulk string.
        assert_eq!(
            parse_reply(b"$5\r\nhello\r\n").unwrap().0,
            RespValue::Bulk(Some(b"hello".to_vec()))
        );
        // Null bulk.
        assert_eq!(parse_reply(b"$-1\r\n").unwrap().0, RespValue::Bulk(None));
        // Array of two bulks.
        let (v, n) = parse_reply(b"*2\r\n$3\r\nfoo\r\n$3\r\nbar\r\n").unwrap();
        assert_eq!(
            v,
            RespValue::Array(Some(vec![
                RespValue::Bulk(Some(b"foo".to_vec())),
                RespValue::Bulk(Some(b"bar".to_vec())),
            ]))
        );
        assert_eq!(n, 22);
    }

    #[test]
    fn resp_reports_incomplete_buffers() {
        // Missing CRLF.
        assert!(matches!(parse_reply(b"+OK"), Err(RespError::Incomplete)));
        // Bulk header but not enough body bytes.
        assert!(matches!(parse_reply(b"$5\r\nhel"), Err(RespError::Incomplete)));
        // Array promising 2 items but only 1 present.
        assert!(matches!(
            parse_reply(b"*2\r\n$3\r\nfoo\r\n"),
            Err(RespError::Incomplete)
        ));
    }

    #[test]
    fn redis_config_and_url_parse() {
        let t = webhook_target("ignored", true); // reuse helper; override fields
        let t = EgressTarget {
            kind: "redis".into(),
            config: serde_json::json!({
                "url": "redis://:s3cr3t@redis.internal:6380/0",
                "mode": "pubsub",
                "key": "wa-events"
            })
            .to_string(),
            ..t
        };
        let cfg = RedisConfig::from_target(&t).unwrap();
        assert_eq!(cfg.mode, RedisMode::PubSub);
        assert_eq!(cfg.key, "wa-events");
        let (host, port, pw) = parse_redis_url(&cfg.url).unwrap();
        assert_eq!(host, "redis.internal");
        assert_eq!(port, 6380);
        assert_eq!(pw.as_deref(), Some("s3cr3t"));

        // Defaults: no mode → list; no port → 6379; no password → None.
        let (h, p, pw2) = parse_redis_url("redis://localhost").unwrap();
        assert_eq!((h.as_str(), p, pw2), ("localhost", 6379, None));
    }

    #[test]
    fn redis_commands_auth_then_publish_verb() {
        let cfg = RedisConfig {
            url: "redis://x".into(),
            mode: RedisMode::List,
            key: "evq".into(),
        };
        // With password → AUTH first, then RPUSH.
        let cmds = redis_publish_commands(&cfg, Some("pw"), b"payload");
        assert_eq!(cmds.len(), 2);
        assert_eq!(cmds[0], encode_command(&[b"AUTH", b"pw"]));
        assert_eq!(cmds[1], encode_command(&[b"RPUSH", b"evq", b"payload"]));

        // PubSub, no password → single PUBLISH.
        let cfg2 = RedisConfig { mode: RedisMode::PubSub, ..cfg };
        let cmds2 = redis_publish_commands(&cfg2, None, b"p");
        assert_eq!(cmds2.len(), 1);
        assert_eq!(cmds2[0], encode_command(&[b"PUBLISH", b"evq", b"p"]));
    }

    #[tokio::test]
    async fn read_one_reply_parses_from_an_async_reader() {
        // tokio impls AsyncRead for &[u8].
        let mut reader: &[u8] = b":42\r\n+OK\r\n";
        let mut buf = Vec::new();
        let a = read_one_reply(&mut reader, &mut buf).await.unwrap();
        assert_eq!(a, RespValue::Int(42));
        // Second reply still in the buffer / reader.
        let b = read_one_reply(&mut reader, &mut buf).await.unwrap();
        assert_eq!(b, RespValue::Simple("OK".into()));
    }

    #[tokio::test]
    async fn egress_transport_trait_is_dyn_dispatchable() {
        // Proves the trait seam B4's fan-out relies on (a mock records bodies).
        struct MockTransport(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);
        #[async_trait::async_trait]
        impl EgressTransport for MockTransport {
            async fn publish(&self, body: &[u8]) -> Result<(), DeliverError> {
                self.0.lock().unwrap().push(body.to_vec());
                Ok(())
            }
        }
        let sink = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let t: Box<dyn EgressTransport> = Box::new(MockTransport(sink.clone()));
        t.publish(b"hello").await.unwrap();
        assert_eq!(sink.lock().unwrap().as_slice(), &[b"hello".to_vec()]);
    }

    #[test]
    fn sse_json_is_the_bare_tagged_event() {
        let ev = SessionEvent::Message {
            id: "m1".into(),
            chat: "c@s".into(),
            from: "x@s".into(),
            body: serde_json::json!({"text": "hi"}),
        };
        let s = event_to_sse_json(&ev);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        // Bare, flat, type-tagged — the unchanged SSE contract.
        assert_eq!(v["type"], "message");
        assert_eq!(v["id"], "m1");
        assert_eq!(v["chat"], "c@s");
        assert_eq!(v["body"]["text"], "hi");
        assert!(v.get("session").is_none());
    }

    #[test]
    fn payload_wraps_the_same_data_in_an_envelope() {
        let ev = SessionEvent::Message {
            id: "m1".into(),
            chat: "c@s".into(),
            from: "x@s".into(),
            body: serde_json::json!({"text": "hi"}),
        };
        let p = event_to_payload("sess-1", &ev, 1234);
        assert_eq!(p["session"], "sess-1");
        assert_eq!(p["event"], "message");
        assert_eq!(p["ts"], 1234);
        // `type` is lifted out; the rest of the fields live under `data`.
        assert_eq!(p["data"]["id"], "m1");
        assert_eq!(p["data"]["chat"], "c@s");
        assert_eq!(p["data"]["from"], "x@s");
        assert_eq!(p["data"]["body"]["text"], "hi");
        assert!(p["data"].get("type").is_none());
    }

    #[test]
    fn event_type_matches_the_tag() {
        assert_eq!(event_type(&SessionEvent::Connected), "connected");
        assert_eq!(event_type(&SessionEvent::Qr { code: "x".into() }), "qr");
        assert_eq!(
            event_type(&SessionEvent::Disconnected { reason: "bye".into() }),
            "disconnected"
        );
        assert_eq!(
            event_type(&SessionEvent::CallOffer {
                call_id: "c1".into(),
                from: "j@s.whatsapp.net".into(),
                media: None
            }),
            "call_offer"
        );
        assert_eq!(
            event_type(&SessionEvent::CallTerminate {
                call_id: "c1".into(),
                from: "j@s.whatsapp.net".into(),
                reason: Some("timeout".into())
            }),
            "call_terminate"
        );
    }

    #[test]
    fn unit_variant_payload_has_empty_data_object() {
        let p = event_to_payload("s", &SessionEvent::Connected, 7);
        assert_eq!(p["event"], "connected");
        // No extra fields beyond the tag → data is an empty object.
        assert!(p["data"].as_object().unwrap().is_empty());
    }

    /// Spin up an ephemeral in-process HTTP receiver that records the last JSON
    /// body it got. Returns (base_url, shared_slot).
    async fn spawn_receiver(
        status: axum::http::StatusCode,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Option<serde_json::Value>>>) {
        use axum::{routing::post, Json, Router};
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<serde_json::Value>));
        let slot2 = slot.clone();
        let app = Router::new().route(
            "/hook",
            post(move |Json(body): Json<serde_json::Value>| {
                let slot2 = slot2.clone();
                async move {
                    *slot2.lock().unwrap() = Some(body);
                    status
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), slot)
    }

    fn webhook_target(url: &str, enabled: bool) -> EgressTarget {
        EgressTarget {
            session_id: "s1".into(),
            kind: "webhook".into(),
            enabled,
            events: None,
            secret: None,
            config: serde_json::json!({ "url": url }).to_string(),
            updated_at: 0,
        }
    }

    #[tokio::test]
    async fn delivers_envelope_to_http_receiver() {
        let (base, slot) = spawn_receiver(axum::http::StatusCode::OK).await;
        let target = webhook_target(&format!("{base}/hook"), true);
        let payload = event_to_payload(
            "s1",
            &SessionEvent::Message {
                id: "m1".into(),
                chat: "c@s".into(),
                from: "x@s".into(),
                body: serde_json::json!({ "text": "hi" }),
            },
            42,
        );
        deliver_webhook(&webhook_client(), &target, &payload)
            .await
            .expect("delivery should succeed");

        let got = slot.lock().unwrap().clone().expect("receiver got a body");
        assert_eq!(got["session"], "s1");
        assert_eq!(got["event"], "message");
        assert_eq!(got["ts"], 42);
        assert_eq!(got["data"]["id"], "m1");
    }

    #[tokio::test]
    async fn non_2xx_is_a_delivery_error() {
        let (base, _slot) =
            spawn_receiver(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let target = webhook_target(&format!("{base}/hook"), true);
        let payload = event_to_payload("s1", &SessionEvent::Connected, 1);
        let err = deliver_webhook(&webhook_client(), &target, &payload)
            .await
            .unwrap_err();
        assert!(matches!(err, DeliverError::Status(500)));
    }

    #[tokio::test]
    async fn signs_body_with_hmac_and_sets_headers() {
        use axum::{routing::post, Router};
        type Slot = std::sync::Arc<
            std::sync::Mutex<Option<(axum::http::HeaderMap, Vec<u8>)>>,
        >;
        let slot: Slot = std::sync::Arc::new(std::sync::Mutex::new(None));
        let slot2 = slot.clone();
        let app = Router::new().route(
            "/hook",
            post(
                move |headers: axum::http::HeaderMap, body: axum::body::Bytes| {
                    let slot2 = slot2.clone();
                    async move {
                        *slot2.lock().unwrap() = Some((headers, body.to_vec()));
                        axum::http::StatusCode::OK
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut target = webhook_target(&format!("http://{addr}/hook"), true);
        target.secret = Some("topsecret".into());
        let payload = event_to_payload("s1", &SessionEvent::Connected, 9);
        deliver_webhook(&webhook_client(), &target, &payload)
            .await
            .unwrap();

        let (headers, body) = slot.lock().unwrap().clone().expect("got a request");
        // Headers present.
        assert_eq!(headers.get("x-ruwa-event").unwrap(), "connected");
        assert!(headers.get("x-ruwa-delivery").is_some());
        // Signature matches an independent recompute over the exact bytes sent.
        let sig = headers
            .get("x-ruwa-signature")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let expected = format!("sha256={}", hmac_sha256_hex(b"topsecret", &body));
        assert_eq!(sig, expected);
    }

    #[tokio::test]
    async fn no_signature_header_without_a_secret() {
        use axum::{routing::post, Router};
        let slot = std::sync::Arc::new(std::sync::Mutex::new(None::<bool>));
        let slot2 = slot.clone();
        let app = Router::new().route(
            "/hook",
            post(move |headers: axum::http::HeaderMap| {
                let slot2 = slot2.clone();
                async move {
                    *slot2.lock().unwrap() = Some(headers.contains_key("x-ruwa-signature"));
                    axum::http::StatusCode::OK
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let target = webhook_target(&format!("http://{addr}/hook"), true); // no secret
        let payload = event_to_payload("s1", &SessionEvent::Connected, 1);
        deliver_webhook(&webhook_client(), &target, &payload)
            .await
            .unwrap();
        assert_eq!(slot.lock().unwrap().clone(), Some(false));
    }

    /// Receiver that 500s for the first `fail_first` hits, then 200s. Returns
    /// (base_url, hit_counter).
    async fn spawn_flaky_receiver(
        fail_first: usize,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use axum::{routing::post, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let hits2 = hits.clone();
        let app = Router::new().route(
            "/hook",
            post(move || {
                let hits2 = hits2.clone();
                async move {
                    let n = hits2.fetch_add(1, Ordering::SeqCst);
                    if n < fail_first {
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR
                    } else {
                        axum::http::StatusCode::OK
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("http://{addr}"), hits)
    }

    #[tokio::test]
    async fn retries_then_succeeds() {
        use crate::session::metrics;
        let (base, hits) = spawn_flaky_receiver(1).await; // fail once, then 200
        let target = webhook_target(&format!("{base}/hook"), true);
        let payload = event_to_payload("s1", &SessionEvent::Connected, 0);

        let before = metrics::get(&metrics::WEBHOOK_DELIVERED_TOTAL);
        deliver_with_retry(
            &webhook_client(),
            &target,
            &payload,
            3,
            std::time::Duration::from_millis(1),
        )
        .await
        .expect("should succeed on the retry");

        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 2); // 1 fail + 1 ok
        assert_eq!(metrics::get(&metrics::WEBHOOK_DELIVERED_TOTAL), before + 1);
    }

    #[tokio::test]
    async fn gives_up_after_max_retries_and_counts_failure() {
        use crate::session::metrics;
        let (base, hits) = spawn_flaky_receiver(usize::MAX).await; // always 500
        let target = webhook_target(&format!("{base}/hook"), true);
        let payload = event_to_payload("s1", &SessionEvent::Connected, 0);

        let before = metrics::get(&metrics::WEBHOOK_FAILED_TOTAL);
        let err = deliver_with_retry(
            &webhook_client(),
            &target,
            &payload,
            2, // 1 initial + 2 retries = 3 attempts
            std::time::Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, DeliverError::Status(500)));
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 3);
        assert_eq!(metrics::get(&metrics::WEBHOOK_FAILED_TOTAL), before + 1);
    }

    #[test]
    fn event_allowlist_include_exclude_and_empty() {
        // Empty/absent filter ⇒ everything passes.
        assert!(event_allowed(&None, "message"));
        assert!(event_allowed(&Some(String::new()), "message"));
        assert!(event_allowed(&Some("  ".into()), "anything"));
        // Non-empty allowlist ⇒ membership required.
        let f = Some("connected, message".into());
        assert!(event_allowed(&f, "connected"));
        assert!(event_allowed(&f, "message")); // whitespace around CSV item ignored
        assert!(!event_allowed(&f, "disconnected"));
        assert!(!event_allowed(&f, "qr"));
    }

    #[tokio::test]
    async fn deliver_event_skips_when_no_target() {
        // No egress rows → nothing to do, Ok(()).
        let store = Store::open(":memory:").unwrap();
        deliver_event(
            &store,
            &webhook_client(),
            "no-such-session",
            &SessionEvent::Connected,
            0,
        )
        .await
        .unwrap();
    }

    /// Seed a minimal session row so FK-bearing egress_targets inserts succeed.
    fn seed_session(store: &Store, id: &str) {
        use crate::store::NewSession;
        store
            .create_session(
                &NewSession {
                    id,
                    label: None,
                    status: "pending",
                    jid: None,
                    registration_id: 1,
                    noise_priv: &[1u8; 32],
                    noise_pub: &[2u8; 32],
                    identity_priv: &[3u8; 32],
                    identity_pub: &[4u8; 32],
                    spk_id: 1,
                    spk_priv: &[5u8; 32],
                    spk_pub: &[6u8; 32],
                    spk_sig: &[0u8; 64],
                    adv_secret: &[7u8; 32],
                    api_key: "k",
                    created_at: 1,
                    updated_at: 1,
                },
                &[(1, &[9u8; 32], &[8u8; 32])],
            )
            .unwrap();
    }

    #[tokio::test]
    async fn fans_out_to_webhook_and_isolates_redis_failure() {
        use crate::store::EgressTarget;
        let (base, slot) = spawn_receiver(axum::http::StatusCode::OK).await;
        let store = Store::open(":memory:").unwrap();
        seed_session(&store, "s1");

        // Two targets: a reachable webhook + a redis pointing at a dead port.
        store
            .egress_set(&EgressTarget {
                session_id: "s1".into(),
                kind: "webhook".into(),
                enabled: true,
                events: None,
                secret: None,
                config: serde_json::json!({ "url": format!("{base}/hook") }).to_string(),
                updated_at: 0,
            })
            .unwrap();
        store
            .egress_set(&EgressTarget {
                session_id: "s1".into(),
                kind: "redis".into(),
                enabled: true,
                events: None,
                secret: None,
                // 127.0.0.1:1 → connection refused, exercises error isolation.
                config: serde_json::json!({ "url": "redis://127.0.0.1:1", "mode": "list", "key": "q" })
                    .to_string(),
                updated_at: 0,
            })
            .unwrap();

        // Fan-out must NOT propagate the redis failure...
        deliver_event(&store, &webhook_client(), "s1", &SessionEvent::Connected, 5)
            .await
            .expect("redis failure is isolated, not propagated");
        // ...and the webhook leg still delivered.
        let got = slot.lock().unwrap().clone().expect("webhook received the event");
        assert_eq!(got["session"], "s1");
        assert_eq!(got["event"], "connected");
    }

    /// B5 (human-gate): live Redis round-trip. Run with a real Redis:
    ///   RUWA_LIVE_TEST=1 cargo test b5_live_redis -- --ignored
    /// (defaults to redis://localhost:6379; override with RUWA_REDIS_TEST_URL).
    #[tokio::test]
    #[ignore]
    async fn b5_live_redis_round_trip() {
        if std::env::var("RUWA_LIVE_TEST").as_deref() != Ok("1") {
            return;
        }
        use tokio::io::AsyncWriteExt;
        let url = std::env::var("RUWA_REDIS_TEST_URL")
            .unwrap_or_else(|_| "redis://localhost:6379".into());
        let key = format!("ruwa-test-{}", crate::session::uuid_v4());
        let cfg = RedisConfig { url: url.clone(), mode: RedisMode::List, key: key.clone() };
        let body = br#"{"session":"s1","event":"connected","data":{},"ts":1}"#;

        // Publish via RPUSH through our transport.
        RedisTransport::new(cfg).unwrap().publish(body).await.unwrap();

        // LPOP it back via our own RESP codec — proves the bytes round-trip.
        let (host, port, _) = parse_redis_url(&url).unwrap();
        let mut s = tokio::net::TcpStream::connect((host.as_str(), port)).await.unwrap();
        s.write_all(&encode_command(&[b"LPOP", key.as_bytes()])).await.unwrap();
        let mut buf = Vec::new();
        let reply = read_one_reply(&mut s, &mut buf).await.unwrap();
        assert_eq!(reply, RespValue::Bulk(Some(body.to_vec())));
    }

    #[test]
    fn should_fire_respects_enabled_and_filter() {
        use crate::store::EgressTarget;
        let mk = |enabled: bool, events: Option<&str>| EgressTarget {
            session_id: "s".into(),
            kind: "webhook".into(),
            enabled,
            events: events.map(str::to_string),
            secret: None,
            config: "{}".into(),
            updated_at: 0,
        };
        assert!(should_fire(&mk(true, None), "message")); // enabled, no filter
        assert!(!should_fire(&mk(false, None), "message")); // disabled
        assert!(should_fire(&mk(true, Some("message,qr")), "qr")); // in allowlist
        assert!(!should_fire(&mk(true, Some("message")), "connected")); // excluded
    }
}
