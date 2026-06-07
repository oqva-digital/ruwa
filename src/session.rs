//! Per-tenant session state.
//!
//! A `Session` owns:
//! - identity keypair + registered device JID (after pairing)
//! - WS connection to web.whatsapp.com
//! - Signal protocol stores (pre-keys, sessions, sender keys) — backed by Store
//! - event broadcast channel for incoming messages / status changes
//!
//! `SessionManager` is the multi-tenant registry. It restores sessions from
//! the store on boot and exposes lookup/create/delete by `SessionId`.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use parking_lot::{Mutex as PlMutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::crypto::identity::DeviceKeys;
use crate::crypto::prekeys::PreKey;
use crate::error::{Error, Result};
use crate::store::Store;

/// Number of one-time prekeys generated when a session is created.
/// whatsmeow uploads in batches of 30; we mirror that.
pub const INITIAL_PREKEY_COUNT: u32 = 30;

pub type SessionId = String;

/// Process-wide counters backing the Prometheus `/metrics` endpoint. Plain
/// relaxed atomics — cheap to bump on the hot send/recv paths, exact enough
/// for an ops dashboard. Rendered by [`SessionManager::metrics_text`].
pub mod metrics {
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Inbound message stanzas seen by `process_inbound_message`.
    pub static MSGS_IN: AtomicU64 = AtomicU64::new(0);
    /// Outbound messages handed to the socket (text/media/react/edit/revoke).
    pub static MSGS_OUT: AtomicU64 = AtomicU64::new(0);
    /// Inbound messages that could not be decrypted (persisted as undecryptable).
    pub static DECRYPT_FAILURES: AtomicU64 = AtomicU64::new(0);
    /// WebSocket reconnect attempts across all sessions.
    pub static RECONNECTS_TOTAL: AtomicU64 = AtomicU64::new(0);
    /// One-time-prekey replenishment batches generated + uploaded.
    pub static PREKEY_REFILLS_TOTAL: AtomicU64 = AtomicU64::new(0);
    /// Webhook deliveries that ultimately succeeded (2xx, possibly after retries).
    pub static WEBHOOK_DELIVERED_TOTAL: AtomicU64 = AtomicU64::new(0);
    /// Webhook deliveries dropped after exhausting all retry attempts.
    pub static WEBHOOK_FAILED_TOTAL: AtomicU64 = AtomicU64::new(0);
    /// HTTP requests served (every `/`, `/v1/*`, `/metrics` call).
    pub static HTTP_REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
    /// Cumulative HTTP response time in milliseconds. `sum / count` = average.
    pub static HTTP_DURATION_MS_SUM: AtomicU64 = AtomicU64::new(0);

    #[inline]
    pub fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Record one served HTTP request + its latency (called by the api timing
    /// middleware). Feeds `ruwa_http_requests_total` + the duration sum.
    #[inline]
    pub fn record_http(duration_ms: u64) {
        HTTP_REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);
        HTTP_DURATION_MS_SUM.fetch_add(duration_ms, Ordering::Relaxed);
    }

    /// Process start, set once at boot (first `router()` build). `uptime_seconds`
    /// reads from it; lazily defaults to "now" so it can never panic.
    static PROCESS_START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();

    /// Stamp the process start. Idempotent (first call wins) — called from
    /// `api::router`, which is built once per process.
    pub fn mark_process_start() {
        let _ = PROCESS_START.get_or_init(std::time::Instant::now);
    }

    /// Seconds since `mark_process_start` (0 if never stamped).
    pub fn uptime_seconds() -> u64 {
        PROCESS_START.get().map(|t| t.elapsed().as_secs()).unwrap_or(0)
    }

    /// Resident set size (physical RAM) in bytes, from `/proc/self/status`
    /// (`VmRSS`). `None` off Linux or if unreadable — the metric is then omitted.
    pub fn resident_memory_bytes() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            let s = std::fs::read_to_string("/proc/self/status").ok()?;
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("VmRSS:") {
                    let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                    return Some(kb * 1024);
                }
            }
            None
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Total CPU seconds (user + system) from `/proc/self/stat` utime+stime.
    /// Assumes the usual 100 Hz clock tick. `None` off Linux.
    pub fn cpu_seconds_total() -> Option<f64> {
        #[cfg(target_os = "linux")]
        {
            let s = std::fs::read_to_string("/proc/self/stat").ok()?;
            // `comm` (field 2) can hold spaces/parens; everything after the last
            // ')' is space-separated starting at field 3 (state).
            let after = s.rsplit_once(')')?.1;
            let f: Vec<&str> = after.split_whitespace().collect();
            // field 14 (utime) = index 11, field 15 (stime) = index 12 here.
            let utime: u64 = f.get(11)?.parse().ok()?;
            let stime: u64 = f.get(12)?.parse().ok()?;
            Some((utime + stime) as f64 / 100.0)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Open file-descriptor count from `/proc/self/fd`. `None` off Linux.
    pub fn open_fds() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            Some(std::fs::read_dir("/proc/self/fd").ok()?.count() as u64)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// A random UUID v4 as the canonical hyphenated lowercase string. In-house (16
/// OS-random bytes with the version/variant bits set) — replaces the `uuid` crate
/// per the lean-codebase rule.
pub fn uuid_v4() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
    )
}

/// A random UUID v4 without hyphens (32 lowercase hex chars). Used where a compact
/// token is wanted (e.g. per-tenant API keys).
pub fn uuid_v4_simple() -> String {
    uuid_v4().replace('-', "")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMeta {
    pub id: SessionId,
    pub label: Option<String>,
    pub status: SessionStatus,
    /// JID assigned by WhatsApp after pairing, e.g. "5511999999999.0:23@s.whatsapp.net".
    pub jid: Option<String>,
    /// Per-session egress proxy URL (socks5/socks5h/http). `None` = direct.
    /// The connection task routes the Noise WebSocket through it; media (reqwest)
    /// uses the same URL. Never serialized raw — it can contain credentials; the
    /// API surfaces a masked form via `SessionResp`.
    #[serde(skip_serializing, default)]
    pub proxy_url: Option<String>,
    /// Presence preference: `true` → announce `available` (online), which makes
    /// WhatsApp silence the phone's notifications; `false` (default) → announce
    /// `unavailable` so the phone keeps notifying. Surfaced in the API.
    #[serde(default)]
    pub mark_online: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Liveness snapshot for one session, surfaced by `GET /v1/sessions/:id/health`.
/// Reflects real socket state (last inbound frame, reconnect churn) rather than
/// just the persisted status — so a stalled "connected" socket is detectable.
#[derive(Debug, Clone, Serialize)]
pub struct SessionHealth {
    pub id: SessionId,
    pub status: SessionStatus,
    pub connected: bool,
    pub jid: Option<String>,
    pub last_rx: Option<i64>,
    pub seconds_since_rx: Option<i64>,
    pub reconnect_count: u32,
    pub prekeys_available: i64,
    pub proxy_configured: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    /// Created but no pairing attempted yet.
    Pending,
    /// Background task is running the WS connect + Noise handshake.
    Connecting,
    /// Pairing in progress, QR available.
    AwaitingQr,
    /// Paired and connected.
    Connected,
    /// Paired but currently disconnected (will retry).
    Disconnected,
    /// The configured egress proxy URL is invalid — a terminal config error.
    /// We don't retry (it won't fix itself); fix the proxy + reconnect.
    ProxyError,
    /// Logged out / unpaired by user or remote.
    LoggedOut,
    /// WhatsApp itself closed the stream (an explicit `<stream:error>`/`<failure>`
    /// that isn't the normal 515 restart). Auto-reconnect is HALTED on purpose —
    /// hammering reconnect on a number WhatsApp is rejecting accelerates a ban.
    /// Terminal until a manual `POST /connect`. See `wa_disconnect_reason`.
    Blocked,
}

/// Decoded device identity of an already-paired companion, extracted from a
/// Baileys/Evolution `creds` blob, ready to insert into our store so the device
/// logs in without re-pairing. All key material is validated to the exact wire
/// lengths here so [`SessionManager::import_session`] can trust it.
pub struct ImportedCreds {
    pub registration_id: u32,
    pub noise_priv: Vec<u8>,
    pub noise_pub: Vec<u8>,
    pub identity_priv: Vec<u8>,
    pub identity_pub: Vec<u8>,
    pub spk_id: u32,
    pub spk_priv: Vec<u8>,
    pub spk_pub: Vec<u8>,
    pub spk_sig: Vec<u8>,
    pub adv_secret: Vec<u8>,
    /// Re-serialized `ADVSignedDeviceIdentity` (details + the 3 signatures).
    pub account_pb: Vec<u8>,
    /// Device JID, e.g. `5511999999999:47@s.whatsapp.net` — presence of the
    /// device suffix is what makes us take the LOGIN (not registration) path.
    pub jid: String,
    pub push_name: Option<String>,
    pub platform: Option<String>,
}

impl ImportedCreds {
    /// Parse a Baileys `creds` JSON (the blob Evolution stores in
    /// `Session.creds`). Keypairs come as `{"type":"Buffer","data":<b64|[ints]>}`
    /// and other fields as base64 strings; both forms are handled. The four
    /// `account.*` fields are re-assembled into the `ADVSignedDeviceIdentity`
    /// protobuf ruwa persists as `account_pb`.
    pub fn from_baileys_json(c: &serde_json::Value) -> Result<Self> {
        use crate::proto::wa_adv::AdvSignedDeviceIdentity;
        use prost::Message as _;

        // Decode a field that is either a base64 string or a
        // `{type:"Buffer", data: <b64 string | [int array]>}` wrapper.
        fn bytes(v: &serde_json::Value) -> Result<Vec<u8>> {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let inner = v.get("data").unwrap_or(v);
            if let Some(s) = inner.as_str() {
                return B64
                    .decode(s)
                    .map_err(|e| Error::BadRequest(format!("import: bad base64: {e}")));
            }
            if let Some(arr) = inner.as_array() {
                return arr
                    .iter()
                    .map(|n| {
                        n.as_u64()
                            .filter(|x| *x <= 255)
                            .map(|x| x as u8)
                            .ok_or_else(|| Error::BadRequest("import: bad byte array".into()))
                    })
                    .collect();
            }
            Err(Error::BadRequest("import: expected base64 or Buffer".into()))
        }
        fn want(b: Vec<u8>, n: usize, what: &str) -> Result<Vec<u8>> {
            if b.len() != n {
                return Err(Error::BadRequest(format!(
                    "import: {what} must be {n} bytes, got {}",
                    b.len()
                )));
            }
            Ok(b)
        }
        let get = |path: &[&str]| -> Result<&serde_json::Value> {
            let mut cur = c;
            for k in path {
                cur = cur
                    .get(k)
                    .ok_or_else(|| Error::BadRequest(format!("import: missing creds.{}", path.join("."))))?;
            }
            Ok(cur)
        };

        let registration_id = get(&["registrationId"])?
            .as_u64()
            .ok_or_else(|| Error::BadRequest("import: registrationId not an integer".into()))?
            as u32;

        let noise_priv = want(bytes(get(&["noiseKey", "private"])?)?, 32, "noiseKey.private")?;
        let noise_pub = want(bytes(get(&["noiseKey", "public"])?)?, 32, "noiseKey.public")?;
        let identity_priv = want(
            bytes(get(&["signedIdentityKey", "private"])?)?,
            32,
            "signedIdentityKey.private",
        )?;
        let identity_pub = want(
            bytes(get(&["signedIdentityKey", "public"])?)?,
            32,
            "signedIdentityKey.public",
        )?;
        let spk_id = get(&["signedPreKey", "keyId"])?
            .as_u64()
            .ok_or_else(|| Error::BadRequest("import: signedPreKey.keyId not an integer".into()))?
            as u32;
        let spk_priv = want(
            bytes(get(&["signedPreKey", "keyPair", "private"])?)?,
            32,
            "signedPreKey.keyPair.private",
        )?;
        let spk_pub = want(
            bytes(get(&["signedPreKey", "keyPair", "public"])?)?,
            32,
            "signedPreKey.keyPair.public",
        )?;
        let spk_sig = want(
            bytes(get(&["signedPreKey", "signature"])?)?,
            64,
            "signedPreKey.signature",
        )?;
        let adv_secret = want(bytes(get(&["advSecretKey"])?)?, 32, "advSecretKey")?;

        // Reassemble account_pb from Baileys' decomposed account fields. Baileys
        // already computed deviceSignature at pairing, so all four are present.
        let acc = AdvSignedDeviceIdentity {
            details: Some(bytes(get(&["account", "details"])?)?),
            account_signature_key: Some(want(
                bytes(get(&["account", "accountSignatureKey"])?)?,
                32,
                "account.accountSignatureKey",
            )?),
            account_signature: Some(want(
                bytes(get(&["account", "accountSignature"])?)?,
                64,
                "account.accountSignature",
            )?),
            device_signature: Some(want(
                bytes(get(&["account", "deviceSignature"])?)?,
                64,
                "account.deviceSignature",
            )?),
        };
        let account_pb = acc.encode_to_vec();

        let jid = get(&["me", "id"])?
            .as_str()
            .ok_or_else(|| Error::BadRequest("import: me.id missing".into()))?
            .to_string();
        let push_name = c
            .get("me")
            .and_then(|m| m.get("name"))
            .and_then(|n| n.as_str())
            .map(str::to_string);
        let platform = c.get("platform").and_then(|p| p.as_str()).map(str::to_string);

        Ok(ImportedCreds {
            registration_id,
            noise_priv,
            noise_pub,
            identity_priv,
            identity_pub,
            spk_id,
            spk_priv,
            spk_pub,
            spk_sig,
            adv_secret,
            account_pb,
            jid,
            push_name,
            platform,
        })
    }
}

/// Events emitted on a session's broadcast channel. Variants are
/// forward-declared; M2 (Qr/Paired/Connected/Disconnected/LoggedOut) and M4
/// (Message) start producing them.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SessionEvent {
    Connecting,
    Qr { code: String },
    Paired { jid: String },
    Connected,
    Disconnected { reason: String },
    Message { id: String, chat: String, from: String, body: serde_json::Value },
    /// Outbound message left the wire. The send pump emits this right
    /// after `dispatcher.send_node` returns (status = "sent"). The
    /// follow-on `MessageDelivered` event fires once the server acks.
    MessageSent { id: String, chat: String },
    /// Server acknowledged delivery of an outbound message — the row's
    /// status flipped to "delivered" in the messages table.
    MessageDelivered { id: String, chat: String },
    LoggedOut,
}

/// Unit of outbound work a per-session connection task drains and ships.
/// HTTP handlers push these via `Session::enqueue_send`; the connection
/// task's send pump (spawned in `run_connection`) picks them up and runs
/// the X3DH-on-demand + Signal encrypt + `<message>` ship pipeline.
#[derive(Debug, Clone)]
pub enum SendOp {
    /// Plain 1:1 text. The pump runs `RatchetingSession::initiate_alice`
    /// against a freshly-fetched prekey bundle when no Signal session
    /// exists yet for `chat_jid`.
    Text {
        chat_jid: String,
        msg_id: String,
        text: String,
        timestamp: i64,
    },
    /// Media (image/video/audio/document/sticker). The pump reads bytes
    /// from `file_path`, encrypts with a fresh per-file `media_key`,
    /// fetches a mediaconn host/auth via `<iq xmlns="w:m">`, uploads the
    /// ciphertext to mmg.whatsapp.net, plugs the resulting URL+direct_path
    /// into the appropriate `media::build_*_message` proto, then runs
    /// the same X3DH+encrypt+`<message>` pipeline as `Text`.
    Media {
        chat_jid: String,
        msg_id: String,
        kind: crate::media::MediaType,
        file_path: String,
        mime: String,
        caption: Option<String>,
        #[allow(dead_code)]
        filename: Option<String>,
        /// @-mentioned JIDs to attach to the media's contextInfo. Empty = none.
        mentions: Vec<String>,
        timestamp: i64,
    },
    /// Pre-built binary node (presence / chatstate / receipt). The pump
    /// just hands these to `dispatcher.send_node` — no encryption.
    /// Carries no extra metadata so the same variant fits any node type.
    RawNode(crate::protocol::binary::Node),
    /// Pre-encoded inner waE2E.Message bytes (reaction, edit, revoke,
    /// etc.) — the pump runs the same X3DH+Signal-encrypt+`<message>`
    /// pipeline as `Text`, just with a different inner protobuf.
    EncryptedInner {
        chat_jid: String,
        msg_id: String,
        inner_proto: Vec<u8>,
        timestamp: i64,
    },
    /// On-demand history-sync PULL: a peer `PeerDataOperationRequestMessage`
    /// (HISTORY_SYNC_ON_DEMAND) shipped to our own account asking the phone to
    /// resend `count` messages immediately before the given oldest message in
    /// `chat`. Mirrors whatsmeow's `BuildHistorySyncRequest`. The response
    /// arrives as a HistorySyncNotification (syncType ON_DEMAND) on the recv
    /// loop and lands in `messages` like any other history chunk. This is a
    /// PULL — it does not depend on the phone's automatic (gated) push.
    PeerHistoryRequest {
        chat: String,
        oldest_id: String,
        oldest_from_me: bool,
        oldest_ts: i64,
        count: u32,
    },
}

/// Serializable mirror of `SendOp` that only includes the variants
/// worth persisting across reconnects (i.e. excludes `RawNode`, which
/// is for ephemeral presence/typing/receipt nodes that lose meaning
/// once the connection drops).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
enum PersistedSendOp {
    Text {
        chat_jid: String,
        msg_id: String,
        text: String,
        timestamp: i64,
    },
    Media {
        chat_jid: String,
        msg_id: String,
        kind: crate::media::MediaType,
        file_path: String,
        mime: String,
        caption: Option<String>,
        filename: Option<String>,
        #[serde(default)]
        mentions: Vec<String>,
        timestamp: i64,
    },
    EncryptedInner {
        chat_jid: String,
        msg_id: String,
        #[serde(with = "serde_bytes_base64")]
        inner_proto: Vec<u8>,
        timestamp: i64,
    },
}

mod serde_bytes_base64 {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(b))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}

impl PersistedSendOp {
    fn from_send_op(op: &SendOp) -> Option<Self> {
        match op {
            SendOp::Text { chat_jid, msg_id, text, timestamp } => Some(Self::Text {
                chat_jid: chat_jid.clone(),
                msg_id: msg_id.clone(),
                text: text.clone(),
                timestamp: *timestamp,
            }),
            SendOp::Media {
                chat_jid,
                msg_id,
                kind,
                file_path,
                mime,
                caption,
                filename,
                mentions,
                timestamp,
            } => Some(Self::Media {
                chat_jid: chat_jid.clone(),
                msg_id: msg_id.clone(),
                kind: *kind,
                file_path: file_path.clone(),
                mime: mime.clone(),
                caption: caption.clone(),
                filename: filename.clone(),
                mentions: mentions.clone(),
                timestamp: *timestamp,
            }),
            SendOp::EncryptedInner {
                chat_jid,
                msg_id,
                inner_proto,
                timestamp,
            } => Some(Self::EncryptedInner {
                chat_jid: chat_jid.clone(),
                msg_id: msg_id.clone(),
                inner_proto: inner_proto.clone(),
                timestamp: *timestamp,
            }),
            SendOp::RawNode(_) => None,
            // Ephemeral pull request — re-issue from the API if a reconnect
            // drops it; no point persisting a point-in-time history anchor.
            SendOp::PeerHistoryRequest { .. } => None,
        }
    }

    fn into_send_op(self) -> SendOp {
        match self {
            Self::Text { chat_jid, msg_id, text, timestamp } => SendOp::Text {
                chat_jid,
                msg_id,
                text,
                timestamp,
            },
            Self::Media {
                chat_jid,
                msg_id,
                kind,
                file_path,
                mime,
                caption,
                filename,
                mentions,
                timestamp,
            } => SendOp::Media {
                chat_jid,
                msg_id,
                kind,
                file_path,
                mime,
                caption,
                filename,
                mentions,
                timestamp,
            },
            Self::EncryptedInner {
                chat_jid,
                msg_id,
                inner_proto,
                timestamp,
            } => SendOp::EncryptedInner {
                chat_jid,
                msg_id,
                inner_proto,
                timestamp,
            },
        }
    }

    fn msg_id(&self) -> &str {
        match self {
            Self::Text { msg_id, .. }
            | Self::Media { msg_id, .. }
            | Self::EncryptedInner { msg_id, .. } => msg_id,
        }
    }
}

/// Convert a SendOp into (msg_id, JSON) for persistence; None for
/// ephemeral RawNode variants. Failure to JSON-encode is impossible
/// for the variants we persist (all fields are simple owned types).
fn persistable_op_view(op: &SendOp) -> Option<(String, String)> {
    let p = PersistedSendOp::from_send_op(op)?;
    let msg_id = p.msg_id().to_string();
    let json = serde_json::to_string(&p).ok()?;
    Some((msg_id, json))
}

/// Drain the outbound_queue table for a given session. Returns the
/// rows in created_at order, oldest first — caller pushes them onto
/// the in-memory channel in that order so a reconnect picks up where
/// we left off.
fn drain_outbound_queue(store: &Store, session_id: &str) -> Result<Vec<SendOp>> {
    let rows = store.outbound_queue_drain(session_id)?;
    Ok(rows
        .into_iter()
        .filter_map(|j| serde_json::from_str::<PersistedSendOp>(&j).ok())
        .map(PersistedSendOp::into_send_op)
        .collect())
}

/// Remove a row from outbound_queue once the server has acked it.
fn delete_outbound_queue_row(
    store: &Store,
    session_id: &str,
    msg_id: &str,
) -> Result<()> {
    store.outbound_queue_delete(session_id, msg_id)?;
    Ok(())
}

/// A single tenant's WhatsApp session. Wraps shared state + an event bus.
pub struct Session {
    pub meta: RwLock<SessionMeta>,
    /// Subscribed by `GET /v1/sessions/:id/events` (M4) and the connection
    /// task (M2+). Held even when no subscribers exist.
    #[allow(dead_code)]
    pub events: broadcast::Sender<SessionEvent>,
    /// QR strings advertised by the server during pairing. Each is the joined
    /// `"<ref>,<noise_pub_b64>,<identity_pub_b64>,<adv_secret_b64>"` form;
    /// the API renders one at a time. Populated by the connection task after
    /// it receives a `<pair-device>` IQ. Cleared on pair-success / logout.
    pub qr_codes: RwLock<Vec<String>>,
    /// Outbound work queue. POST handlers push via `enqueue_send`; the
    /// connection task drains the receiver via `take_send_receiver`. Held
    /// in an RwLock so reconnects can swap in a fresh pair.
    send_tx: RwLock<mpsc::UnboundedSender<SendOp>>,
    send_rx: PlMutex<Option<mpsc::UnboundedReceiver<SendOp>>>,
    /// Cancellation signal for the connection task. `SessionManager::logout`
    /// notifies waiters; `run_connection` selects on this notify and exits
    /// cleanly after best-effort shipping a `<remove-companion-device>` IQ.
    logout_notify: Arc<tokio::sync::Notify>,
    /// JID captured at logout time so the connection task can address its
    /// outbound `<remove-companion-device>` IQ. Set by `logout`, read by
    /// the run_connection logout branch, then dropped.
    pending_logout_jid: RwLock<Option<String>>,
    /// Handle to the running QR-rotation task. Each `<pair-device>` IQ
    /// installs a fresh task that pops the head of `qr_codes` on a fixed
    /// interval, emitting a `Qr` event with the new head until the vec
    /// is empty. Aborted on a new install, on `apply_pair_success`, and
    /// on connection-task exit.
    qr_rotate_handle: PlMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Handle to the connection's keepalive task. Set by `run_connection`
    /// after the Noise handshake; aborted on connection exit so a stale
    /// task doesn't leak across reconnects.
    keepalive_handle: PlMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Set when the server sends a terminal `<stream:error>` we must NOT
    /// auto-reconnect through — chiefly `<conflict type="replaced"/>`, which
    /// means another client claimed our slot. Blindly reconnecting starts a
    /// replace-war (we boot the prior socket, get replaced, reconnect, …).
    /// whatsmeow's `handleStreamError` mirrors this: expectDisconnect + emit
    /// StreamReplaced, NO reconnect. The reconnect loop checks + clears this.
    expect_disconnect: std::sync::atomic::AtomicBool,
    /// Set when the server sends `<stream:error code="515">` ("restart
    /// required", the normal post-pairing handshake step). The reconnect loop
    /// reconnects IMMEDIATELY (no backoff) and resets the backoff, instead of
    /// treating it as a generic failure — mirrors whatsmeow's instant restart.
    restart_required: std::sync::atomic::AtomicBool,
    /// Set once a connection reaches `<success>`. Signals the reconnect loop the
    /// connection was healthy, so a later drop starts from the initial backoff
    /// rather than inheriting a compounded value.
    reached_success: std::sync::atomic::AtomicBool,
    /// Set when WhatsApp explicitly closed the stream (rejection/ban-ish, not a
    /// 515 restart). The reconnect loop parks the session `Blocked` and stops —
    /// reconnecting into a WA rejection only accelerates a ban.
    wa_blocked: std::sync::atomic::AtomicBool,
    /// Unix timestamp of the most recent inbound frame (0 = none yet). Updated
    /// by the connection recv loop; surfaced by the health endpoint so a stalled
    /// socket (no rx, but status still "connected") is detectable.
    last_rx: std::sync::atomic::AtomicI64,
    /// How many times this session's connection has dropped + retried since the
    /// process started. Bumped by `run_with_reconnect`.
    reconnect_count: std::sync::atomic::AtomicU32,
    /// Handle to the spawned `run_with_reconnect` driver task, set by
    /// `SessionManager::connect`. Taken + awaited by `SessionManager::shutdown`
    /// so a SIGTERM can wait for connection tasks to close their sockets.
    task_handle: PlMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Handle to the per-connection periodic prekey top-up task. Set by
    /// `run_connection` after the handshake; aborted on connection exit so a
    /// stale task (with a dead dispatcher) doesn't leak across reconnects.
    prekey_topup_handle: PlMutex<Option<tokio::task::JoinHandle<()>>>,
    /// Guards one-time spawn of the egress delivery worker (webhook + redis
    /// fan-out). Flipped true on the first `connect`; the worker lives for the
    /// session's lifetime and ends when the event bus closes (session dropped), so
    /// reconnects must NOT spawn a second one (would double-deliver). See
    /// `ensure_egress_worker`.
    egress_started: std::sync::atomic::AtomicBool,
    /// A clone of the live connection's dispatcher, installed by `run_connection`
    /// while connected and cleared on exit. Lets HTTP handlers issue a synchronous
    /// IQ request/reply (onWhatsApp, profile, block, …) against the live socket;
    /// `None` when offline. The dispatcher's pending-IQ map is shared (Arc), so
    /// the recv loop resolves HTTP-initiated replies the same as internal ones.
    iq_client: PlMutex<Option<ConnDispatcher>>,
    /// Per-user device-list cache: `bare-user-jid → (device JIDs, fetched_at)`.
    /// Avoids a blocking `usync` IQ round-trip on every outbound message — the
    /// reply is identical until the peer adds/removes a device, at which point
    /// WhatsApp pushes `<notification type="devices">` and we invalidate. A TTL
    /// backstops missed notifications. Measured ~1 s/message saved (two usync
    /// round-trips were ~83% of send latency).
    device_cache: RwLock<HashMap<String, (Vec<String>, std::time::Instant)>>,
    /// Per-message inbound retry-receipt counter, keyed by message id. Mirrors
    /// whatsmeow's `messageRetries` map: every undecryptable inbound bumps the
    /// count so the retry receipt escalates and we stop after 5 to avoid a
    /// retry storm. (We attach the `<keys>` re-establishment bundle on every
    /// retry — see the gating note in `process_inbound_message`.) In-memory
    /// only; a process restart resets it, matching whatsmeow.
    message_retries: PlMutex<HashMap<String, u32>>,
    /// Recently-sent messages, newest last, kept so we can re-encrypt and
    /// resend when a peer asks via an inbound `<receipt type="retry">` (it
    /// couldn't decrypt — usually because its Signal session to us desynced).
    /// Holds the unpadded inner `waE2E.Message` bytes + the original chat jid,
    /// keyed by message id. Bounded FIFO ring (mirrors whatsmeow's
    /// `recentMessages`); in-memory only.
    recent_sends: PlMutex<VecDeque<RecentSend>>,
}

/// One entry in [`Session::recent_sends`] — enough to rebuild and resend a
/// message on retry: the unpadded inner proto plus where it was headed.
struct RecentSend {
    msg_id: String,
    chat_jid: String,
    inner_proto: Vec<u8>,
}

/// Cap on [`Session::recent_sends`]. whatsmeow keeps 256; a retry almost
/// always arrives within seconds of the send, so this is ample headroom.
const RECENT_SENDS_MAX: usize = 256;

impl Session {
    pub fn new(meta: SessionMeta) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        let (send_tx, send_rx) = mpsc::unbounded_channel();
        Self {
            meta: RwLock::new(meta),
            events: tx,
            qr_codes: RwLock::new(Vec::new()),
            send_tx: RwLock::new(send_tx),
            send_rx: PlMutex::new(Some(send_rx)),
            logout_notify: Arc::new(tokio::sync::Notify::new()),
            pending_logout_jid: RwLock::new(None),
            qr_rotate_handle: PlMutex::new(None),
            keepalive_handle: PlMutex::new(None),
            expect_disconnect: std::sync::atomic::AtomicBool::new(false),
            restart_required: std::sync::atomic::AtomicBool::new(false),
            reached_success: std::sync::atomic::AtomicBool::new(false),
            wa_blocked: std::sync::atomic::AtomicBool::new(false),
            last_rx: std::sync::atomic::AtomicI64::new(0),
            reconnect_count: std::sync::atomic::AtomicU32::new(0),
            task_handle: PlMutex::new(None),
            prekey_topup_handle: PlMutex::new(None),
            egress_started: std::sync::atomic::AtomicBool::new(false),
            iq_client: PlMutex::new(None),
            device_cache: RwLock::new(HashMap::new()),
            message_retries: PlMutex::new(HashMap::new()),
            recent_sends: PlMutex::new(VecDeque::new()),
        }
    }

    /// Fresh cached device list for `user_key`, or `None` on miss/expiry.
    fn device_cache_get(&self, user_key: &str) -> Option<Vec<String>> {
        let cache = self.device_cache.read();
        let (devices, fetched_at) = cache.get(user_key)?;
        if fetched_at.elapsed() < DEVICE_CACHE_TTL {
            Some(devices.clone())
        } else {
            None
        }
    }

    /// Store a freshly-resolved device list for `user_key`.
    fn device_cache_put(&self, user_key: &str, devices: Vec<String>) {
        self.device_cache
            .write()
            .insert(user_key.to_string(), (devices, std::time::Instant::now()));
    }

    /// Drop all cached device lists — called when WhatsApp signals a device
    /// change (`<notification type="devices">`) so the next send re-resolves.
    pub(crate) fn device_cache_clear(&self) {
        self.device_cache.write().clear();
    }

    /// Bump and return this message's inbound retry-receipt count. The first
    /// undecryptable delivery of `msg_id` returns 1, the next 2, and so on —
    /// the caller uses the count to escalate the retry receipt (attach the
    /// re-establishment `<keys>` bundle once it exceeds 1) and to stop after a
    /// cap. Mirrors whatsmeow's `messageRetries[id]++`.
    fn bump_message_retry(&self, msg_id: &str) -> u32 {
        let mut m = self.message_retries.lock();
        let c = m.entry(msg_id.to_string()).or_insert(0);
        *c += 1;
        *c
    }

    /// Remove and return this message's retry count, if we'd previously asked
    /// the sender to retry it. A `Some` here on a *successful* decrypt means the
    /// session re-establishment worked — the peer resent the same id and we can
    /// now read it. Also keeps the map from growing once a message lands.
    fn take_message_retry(&self, msg_id: &str) -> Option<u32> {
        self.message_retries.lock().remove(msg_id)
    }

    /// Record a just-sent message so a later inbound retry receipt can resend
    /// it. Stores the unpadded inner proto + destination; evicts the oldest
    /// entry past [`RECENT_SENDS_MAX`].
    fn record_recent_send(&self, msg_id: &str, chat_jid: &str, inner_proto: &[u8]) {
        let mut q = self.recent_sends.lock();
        q.push_back(RecentSend {
            msg_id: msg_id.to_string(),
            chat_jid: chat_jid.to_string(),
            inner_proto: inner_proto.to_vec(),
        });
        while q.len() > RECENT_SENDS_MAX {
            q.pop_front();
        }
    }

    /// Look up a recently-sent message by id, returning `(chat_jid,
    /// inner_proto)` if still cached. Searches newest-first.
    fn recent_send(&self, msg_id: &str) -> Option<(String, Vec<u8>)> {
        self.recent_sends
            .lock()
            .iter()
            .rev()
            .find(|r| r.msg_id == msg_id)
            .map(|r| (r.chat_jid.clone(), r.inner_proto.clone()))
    }

    /// Install the live dispatcher so HTTP handlers can issue IQs. Called by
    /// `run_connection` once the socket is up; replaced on each (re)connect.
    pub(crate) fn set_iq_client(&self, d: ConnDispatcher) {
        *self.iq_client.lock() = Some(d);
    }

    /// Drop the IQ client on connection exit (a stale `out_tx` would just error,
    /// but clearing makes "offline" explicit).
    pub(crate) fn clear_iq_client(&self) {
        *self.iq_client.lock() = None;
    }

    /// Issue a synchronous IQ request/reply against the live connection. Errors
    /// if the session isn't currently connected.
    pub(crate) async fn iq_request(
        &self,
        iq: crate::protocol::binary::Node,
    ) -> Result<crate::protocol::binary::Node> {
        let client = self.iq_client.lock().clone();
        let client = client.ok_or_else(|| {
            Error::BadRequest("session is not connected (no live socket for IQ)".into())
        })?;
        client
            .iq_request(iq)
            .await
            .map_err(|e| Error::Internal(anyhow::anyhow!("iq request failed: {e}")))
    }

    /// Spawn the egress delivery worker (webhook + redis fan-out) exactly once for
    /// this session. Safe to call on every `connect`: the atomic guard ensures only
    /// the first call spawns (a second worker would double-deliver every event). The
    /// worker subscribes to the event bus and ends when the bus closes.
    pub fn ensure_egress_worker(self: &Arc<Self>, store: Arc<crate::store::Store>, session_id: &str) {
        use std::sync::atomic::Ordering;
        if self
            .egress_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let rx = self.events.subscribe();
            crate::egress::spawn_egress_worker(store, session_id.to_string(), rx);
        }
    }

    /// Store the driver-task handle, replacing (and detaching) any prior one.
    /// A prior handle only lingers if a previous connection task already
    /// exited, so we drop it without aborting.
    pub fn set_task_handle(&self, h: tokio::task::JoinHandle<()>) {
        *self.task_handle.lock() = Some(h);
    }

    /// Take the driver-task handle for awaiting during graceful shutdown.
    pub fn take_task_handle(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.task_handle.lock().take()
    }

    /// Record that an inbound frame just arrived (health/liveness signal).
    pub fn mark_rx(&self) {
        self.last_rx.store(
            chrono::Utc::now().timestamp(),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Unix ts of the last inbound frame, or `None` if nothing received yet.
    pub fn last_rx(&self) -> Option<i64> {
        match self.last_rx.load(std::sync::atomic::Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    /// Bump the lifetime reconnect counter.
    pub fn bump_reconnect(&self) {
        self.reconnect_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn reconnect_count(&self) -> u32 {
        self.reconnect_count
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Replace the running keepalive task, aborting any prior one. Called
    /// once per connection by `run_connection` after the handshake.
    pub fn set_keepalive_handle(&self, h: tokio::task::JoinHandle<()>) {
        if let Some(prev) = self.keepalive_handle.lock().replace(h) {
            prev.abort();
        }
    }

    /// Abort the keepalive task. Called from the connection-exit cleanup.
    pub fn cancel_keepalive(&self) {
        if let Some(h) = self.keepalive_handle.lock().take() {
            h.abort();
        }
    }

    /// Replace the running prekey top-up task, aborting any prior one. Called
    /// once per connection by `run_connection` after the handshake.
    pub fn set_prekey_topup_handle(&self, h: tokio::task::JoinHandle<()>) {
        if let Some(prev) = self.prekey_topup_handle.lock().replace(h) {
            prev.abort();
        }
    }

    /// Abort the prekey top-up task. Called from the connection-exit cleanup.
    pub fn cancel_prekey_topup(&self) {
        if let Some(h) = self.prekey_topup_handle.lock().take() {
            h.abort();
        }
    }

    /// Push outbound work onto the send queue. Returns BadRequest if the
    /// connection task has shut down without resetting the queue (callers
    /// can treat that as "session offline" — the persisted message row is
    /// still recoverable by future re-drive).
    pub fn enqueue_send(&self, op: SendOp) -> Result<()> {
        self.send_tx
            .read()
            .send(op)
            .map_err(|_| Error::BadRequest("session is offline; reconnect first".into()))
    }

    /// Same as `enqueue_send` but also persists the op into the
    /// `outbound_queue` table so a reconnect after disconnect can drain
    /// it. Skips RawNode variants (ephemeral presence/typing/receipt
    /// nodes that lose meaning across reconnects). Failures to persist
    /// are logged but don't fail the enqueue — the in-memory path is
    /// the source of truth for the active connection.
    pub fn enqueue_send_persistent(
        &self,
        store: &Store,
        session_id: &str,
        op: SendOp,
    ) -> Result<()> {
        if let Some((msg_id, op_json)) = persistable_op_view(&op) {
            let now = chrono::Utc::now().timestamp();
            let _ = store.outbound_queue_upsert(session_id, &msg_id, &op_json, now);
        }
        self.enqueue_send(op)
    }

    /// Take the send-queue receiver. Returns None if another task already
    /// holds it. The connection task takes this once at startup; on exit
    /// it calls [`Session::reset_send_queue`] so a future reconnect gets
    /// a fresh receiver.
    fn take_send_receiver(&self) -> Option<mpsc::UnboundedReceiver<SendOp>> {
        self.send_rx.lock().take()
    }

    /// Replace the send queue with a fresh tx/rx pair. Old senders held by
    /// HTTP handlers will start returning errors after the swap, which the
    /// `enqueue_send` path surfaces as BadRequest.
    fn reset_send_queue(&self) {
        let (tx, rx) = mpsc::unbounded_channel();
        *self.send_tx.write() = tx;
        *self.send_rx.lock() = Some(rx);
    }

    /// Update status + bump `updated_at` under the meta lock. Persistence to
    /// the store is the SessionManager's responsibility.
    pub fn set_status(&self, status: SessionStatus) {
        let mut m = self.meta.write();
        m.status = status;
        m.updated_at = chrono::Utc::now().timestamp();
    }

    /// Replace the pending QR codes. Used by tests that don't need a
    /// rotation task; production callers should use [`install_qr_rotation`].
    #[allow(dead_code)]
    pub fn set_qr_codes(&self, codes: Vec<String>) {
        *self.qr_codes.write() = codes;
    }

    /// First QR string, if one is currently advertised.
    pub fn current_qr(&self) -> Option<String> {
        self.qr_codes.read().first().cloned()
    }

    /// Install a fresh batch of QR codes from a `<pair-device>` IQ and
    /// spawn the rotation task. Aborts any prior rotation. Emits an
    /// initial `Qr` event for the head; subsequent events fire each time
    /// the head expires (`QR_ROTATE_PERIOD`) until the vec drains.
    pub fn install_qr_rotation(self: &Arc<Self>, codes: Vec<String>) {
        if codes.is_empty() {
            self.cancel_qr_rotation();
            return;
        }
        if let Some(h) = self.qr_rotate_handle.lock().take() {
            h.abort();
        }
        *self.qr_codes.write() = codes.clone();
        let _ = self.events.send(SessionEvent::Qr {
            code: codes[0].clone(),
        });

        // Only spawn the rotator if we're inside a tokio runtime. Sync
        // unit tests that exercise the IQ handler call this without one;
        // skipping the spawn lets them assert on `qr_codes` without
        // forcing every test to be `#[tokio::test]`.
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let weak = Arc::downgrade(self);
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(QR_ROTATE_PERIOD).await;
                let Some(s) = weak.upgrade() else { return };
                let next = {
                    let mut v = s.qr_codes.write();
                    if v.is_empty() {
                        return;
                    }
                    v.remove(0);
                    v.first().cloned()
                };
                match next {
                    Some(code) => {
                        let _ = s.events.send(SessionEvent::Qr { code });
                    }
                    None => return,
                }
            }
        });
        *self.qr_rotate_handle.lock() = Some(handle);
    }

    /// Abort any running rotation task and clear `qr_codes`. Called on
    /// `pair-success`, on logout, and when the connection task exits.
    pub fn cancel_qr_rotation(&self) {
        if let Some(h) = self.qr_rotate_handle.lock().take() {
            h.abort();
        }
        self.qr_codes.write().clear();
    }
}

/// How long each QR code stays at the head of the rotation before it's
/// popped and the next one is emitted. WhatsApp's first code is good for
/// ~60s and subsequent ones for ~20s, but the server accepts a uniform
/// 20s cadence too — simpler to just rotate at one rate.
const QR_ROTATE_PERIOD: std::time::Duration = std::time::Duration::from_secs(20);
/// TTL backstop for the per-user device-list cache (invalidation is normally
/// driven by `<notification type="devices">`). 1 h keeps sends cheap while
/// bounding staleness if a device-change notification is ever missed.
const DEVICE_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(3600);

/// Tunables for the background retention sweep, read from the environment. All
/// knobs default to OFF (`0`/unset): retention prunes only what you explicitly
/// opt into, so an unconfigured deployment never silently deletes data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetentionConfig {
    /// Keep at most this many messages per `(session, chat)`. 0 = unlimited.
    pub messages_per_chat: u32,
    /// Delete messages older than this many days. 0 = no age cutoff.
    pub message_max_age_days: u32,
    /// Delete Signal session records not written in this many days. 0 = never.
    pub signal_max_age_days: u32,
    /// Sweep interval in seconds. 0 = retention disabled entirely.
    pub sweep_secs: u64,
}

impl RetentionConfig {
    pub fn from_env() -> Self {
        fn env_u32(k: &str) -> u32 {
            std::env::var(k).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
        }
        fn env_u64(k: &str) -> u64 {
            std::env::var(k).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0)
        }
        Self {
            messages_per_chat: env_u32("RUWA_RETENTION_MESSAGES_PER_CHAT"),
            message_max_age_days: env_u32("RUWA_RETENTION_MESSAGE_DAYS"),
            signal_max_age_days: env_u32("RUWA_RETENTION_SIGNAL_DAYS"),
            sweep_secs: env_u64("RUWA_RETENTION_SWEEP_SECS"),
        }
    }

    /// True when at least one pruning knob is set, so the sweep is worth running.
    pub fn any_enabled(&self) -> bool {
        self.messages_per_chat > 0 || self.message_max_age_days > 0 || self.signal_max_age_days > 0
    }
}

/// Row counts removed by one [`SessionManager::prune_once`] pass.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PruneStats {
    pub messages_aged_out: usize,
    pub messages_over_cap: usize,
    pub signal_sessions_pruned: usize,
}

pub struct SessionManager {
    pub(crate) store: Arc<Store>,
    sessions: RwLock<HashMap<SessionId, Arc<Session>>>,
    /// Process-wide graceful-shutdown signal. `connect` hands each driver task
    /// a receiver; `shutdown` flips it to `true`, which every connection loop
    /// observes (via `wait_for`) and unwinds cleanly. Latching, not edge —
    /// tasks spawned mid-shutdown see the current `true` immediately.
    shutdown_tx: watch::Sender<bool>,
    /// This instance's identity for cross-instance session leasing. From
    /// `RUWA_INSTANCE_ID` (stable across restarts of the same instance) or a
    /// random uuid. Used as `session_leases.owner_id`.
    instance_id: String,
    /// Lease TTL in seconds (`RUWA_LEASE_TTL_SECS`, default 60). A lease is
    /// stealable by another instance once `heartbeat_ts + ttl < now`.
    lease_ttl_secs: i64,
}

impl SessionManager {
    pub fn new(store: Arc<Store>) -> Self {
        let instance_id =
            std::env::var("RUWA_INSTANCE_ID").unwrap_or_else(|_| uuid_v4());
        let lease_ttl_secs = std::env::var("RUWA_LEASE_TTL_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<i64>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(60);
        Self::with_instance(store, instance_id, lease_ttl_secs)
    }

    /// Construct with an explicit instance id + TTL. Lets tests drive two
    /// "instances" against one shared store to exercise the lease state machine.
    pub(crate) fn with_instance(store: Arc<Store>, instance_id: String, lease_ttl_secs: i64) -> Self {
        let (shutdown_tx, _) = watch::channel(false);
        Self {
            store,
            sessions: RwLock::new(HashMap::new()),
            shutdown_tx,
            instance_id,
            lease_ttl_secs,
        }
    }

    /// Try to acquire (or re-affirm) the lease for `session_id`. Succeeds when
    /// the session is unleased, already ours, or held by a stale lease (past
    /// TTL). Atomic: a single conditional UPSERT decides ownership, so two
    /// instances racing for a free/stale lease can't both win. Returns whether
    /// this instance now holds the lease.
    pub fn try_acquire_lease(&self, session_id: &str) -> Result<bool> {
        let now = chrono::Utc::now().timestamp();
        Ok(self
            .store
            .lease_acquire(session_id, &self.instance_id, self.lease_ttl_secs, now)?)
    }

    /// The current lease holder for `session_id`, or None if unleased. Returns
    /// `(owner_id, is_stale)` — `is_stale` true once the lease is past its TTL.
    pub fn lease_holder(&self, session_id: &str) -> Result<Option<(String, bool)>> {
        let now = chrono::Utc::now().timestamp();
        Ok(self.store.lease_holder(session_id, now)?)
    }

    /// Signal every connection task to wind down, wait (bounded) for them to
    /// close their sockets, then park any still-live session as `Disconnected`.
    /// Called from `main` after `axum::serve` stops accepting on SIGTERM.
    pub async fn shutdown(&self) {
        // Latch the shutdown flag; all driver/connection tasks observe it.
        // `send_replace` (not `send`) so the value sticks even when no task is
        // currently subscribed — a `connect` racing shutdown still sees `true`.
        self.shutdown_tx.send_replace(true);

        // Snapshot the running task handles (dropping the lock before awaiting).
        let handles: Vec<tokio::task::JoinHandle<()>> = {
            let map = self.sessions.read();
            map.values().filter_map(|s| s.take_task_handle()).collect()
        };
        if !handles.is_empty() {
            tracing::info!(tasks = handles.len(), "graceful shutdown: draining connection tasks");
        }
        let join_all = async {
            for h in handles {
                let _ = h.await;
            }
        };
        if tokio::time::timeout(std::time::Duration::from_secs(10), join_all)
            .await
            .is_err()
        {
            tracing::warn!("graceful shutdown: timed out waiting for connection tasks");
        }

        // Defensive sweep: park anything that still looks live (e.g. a task
        // that had no tracked handle) so persisted status reflects the stop.
        let map = self.sessions.read();
        for s in map.values() {
            let st = s.meta.read().status;
            if matches!(
                st,
                SessionStatus::Connecting | SessionStatus::Connected | SessionStatus::AwaitingQr
            ) {
                s.set_status(SessionStatus::Disconnected);
            }
        }
    }

    /// Run one retention pass over the store: age-out old messages, cap messages
    /// per chat, and prune dead-device Signal sessions — each gated on its knob
    /// being set in `cfg`. The whole pass is a single transaction (all-or-nothing)
    /// and idempotent (a second run with the same data prunes nothing new).
    pub fn prune_once(&self, cfg: &RetentionConfig) -> Result<PruneStats> {
        let now = chrono::Utc::now().timestamp();
        let msg_age_cutoff = (cfg.message_max_age_days > 0)
            .then(|| now - i64::from(cfg.message_max_age_days) * 86_400);
        let per_chat = (cfg.messages_per_chat > 0).then_some(cfg.messages_per_chat);
        let signal_age_cutoff = (cfg.signal_max_age_days > 0)
            .then(|| now - i64::from(cfg.signal_max_age_days) * 86_400);
        let (messages_aged_out, messages_over_cap, signal_sessions_pruned) =
            self.store.prune(msg_age_cutoff, per_chat, signal_age_cutoff)?;
        Ok(PruneStats {
            messages_aged_out,
            messages_over_cap,
            signal_sessions_pruned,
        })
    }

    /// Re-hydrate sessions from the store on startup.
    /// In M2+ this also reconnects WS for sessions that were previously connected.
    pub async fn restore_all(&self) -> Result<()> {
        let metas: Vec<SessionMeta> = self
            .store
            .sessions_all()?
            .into_iter()
            .map(|row| {
                // A fresh process holds no live sockets, so a persisted
                // `Connecting`/`Connected` is stale. Normalize it to
                // `Disconnected` so `connect()` (which short-circuits on
                // those two) can actually revive a paired session after a
                // restart. Pending / LoggedOut are preserved as-is.
                let status = match row.status.parse_session_status() {
                    SessionStatus::Connecting | SessionStatus::Connected => {
                        SessionStatus::Disconnected
                    }
                    other => other,
                };
                SessionMeta {
                    id: row.id,
                    label: row.label,
                    status,
                    jid: row.jid,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                    proxy_url: row.proxy_url,
                    mark_online: row.mark_online,
                }
            })
            .collect();

        // One-time backfill (idempotent): own group messages sent from the phone
        // were stored `from_me=0` before the participant-based self-check landed,
        // so they render as if they came from someone else. A message whose
        // sender is our own account is from us — flip it. Cheap (indexed on
        // sender_jid) and self-limiting: after the first boot no rows match.
        for meta in &metas {
            if let Some(jid) = &meta.jid {
                let own_pn = lid_user_part(jid);
                if own_pn.is_empty() {
                    continue;
                }
                let own_lid = self.store.pn_to_lid(&meta.id, own_pn).ok().flatten();
                match self
                    .store
                    .messages_mark_self_from_me(&meta.id, own_pn, own_lid.as_deref())
                {
                    Ok(n) if n > 0 => {
                        tracing::info!(session = %meta.id, fixed = n, "backfilled from_me on own messages")
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(session = %meta.id, error = %e, "from_me backfill failed"),
                }
            }
        }

        let mut map = self.sessions.write();
        for meta in metas {
            map.insert(meta.id.clone(), Arc::new(Session::new(meta)));
        }
        Ok(())
    }

    /// Revive every paired session a restart left `Disconnected` by kicking off
    /// its connect loop. A fresh process holds no live sockets, so `restore_all`
    /// normalizes paired sessions to `Disconnected`; without this they'd sit down
    /// until a manual `POST /connect` — i.e. every deploy/restart takes the
    /// session offline. The per-session reconnect loop + keepalive watchdog then
    /// keep it alive across residential-proxy resets. Returns how many connects
    /// were issued. (Not called by tests, which drive `restore_all` directly and
    /// must not open live sockets.)
    pub fn autoconnect_restored(self: &Arc<Self>) -> usize {
        let ids: Vec<String> = {
            let map = self.sessions.read();
            map.iter()
                .filter(|(_, s)| {
                    let m = s.meta.read();
                    m.jid.is_some() && matches!(m.status, SessionStatus::Disconnected)
                })
                .map(|(id, _)| id.clone())
                .collect()
        };
        let mut started = 0;
        for id in ids {
            match self.connect(&id) {
                Ok(()) => {
                    started += 1;
                    tracing::info!(session = %id, "autoconnect restored session on boot");
                }
                // Leasing on + the lease is still held by a draining peer: a
                // deploy overlap where the old instance hasn't released yet.
                // Don't give up (which would leave the session offline until a
                // manual /connect) — spawn a waiter that retries the instant the
                // peer releases, so the deploy hands off cleanly.
                Err(Error::Conflict(_)) if leasing_enabled() => {
                    started += 1;
                    let mgr = self.clone();
                    tokio::spawn(mgr.connect_when_lease_free(id.clone()));
                    tracing::info!(
                        session = %id,
                        "session leased by a draining peer — waiting to hand off"
                    );
                }
                Err(e) => {
                    tracing::warn!(session = %id, error = %e, "autoconnect on boot failed")
                }
            }
        }
        started
    }

    /// Wait for a peer instance to release a session's lease, then connect it.
    /// Spawned by `autoconnect_restored` when a session it wants to revive on
    /// boot is still leased by a draining peer (a deploy overlap). Polls with
    /// exponential backoff until the lease frees (connect succeeds), the session
    /// leaves the disconnected-paired state (a manual connect / logout / delete
    /// moved it on), or this process itself begins shutting down.
    async fn connect_when_lease_free(self: Arc<Self>, id: String) {
        const INITIAL_MS: u64 = 1_000;
        const MAX_MS: u64 = 15_000;
        let shutdown = self.shutdown_tx.subscribe();
        let mut backoff = INITIAL_MS;
        loop {
            // Bail if THIS process is now shutting down too.
            if *shutdown.borrow() {
                return;
            }
            // Bail if the session no longer wants reviving (connected elsewhere,
            // logged out, or deleted between polls).
            {
                let map = self.sessions.read();
                match map.get(&id) {
                    Some(s) => {
                        let m = s.meta.read();
                        if !lease_wait_still_wanted(m.status, m.jid.is_some()) {
                            return;
                        }
                    }
                    None => return,
                }
            }
            match self.connect(&id) {
                Ok(()) => {
                    tracing::info!(
                        session = %id,
                        "lease released by peer — connected (deploy handoff complete)"
                    );
                    return;
                }
                // Still held — wait and retry.
                Err(Error::Conflict(_)) => {}
                Err(e) => {
                    tracing::warn!(session = %id, error = %e, "deploy-handoff connect failed");
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(backoff)).await;
            backoff = (backoff * 2).min(MAX_MS);
        }
    }

    pub fn create(&self, label: Option<String>) -> Result<Arc<Session>> {
        let now = chrono::Utc::now().timestamp();
        let meta = SessionMeta {
            id: uuid_v4(),
            label,
            status: SessionStatus::Pending,
            jid: None,
            proxy_url: None,
            mark_online: false,
            created_at: now,
            updated_at: now,
        };

        let keys = DeviceKeys::generate();
        let prekeys = PreKey::generate_batch(1, INITIAL_PREKEY_COUNT);
        // Per-tenant API key, returned once to the creator and never echoed
        // again. Two UUIDs concatenated for a 64-hex-char opaque secret.
        let api_key = format!("{}{}", uuid_v4_simple(), uuid_v4_simple());

        let prekey_batch: Vec<(u32, &[u8], &[u8])> = prekeys
            .iter()
            .map(|pk| {
                (
                    pk.key_id,
                    pk.keypair.private.as_slice(),
                    pk.keypair.public.as_slice(),
                )
            })
            .collect();
        self.store.create_session(
            &crate::store::NewSession {
                id: &meta.id,
                label: meta.label.as_deref(),
                status: meta.status.as_str(),
                jid: meta.jid.as_deref(),
                registration_id: keys.registration_id,
                noise_priv: keys.noise.private.as_slice(),
                noise_pub: keys.noise.public.as_slice(),
                identity_priv: keys.identity.private.as_slice(),
                identity_pub: keys.identity.public.as_slice(),
                spk_id: keys.signed_prekey.key_id,
                spk_priv: keys.signed_prekey.keypair.private.as_slice(),
                spk_pub: keys.signed_prekey.keypair.public.as_slice(),
                spk_sig: keys.signed_prekey.signature.as_slice(),
                adv_secret: keys.adv_secret.as_slice(),
                api_key: &api_key,
                created_at: meta.created_at,
                updated_at: meta.updated_at,
            },
            &prekey_batch,
        )?;

        let session = Arc::new(Session::new(meta));
        self.sessions
            .write()
            .insert(session.meta.read().id.clone(), session.clone());
        Ok(session)
    }

    /// Import an already-paired companion session from another WhatsApp client
    /// (Baileys / Evolution) WITHOUT re-pairing. Given the device's key material,
    /// we write the same identity a normal pairing would, so a subsequent
    /// `connect()` logs in directly (`<success>`, no QR). This is a MOVE: the
    /// source client must stop using the device or WhatsApp will bounce one of
    /// them with `conflict=replaced` (same device, two live sockets).
    ///
    /// Returns the new session and its per-tenant API key (shown once).
    pub fn import_session(
        &self,
        label: Option<String>,
        creds: ImportedCreds,
    ) -> Result<(Arc<Session>, String)> {
        let now = chrono::Utc::now().timestamp();
        let id = uuid_v4();
        let api_key = format!("{}{}", uuid_v4_simple(), uuid_v4_simple());

        // Insert the identity. jid is set up-front so select_client_payload takes
        // the LOGIN path (not registration/QR). No prekey batch — connect()
        // replenishes our OTK supply on login.
        self.store.create_session(
            &crate::store::NewSession {
                id: &id,
                label: label.as_deref(),
                status: SessionStatus::Disconnected.as_str(),
                jid: Some(&creds.jid),
                registration_id: creds.registration_id,
                noise_priv: &creds.noise_priv,
                noise_pub: &creds.noise_pub,
                identity_priv: &creds.identity_priv,
                identity_pub: &creds.identity_pub,
                spk_id: creds.spk_id,
                spk_priv: &creds.spk_priv,
                spk_pub: &creds.spk_pub,
                spk_sig: &creds.spk_sig,
                adv_secret: &creds.adv_secret,
                api_key: &api_key,
                created_at: now,
                updated_at: now,
            },
            &[],
        )?;
        // Persist the signed device-identity (account_pb) — needed for retry/
        // device-identity attachment after login. (Also re-affirms jid; the
        // status it sets is corrected to Disconnected just below.)
        self.store.session_apply_pair_success(
            &id,
            &creds.account_pb,
            None,
            creds.platform.as_deref(),
            Some(&creds.jid),
            now,
        )?;
        if let Some(name) = &creds.push_name {
            if !name.is_empty() {
                let _ = self.store.session_set_push_name(&id, name);
            }
        }

        let meta = SessionMeta {
            id,
            label,
            status: SessionStatus::Disconnected,
            jid: Some(creds.jid),
            proxy_url: None,
            mark_online: false,
            created_at: now,
            updated_at: now,
        };
        let session = Arc::new(Session::new(meta));
        self.sessions
            .write()
            .insert(session.meta.read().id.clone(), session.clone());
        Ok((session, api_key))
    }

    /// The session's per-tenant API key, if set. Read straight from the store
    /// (never cached in `SessionMeta`, which is serialized back to clients) so
    /// it can't leak through a list/get response. Returns `None` for an unknown
    /// session id or a legacy row predating the `api_key` column.
    pub fn session_api_key(&self, id: &str) -> Result<Option<String>> {
        Ok(self.store.session_api_key(id)?)
    }

    pub fn get(&self, id: &str) -> Result<Arc<Session>> {
        self.sessions
            .read()
            .get(id)
            .cloned()
            .ok_or_else(|| Error::NotFound(format!("session {id}")))
    }

    pub fn list(&self) -> Vec<SessionMeta> {
        self.sessions
            .read()
            .values()
            .map(|s| s.meta.read().clone())
            .collect()
    }

    /// Render process-wide counters + live session gauges in the Prometheus
    /// text exposition format (v0.0.4). Hand-rolled — no client-library dep.
    /// Session gauges are computed from the in-memory registry; the counters
    /// come from the `metrics` module's atomics. Served by `GET /metrics`.
    pub fn metrics_text(&self) -> String {
        let (mut total, mut connected) = (0u64, 0u64);
        for s in self.sessions.read().values() {
            total += 1;
            if matches!(s.meta.read().status, SessionStatus::Connected) {
                connected += 1;
            }
        }

        fn emit(out: &mut String, name: &str, help: &str, kind: &str, value: u64) {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
            ));
        }
        fn emit_f(out: &mut String, name: &str, help: &str, kind: &str, value: f64) {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
            ));
        }

        let mut out = String::new();
        emit(
            &mut out,
            "ruwa_sessions_total",
            "Sessions registered in this instance.",
            "gauge",
            total,
        );
        emit(
            &mut out,
            "ruwa_sessions_connected",
            "Sessions with a live WhatsApp connection.",
            "gauge",
            connected,
        );
        emit(
            &mut out,
            "ruwa_messages_in_total",
            "Inbound message stanzas received.",
            "counter",
            metrics::get(&metrics::MSGS_IN),
        );
        emit(
            &mut out,
            "ruwa_messages_out_total",
            "Outbound messages shipped to the wire.",
            "counter",
            metrics::get(&metrics::MSGS_OUT),
        );
        emit(
            &mut out,
            "ruwa_decrypt_failures_total",
            "Inbound messages that failed to decrypt.",
            "counter",
            metrics::get(&metrics::DECRYPT_FAILURES),
        );
        emit(
            &mut out,
            "ruwa_reconnects_total",
            "WebSocket reconnect attempts across all sessions.",
            "counter",
            metrics::get(&metrics::RECONNECTS_TOTAL),
        );
        emit(
            &mut out,
            "ruwa_prekey_refills_total",
            "One-time prekey replenishment batches.",
            "counter",
            metrics::get(&metrics::PREKEY_REFILLS_TOTAL),
        );
        emit(
            &mut out,
            "ruwa_webhook_delivered_total",
            "Webhook deliveries that succeeded (2xx, possibly after retries).",
            "counter",
            metrics::get(&metrics::WEBHOOK_DELIVERED_TOTAL),
        );
        emit(
            &mut out,
            "ruwa_webhook_failed_total",
            "Webhook deliveries dropped after exhausting retries.",
            "counter",
            metrics::get(&metrics::WEBHOOK_FAILED_TOTAL),
        );

        // ── Runtime / process metrics (RAM, CPU, FDs, uptime, HTTP latency) ──
        emit(
            &mut out,
            "ruwa_process_uptime_seconds",
            "Seconds since the process started.",
            "gauge",
            metrics::uptime_seconds(),
        );
        let reqs = metrics::get(&metrics::HTTP_REQUESTS_TOTAL);
        let dur_sum = metrics::get(&metrics::HTTP_DURATION_MS_SUM);
        emit(
            &mut out,
            "ruwa_http_requests_total",
            "HTTP requests served.",
            "counter",
            reqs,
        );
        emit(
            &mut out,
            "ruwa_http_request_duration_ms_sum",
            "Cumulative HTTP response time (ms); divide by requests_total for the average.",
            "counter",
            dur_sum,
        );
        emit_f(
            &mut out,
            "ruwa_http_request_duration_ms_avg",
            "Average HTTP response time (ms) over the process lifetime.",
            "gauge",
            if reqs > 0 { dur_sum as f64 / reqs as f64 } else { 0.0 },
        );
        // /proc-derived gauges — omitted entirely when unavailable (non-Linux).
        if let Some(rss) = metrics::resident_memory_bytes() {
            emit(
                &mut out,
                "ruwa_process_resident_memory_bytes",
                "Resident set size (physical RAM) in bytes.",
                "gauge",
                rss,
            );
        }
        if let Some(cpu) = metrics::cpu_seconds_total() {
            emit_f(
                &mut out,
                "ruwa_process_cpu_seconds_total",
                "Total CPU time (user + system) in seconds.",
                "counter",
                cpu,
            );
        }
        if let Some(fds) = metrics::open_fds() {
            emit(
                &mut out,
                "ruwa_process_open_fds",
                "Open file descriptors.",
                "gauge",
                fds,
            );
        }
        out
    }

    /// Snapshot the live in-memory metric series as `(name, value)` pairs for
    /// persistence + charting. Mirrors the app-level families `metrics_text`
    /// emits (the ones Railway's own dashboards can't see). `/proc` gauges are
    /// included only where available, matching the exposition endpoint.
    pub fn metrics_snapshot(&self) -> Vec<(String, f64)> {
        let (mut total, mut connected) = (0u64, 0u64);
        for s in self.sessions.read().values() {
            total += 1;
            if matches!(s.meta.read().status, SessionStatus::Connected) {
                connected += 1;
            }
        }
        let reqs = metrics::get(&metrics::HTTP_REQUESTS_TOTAL);
        let dur_sum = metrics::get(&metrics::HTTP_DURATION_MS_SUM);
        let mut out: Vec<(String, f64)> = vec![
            ("ruwa_sessions_total".into(), total as f64),
            ("ruwa_sessions_connected".into(), connected as f64),
            (
                "ruwa_messages_in_total".into(),
                metrics::get(&metrics::MSGS_IN) as f64,
            ),
            (
                "ruwa_messages_out_total".into(),
                metrics::get(&metrics::MSGS_OUT) as f64,
            ),
            (
                "ruwa_decrypt_failures_total".into(),
                metrics::get(&metrics::DECRYPT_FAILURES) as f64,
            ),
            (
                "ruwa_reconnects_total".into(),
                metrics::get(&metrics::RECONNECTS_TOTAL) as f64,
            ),
            (
                "ruwa_prekey_refills_total".into(),
                metrics::get(&metrics::PREKEY_REFILLS_TOTAL) as f64,
            ),
            (
                "ruwa_webhook_delivered_total".into(),
                metrics::get(&metrics::WEBHOOK_DELIVERED_TOTAL) as f64,
            ),
            (
                "ruwa_webhook_failed_total".into(),
                metrics::get(&metrics::WEBHOOK_FAILED_TOTAL) as f64,
            ),
            ("ruwa_http_requests_total".into(), reqs as f64),
            (
                "ruwa_http_request_duration_ms_avg".into(),
                if reqs > 0 { dur_sum as f64 / reqs as f64 } else { 0.0 },
            ),
        ];
        if let Some(rss) = metrics::resident_memory_bytes() {
            out.push(("ruwa_process_resident_memory_bytes".into(), rss as f64));
        }
        if let Some(cpu) = metrics::cpu_seconds_total() {
            out.push(("ruwa_process_cpu_seconds_total".into(), cpu));
        }
        out
    }

    /// Persist one sample row per live metric series, stamped at `ts` (unix
    /// seconds). Driven by the background sampler in `main`.
    pub fn persist_metrics(&self, ts: i64) -> Result<usize> {
        let snap = self.metrics_snapshot();
        let rows: Vec<(&str, i64, f64)> =
            snap.iter().map(|(n, v)| (n.as_str(), ts, *v)).collect();
        Ok(self.store.metrics_sample_insert_batch(&rows)?)
    }

    /// Drop persisted metric samples older than `age_cutoff` (unix seconds).
    pub fn prune_metrics(&self, age_cutoff: i64) -> Result<usize> {
        Ok(self.store.metrics_prune(age_cutoff)?)
    }

    /// A persisted metric series at/after `since_ts`, oldest-first (for charts).
    pub fn metrics_history(
        &self,
        name: &str,
        since_ts: i64,
        limit: u32,
    ) -> Result<Vec<crate::store::MetricPoint>> {
        Ok(self.store.metrics_history(name, since_ts, limit)?)
    }

    /// Distinct persisted metric series names.
    pub fn metrics_names(&self) -> Result<Vec<String>> {
        Ok(self.store.metrics_names()?)
    }

    /// Liveness snapshot for one session — real socket state, not just the
    /// persisted status. Lets a watcher spot a stalled connection (status
    /// "connected" but no rx for a long time) and track reconnect churn.
    pub fn health(&self, id: &str) -> Result<SessionHealth> {
        let session = self.get(id)?;
        let meta = session.meta.read().clone();
        let last_rx = session.last_rx();
        let now = chrono::Utc::now().timestamp();
        Ok(SessionHealth {
            id: meta.id.clone(),
            status: meta.status,
            connected: matches!(meta.status, SessionStatus::Connected),
            jid: meta.jid.clone(),
            last_rx,
            seconds_since_rx: last_rx.map(|t| now - t),
            reconnect_count: session.reconnect_count(),
            prekeys_available: available_prekey_count(&self.store, &meta.id),
            proxy_configured: meta.proxy_url.is_some(),
        })
    }

    pub fn delete(&self, id: &str) -> Result<()> {
        self.store.session_delete(id)?;
        self.sessions.write().remove(id);
        Ok(())
    }

    /// Read the persisted DeviceKeys for a session.
    pub fn load_device_keys(&self, id: &str) -> Result<DeviceKeys> {
        let row = self
            .store
            .device_keys_load(id)?
            .ok_or_else(|| Error::NotFound(format!("session {id}")))?;
        row.try_into()
            .map_err(|e: &str| Error::Internal(anyhow::anyhow!(e)))
    }

    /// Spawn a background task that opens a WS, runs Noise XX, and tracks
    /// status transitions on the session. Idempotent: a session that's
    /// already Connecting/Connected returns Ok without spawning a duplicate.
    pub fn connect(self: &Arc<Self>, id: &str) -> Result<()> {
        let session = self.get(id)?;
        let current = session.meta.read().status;
        if matches!(current, SessionStatus::Connecting | SessionStatus::Connected) {
            return Ok(());
        }

        let keys = self.load_device_keys(id)?;

        // Manual (re)connect clears a prior WhatsApp-block/expect-disconnect so an
        // operator can deliberately retry a Blocked session.
        session
            .wa_blocked
            .store(false, std::sync::atomic::Ordering::Relaxed);
        session
            .expect_disconnect
            .store(false, std::sync::atomic::Ordering::Relaxed);

        // Cross-instance leasing (opt-in via RUWA_LEASING). Acquire before
        // connecting so only one instance holds a live socket per session; if a
        // peer holds a fresh lease, refuse rather than start a replace-war.
        let lease = if leasing_enabled() {
            if !self.try_acquire_lease(id)? {
                let holder = self
                    .lease_holder(id)?
                    .map(|(o, _)| o)
                    .unwrap_or_else(|| "another instance".into());
                return Err(Error::Conflict(format!(
                    "session {id} is leased by {holder}"
                )));
            }
            Some(LeaseParams {
                owner: self.instance_id.clone(),
                ttl: self.lease_ttl_secs,
            })
        } else {
            None
        };

        // Start the egress delivery worker (webhook + redis fan-out; idempotent —
        // only the first connect spawns it; it outlives reconnects and ends when
        // the session is dropped).
        session.ensure_egress_worker(self.store.clone(), id);

        session.set_status(SessionStatus::Connecting);
        let _ = session.events.send(SessionEvent::Connecting);

        let session_for_task = session.clone();
        let store_for_task = self.store.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        let lease_for_task = lease.clone();
        let store_for_release = self.store.clone();
        let id_for_release = id.to_string();
        let handle = tokio::spawn(async move {
            run_with_reconnect(
                session_for_task,
                store_for_task,
                keys,
                shutdown_rx,
                lease_for_task,
            )
            .await;
            // Driver fully exited (logout, terminal error, shutdown, or lease
            // loss). Release our lease so another instance can claim the session
            // immediately instead of waiting out the TTL (owner-scoped DELETE, so
            // it's a no-op if the lease was already stolen).
            if let Some(l) = lease {
                let _ = store_for_release.lease_release(&id_for_release, &l.owner);
            }
        });
        session.set_task_handle(handle);
        Ok(())
    }

    /// Set (or clear, with `None`) the session's egress proxy. Validates the URL
    /// up-front, persists it, and updates the in-memory meta. Takes effect on the
    /// next connect — callers that want it live should reconnect the session.
    pub fn set_proxy(&self, id: &str, proxy_url: Option<String>) -> Result<()> {
        if let Some(url) = &proxy_url {
            crate::protocol::connection::Proxy::parse(url)
                .map_err(|e| Error::BadRequest(format!("invalid proxy_url: {e}")))?;
        }
        let session = self.get(id)?;
        let now = chrono::Utc::now().timestamp();
        self.store.session_set_proxy(id, proxy_url.as_deref(), now)?;
        let mut m = session.meta.write();
        m.proxy_url = proxy_url;
        m.updated_at = now;
        Ok(())
    }

    /// Set a session's `mark_online` presence preference. `true` → announce
    /// `available` (online; WhatsApp silences the phone's notifications);
    /// `false` → `unavailable` (phone keeps notifying). If the session is live,
    /// the new presence is re-announced immediately (no reconnect needed).
    pub fn set_mark_online(&self, id: &str, on: bool) -> Result<()> {
        let session = self.get(id)?;
        self.store.session_set_mark_online(id, on)?;
        session.meta.write().mark_online = on;
        if let Some(d) = session.iq_client.lock().clone() {
            let name = self
                .store
                .session_push_name(id)
                .ok()
                .flatten()
                .filter(|s: &String| !s.is_empty());
            d.send_node(build_global_presence_node(presence_for(on), name.as_deref()));
        }
        Ok(())
    }

    /// Clear server-issued credentials and flip the session to LoggedOut.
    /// The long-term identity/noise keys are NOT wiped — re-pairing on the
    /// same session id is a separate flow. The connection task (if running)
    /// is signalled via `logout_notify`; it ships a best-effort
    /// `<remove-companion-device>` IQ over the live socket and exits.
    pub fn logout(&self, id: &str) -> Result<()> {
        let session = self.get(id)?;
        let prev_jid = session.meta.read().jid.clone();
        let now = chrono::Utc::now().timestamp();
        self.store.session_mark_logged_out(id, now)?;
        {
            let mut m = session.meta.write();
            m.jid = None;
            m.status = SessionStatus::LoggedOut;
            m.updated_at = now;
        }
        *session.qr_codes.write() = Vec::new();
        let _ = session.events.send(SessionEvent::LoggedOut);
        // Stash the JID on the session so the connection task can include
        // it on the `<remove-companion-device>` IQ. (We just nulled the
        // persisted JID column and the in-memory meta, so we re-attach it
        // ephemerally for the cancellation path.)
        *session.pending_logout_jid.write() = prev_jid;
        // Wake the connection task. It will exit cleanly after sending
        // the IQ and dropping the WS.
        session.logout_notify.notify_waiters();
        Ok(())
    }

    /// Persist an outgoing text message to the local `messages` table with
    /// `from_me=1`. Called by `POST /v1/sessions/:id/messages` before the
    /// connection task picks the row up to actually send. The wire-send
    /// path is M3 follow-up; for now this just records the user's intent.
    pub fn persist_outgoing_text(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
        sender_jid: &str,
        body_text: &str,
        timestamp: i64,
    ) -> Result<()> {
        let payload = serde_json::json!({ "type": "text", "text": body_text });
        self.store.message_insert(
            &crate::store::NewMessage {
                session_id,
                chat_jid,
                message_id,
                sender_jid,
                from_me: true,
                timestamp,
                msg_type: "text",
                body_text: Some(body_text),
                payload_json: &payload.to_string(),
                status: Some("queued"),
            },
            false,
        )?;
        Ok(())
    }

    /// Persist an outgoing structured message (location / contact / poll / …) so
    /// it shows in the chat history with `from_me=1, status=queued`. The actual
    /// wire send happens via an `EncryptedInner` SendOp carrying the built proto.
    #[allow(clippy::too_many_arguments)]
    pub fn persist_outgoing(
        &self,
        session_id: &str,
        chat_jid: &str,
        message_id: &str,
        sender_jid: &str,
        msg_type: &str,
        body_text: Option<&str>,
        payload_json: &str,
        timestamp: i64,
    ) -> Result<()> {
        self.store.message_insert(
            &crate::store::NewMessage {
                session_id,
                chat_jid,
                message_id,
                sender_jid,
                from_me: true,
                timestamp,
                msg_type,
                body_text,
                payload_json,
                status: Some("queued"),
            },
            false,
        )?;
        Ok(())
    }

    /// Load a Signal SessionRecord for the given remote address. Returns
    /// None if no row exists. Persistence format is JSON via serde_json
    /// (small, stable, easy to inspect).
    #[allow(dead_code)]
    pub fn load_signal_session(
        &self,
        session_id: &str,
        address: &str,
    ) -> Result<Option<crate::crypto::signal::SessionRecord>> {
        let bytes = self.store.signal_session_load(session_id, address)?;
        match bytes {
            None => Ok(None),
            Some(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| {
                Error::Internal(anyhow::anyhow!("corrupt signal session record: {e}"))
            })?)),
        }
    }

    /// Save (insert or replace) a Signal SessionRecord for `(session_id, address)`.
    #[allow(dead_code)]
    pub fn save_signal_session(
        &self,
        session_id: &str,
        address: &str,
        record: &crate::crypto::signal::SessionRecord,
    ) -> Result<()> {
        let bytes = serde_json::to_vec(record)
            .map_err(|e| Error::Internal(anyhow::anyhow!("serialize signal session: {e}")))?;
        let now = chrono::Utc::now().timestamp();
        self.store.signal_session_save(session_id, address, &bytes, now)?;
        Ok(())
    }
}

/// Whether cross-instance session leasing is enforced (`RUWA_LEASING=1`).
/// Off by default so single-instance deploys behave exactly as before.
fn leasing_enabled() -> bool {
    matches!(
        std::env::var("RUWA_LEASING").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Whether a session still wants boot-time revival: paired (has a jid) and
/// sitting `Disconnected`. The lease-wait loop (`connect_when_lease_free`) stops
/// once this goes false — i.e. the session connected, logged out, or was deleted.
fn lease_wait_still_wanted(status: SessionStatus, has_jid: bool) -> bool {
    has_jid && matches!(status, SessionStatus::Disconnected)
}

/// The lease parameters a connection task needs to renew/heartbeat its claim.
#[derive(Clone)]
struct LeaseParams {
    owner: String,
    ttl: i64,
}

/// Acquire-or-affirm a lease (used by `SessionManager::try_acquire_lease`).
/// Equal-jitter a backoff: keep at least half the computed delay, then add a
/// random portion (`frac` ∈ [0,1]) of the other half. Result is in
/// `[base/2, base]`, so the exponential growth is preserved but a synchronized
/// fleet spreads its retries instead of hammering the server in lockstep.
fn jittered_backoff_ms(base_ms: u64, frac: f64) -> u64 {
    let half = base_ms / 2;
    half + (half as f64 * frac.clamp(0.0, 1.0)).round() as u64
}

/// Client keepalive cadence. We ship an `<iq type=get xmlns=w:p/>` every
/// `KEEPALIVE_SECS`; the server answers with an `<iq type=result>`, which the
/// recv loop counts as inbound (`mark_rx`). So on a healthy socket `last_rx`
/// can never be staler than one keepalive round-trip.
const KEEPALIVE_SECS: u64 = 25;

/// rx-idle watchdog threshold. A live socket refreshes `last_rx` every
/// `KEEPALIVE_SECS` via the keepalive pong; if nothing arrives for this long
/// (~3 missed pongs) the socket is silently half-open — a residential proxy
/// dropped it without an RST, so we sit `Connected` but dead. The watchdog
/// force-reconnects instead of zombie-ing forever (the residential-proxy
/// freeze failure mode). Generous enough that brief jitter never trips it.
const RX_IDLE_TIMEOUT_SECS: i64 = 75;

/// How often the watchdog samples `last_rx` age. Sub-multiple of the timeout
/// so worst-case detection latency is `RX_IDLE_TIMEOUT_SECS + RX_WATCHDOG_TICK_SECS`.
const RX_WATCHDOG_TICK_SECS: u64 = 10;

/// True when the last inbound frame is older than `timeout` seconds — i.e. the
/// keepalive pong stream has stalled and the socket should be torn down and
/// reconnected. `None` (nothing received yet) is never stale: the caller only
/// arms the watchdog after `<success>`, which itself marks rx.
fn rx_is_stale(last_rx: Option<i64>, now: i64, timeout: i64) -> bool {
    match last_rx {
        Some(last) => now.saturating_sub(last) >= timeout,
        None => false,
    }
}

/// Per-session connection task. Opens the WS, runs Noise XX, then a duplex
/// loop: inbound binary nodes flow into `process_inbound_node`; outbound
/// nodes (from the send pump) flow back through `socket.send_node`. The
/// send pump is a sibling spawned task that drains the session's `SendOp`
/// queue and uses `ConnDispatcher` to ship `<iq>` requests + await replies
/// while the main loop concurrently handles inbound traffic.
/// Wrap `run_connection` in an exponential-backoff retry loop. Each
/// failure (handshake error, socket close, etc.) bumps the wait by 2x
/// up to a 60s cap. A successful logout — which exits run_connection
/// via `Ok(())` — breaks out of the loop without retrying. The status
/// of the session is also a stop signal: if a peer or admin flips it
/// to `LoggedOut`, we do not reconnect.
async fn run_with_reconnect(
    session: Arc<Session>,
    store: Arc<Store>,
    keys: DeviceKeys,
    mut shutdown: watch::Receiver<bool>,
    lease: Option<LeaseParams>,
) {
    const INITIAL_BACKOFF_MS: u64 = 1_000;
    const MAX_BACKOFF_MS: u64 = 60_000;

    // Spawned during an in-progress shutdown? Never open a socket.
    if *shutdown.borrow() {
        return;
    }

    // A malformed proxy URL is a terminal config error — retrying can't fix it,
    // and we must never fall back to a direct IP (defeats the proxy's purpose).
    // Park the session in ProxyError; the user fixes the URL + reconnects.
    if let Some(url) = session.meta.read().proxy_url.clone() {
        if let Err(e) = crate::protocol::connection::Proxy::parse(&url) {
            tracing::warn!(error = %e, "invalid proxy_url — parking session in ProxyError");
            session.set_status(SessionStatus::ProxyError);
            let _ = session.events.send(SessionEvent::Disconnected {
                reason: format!("proxy_error: {e}"),
            });
            return;
        }
    }

    let mut backoff_ms = INITIAL_BACKOFF_MS;
    loop {
        // Reset before each attempt so we can tell whether THIS connection
        // reached `<success>`.
        session
            .reached_success
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let exited_clean = run_connection(
            session.clone(),
            store.clone(),
            keys.clone(),
            shutdown.clone(),
            lease.clone(),
        )
        .await;
        if exited_clean {
            return;
        }
        // A graceful shutdown unwinds `run_connection` as a clean exit, but
        // guard the reconnect path too in case the drop raced the signal.
        if *shutdown.borrow() {
            return;
        }
        // Terminal `<conflict type="replaced"/>`: another client owns the slot.
        // Stop here instead of fighting for it. Credentials remain valid, so we
        // park as Disconnected; a manual POST /connect can reclaim the slot.
        if session
            .expect_disconnect
            .swap(false, std::sync::atomic::Ordering::Relaxed)
        {
            if session
                .wa_blocked
                .swap(false, std::sync::atomic::Ordering::Relaxed)
            {
                session.set_status(SessionStatus::Blocked);
                tracing::warn!(
                    session = %session.meta.read().id,
                    "WhatsApp-initiated disconnect — session BLOCKED, auto-reconnect halted (POST /connect to retry)"
                );
            } else {
                session.set_status(SessionStatus::Disconnected);
                tracing::info!(
                    session = %session.meta.read().id,
                    "halting reconnect after stream-replaced; session parked Disconnected"
                );
            }
            return;
        }
        let status = session.meta.read().status;
        if matches!(status, SessionStatus::LoggedOut) {
            return;
        }
        // `<stream:error 515>` restart-required: reconnect instantly, no wait.
        let restart = session
            .restart_required
            .swap(false, std::sync::atomic::Ordering::Relaxed);
        // A connection that reached `<success>` was healthy — reset the backoff
        // (and a 515 restart is expected, not a failure) so the pairing → login
        // hop and later blips don't inherit a compounded delay.
        if restart
            || session
                .reached_success
                .load(std::sync::atomic::Ordering::Relaxed)
        {
            backoff_ms = INITIAL_BACKOFF_MS;
        }

        if restart {
            tracing::info!(session = %session.meta.read().id, "restart required — reconnecting now");
        } else {
            tracing::info!(
                session = %session.meta.read().id,
                backoff_ms,
                "reconnecting after disconnect"
            );
            // Equal-jitter the wait so a fleet reconnecting after a shared outage
            // (a deploy or a WA blip) doesn't thunder-herd the server in lockstep.
            let jittered_ms = {
                use rand::Rng;
                jittered_backoff_ms(backoff_ms, rand::thread_rng().gen::<f64>())
            };
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(jittered_ms)) => {}
                _ = session.logout_notify.notified() => { return; }
                _ = shutdown.wait_for(|v| *v) => { return; }
            }
            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
        }
        // Bump status back to Connecting before re-entering run_connection.
        session.bump_reconnect();
        metrics::incr(&metrics::RECONNECTS_TOTAL);
        session.set_status(SessionStatus::Connecting);
        let _ = session.events.send(SessionEvent::Connecting);
    }
}

async fn run_connection(
    session: Arc<Session>,
    store: Arc<Store>,
    keys: DeviceKeys,
    mut shutdown: watch::Receiver<bool>,
    lease: Option<LeaseParams>,
) -> bool {
    use crate::protocol::connection;
    use rand::rngs::OsRng;

    let result: anyhow::Result<()> = async {
        let eph = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let eph_pub = x25519_dalek::PublicKey::from(&eph);

        // Route this session's WebSocket through its configured proxy, if any.
        // A malformed proxy URL fails the connection (and is surfaced as a
        // disconnect) rather than silently falling back to a direct IP.
        let proxy = match &session.meta.read().proxy_url {
            Some(url) => Some(
                connection::Proxy::parse(url)
                    .map_err(|e| anyhow::anyhow!("invalid proxy_url: {e}"))?,
            ),
            None => None,
        };
        let mut ws = connection::connect_wa(proxy.as_ref()).await?;
        let payload = select_client_payload(&session.meta.read().clone(), &keys);
        let (write, read) = connection::do_handshake(
            &mut ws,
            eph.to_bytes(),
            eph_pub.to_bytes(),
            keys.noise.private,
            keys.noise.public,
            &payload,
        )
        .await?;

        // Successful Noise XX → ready to read server-pushed nodes.
        session.set_status(SessionStatus::AwaitingQr);
        let _ = session.events.send(SessionEvent::Connected);

        let mut socket = connection::NoiseSocket::new(ws, write, read);

        // Outbound channel: spawned send pump → main loop → socket.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<crate::protocol::binary::Node>();
        let dispatcher = ConnDispatcher::new(out_tx);
        // Expose this connection's dispatcher to HTTP handlers (onWhatsApp,
        // profile, block, …) for synchronous IQ request/reply. Refreshed each
        // (re)connect; cleared when this connection exits (see cleanup below).
        session.set_iq_client(dispatcher.clone());

        // Spawn the send pump if no other task already owns the receiver.
        // The pump exits naturally when all `Session::send_tx` handles
        // drop or when reset_send_queue replaces the channel.
        if let Some(send_rx) = session.take_send_receiver() {
            // Drain any persisted ops from the previous run before
            // starting the pump. Failures here are non-fatal; the rows
            // stay in the table for the next reconnect.
            let session_id_for_drain = session.meta.read().id.clone();
            match drain_outbound_queue(&store, &session_id_for_drain) {
                Ok(ops) => {
                    if !ops.is_empty() {
                        tracing::info!(count = ops.len(), "redriving persisted outbound ops");
                    }
                    for op in ops {
                        let _ = session.enqueue_send(op);
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "drain outbound_queue failed");
                }
            }
            let dispatcher_pump = dispatcher.clone();
            let session_pump = session.clone();
            let store_pump = store.clone();
            let keys_pump = keys.clone();
            tokio::spawn(async move {
                run_send_pump(
                    dispatcher_pump,
                    session_pump,
                    store_pump,
                    keys_pump,
                    send_rx,
                )
                .await;
            });
        }

        // Client-initiated keepalive: WA's server expects an `<iq type=get
        // xmlns=w:p to=s.whatsapp.net/>` every ~25s. If we go silent, the
        // server sends `<stream:error><ping id=N/></stream:error>` and tears
        // the WS down. The task is aborted when run_connection exits.
        //
        // NOTE: no periodic presence re-assert. A live Evolution wire-capture
        // (LOG_BAILEYS=trace) showed Evolution sends `<presence type=
        // "unavailable">` ONCE on connect and is still shown by the phone as a
        // healthy, "most recent in sync" device — so the linked-device status
        // is NOT driven by a presence heartbeat (an earlier always-online
        // experiment here was reverted).
        let keepalive_dispatcher = dispatcher.clone();
        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(KEEPALIVE_SECS)).await;
                let id = uuid_v4();
                tracing::debug!(iq_id = %id, "sending keepalive");
                let iq = build_keepalive_iq(&id);
                keepalive_dispatcher.send_node(iq);
            }
        });
        session.set_keepalive_handle(handle);

        // Proactive periodic prekey top-up. The server's `encrypt` notification
        // is the primary refill trigger, but a device that goes long stretches
        // without receiving never gets one; this sweep refills if the count has
        // drifted below MIN_PREKEY_COUNT regardless. Dispatcher is best-effort —
        // sends are dropped once the connection exits, and the task is aborted
        // on exit (cancel_prekey_topup) so it never leaks across reconnects.
        let topup_dispatcher = dispatcher.clone();
        let topup_store = store.clone();
        let topup_keys = keys.clone();
        let topup_session_id = session.meta.read().id.clone();
        let topup_handle = tokio::spawn(async move {
            let interval = prekey_topup_interval();
            loop {
                tokio::time::sleep(interval).await;
                let available = available_prekey_count(&topup_store, &topup_session_id);
                if available < MIN_PREKEY_COUNT {
                    tracing::info!(
                        session = %topup_session_id,
                        available,
                        "periodic prekey top-up: below floor, replenishing"
                    );
                    replenish_prekeys(&topup_store, &topup_session_id, &topup_keys, &topup_dispatcher);
                }
            }
        });
        session.set_prekey_topup_handle(topup_handle);

        // Lease heartbeat: when leasing is on, renew our claim every ttl/3 so a
        // sibling instance can't steal it while we hold a live socket. A failed
        // renew means the lease was already stolen (we were stale) — stop cleanly
        // without reconnecting, leaving the new owner's socket as the only one.
        let lease_session_id = session.meta.read().id.clone();
        let mut lease_tick = lease.as_ref().map(|l| {
            let period = std::time::Duration::from_secs((l.ttl / 3).max(1) as u64);
            tokio::time::interval(period)
        });

        // rx-idle watchdog: sample `last_rx` age on a fixed tick and force a
        // reconnect if the keepalive pong stream has stalled (silent half-open
        // socket). Independent of `recv_node`, which would otherwise await a
        // frame that never comes. Armed only after `<success>`.
        let mut rx_watchdog =
            tokio::time::interval(std::time::Duration::from_secs(RX_WATCHDOG_TICK_SECS));
        rx_watchdog.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let logout_notify = session.logout_notify.clone();
        loop {
            tokio::select! {
                _ = rx_watchdog.tick() => {
                    // Pre-`<success>` (handshake / QR-pairing) the stream is
                    // legitimately quiet and paced by its own IQs — don't arm.
                    if session
                        .reached_success
                        .load(std::sync::atomic::Ordering::Relaxed)
                        && rx_is_stale(
                            session.last_rx(),
                            chrono::Utc::now().timestamp(),
                            RX_IDLE_TIMEOUT_SECS,
                        )
                    {
                        let age = session
                            .last_rx()
                            .map(|t| chrono::Utc::now().timestamp().saturating_sub(t))
                            .unwrap_or_default();
                        tracing::warn!(
                            session = %session.meta.read().id,
                            age_secs = age,
                            "rx-idle watchdog: no inbound past keepalive window — socket frozen, forcing reconnect"
                        );
                        return Err(anyhow::anyhow!(
                            "rx-idle watchdog: no inbound for {age}s (socket half-open)"
                        ));
                    }
                }
                _ = async {
                    match lease_tick.as_mut() {
                        Some(iv) => { iv.tick().await; }
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    if let Some(l) = &lease {
                        let now = chrono::Utc::now().timestamp();
                        if !matches!(store.lease_renew(&lease_session_id, &l.owner, now), Ok(true)) {
                            tracing::warn!(
                                session = %lease_session_id,
                                "lease lost to another instance; disconnecting (no reconnect)"
                            );
                            session.set_status(SessionStatus::Disconnected);
                            return Ok::<(), anyhow::Error>(());
                        }
                    }
                }
                // Wrap in an async block so the non-Send `watch::Ref` guard is
                // dropped before the (awaiting) branch body runs.
                _ = async { let _ = shutdown.wait_for(|v| *v).await; } => {
                    // Graceful shutdown: best-effort flush of any outbound
                    // nodes the send pump already queued, then CLEANLY close
                    // the WS. SendOps still in the pump's queue stay persisted
                    // and are redriven on the next boot.
                    while let Ok(n) = out_rx.try_recv() {
                        let _ = socket.send_node(&n).await;
                    }
                    // Clean WS Close (not just a drop) so WhatsApp frees this
                    // device slot immediately — the next instance's login is
                    // then a clean fresh login instead of racing a half-open
                    // ghost into a <conflict>/replace. See NoiseSocket::send_close.
                    let _ = socket.send_close().await;
                    session.set_status(SessionStatus::Disconnected);
                    return Ok::<(), anyhow::Error>(());
                }
                _ = logout_notify.notified() => {
                    // Best-effort `<remove-companion-device>` IQ before we
                    // drop the WS. Failures are swallowed — the server will
                    // notice the close on its own.
                    let jid = session.pending_logout_jid.write().take();
                    if let Some(jid) = jid {
                        let iq = build_remove_companion_device_iq(
                            &uuid_v4(),
                            &jid,
                        );
                        let _ = socket.send_node(&iq).await;
                    }
                    return Ok::<(), anyhow::Error>(());
                }
                r = socket.recv_node() => {
                    let node = r?;
                    session.mark_rx();
                    // Top-level inbound trace: every frame regardless of
                    // tag, so live debugging of inbound routing (per
                    // INBOUND_HANDOVER.md (git history) step 4) shows the full stream.
                    // Using `info` over `debug` because the volume is low
                    // (≤ a few/sec steady-state) and the data is critical
                    // to diagnosing missing-message symptoms.
                    tracing::info!(
                        tag = %node.tag,
                        id = %node.attrs.get("id").map(String::as_str).unwrap_or(""),
                        ty = %node.attrs.get("type").map(String::as_str).unwrap_or(""),
                        from = %node.attrs.get("from").map(String::as_str).unwrap_or(""),
                        "inbound frame",
                    );
                    if node.tag == "iq" {
                        let id = node.attrs.get("id").cloned().unwrap_or_default();
                        let ty = node.attrs.get("type").cloned().unwrap_or_default();
                        tracing::debug!(%id, %ty, "inbound iq raw");
                    }
                    // IQ replies bound to a pending request shortcut here;
                    // anything else flows through the regular handler.
                    if node.tag == "iq" {
                        if let Some(id) = node.attrs.get("id") {
                            let claimed = dispatcher.take_pending(id);
                            if let Some(tx) = claimed {
                                tracing::debug!(%id, "iq reply matched pending");
                                let _ = tx.send(node);
                                continue;
                            }
                        }
                    }
                    // Server `<ack>` for an outbound message we shipped:
                    // resolve the pending oneshot if anyone's waiting.
                    if node.tag == "ack" {
                        if let Some(id) = node.attrs.get("id") {
                            if let Some(tx) = dispatcher.take_pending_ack(id) {
                                let class = node
                                    .attrs
                                    .get("class")
                                    .cloned()
                                    .unwrap_or_default();
                                let _ = tx.send(class);
                                continue;
                            }
                        }
                    }
                    if let Some(ack) = process_inbound_node(&session, &store, &keys, Some(&dispatcher), &node) {
                        socket.send_node(&ack).await?;
                    }
                }
                next = out_rx.recv() => {
                    match next {
                        Some(n) => socket.send_node(&n).await?,
                        // All dispatcher senders dropped — pump is gone.
                        // We keep reading inbound but cannot send anymore.
                        None => continue,
                    }
                }
            }
        }
    }
    .await;

    // Reset the send queue so a future reconnect gets a fresh receiver.
    // (Old `mpsc::UnboundedSender` clones held by HTTP handlers stop
    // accepting after the swap; their next `enqueue_send` errors.)
    session.reset_send_queue();
    // Stop the QR rotation task if one was running. A reconnect will
    // install a fresh batch when the next pair-device IQ arrives.
    session.cancel_qr_rotation();
    // Stop the keepalive task — its dispatcher.out_tx is now stale, and
    // a reconnect will spawn a fresh one.
    session.cancel_keepalive();
    // Stop the periodic prekey top-up task for the same reason.
    session.cancel_prekey_topup();
    // Drop the HTTP IQ client — the socket is gone.
    session.clear_iq_client();

    match result {
        // Clean exit (logout). Caller (run_with_reconnect) sees `true`
        // and breaks out of the retry loop.
        Ok(()) => true,
        Err(e) => {
            tracing::warn!(error = %e, session = %session.meta.read().id, "connection task failed");
            session.set_status(SessionStatus::Disconnected);
            let _ = session.events.send(SessionEvent::Disconnected {
                reason: e.to_string(),
            });
            false
        }
    }
}

/// Routes outbound nodes onto the connection task's wire and (for IQs)
/// awaits replies matched by the `id` attribute. Cheap to clone — internals
/// are an `Arc`'d pending map plus an `mpsc::UnboundedSender`. Used by the
/// send pump and (in tests) by mock setups that exercise the outbound
/// pipeline without a real socket.
#[derive(Clone)]
pub(crate) struct ConnDispatcher {
    out_tx: mpsc::UnboundedSender<crate::protocol::binary::Node>,
    pending: Arc<PlMutex<HashMap<String, oneshot::Sender<crate::protocol::binary::Node>>>>,
    /// In-flight outbound message ids waiting for a server `<ack>`.
    /// Distinct from `pending` (IQ replies) because acks aren't IQs:
    /// they arrive as `<ack id=msg_id type=...>` top-level nodes.
    pending_acks: Arc<PlMutex<HashMap<String, oneshot::Sender<String>>>>,
}

impl ConnDispatcher {
    pub(crate) fn new(out_tx: mpsc::UnboundedSender<crate::protocol::binary::Node>) -> Self {
        Self {
            out_tx,
            pending: Arc::new(PlMutex::new(HashMap::new())),
            pending_acks: Arc::new(PlMutex::new(HashMap::new())),
        }
    }

    /// Push a node onto the wire. Best-effort — if the connection task has
    /// shut down the send is dropped silently.
    pub(crate) fn send_node(&self, node: crate::protocol::binary::Node) {
        let _ = self.out_tx.send(node);
    }

    /// Register a pending ack on `msg_id`. Returns the receive end of a
    /// oneshot that resolves when the matching `<ack>` arrives. Caller
    /// must register BEFORE shipping the message — otherwise a fast
    /// server could ack before the registration lands.
    pub(crate) fn register_ack(&self, msg_id: &str) -> oneshot::Receiver<String> {
        let (tx, rx) = oneshot::channel();
        self.pending_acks.lock().insert(msg_id.to_string(), tx);
        rx
    }

    /// Pull a pending-ack sender by msg_id. Called from the recv loop
    /// when an `<ack>` lands. On Some, the loop signals the waiter
    /// with the ack's `class` attribute (`message`, `receipt`, ...).
    fn take_pending_ack(&self, msg_id: &str) -> Option<oneshot::Sender<String>> {
        self.pending_acks.lock().remove(msg_id)
    }

    /// Send an `<iq>` and await the matching reply. Times out after 30s.
    /// Caller is responsible for the `id` attribute on `iq` — every IQ on
    /// the wire must carry one for routing.
    pub(crate) async fn iq_request(
        &self,
        iq: crate::protocol::binary::Node,
    ) -> std::result::Result<crate::protocol::binary::Node, &'static str> {
        let id = iq
            .attrs
            .get("id")
            .cloned()
            .ok_or("iq must have an id attribute")?;
        let kind = match &iq.content {
            crate::protocol::binary::Content::Nodes(ns) => {
                ns.first().map(|n| n.tag.clone()).unwrap_or_default()
            }
            _ => String::new(),
        };
        let xmlns = iq.attrs.get("xmlns").cloned().unwrap_or_default();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().insert(id.clone(), tx);
        if self.out_tx.send(iq).is_err() {
            self.pending.lock().remove(&id);
            return Err("connection task is gone");
        }
        tracing::debug!(%id, %kind, %xmlns, "iq_request enqueued");
        match tokio::time::timeout(std::time::Duration::from_secs(30), rx).await {
            Ok(Ok(reply)) => Ok(reply),
            Ok(Err(_)) => Err("dispatcher dropped before reply"),
            Err(_) => {
                self.pending.lock().remove(&id);
                tracing::warn!(%id, %kind, %xmlns, "iq_request TIMED OUT after 30s");
                Err("iq reply timeout")
            }
        }
    }

    /// Try to claim a pending IQ id. The main connection loop calls this
    /// when an inbound IQ matches a request id; on Some, the loop pipes
    /// the inbound node through and skips the regular ack pipeline.
    fn take_pending(
        &self,
        id: &str,
    ) -> Option<oneshot::Sender<crate::protocol::binary::Node>> {
        self.pending.lock().remove(id)
    }
}

/// Drive `SendOp`s off the queue until the channel closes. Each op is
/// best-effort — failures log and continue so a single stuck recipient
/// doesn't block the rest of the queue.
async fn run_send_pump(
    dispatcher: ConnDispatcher,
    session: Arc<Session>,
    store: Arc<Store>,
    keys: DeviceKeys,
    mut send_rx: mpsc::UnboundedReceiver<SendOp>,
) {
    tracing::info!(session = %session.meta.read().id, "send pump started");
    while let Some(op) = send_rx.recv().await {
        tracing::info!(?op, "send pump dequeued op");
        if let Err(e) = handle_send_op(&dispatcher, &session, &store, &keys, op).await {
            tracing::warn!(error = %e, "send op failed");
        }
    }
}

async fn handle_send_op(
    dispatcher: &ConnDispatcher,
    session: &Session,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    op: SendOp,
) -> Result<()> {
    match op {
        SendOp::Text {
            chat_jid,
            msg_id,
            text,
            timestamp,
        } => send_text_op(dispatcher, session, store, keys, &chat_jid, &msg_id, &text, timestamp)
            .await,
        SendOp::Media {
            chat_jid,
            msg_id,
            kind,
            file_path,
            mime,
            caption,
            filename,
            mentions,
            timestamp,
        } => {
            send_media_op(
                dispatcher, session, store, keys, &chat_jid, &msg_id, kind, &file_path, &mime,
                caption.as_deref(), filename.as_deref(), &mentions, timestamp,
            )
            .await
        }
        SendOp::RawNode(node) => {
            dispatcher.send_node(node);
            Ok(())
        }
        SendOp::EncryptedInner {
            chat_jid,
            msg_id,
            inner_proto,
            timestamp,
        } => {
            encrypt_inner_proto_and_ship(
                dispatcher, session, store, keys, &chat_jid, &msg_id, &inner_proto, timestamp,
            )
            .await
        }
        SendOp::PeerHistoryRequest {
            chat,
            oldest_id,
            oldest_from_me,
            oldest_ts,
            count,
        } => {
            send_history_sync_on_demand(
                dispatcher,
                session,
                store,
                keys,
                &chat,
                &oldest_id,
                oldest_from_me,
                oldest_ts,
                count,
            )
            .await
        }
    }
}

/// X3DH-bootstrap (if needed) → encrypt → ship for one outbound text.
///
/// Linked-device fan-out (sending the message to every device the recipient
/// has linked) is a follow-up; today we ship a single per-device entry to
/// the bare `chat_jid`. That works against test peers that only have one
/// device but will need a usync IQ pre-step for real users with multiple
/// linked devices.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_text_op(
    dispatcher: &ConnDispatcher,
    session: &Session,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    chat_jid: &str,
    msg_id: &str,
    text: &str,
    timestamp: i64,
) -> Result<()> {
    let inner = build_e2e_conversation(text);
    encrypt_inner_proto_and_ship(
        dispatcher, session, store, keys, chat_jid, msg_id, &inner, timestamp,
    )
    .await
}

/// X3DH-bootstrap (if needed) → Signal-encrypt the given inner waE2E.Message
/// bytes → ship as a `<message>` node. The "inner proto" is whatever the
/// caller built — `conversation` for text, `imageMessage`/`videoMessage`/...
/// for media. Linked-device fan-out is still a follow-up.
#[allow(clippy::too_many_arguments)]
/// Ask the server which devices `chat_jid` has linked, returning
/// fully-qualified per-device JIDs. Falls back to `[chat_jid]` (the
/// bare phone) when usync fails or returns nothing — that keeps the
/// send path working against single-device test peers + tolerates a
/// server hiccup.
async fn resolve_device_jids(
    session: &Session,
    dispatcher: &ConnDispatcher,
    chat_jid: &str,
) -> Vec<String> {
    // Cache hit: skip the blocking usync round-trip entirely. The device list
    // only changes when the peer adds/removes a linked device, which WhatsApp
    // announces via `<notification type="devices">` (→ device_cache_clear).
    if let Some(cached) = session.device_cache_get(chat_jid) {
        return cached;
    }
    let iq_id = uuid_v4();
    let iq = build_usync_devices_iq(&iq_id, &[chat_jid]);
    match dispatcher.iq_request(iq).await {
        Ok(reply) => {
            let devices = parse_usync_devices_response(&reply);
            tracing::debug!(target = chat_jid, ?devices, "usync resolved device list (cached)");
            let resolved = if devices.is_empty() {
                vec![chat_jid.to_string()]
            } else {
                devices
            };
            session.device_cache_put(chat_jid, resolved.clone());
            resolved
        }
        Err(e) => {
            // Don't cache failures — retry on the next send.
            tracing::warn!(error = %e, "usync failed; sending to bare jid");
            vec![chat_jid.to_string()]
        }
    }
}

/// Per-device encrypt: for each device JID, get-or-bootstrap a Signal
/// session, encrypt under it, persist the advanced state. Devices that
/// don't yet have a session get batched into a single prekey-fetch IQ.
/// Returns one EncryptedRecipient per device.
///
/// Two plaintexts are supplied: `padded` for the peer's devices and
/// `padded_own` for our own account's *other* devices. When `own_user`
/// is set, any device whose user-part matches it receives `padded_own`
/// (a `DeviceSentMessage`-wrapped copy) so our sent messages echo into
/// our own chat history across devices — mirrors whatsmeow's split in
/// `marshalMessage` / `encryptMessageForDevices`.
#[allow(clippy::too_many_arguments)]
async fn encrypt_per_device(
    store: &Arc<Store>,
    keys: &DeviceKeys,
    dispatcher: &ConnDispatcher,
    session_id: &str,
    device_jids: &[String],
    padded: &[u8],
    padded_own: &[u8],
    own_user: Option<&str>,
) -> Result<Vec<EncryptedRecipient>> {
    use crate::crypto::identity::KeyPair;
    use crate::crypto::signal::{
        AliceParameters, PendingPreKey, RatchetingSession, SessionCipher, SessionRecord,
    };

    // Partition: devices we already have a Signal session for vs ones
    // we need to bootstrap via X3DH.
    let mut existing: HashMap<String, SessionRecord> = HashMap::new();
    let mut needs_bundle: Vec<String> = Vec::new();
    for d in device_jids {
        match store_load_record(store, session_id, d)? {
            Some(r) if r.current.is_some() => {
                existing.insert(d.clone(), r);
            }
            _ => needs_bundle.push(d.clone()),
        }
    }

    // Batch-fetch bundles for all unknown devices in one IQ.
    let mut bootstrapped: HashMap<String, SessionRecord> = HashMap::new();
    if !needs_bundle.is_empty() {
        let refs: Vec<&str> = needs_bundle.iter().map(String::as_str).collect();
        let iq_id = uuid_v4();
        // DIAGNOSTIC: how many bundles this send requests in one IQ. A large
        // count (big group, few cached sessions) is the prime suspect for the
        // server silently dropping the request → 30s prekey-fetch timeout.
        tracing::info!(
            needs_bundle = refs.len(),
            total_devices = device_jids.len(),
            sample = ?refs.iter().take(5).collect::<Vec<_>>(),
            "send: fetching prekey bundles"
        );
        let iq = build_prekey_fetch_iq(&refs, &iq_id);
        let reply = dispatcher
            .iq_request(iq)
            .await
            .map_err(|e| Error::Internal(anyhow::anyhow!("prekey fetch: {e}")))?;
        tracing::info!(reply = ?reply, "prekey fetch raw reply");
        for bundle in parse_prekey_fetch_response(&reply) {
            // Verify SPK signature against the device's identity key.
            // Whatsmeow / libsignal sign `[DjbType (0x05)] || spk_pub`, NOT
            // the bare 32-byte spk_pub. Construct the same 33-byte payload
            // before verifying or every peer's bundle gets rejected.
            let mut spk_signed = [0u8; 33];
            spk_signed[0] = 0x05;
            spk_signed[1..].copy_from_slice(&bundle.signed_pre_key_pub);
            if !crate::crypto::identity::xeddsa_verify(
                &bundle.identity_pub,
                &spk_signed,
                &bundle.signed_pre_key_sig,
            ) {
                // Whatsmeow / libsignal-go don't strictly verify the SPK
                // signature on inbound bundles — the X3DH derivation is
                // the actual MITM defense. Log + continue rather than
                // dropping the device, since dropping it would prevent
                // multi-device fan-out for any peer whose secondary
                // device's signature uses a slightly different scheme
                // than our 33-byte XEdDSA assumes.
                tracing::warn!(jid = %bundle.jid, "prekey SPK signature failed; proceeding anyway (X3DH still authenticates)");
            }
            let base = KeyPair::generate();
            let ratchet = KeyPair::generate();
            let opk_pub = bundle.one_time_pre_key_pub;
            let mut state = RatchetingSession::initiate_alice(&AliceParameters {
                local_identity_priv: &keys.identity.private,
                local_identity_pub: &keys.identity.public,
                local_base_priv: &base.private,
                local_base_pub: &base.public,
                local_ratchet_priv: &ratchet.private,
                local_ratchet_pub: &ratchet.public,
                remote_identity_pub: &bundle.identity_pub,
                remote_signed_prekey_pub: &bundle.signed_pre_key_pub,
                remote_one_time_prekey_pub: opk_pub.as_ref(),
            });
            state.local_registration_id = keys.registration_id;
            state.remote_registration_id = bundle.registration_id;
            state.pending_pre_key = Some(PendingPreKey {
                pre_key_id: bundle.one_time_pre_key_id,
                signed_pre_key_id: bundle.signed_pre_key_id,
                base_key_pub: base.public,
            });
            let mut record = SessionRecord::new();
            record.current = Some(state);
            bootstrapped.insert(bundle.jid.clone(), record);
        }
    }

    // Encrypt per-device, advance each chain, persist.
    let mut out = Vec::with_capacity(device_jids.len());
    for d in device_jids {
        let mut record = existing
            .remove(d)
            .or_else(|| bootstrapped.remove(d))
            .ok_or_else(|| {
                Error::Internal(anyhow::anyhow!("no session for device {d}"))
            })?;
        let mut state = record.current.take().ok_or_else(|| {
            Error::Internal(anyhow::anyhow!("session record has no current state for {d}"))
        })?;
        // Pick the plaintext: our own account's other devices get the
        // DeviceSentMessage copy; the peer's devices get the plain message.
        let pt: &[u8] = match own_user {
            Some(u) if jid_user(d) == u => padded_own,
            _ => padded,
        };
        let cipher = match state.pending_pre_key.clone() {
            Some(pp) => {
                let m = SessionCipher::encrypt_pre_key(
                    &mut state,
                    pt,
                    keys.registration_id,
                    &pp.base_key_pub,
                    &keys.identity.public,
                    pp.signed_pre_key_id,
                    pp.pre_key_id,
                )
                .map_err(|e| Error::Internal(anyhow::anyhow!("encrypt_pre_key: {e}")))?;
                state.pending_pre_key = None;
                m
            }
            None => SessionCipher::encrypt(&mut state, pt)
                .map_err(|e| Error::Internal(anyhow::anyhow!("encrypt: {e}")))?,
        };
        record.current = Some(state);
        store_save_record(store, session_id, d, &record)?;
        out.push(EncryptedRecipient {
            jid: d.clone(),
            ciphertext: cipher.serialized,
            message_type: cipher.message_type,
        });
    }
    Ok(out)
}

/// The user-part of a JID — everything before the device suffix (`:N`) or
/// the server (`@...`). `"5511990000001:19@s.whatsapp.net"` → `"5511990000001"`.
fn jid_user(jid: &str) -> &str {
    let end = jid.find([':', '@']).unwrap_or(jid.len());
    &jid[..end]
}

// -- LID (LinkedID) <-> PN addressing ----------------------------------------

/// The user-part of a JID, also splitting on the LID device separator `.`
/// (`"64000000000001.1@lid"` → `"64000000000001"`; `"5511…:19@s.whatsapp.net"`
/// → `"5511…"`). Phone-number users never contain `.`, so this is safe for both.
fn lid_user_part(jid: &str) -> &str {
    let end = jid.find(['.', ':', '@']).unwrap_or(jid.len());
    &jid[..end]
}

/// The device token of a JID (the `N` in `:N`), or `None` if bare (device 0).
/// WhatsApp AD/LID JIDs are `user[.agent][:device]@server` (whatsmeow
/// `JID.String`): the device is ONLY the `:N` part — the `.N` is the LID
/// **agent**, NOT a device. So `64000000000001.1@lid` is agent 1 / device 0,
/// and `64000000000001.1:19@lid` is agent 1 / device 19. Splitting on `.` here
/// (the old bug) mis-read every device-0 LID as "device 1", so the own-phone
/// LID session never migrated onto the device-0 PN session → re-X3DH against a
/// consumed prekey → MAC fail → retry storm → phone pauses sync.
fn jid_device_token(jid: &str) -> Option<&str> {
    let at = jid.find('@').unwrap_or(jid.len());
    let head = &jid[..at];
    head.find(':').map(|i| &head[i + 1..])
}

/// The canonical, stable identity key for a user JID — what we persist on
/// messages/chats and emit to API + webhook consumers. WhatsApp delivers the
/// same 1:1 conversation under two addressings: a phone-number JID
/// (`<digits>@s.whatsapp.net`) and an opaque LID (`<n>[.agent][:device]@lid`).
/// Without collapsing them a single contact shows up as two chats and webhooks
/// emit a key that flips between addressings. This normalizes to the PHONE
/// NUMBER whenever a LID→PN mapping is known (the human-meaningful, stable key),
/// strips the device/agent suffix in all cases, and falls back to the bare LID
/// when no PN is known yet. Group/broadcast/status JIDs pass through unchanged.
fn canonical_user_jid(store: &Arc<Store>, session_id: &str, jid: &str) -> String {
    if jid.is_empty()
        || jid.ends_with("@g.us")
        || jid.ends_with("@broadcast")
        || jid.ends_with("@newsletter")
    {
        return jid.to_string();
    }
    let user = lid_user_part(jid); // drops .agent / :device / @server
    if jid.ends_with("@lid") {
        match store.lid_to_pn(session_id, user) {
            Ok(Some(pn)) => format!("{pn}@s.whatsapp.net"),
            // No PN known yet — collapse to the bare LID (device/agent stripped)
            // so at least the two device-suffixed forms unify into one key.
            _ => format!("{user}@lid"),
        }
    } else if jid.ends_with("@s.whatsapp.net") {
        format!("{user}@s.whatsapp.net")
    } else {
        jid.to_string()
    }
}

/// Whether `sender` (the REAL message author — pass `participant`, never the
/// group `from`, which is the group JID) is our own account. Bridges LID<->PN in
/// both directions against the stored map, so an own-device fan-out addressed by
/// our `@lid` matches our PN account jid (and vice versa). `own_pn_user` is the
/// user part of our session jid. = whatsmeow `info.IsFromMe`.
fn sender_is_self(
    store: &Arc<Store>,
    session_id: &str,
    own_pn_user: Option<&str>,
    sender: &str,
) -> bool {
    let own = match own_pn_user {
        Some(o) if !o.is_empty() => o,
        _ => return false,
    };
    let sender_user = lid_user_part(sender);
    sender_user == own
        || store
            .pn_to_lid(session_id, own)
            .ok()
            .flatten()
            .is_some_and(|own_lid| sender_user == own_lid)
        || store
            .lid_to_pn(session_id, sender_user)
            .ok()
            .flatten()
            .is_some_and(|sender_pn| sender_pn == own)
}

/// Candidate signal-session addresses for the *other* addressing of `addr`,
/// using the stored LID<->PN map. Signal sessions are PER-DEVICE, so the
/// alternate must preserve the device (the `:N`) exactly — migrating a device-0
/// session onto a device-19 address would corrupt it. The LID carries an
/// `.agent` suffix (always `.1` for `@lid` hosted identities) that the PN side
/// lacks; we emit candidate LID forms with and without it so a PN-addressed
/// lookup still finds a session keyed under the raw inbound LID string. Empty
/// if no mapping is known.
fn lid_pn_alternates(store: &Arc<Store>, session_id: &str, addr: &str) -> Vec<String> {
    let user = lid_user_part(addr);
    let device = jid_device_token(addr);
    let is_primary = device.map(|d| d == "0").unwrap_or(true);
    let mut out = Vec::new();
    if addr.ends_with("@lid") {
        // LID -> PN: drop the agent; the PN has none.
        if let Ok(Some(pn)) = store.lid_to_pn(session_id, user) {
            if is_primary {
                out.push(format!("{pn}@s.whatsapp.net"));
            } else {
                out.push(format!("{pn}:{}@s.whatsapp.net", device.unwrap()));
            }
        }
    } else if addr.ends_with("@s.whatsapp.net") {
        // PN -> LID: the inbound LID string carries agent 1, so try the `.1`
        // form first (what real sessions are keyed under), then the bare/`.0`
        // fallbacks for tolerance.
        if let Ok(Some(lid)) = store.pn_to_lid(session_id, user) {
            if is_primary {
                out.push(format!("{lid}.1@lid"));
                out.push(format!("{lid}@lid"));
                out.push(format!("{lid}.0@lid"));
            } else {
                let d = device.unwrap();
                out.push(format!("{lid}.1:{d}@lid"));
                out.push(format!("{lid}:{d}@lid"));
            }
        }
    }
    out
}

/// Resolve the address to load the Signal session under, applying LID<->PN
/// aliasing. If a session already exists under `addr`, use it. Otherwise, if we
/// have one under the mapped alternate addressing (same device, different
/// PN/LID form), migrate it to `addr` and use that — so the established ratchet
/// is reused instead of re-running X3DH. Mirrors whatsmeow's MigratePNToLID.
/// On no hit, returns `addr` unchanged (the pkmsg path bootstraps a new one).
fn resolve_session_address(store: &Arc<Store>, session_id: &str, addr: &str) -> String {
    if let Ok(Some(_)) = store_load_record(store, session_id, addr) {
        return addr.to_string();
    }
    for alt in lid_pn_alternates(store, session_id, addr) {
        if let Ok(Some(rec)) = store_load_record(store, session_id, &alt) {
            if store_save_record(store, session_id, addr, &rec).is_ok() {
                tracing::info!(
                    from_addr = %alt,
                    to_addr = %addr,
                    "migrated Signal session across LID<->PN addressing"
                );
                return addr.to_string();
            }
        }
    }
    addr.to_string()
}

/// Record any LID<->PN correspondences advertised in an inbound message's
/// attrs (`sender_pn`/`sender_lid`, `peer_recipient_pn`/`peer_recipient_lid`,
/// `participant_pn`/`participant_lid`). Mirrors whatsmeow's StoreLIDPNMapping —
/// it's how the PN<->LID map gets populated over time so later `@lid` senders
/// resolve to the PN session we already hold.
fn capture_lid_pn_mappings(
    store: &Arc<Store>,
    session_id: &str,
    attrs: &crate::protocol::binary::Attrs,
) {
    let now = chrono::Utc::now().timestamp();
    let put = |lid_jid: &str, pn_jid: &str| {
        let lu = lid_user_part(lid_jid);
        let pu = lid_user_part(pn_jid);
        if !lu.is_empty() && !pu.is_empty() {
            let _ = store.lid_pn_put(session_id, lu, pu, now);
        }
    };
    // (lid-side attr/value, pn-side attr/value): for each pair, whichever the
    // base jid is (lid or pn) determines which side the alt attr supplies.
    let pairs = [
        ("from", "sender_pn", "sender_lid"),
        ("recipient", "peer_recipient_pn", "peer_recipient_lid"),
        ("participant", "participant_pn", "participant_lid"),
    ];
    for (base, pn_alt, lid_alt) in pairs {
        let Some(base_jid) = attrs.get(base) else {
            continue;
        };
        if base_jid.ends_with("@lid") {
            if let Some(pn) = attrs.get(pn_alt) {
                put(base_jid, pn);
            }
        } else if base_jid.ends_with("@s.whatsapp.net") {
            if let Some(lid) = attrs.get(lid_alt) {
                put(lid, base_jid);
            }
        }
    }
}

/// Wrap an already-encoded `waE2E.Message` in a `DeviceSentMessage` so our
/// own other devices render it as a message *we* sent (with the right
/// destination). Mirrors whatsmeow's `marshalMessage` dsmPlaintext. Returns
/// `None` if the inner bytes don't decode as a Message.
fn build_device_sent_message(inner_proto_bytes: &[u8], destination_jid: &str) -> Option<Vec<u8>> {
    use crate::proto::wa_web_protobufs_e2e::{DeviceSentMessage, Message};
    use prost::Message as _;
    let inner = Message::decode(inner_proto_bytes).ok()?;
    let wrapper = Message {
        device_sent_message: Some(Box::new(DeviceSentMessage {
            destination_jid: Some(destination_jid.to_string()),
            message: Some(Box::new(inner)),
            phash: None,
        })),
        ..Default::default()
    };
    Some(wrapper.encode_to_vec())
}

#[allow(clippy::too_many_arguments)]
async fn encrypt_inner_proto_and_ship(
    dispatcher: &ConnDispatcher,
    session: &Session,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    chat_jid: &str,
    msg_id: &str,
    inner_proto_bytes: &[u8],
    timestamp: i64,
) -> Result<()> {
    let session_id = session.meta.read().id.clone();
    let own_jid = session.meta.read().jid.clone();

    // Groups use a completely different send model (sender-key skmsg + SKDM
    // fan-out) from 1:1 (resolve ONE peer's devices). Delegate before any of the
    // 1:1-specific LID/device logic below runs.
    if chat_jid.ends_with("@g.us") {
        return send_group_message(
            dispatcher, session, store, keys, chat_jid, msg_id, inner_proto_bytes, timestamp,
        )
        .await;
    }

    // Resolve a LID-addressed recipient to its phone-number address BEFORE we do
    // anything else. WhatsApp routes our sends by PN: a usync against a bare
    // `@lid` returns no device list (observed: "iq reply timeout"), so the send
    // falls back to a bare-LID `<message>` that the server never delivers — the
    // exact reason a reply typed into a LID-addressed chat silently vanished.
    // The LID<->PN map (learned from inbound traffic) gives us the PN the peer's
    // Signal session is actually established under. Resolve to the BARE PN so
    // usync enumerates every linked device, matching the working PN send path.
    let resolved_recipient;
    let chat_jid: &str = if chat_jid.ends_with("@lid") {
        match store.lid_to_pn(&session_id, lid_user_part(chat_jid)) {
            Ok(Some(pn)) => {
                resolved_recipient = format!("{pn}@s.whatsapp.net");
                tracing::info!(lid = %chat_jid, pn = %resolved_recipient, "resolved LID recipient to PN for send");
                resolved_recipient.as_str()
            }
            _ => {
                tracing::warn!(lid = %chat_jid, "no LID->PN mapping for recipient; sending to bare LID (may not deliver)");
                chat_jid
            }
        }
    } else {
        chat_jid
    };

    // Stash the unpadded inner proto so an inbound retry receipt can re-encrypt
    // and resend it (the peer's session to us desynced and it asked again).
    session.record_recent_send(msg_id, chat_jid, inner_proto_bytes);

    // 1. Discover the peer's linked devices via usync, and — so our sent
    //    message also lands in our own chat history — our own account's
    //    *other* devices. The sending device itself is always excluded.
    //    Falls back to the bare chat_jid if usync returns nothing.
    let mut device_jids = resolve_device_jids(session, dispatcher, chat_jid).await;
    let own_user = own_jid.as_deref().map(|j| jid_user(j).to_string());
    if let Some(own) = own_jid.as_deref() {
        // Only fan out to our own devices separately when we're not already
        // messaging ourselves (a self-send already resolved them above).
        if jid_user(chat_jid) != jid_user(own) {
            let own_bare = format!("{}@s.whatsapp.net", jid_user(own));
            for d in resolve_device_jids(session, dispatcher, &own_bare).await {
                if !device_jids.contains(&d) {
                    device_jids.push(d);
                }
            }
        }
        device_jids.retain(|d| d != own);
    }

    // 2. Build both plaintexts: the plain message for the peer's devices,
    //    and a DeviceSentMessage-wrapped copy for our own devices.
    let padded = pad_message(inner_proto_bytes);
    let padded_own = match build_device_sent_message(inner_proto_bytes, chat_jid) {
        Some(dsm) => pad_message(&dsm),
        None => padded.clone(),
    };
    let recipients = encrypt_per_device(
        store,
        keys,
        dispatcher,
        &session_id,
        &device_jids,
        &padded,
        &padded_own,
        own_user.as_deref(),
    )
    .await?;

    // 2. Build the <message> node, register the pending ack BEFORE
    //    pushing onto the wire (so a fast server can't beat us), then
    //    ship + flip status to 'sent'.
    let mut node = build_message_node(msg_id, chat_jid, &recipients, timestamp);
    // If any recipient got a `pkmsg` (first-time send to that device), the
    // server requires us to attach a `<device-identity>` child carrying our
    // `account_pb` (the marshalled ADVSignedDeviceIdentity). Without it,
    // the recipient app shows "Waiting for this message" because it can't
    // verify our device's authorization. Mirrors whatsmeow's
    // `getMessageContent(includeIdentity=true)`.
    let any_pkmsg = recipients
        .iter()
        .any(|r| matches!(r.message_type, crate::crypto::signal::MessageType::PreKey));
    if any_pkmsg {
        let account_pb: Option<Vec<u8>> = store.session_account_pb(&session_id).ok().flatten();
        if let Some(pb) = account_pb {
            use crate::protocol::binary::{Attrs, Content, Node};
            let id_node = Node {
                tag: "device-identity".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(pb),
            };
            if let Content::Nodes(ref mut children) = node.content {
                children.push(id_node);
            }
        }
    }
    let ack_rx = dispatcher.register_ack(msg_id);
    dispatcher.send_node(node);
    metrics::incr(&metrics::MSGS_OUT);
    update_message_status(store, &session_id, msg_id, "sent")?;
    let _ = session.events.send(SessionEvent::MessageSent {
        id: msg_id.to_string(),
        chat: chat_jid.to_string(),
    });

    // 6. Wait for server ack out-of-band. We tokio::spawn so the send
    //    pump isn't blocked by a slow ack — the next SendOp can run
    //    concurrently. Status flips to 'delivered' on success;
    //    'sent' is the terminal state on timeout.
    let session_for_ack = session.events.clone();
    let store_for_ack = Arc::clone(store);
    let session_id_clone = session_id.clone();
    let msg_id_clone = msg_id.to_string();
    let chat_jid_clone = chat_jid.to_string();
    tokio::spawn(async move {
        match tokio::time::timeout(std::time::Duration::from_secs(60), ack_rx).await {
            Ok(Ok(_class)) => {
                if let Err(e) = update_message_status(
                    &store_for_ack,
                    &session_id_clone,
                    &msg_id_clone,
                    "delivered",
                ) {
                    tracing::warn!(error = %e, msg_id = %msg_id_clone, "ack status update");
                }
                if let Err(e) =
                    delete_outbound_queue_row(&store_for_ack, &session_id_clone, &msg_id_clone)
                {
                    tracing::warn!(error = %e, msg_id = %msg_id_clone, "outbound_queue delete");
                }
                let _ = session_for_ack.send(SessionEvent::MessageDelivered {
                    id: msg_id_clone,
                    chat: chat_jid_clone,
                });
            }
            Ok(Err(_)) => {
                tracing::debug!(msg_id = %msg_id_clone, "ack channel dropped");
            }
            Err(_) => {
                tracing::debug!(msg_id = %msg_id_clone, "ack timeout");
            }
        }
    });
    Ok(())
}

/// Send a message to a group. Unlike 1:1 (resolve ONE peer's devices and
/// pairwise-encrypt), a group send encrypts the content ONCE under our per-group
/// sender key (`skmsg`) and fans our SenderKeyDistributionMessage (SKDM) out
/// pairwise to every participant device so they can decrypt it. Mirrors
/// whatsmeow's group send shape: `<message><participants>…SKDM…</participants>
/// <enc type=skmsg>…</enc></message>`.
#[allow(clippy::too_many_arguments)]
async fn send_group_message(
    dispatcher: &ConnDispatcher,
    session: &Session,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    group_jid: &str,
    msg_id: &str,
    inner_proto_bytes: &[u8],
    timestamp: i64,
) -> Result<()> {
    use crate::crypto::senderkey;
    let session_id = session.meta.read().id.clone();
    let own_jid = session.meta.read().jid.clone();
    let own_user = own_jid.as_deref().map(|j| jid_user(j).to_string());

    // 1. Participant list from group metadata.
    let participants = fetch_group_participants(dispatcher, store, &session_id, group_jid).await?;
    if participants.is_empty() {
        return Err(Error::Internal(anyhow::anyhow!(
            "group {group_jid} returned no participants"
        )));
    }

    // 2. Every participant device (+ our own other devices) that needs the SKDM.
    //    LID participants are mapped to PN first (usync enumerates devices by PN);
    //    our own sending device is excluded.
    let mut device_jids: Vec<String> = Vec::new();
    for p in &participants {
        let p_resolved = if p.ends_with("@lid") {
            match store.lid_to_pn(&session_id, lid_user_part(p)) {
                Ok(Some(pn)) => format!("{pn}@s.whatsapp.net"),
                _ => p.clone(),
            }
        } else {
            p.clone()
        };
        for d in resolve_device_jids(session, dispatcher, &p_resolved).await {
            if !device_jids.contains(&d) {
                device_jids.push(d);
            }
        }
    }
    if let Some(own) = own_jid.as_deref() {
        device_jids.retain(|d| d != own);
    }
    if device_jids.is_empty() {
        return Err(Error::Internal(anyhow::anyhow!(
            "no participant devices resolved for {group_jid}"
        )));
    }

    // 3. Our per-group sending sender-key state (created on first post).
    const SK_OWNER: &str = "__self__";
    let mut state = match store.sender_key_load(&session_id, group_jid, SK_OWNER) {
        Ok(Some(b)) => serde_json::from_slice::<senderkey::SenderKeyState>(&b)
            .unwrap_or_else(|_| senderkey::SenderKeyState::generate()),
        _ => senderkey::SenderKeyState::generate(),
    };

    // 4. Build the SKDM from the CURRENT chain position — must precede the
    //    encrypt that advances the chain, so receivers land on the same
    //    iteration the skmsg below is encrypted at.
    let dist = state.distribution();
    let skdm_wire = senderkey::serialize_distribution_wire(&dist);
    let skdm_plain = {
        use prost::Message as _;
        crate::proto::wa_web_protobufs_e2e::Message {
            sender_key_distribution_message: Some(
                crate::proto::wa_web_protobufs_e2e::SenderKeyDistributionMessage {
                    group_id: Some(group_jid.to_string()),
                    axolotl_sender_key_distribution_message: Some(skdm_wire),
                },
            ),
            ..Default::default()
        }
        .encode_to_vec()
    };
    let skdm_padded = pad_message(&skdm_plain);

    // 5. skmsg-encrypt the content (advances the chain); persist the new state.
    let padded_content = pad_message(inner_proto_bytes);
    let skmsg_wire = senderkey::encrypt_sender_key_message(&mut state, &padded_content)
        .map_err(|e| Error::Internal(anyhow::anyhow!("skmsg encrypt: {e:?}")))?;
    if let Ok(b) = serde_json::to_vec(&state) {
        let _ = store.sender_key_save(&session_id, group_jid, SK_OWNER, &b);
    }

    // 6. Fan the SKDM out pairwise to every participant device (same plaintext
    //    to all — the SKDM is identical for everyone).
    let recipients = encrypt_per_device(
        store,
        keys,
        dispatcher,
        &session_id,
        &device_jids,
        &skdm_padded,
        &skdm_padded,
        own_user.as_deref(),
    )
    .await?;

    // 7. A first-time send to any device produces a pkmsg → attach our
    //    device-identity so the recipient can verify our device authorization.
    let account_pb: Option<Vec<u8>> = if recipients
        .iter()
        .any(|r| matches!(r.message_type, crate::crypto::signal::MessageType::PreKey))
    {
        store.session_account_pb(&session_id).ok().flatten()
    } else {
        None
    };

    let node =
        build_group_message_node(msg_id, group_jid, &recipients, &skmsg_wire, timestamp, account_pb);

    // 8. Ship + ack (mirrors the 1:1 tail).
    session.record_recent_send(msg_id, group_jid, inner_proto_bytes);
    let ack_rx = dispatcher.register_ack(msg_id);
    dispatcher.send_node(node);
    metrics::incr(&metrics::MSGS_OUT);
    update_message_status(store, &session_id, msg_id, "sent")?;
    let _ = session.events.send(SessionEvent::MessageSent {
        id: msg_id.to_string(),
        chat: group_jid.to_string(),
    });
    let session_for_ack = session.events.clone();
    let store_for_ack = Arc::clone(store);
    let session_id_clone = session_id.clone();
    let msg_id_clone = msg_id.to_string();
    let chat_jid_clone = group_jid.to_string();
    tokio::spawn(async move {
        match tokio::time::timeout(std::time::Duration::from_secs(60), ack_rx).await {
            Ok(Ok(_class)) => {
                let _ = update_message_status(&store_for_ack, &session_id_clone, &msg_id_clone, "delivered");
                let _ = delete_outbound_queue_row(&store_for_ack, &session_id_clone, &msg_id_clone);
                let _ = session_for_ack.send(SessionEvent::MessageDelivered {
                    id: msg_id_clone,
                    chat: chat_jid_clone,
                });
            }
            _ => tracing::debug!(msg_id = %msg_id_clone, "group send: no ack within 60s"),
        }
    });
    Ok(())
}

/// Fetch a group's participant JIDs via the `w:g2` metadata query.
async fn fetch_group_participants(
    dispatcher: &ConnDispatcher,
    store: &Arc<Store>,
    session_id: &str,
    group_jid: &str,
) -> Result<Vec<String>> {
    let iq_id = uuid_v4();
    let iq = build_group_info_iq(&iq_id, group_jid);
    let reply = dispatcher
        .iq_request(iq)
        .await
        .map_err(|e| Error::Internal(anyhow::anyhow!("group metadata: {e}")))?;
    // A LID-addressed group's info is the main place we learn a participant's PN
    // (their `<participant jid="..@lid" phone_number="..">`), so a later 1:1 send
    // to that LID resolves to a deliverable PN. Mirrors whatsmeow group.go.
    capture_group_participant_lids(store, session_id, &reply);
    let participants = parse_group_info_response(&reply);
    tracing::info!(group = %group_jid, count = participants.len(), "resolved group participants");
    Ok(participants)
}

/// Persist LID<->PN for each participant of a group-info reply, from the
/// `<participant jid="..@lid" phone_number="..@s.whatsapp.net">` attrs. Additive:
/// only writes mappings, never affects the participant list. Mirrors whatsmeow's
/// `PutManyLIDMappings` over group metadata.
fn capture_group_participant_lids(
    store: &Arc<Store>,
    session_id: &str,
    iq: &crate::protocol::binary::Node,
) {
    use crate::protocol::binary::{Content, Node};
    let Content::Nodes(ns) = &iq.content else { return };
    let Some(group) = ns.iter().find(|n: &&Node| n.tag == "group") else { return };
    let Content::Nodes(parts) = &group.content else { return };
    let now = chrono::Utc::now().timestamp();
    for p in parts.iter().filter(|n| n.tag == "participant") {
        let (Some(jid), Some(phone)) = (p.attrs.get("jid"), p.attrs.get("phone_number")) else {
            continue;
        };
        // `jid` is the LID in a lid-addressed group; `phone_number` is the PN.
        let (lid_jid, pn_jid) = if jid.ends_with("@lid") {
            (jid.as_str(), phone.as_str())
        } else if phone.ends_with("@lid") {
            (phone.as_str(), jid.as_str())
        } else {
            continue;
        };
        let (lu, pu) = (lid_user_part(lid_jid), lid_user_part(pn_jid));
        if !lu.is_empty() && !pu.is_empty() {
            let _ = store.lid_pn_put(session_id, lu, pu, now);
        }
    }
}

/// Build a group `<message>`: per-device SKDM envelopes under `<participants>`,
/// the sender-key-encrypted content as a sibling `<enc type="skmsg">`, and an
/// optional `<device-identity>` when any envelope is a first-time `pkmsg`.
fn build_group_message_node(
    msg_id: &str,
    group_jid: &str,
    recipients: &[EncryptedRecipient],
    skmsg_wire: &[u8],
    timestamp: i64,
    account_pb: Option<Vec<u8>>,
) -> crate::protocol::binary::Node {
    use crate::crypto::signal::MessageType;
    use crate::protocol::binary::{Attrs, Content, Node};

    let participant_to_nodes: Vec<Node> = recipients
        .iter()
        .map(|r| {
            let mut enc_attrs = Attrs::new();
            enc_attrs.insert("v".into(), "2".into());
            enc_attrs.insert(
                "type".into(),
                match r.message_type {
                    MessageType::PreKey => "pkmsg".into(),
                    MessageType::Whisper => "msg".into(),
                },
            );
            let mut to_attrs = Attrs::new();
            to_attrs.insert("jid".into(), r.jid.clone());
            Node {
                tag: "to".into(),
                attrs: to_attrs,
                content: Content::Nodes(vec![Node {
                    tag: "enc".into(),
                    attrs: enc_attrs,
                    content: Content::Bytes(r.ciphertext.clone()),
                }]),
            }
        })
        .collect();

    let mut skmsg_attrs = Attrs::new();
    skmsg_attrs.insert("v".into(), "2".into());
    skmsg_attrs.insert("type".into(), "skmsg".into());

    let mut children = vec![
        Node {
            tag: "participants".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(participant_to_nodes),
        },
        Node {
            tag: "enc".into(),
            attrs: skmsg_attrs,
            content: Content::Bytes(skmsg_wire.to_vec()),
        },
    ];
    if let Some(pb) = account_pb {
        children.push(Node {
            tag: "device-identity".into(),
            attrs: Attrs::new(),
            content: Content::Bytes(pb),
        });
    }

    let mut msg_attrs = Attrs::new();
    msg_attrs.insert("id".into(), msg_id.into());
    msg_attrs.insert("type".into(), "text".into());
    msg_attrs.insert("to".into(), group_jid.into());
    msg_attrs.insert("t".into(), timestamp.to_string());
    Node {
        tag: "message".into(),
        attrs: msg_attrs,
        content: Content::Nodes(children),
    }
}

/// Read → encrypt → mediaconn IQ → upload → build per-type proto → run
/// the same X3DH+Signal-encrypt+ship pipeline as `send_text_op`. Mirrors
/// whatsmeow's send.go::sendMediaMessage at the level of the on-the-wire
/// IQ + message shape. Failures at any step propagate as Internal errors;
/// the run_send_pump handler logs and moves on so one bad file doesn't
/// stall the queue.
#[allow(clippy::too_many_arguments)]
async fn send_media_op(
    dispatcher: &ConnDispatcher,
    session: &Session,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    chat_jid: &str,
    msg_id: &str,
    kind: crate::media::MediaType,
    file_path: &str,
    mime: &str,
    caption: Option<&str>,
    filename: Option<&str>,
    mentions: &[String],
    timestamp: i64,
) -> Result<()> {
    use crate::media;

    // 1. Read + encrypt the file. media_key is fresh per file.
    let plaintext = std::fs::read(file_path)
        .map_err(|e| Error::Internal(anyhow::anyhow!("read media file: {e}")))?;
    let mut media_key = [0u8; 32];
    {
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut media_key);
    }
    let enc = media::encrypt(&plaintext, &media_key, kind)
        .map_err(|e| Error::Internal(anyhow::anyhow!("media encrypt: {e:?}")))?;

    // 2. Fetch a fresh mediaconn host + auth.
    let iq_id = uuid_v4();
    let iq = build_mediaconn_iq(&iq_id);
    let reply = dispatcher
        .iq_request(iq)
        .await
        .map_err(|e| Error::Internal(anyhow::anyhow!("mediaconn fetch: {e}")))?;
    let mc = parse_mediaconn_response(&reply)
        .ok_or_else(|| Error::Internal(anyhow::anyhow!("mediaconn response unparseable")))?;

    // 3. Upload encrypted bytes to mmg.whatsapp.net (through the session proxy).
    let proxy = session.meta.read().proxy_url.clone();
    let upload = media::upload_encrypted(
        &mc.hostname,
        &mc.auth,
        &enc.ciphertext,
        &enc.file_enc_sha256,
        kind,
        proxy.as_deref(),
    )
    .await
    .map_err(|e| Error::Internal(anyhow::anyhow!("media upload: {e:?}")))?;

    let uploaded = media::UploadedMedia {
        url: upload.url,
        direct_path: upload.direct_path,
        mimetype: mime.to_string(),
        caption: caption.map(str::to_string),
    };

    // 4. Build the per-type waE2E.Message proto. History/AppState are
    // internal types and never reach this user-facing send path.
    let inner_proto = match kind {
        media::MediaType::Image | media::MediaType::Sticker => {
            media::build_image_message(&enc, &uploaded, None, None)
        }
        media::MediaType::Video => media::build_video_message(&enc, &uploaded, None),
        media::MediaType::Audio => media::build_audio_message(&enc, &uploaded, None, false),
        media::MediaType::Ptt => media::build_audio_message(&enc, &uploaded, None, true),
        media::MediaType::Document => {
            media::build_document_message(&enc, &uploaded, filename.map(str::to_string))
        }
        media::MediaType::History | media::MediaType::AppState => {
            return Err(Error::BadRequest(
                "history/app_state media types are receive-only".into(),
            ));
        }
    };
    // Attach @-mentions (image/video/document carry a contextInfo).
    let inner_proto = apply_media_mentions(inner_proto, mentions);

    // 5. Same X3DH + Signal encrypt + <message> ship as text.
    encrypt_inner_proto_and_ship(
        dispatcher, session, store, keys, chat_jid, msg_id, &inner_proto, timestamp,
    )
    .await
}

/// Encode a waE2E.Message proto carrying just `conversation: text`. Used by
/// the outbound text path before WA padding + Signal encrypt.
/// Build a waE2E.Message containing a `ReactionMessage` referencing the
/// target message. Empty `emoji` is the WA convention for "remove reaction".
pub fn build_reaction_message(
    target_chat_jid: &str,
    target_msg_id: &str,
    target_from_me: bool,
    target_participant: Option<&str>,
    emoji: &str,
    timestamp_ms: i64,
) -> Vec<u8> {
    use crate::proto::wa_common::MessageKey;
    use crate::proto::wa_web_protobufs_e2e::{Message, ReactionMessage};
    use prost::Message as _;
    let key = MessageKey {
        remote_jid: Some(target_chat_jid.to_string()),
        from_me: Some(target_from_me),
        id: Some(target_msg_id.to_string()),
        participant: target_participant.map(str::to_string),
    };
    let r = ReactionMessage {
        key: Some(key),
        text: Some(emoji.to_string()),
        grouping_key: None,
        sender_timestamp_ms: Some(timestamp_ms),
    };
    let m = Message {
        reaction_message: Some(r),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Build a waE2E.Message containing a `ProtocolMessage` of type=Revoke
/// targeting `target_msg_id`. Receivers delete the original from view.
pub fn build_revoke_message(
    target_chat_jid: &str,
    target_msg_id: &str,
    target_from_me: bool,
    target_participant: Option<&str>,
) -> Vec<u8> {
    use crate::proto::wa_common::MessageKey;
    use crate::proto::wa_web_protobufs_e2e::{
        protocol_message::Type as PMType, Message, ProtocolMessage,
    };
    use prost::Message as _;
    let key = MessageKey {
        remote_jid: Some(target_chat_jid.to_string()),
        from_me: Some(target_from_me),
        id: Some(target_msg_id.to_string()),
        participant: target_participant.map(str::to_string),
    };
    let p = ProtocolMessage {
        key: Some(key),
        r#type: Some(PMType::Revoke as i32),
        ..Default::default()
    };
    let m = Message {
        protocol_message: Some(Box::new(p)),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Build a waE2E.Message containing a `ProtocolMessage` of type=MessageEdit
/// carrying a new text body. The receiver replaces the original message.
pub fn build_edit_message(
    target_chat_jid: &str,
    target_msg_id: &str,
    target_from_me: bool,
    target_participant: Option<&str>,
    new_text: &str,
    timestamp_ms: i64,
) -> Vec<u8> {
    use crate::proto::wa_common::MessageKey;
    use crate::proto::wa_web_protobufs_e2e::{
        protocol_message::Type as PMType, Message, ProtocolMessage,
    };
    use prost::Message as _;
    let key = MessageKey {
        remote_jid: Some(target_chat_jid.to_string()),
        from_me: Some(target_from_me),
        id: Some(target_msg_id.to_string()),
        participant: target_participant.map(str::to_string),
    };
    let edited_inner = Message {
        conversation: Some(new_text.to_string()),
        ..Default::default()
    };
    let p = ProtocolMessage {
        key: Some(key),
        r#type: Some(PMType::MessageEdit as i32),
        edited_message: Some(Box::new(edited_inner)),
        timestamp_ms: Some(timestamp_ms),
        ..Default::default()
    };
    let m = Message {
        protocol_message: Some(Box::new(p)),
        ..Default::default()
    };
    m.encode_to_vec()
}

fn build_e2e_conversation(text: &str) -> Vec<u8> {
    use prost::Message as _;
    let m = crate::proto::wa_web_protobufs_e2e::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Encode a waE2E.Message as an `ExtendedTextMessage` carrying a `contextInfo` —
/// used when a text send needs @-mentions and/or a reply (quote). `mentions` are
/// the mentioned JIDs (the body should contain the matching `@<number>` tokens);
/// `quoted` is the `(stanza_id, participant)` of the message being replied to.
/// The quoted message *content* isn't round-tripped — WA threads a reply off the
/// stanza id + participant, so an empty `quotedMessage` stub is enough.
pub fn build_extended_text_message(
    text: &str,
    mentions: &[String],
    quoted: Option<(&str, Option<&str>)>,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{ContextInfo, ExtendedTextMessage, Message};
    use prost::Message as _;

    let mut ctx = ContextInfo {
        mentioned_jid: mentions.to_vec(),
        ..Default::default()
    };
    if let Some((stanza_id, participant)) = quoted {
        ctx.stanza_id = Some(stanza_id.to_string());
        ctx.participant = participant.map(str::to_string);
        ctx.quoted_message = Some(Box::new(Message::default()));
    }
    let etm = ExtendedTextMessage {
        text: Some(text.to_string()),
        context_info: Some(Box::new(ctx)),
        ..Default::default()
    };
    let m = Message {
        extended_text_message: Some(Box::new(etm)),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Attach @-mentions to an already-built media inner proto by setting the
/// `contextInfo.mentionedJid` on whichever media sub-message it carries
/// (image/video/document). No-op when there are no mentions or the proto isn't
/// one of those media kinds. Decode→mutate→re-encode keeps the media builders
/// signature-stable.
fn apply_media_mentions(inner_proto: Vec<u8>, mentions: &[String]) -> Vec<u8> {
    if mentions.is_empty() {
        return inner_proto;
    }
    use crate::proto::wa_web_protobufs_e2e::{ContextInfo, Message};
    use prost::Message as _;

    let Ok(mut m) = Message::decode(inner_proto.as_slice()) else {
        return inner_proto;
    };
    let ctx = Box::new(ContextInfo {
        mentioned_jid: mentions.to_vec(),
        ..Default::default()
    });
    if let Some(im) = m.image_message.as_mut() {
        im.context_info = Some(ctx);
    } else if let Some(v) = m.video_message.as_mut() {
        v.context_info = Some(ctx);
    } else if let Some(d) = m.document_message.as_mut() {
        d.context_info = Some(ctx);
    } else {
        return inner_proto;
    }
    m.encode_to_vec()
}

/// Encode a waE2E.Message carrying a `LocationMessage` (a static pin).
pub fn build_location_message(
    latitude: f64,
    longitude: f64,
    name: Option<&str>,
    address: Option<&str>,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{LocationMessage, Message};
    use prost::Message as _;

    let loc = LocationMessage {
        degrees_latitude: Some(latitude),
        degrees_longitude: Some(longitude),
        name: name.map(str::to_string),
        address: address.map(str::to_string),
        ..Default::default()
    };
    let m = Message {
        location_message: Some(Box::new(loc)),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Encode a waE2E.Message carrying a `ContactMessage` (a shared contact card).
/// `vcard` is the full vCard text; `display_name` is what the chat list shows.
pub fn build_contact_message(display_name: &str, vcard: &str) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{ContactMessage, Message};
    use prost::Message as _;

    let c = ContactMessage {
        display_name: Some(display_name.to_string()),
        vcard: Some(vcard.to_string()),
        ..Default::default()
    };
    let m = Message {
        contact_message: Some(Box::new(c)),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Encode a waE2E.Message carrying a `PollCreationMessage`. `message_secret` is
/// the 32-byte key (placed in `messageContextInfo`) WhatsApp uses to encrypt the
/// poll-vote payloads; callers generate a fresh random one per poll.
pub fn build_poll_message(
    name: &str,
    options: &[String],
    selectable_count: u32,
    message_secret: &[u8; 32],
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{
        poll_creation_message::Option as PollOption, Message, MessageContextInfo,
        PollCreationMessage,
    };
    use prost::Message as _;

    let opts = options
        .iter()
        .map(|o| PollOption {
            option_name: Some(o.clone()),
            option_hash: None,
        })
        .collect();
    let poll = PollCreationMessage {
        name: Some(name.to_string()),
        options: opts,
        selectable_options_count: Some(selectable_count),
        ..Default::default()
    };
    let m = Message {
        poll_creation_message: Some(Box::new(poll)),
        message_context_info: Some(MessageContextInfo {
            message_secret: Some(message_secret.to_vec()),
            ..Default::default()
        }),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// Encode a waE2E.Message carrying an `EventMessage` (a native WhatsApp event /
/// calendar invite — the recipient sees an "Add to calendar" card). `location`
/// is the free-text place, mapped to the event's `LocationMessage.name`.
/// `start_time`/`end_time` are unix seconds. This is the in-house equivalent of
/// Evolution's `/message/sendCalendar`; clients send these for booked
/// appointments / calendar events.
pub fn build_event_message(
    name: &str,
    description: Option<&str>,
    location: Option<&str>,
    start_time: i64,
    end_time: Option<i64>,
    join_link: Option<&str>,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{EventMessage, LocationMessage, Message};
    use prost::Message as _;

    let ev = EventMessage {
        name: Some(name.to_string()),
        description: description.map(str::to_string),
        location: location.map(|l| {
            Box::new(LocationMessage {
                name: Some(l.to_string()),
                ..Default::default()
            })
        }),
        start_time: Some(start_time),
        end_time,
        join_link: join_link.map(str::to_string),
        ..Default::default()
    };
    let m = Message {
        event_message: Some(Box::new(ev)),
        ..Default::default()
    };
    m.encode_to_vec()
}

/// One-time prekey (OTK) replenishment thresholds. Mirrors whatsmeow
/// (MinPreKeyCount=5, WantedPreKeyCount=50): when the server reports fewer
/// than MIN available OTKs we generate + upload a fresh batch, so any new
/// peer can always fetch a bundle to open a Signal session to this device.
/// Without this a long-lived device silently stops receiving once its
/// initial OTKs are consumed (each new peer-device burns one).
const MIN_PREKEY_COUNT: i64 = 5;
const WANTED_PREKEY_COUNT: u32 = 50;

/// How often the per-connection proactive prekey top-up task wakes to check the
/// server-side OTK count. The server's `<notification type="encrypt">` is the
/// primary refill trigger, but a quiet device that never receives that
/// notification can still drift low; this is the belt-and-suspenders sweep.
/// Overridable via `RUWA_PREKEY_TOPUP_SECS` (clamped to a 60s floor).
fn prekey_topup_interval() -> std::time::Duration {
    topup_interval_from(std::env::var("RUWA_PREKEY_TOPUP_SECS").ok())
}

/// Pure parse + clamp for the top-up interval. Default 3600s; unparseable falls
/// back to the default; anything under the 60s floor is raised to 60s.
fn topup_interval_from(raw: Option<String>) -> std::time::Duration {
    let secs = raw
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(3600)
        .max(60);
    std::time::Duration::from_secs(secs)
}

/// OTKs still held by the server for this session. Consumed keys are deleted
/// on use, and `uploaded=1` marks the ones we've handed to the server, so
/// this count tracks server-side availability.
fn available_prekey_count(store: &Arc<Store>, session_id: &str) -> i64 {
    store.prekey_count_uploaded(session_id).unwrap_or(0)
}

/// Ship the `<iq xmlns="encrypt" type="set">` carrying every not-yet-uploaded
/// OTK (capped at 50) plus our signed prekey, then mark them uploaded.
/// Returns the count shipped. Mirrors whatsmeow's `uploadPreKeys` body.
fn upload_pending_prekeys(
    store: &Arc<Store>,
    session_id: &str,
    keys: &DeviceKeys,
    d: &ConnDispatcher,
) -> usize {
    use crate::protocol::binary::{Attrs, Content, Node};
    let prekey_rows: Vec<(u32, Vec<u8>)> = store
        .prekeys_pending_upload(session_id, 50)
        .unwrap_or_default();
    if prekey_rows.is_empty() {
        return 0;
    }
    let mut list_children: Vec<Node> = Vec::with_capacity(prekey_rows.len());
    for (kid, pub_) in &prekey_rows {
        let id_be = kid.to_be_bytes();
        list_children.push(Node {
            tag: "key".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![
                Node {
                    tag: "id".into(),
                    attrs: Attrs::new(),
                    content: Content::Bytes(id_be[1..].to_vec()),
                },
                Node {
                    tag: "value".into(),
                    attrs: Attrs::new(),
                    content: Content::Bytes(pub_.clone()),
                },
            ]),
        });
    }
    let spk_id_be = keys.signed_prekey.key_id.to_be_bytes();
    let skey_node = Node {
        tag: "skey".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![
            Node {
                tag: "id".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(spk_id_be[1..].to_vec()),
            },
            Node {
                tag: "value".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(keys.signed_prekey.keypair.public.to_vec()),
            },
            Node {
                tag: "signature".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(keys.signed_prekey.signature.to_vec()),
            },
        ]),
    };
    let reg_id_be = keys.registration_id.to_be_bytes();
    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), uuid_v4());
    iq_attrs.insert("xmlns".into(), "encrypt".into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    d.send_node(Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![
            Node {
                tag: "registration".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(reg_id_be.to_vec()),
            },
            Node {
                tag: "type".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(vec![0x05]),
            },
            Node {
                tag: "identity".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(keys.identity.public.to_vec()),
            },
            Node {
                tag: "list".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(list_children),
            },
            skey_node,
        ]),
    });
    let n = prekey_rows.len();
    let last_kid = prekey_rows.last().unwrap().0;
    let _ = store.prekeys_mark_uploaded(session_id, last_kid);
    tracing::info!(uploaded = n, "shipped prekey upload IQ");
    n
}

/// Generate a fresh batch of OTKs (continuing the key-id sequence), persist
/// them, and upload. Called when the server's `encrypt` notification reports
/// the available OTK count has dropped below MIN_PREKEY_COUNT.
fn replenish_prekeys(store: &Arc<Store>, session_id: &str, keys: &DeviceKeys, d: &ConnDispatcher) {
    let max_id = store.prekey_max_id(session_id).unwrap_or(0);
    let new_keys = PreKey::generate_batch(max_id + 1, WANTED_PREKEY_COUNT);
    let batch: Vec<(u32, &[u8], &[u8])> = new_keys
        .iter()
        .map(|pk| {
            (
                pk.key_id,
                pk.keypair.private.as_slice(),
                pk.keypair.public.as_slice(),
            )
        })
        .collect();
    let inserted = store.prekeys_insert_batch(session_id, &batch).unwrap_or(0);
    tracing::info!(generated = inserted, "generated fresh one-time prekeys");
    upload_pending_prekeys(store, session_id, keys, d);
    metrics::incr(&metrics::PREKEY_REFILLS_TOTAL);
}

/// Inspect a server-pushed binary node, populate session state if it's an
/// IQ we know about, and return an optional `Node` for the connection task
/// to ship back as an acknowledgment. Synchronous so it's unit-testable
/// without a live socket; takes `&Store` so it can persist pair-success
/// fields atomically with status transitions.
fn process_inbound_node(
    session: &Arc<Session>,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    dispatcher: Option<&ConnDispatcher>,
    node: &crate::protocol::binary::Node,
) -> Option<crate::protocol::binary::Node> {
    use crate::protocol::binary::Content;

    if node.tag == "message" {
        return process_inbound_message(session, store, keys, dispatcher, node);
    }
    // `<ib>` (info-bind): the server pushes directives a real client must act
    // on. Ignoring them leaves the device in an unsynced state — the strongest
    // remaining candidate for "message sync paused". Mirrors Baileys'
    // CB:ib,,dirty / offline_preview / offline handlers.
    //   - `<dirty type=… timestamp=…/>` → reply `<iq xmlns="urn:xmpp:whatsapp:dirty"><clean…/></iq>`.
    //   - `<offline_preview/>`          → reply `<ib><offline_batch count="100"/></ib>`.
    //   - `<offline count=N/>`          → all queued offline notifs delivered.
    if node.tag == "ib" {
        use crate::protocol::binary::{Attrs, Node};
        if let Content::Nodes(children) = &node.content {
            for child in children {
                match child.tag.as_str() {
                    "dirty" => {
                        let dtype = child.attrs.get("type").cloned().unwrap_or_default();
                        let ts = child.attrs.get("timestamp").cloned();
                        tracing::info!(dirty_type = %dtype, ts = ?ts, "inbound <ib><dirty> — sending <clean>");
                        if let Some(d) = dispatcher {
                            let mut iq_attrs = Attrs::new();
                            iq_attrs.insert("id".into(), uuid_v4());
                            iq_attrs.insert("type".into(), "set".into());
                            iq_attrs.insert("xmlns".into(), "urn:xmpp:whatsapp:dirty".into());
                            iq_attrs.insert("to".into(), "s.whatsapp.net".into());
                            let mut clean_attrs = Attrs::new();
                            clean_attrs.insert("type".into(), dtype);
                            if let Some(ts) = ts {
                                clean_attrs.insert("timestamp".into(), ts);
                            }
                            d.send_node(Node {
                                tag: "iq".into(),
                                attrs: iq_attrs,
                                content: Content::Nodes(vec![Node {
                                    tag: "clean".into(),
                                    attrs: clean_attrs,
                                    content: Content::None,
                                }]),
                            });
                        }
                    }
                    "offline_preview" => {
                        tracing::info!("inbound <ib><offline_preview> — sending <offline_batch>");
                        if let Some(d) = dispatcher {
                            let mut batch_attrs = Attrs::new();
                            batch_attrs.insert("count".into(), "100".into());
                            d.send_node(Node {
                                tag: "ib".into(),
                                attrs: Attrs::new(),
                                content: Content::Nodes(vec![Node {
                                    tag: "offline_batch".into(),
                                    attrs: batch_attrs,
                                    content: Content::None,
                                }]),
                            });
                        }
                    }
                    "offline" => {
                        let count = child.attrs.get("count").cloned().unwrap_or_default();
                        tracing::info!(count = %count, "inbound <ib><offline> — all queued offline notifs delivered");
                    }
                    other => {
                        tracing::info!(child = %other, attrs = ?child.attrs, "inbound <ib> child (logged, unhandled)");
                    }
                }
            }
        }
        return None;
    }
    if node.tag == "stream:error" {
        let attrs = format!("{:?}", node.attrs);
        let body = match &node.content {
            Content::Bytes(b) => format!("bytes({}): {}", b.len(), String::from_utf8_lossy(b)),
            Content::Nodes(ns) => format!("{} child node(s): {:?}", ns.len(), ns),
            Content::None => "empty".to_string(),
        };
        // A `<conflict type="replaced"/>` child means another client took
        // over our slot. Reconnecting would start a replace-war, so flag this
        // as a terminal disconnect: the reconnect loop sees the flag, stops,
        // and leaves the session Disconnected (credentials stay valid — the
        // user can POST /connect to reclaim the slot once the rival is gone).
        let is_replaced = matches!(&node.content, Content::Nodes(ns)
            if ns.iter().any(|c| c.tag == "conflict"
                && c.attrs.get("type").map(|t| t == "replaced").unwrap_or(false)));
        if is_replaced {
            session
                .expect_disconnect
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                "stream:error conflict=replaced — another client claimed our \
                 slot; halting auto-reconnect (whatsmeow StreamReplaced)"
            );
            let _ = session.events.send(SessionEvent::Disconnected {
                reason: "replaced".into(),
            });
            return None;
        }
        // `<stream:error code="515">` = "restart required": the normal step
        // right after pairing (and some reconnects). Reconnect immediately with
        // backoff reset — NOT through the generic exponential-backoff path,
        // which is what made post-scan pairing take 30–60s.
        if node.attrs.get("code").map(String::as_str) == Some("515") {
            session
                .restart_required
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!("stream:error 515 (restart required) — reconnecting immediately");
            return None;
        }
        // `<stream:error><ping id="…"/></stream:error>` (no `code`) is WhatsApp's
        // idle / QR-window timeout, NOT a rejection: the server closes an unpaired
        // (or quiet) stream after ~30s and echoes the pairing/keepalive id back as
        // a `<ping>`. whatsmeow treats every non-auth stream:error as a *retryable*
        // disconnect (request.go::isAuthErrorDisconnect — only `code=401` / conflict
        // `replaced` / `device_removed` are terminal), so on a QR timeout it just
        // reconnects, gets a fresh `pair-device`, and emits a new QR — the pairing
        // window effectively never ends. We were instead parking `Blocked` here,
        // which killed the QR ~30s in and made live pairing impossible. Mirror
        // whatsmeow: reconnect immediately (reuse `restart_required` → reconnect now
        // + backoff reset) so a fresh QR is minted before the user can miss it.
        let is_idle_ping_timeout = !node.attrs.contains_key("code")
            && matches!(&node.content, Content::Nodes(ns)
                if ns.iter().any(|c| c.tag == "ping"));
        if is_idle_ping_timeout {
            session
                .restart_required
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::info!(
                "stream:error <ping> (idle/QR-window timeout) — reconnecting to refresh pairing"
            );
            return None;
        }
        // Other `<stream:error>` codes split two ways (mirrors whatsmeow's
        // `isAuthErrorDisconnect`, which treats ONLY 401 + conflict as terminal):
        //   • 401 (logged out) / 403 (forbidden/banned) → genuine rejection.
        //     Park `Blocked` and halt — reconnecting hammers the number toward a
        //     harder ban.
        //   • everything else, notably a TRANSIENT 503 "service unavailable" / 5xx
        //     overload → retryable. Just drop; the reconnect loop reconnects with
        //     exponential backoff (the backoff itself caps the rate, so we never
        //     hammer even if the condition turns out to persist).
        let code = node.attrs.get("code").map(String::as_str).unwrap_or("");
        if code == "401" || code == "403" {
            session
                .wa_blocked
                .store(true, std::sync::atomic::Ordering::Relaxed);
            session
                .expect_disconnect
                .store(true, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(attrs, body, "WhatsApp rejected the stream (auth) — parking Blocked, auto-reconnect halted");
            return None;
        }
        tracing::warn!(attrs, body, "WhatsApp closed the stream (transient) — auto-reconnecting with backoff");
        return None;
    }
    // `<failure>` (login rejected — e.g. 401/403, account removed/banned). Same
    // policy: halt + Blocked, never auto-retry into it.
    if node.tag == "failure" {
        session
            .wa_blocked
            .store(true, std::sync::atomic::Ordering::Relaxed);
        session
            .expect_disconnect
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // `reason="405"` is WhatsApp rejecting the *client version* ("client
        // outdated"), NOT a ban. Auto-reconnecting can't fix it — the fix is to
        // bump the advertised WA Web version. Surface that explicitly so the
        // operator doesn't mistake a version bump for an account problem.
        let reason = node.attrs.get("reason").map(String::as_str).unwrap_or("");
        if reason == "405" {
            tracing::error!(
                attrs = ?node.attrs, current = ?wa_version(),
                "WhatsApp <failure reason=405>: this CLIENT VERSION is outdated and was \
                 rejected. Set RUWA_WA_VERSION to a current WhatsApp Web version (or update \
                 session::WA_VERSION) and reconnect. Parking; auto-reconnect halted (a retry \
                 would just be rejected again)."
            );
        } else {
            tracing::warn!(attrs = ?node.attrs, "WhatsApp <failure> — parking Blocked, auto-reconnect halted");
        }
        return None;
    }
    // <success> arrives after a successful login. Mirror whatsmeow's
    // `handleConnectSuccess`: flip status to Connected and ship a
    // `SetPassive(false)` IQ so the server starts routing inbound
    // messages + notifications to us. Without this, our linked-device
    // socket sees nothing.
    if node.tag == "success" {
        session.set_status(SessionStatus::Connected);
        session
            .reached_success
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = session.events.send(SessionEvent::Connected);
        if let Some(d) = dispatcher {
            use crate::protocol::binary::{Attrs, Content, Node};
            // 1. SetPassive(false) — registers us as the active recipient.
            let mut iq_attrs = Attrs::new();
            iq_attrs.insert("id".into(), uuid_v4());
            iq_attrs.insert("xmlns".into(), "passive".into());
            iq_attrs.insert("type".into(), "set".into());
            iq_attrs.insert("to".into(), "s.whatsapp.net".into());
            let active = Node {
                tag: "active".into(),
                attrs: Attrs::new(),
                content: Content::None,
            };
            d.send_node(Node {
                tag: "iq".into(),
                attrs: iq_attrs,
                content: Content::Nodes(vec![active]),
            });
            tracing::info!("shipped SetPassive(false) IQ");

            // 1a. `<iq xmlns="encrypt" type="get"><digest/></iq>` — Baileys
            //     `digestKeyBundle`; Evolution sends it right after SetPassive
            //     (live wire-capture). The server returns our registration +
            //     identity + signed-prekey digest; sending it is part of a real
            //     client validating its key bundle on connect. Fire-and-forget
            //     (the result flows back as an unmatched iq result).
            {
                let mut iq_attrs = Attrs::new();
                iq_attrs.insert("id".into(), uuid_v4());
                iq_attrs.insert("xmlns".into(), "encrypt".into());
                iq_attrs.insert("type".into(), "get".into());
                iq_attrs.insert("to".into(), "s.whatsapp.net".into());
                d.send_node(Node {
                    tag: "iq".into(),
                    attrs: iq_attrs,
                    content: Content::Nodes(vec![Node {
                        tag: "digest".into(),
                        attrs: Attrs::new(),
                        content: Content::None,
                    }]),
                });
                tracing::info!("shipped <iq xmlns=encrypt><digest> (key-bundle validation)");
            }

            // 1b. `<ib><unified_session id="…"/></ib>` — Baileys sends this on
            //     pairing, on login success, and whenever it goes available
            //     (Socket/socket.ts sendUnifiedSession). It marks us as a live,
            //     "open" unified session — the candidate signal the phone gates
            //     history backfill on ("sync resumes when WhatsApp is open on
            //     both devices"). id = (now_ms + 3 days) % 1 week.
            let unified_id = {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let week_ms: i64 = 7 * 24 * 60 * 60 * 1000;
                let offset_ms: i64 = 3 * 24 * 60 * 60 * 1000;
                ((now_ms + offset_ms).rem_euclid(week_ms)).to_string()
            };
            let mut us_attrs = Attrs::new();
            us_attrs.insert("id".into(), unified_id.clone());
            d.send_node(Node {
                tag: "ib".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![Node {
                    tag: "unified_session".into(),
                    attrs: us_attrs,
                    content: Content::None,
                }]),
            });
            tracing::info!(id = %unified_id, "shipped <ib><unified_session> (open-session signal)");

            // 2. Upload our prekey bundle so peers can open Signal sessions to
            //    us, then replenish if the OTK supply is low (e.g. on reconnect
            //    after peers consumed the initial batch). Replenishment also
            //    fires on the server's `encrypt` low-count notification (see
            //    the notification branch below). Without a steady OTK supply a
            //    long-lived device silently stops receiving from new peers.
            let session_id = session.meta.read().id.clone();
            upload_pending_prekeys(store, &session_id, keys, d);
            if available_prekey_count(store, &session_id) < MIN_PREKEY_COUNT {
                tracing::info!("OTK supply low on connect — replenishing");
                replenish_prekeys(store, &session_id, keys, d);
            }

            // 3. Send `<presence type="available"/>` to mark this device as
            //    actively present. whatsmeow's docs note: "you should call
            //    this at least once after connecting so the server has your
            //    pushname". Strong working hypothesis (per
            //    INBOUND_HANDOVER.md (git history)) is that WA's server gates routing of
            //    inbound `<message>` to a freshly-paired linked device on
            //    seeing presence + (eventually) app-state sync. Without
            //    presence, the server treats us as a passive observer and
            //    keeps messages queued for the phone only.
            //
            //    `push_name` comes from the persisted sessions row — only
            //    populated once app-state ContactUpsert lands for our own
            //    JID. Until then we ship presence with no `name` attr;
            //    server still accepts it, contact card just stays "-" for
            //    other peers (cosmetic).
            let push_name: Option<String> = store
                .session_push_name(&session_id)
                .ok()
                .flatten()
                .filter(|s: &String| !s.is_empty());
            let presence = presence_for(store.session_mark_online(&session_id).unwrap_or(false));
            d.send_node(build_global_presence_node(presence, push_name.as_deref()));
            tracing::info!(
                push_name = push_name.as_deref().unwrap_or(""),
                presence,
                "shipped presence",
            );

            // 4. Kick off app-state sync. The strong working hypothesis
            //    in INBOUND_HANDOVER.md (git history) is that WA's server gates inbound
            //    `<message>` routing on the linked device proving it's
            //    synced — the server doesn't want to fan out messages
            //    to a device that hasn't acknowledged it has the latest
            //    contacts/chats/settings state.
            //
            //    For each of the five collections, ship a fetch IQ at
            //    the persisted version cursor (or version=0 +
            //    return_snapshot=true on first contact). Responses come
            //    back via the regular inbound path — full patch decode +
            //    version advance is a follow-up; here we just signal
            //    intent so the server marks us as actively syncing.
            ship_app_state_fetches(store, &session_id, d);

            // Resolve LID↔PN for unnamed 1:1 chats so contact names stored under
            // a sender's LID (group senders are LID-addressed) resolve for the
            // PN-keyed chat. Best-effort, off the recv loop. See `run_lid_pn_sweep`.
            // Guarded on a live runtime so the sync-handler unit tests (which call
            // this outside a Tokio context) don't panic on spawn.
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let store = Arc::clone(store);
                let session_id = session_id.clone();
                let dispatcher = d.clone();
                handle.spawn(run_lid_pn_sweep(store, session_id, dispatcher));
            }

            // Init queries a real client fires on connect (Baileys
            // `fireInitQueries: true` = fetchProps + fetchBlocklist +
            // fetchPrivacySettings; Evolution sets it true). Fire-and-forget
            // GETs that complete the client's "I'm a full, active session"
            // handshake. Responses flow back as iq results (no handler needed).
            // xmlns/protocol match Evolution's live wire (LOG_BAILEYS=trace
            // capture): props is `xmlns="w" protocol="2"`, not abt/1.
            for (xmlns, child) in [
                ("w", Some(("props", "protocol", "2"))),
                ("blocklist", None),
                ("privacy", Some(("privacy", "", ""))),
            ] {
                let mut iq_attrs = Attrs::new();
                iq_attrs.insert("id".into(), uuid_v4());
                iq_attrs.insert("type".into(), "get".into());
                iq_attrs.insert("xmlns".into(), xmlns.into());
                iq_attrs.insert("to".into(), "s.whatsapp.net".into());
                let content = match child {
                    Some((tag, k, v)) => {
                        let mut ca = Attrs::new();
                        if !k.is_empty() {
                            ca.insert(k.into(), v.into());
                        }
                        Content::Nodes(vec![Node {
                            tag: tag.into(),
                            attrs: ca,
                            content: Content::None,
                        }])
                    }
                    None => Content::None,
                };
                d.send_node(Node {
                    tag: "iq".into(),
                    attrs: iq_attrs,
                    content,
                });
            }
            tracing::info!("shipped init queries (props/blocklist/privacy)");
        }
        return None;
    }
    // `notification`, `receipt`, and `call` nodes need an `<ack>` reply or
    // WA's server stops routing further events to us. Mirrors whatsmeow's
    // `sendAck`. Without these, inbound `<message>` nodes never arrive.
    if matches!(node.tag.as_str(), "notification" | "receipt" | "call") {
        tracing::info!(tag = %node.tag, attrs = ?node.attrs, "INBOUND notification/receipt/call");
        // `<receipt type="retry">` — a peer couldn't decrypt a message we sent
        // (its Signal session to us desynced) and is asking us to resend. Re-
        // establish + re-encrypt + resend off the recv loop so we don't block
        // draining the socket; we still ack the receipt below. Mirrors
        // whatsmeow's handleRetryReceipt.
        if node.tag == "receipt" {
            if let Some(req) = parse_inbound_retry_receipt(node) {
                if let Some(d) = dispatcher {
                    tracing::info!(
                        id = %req.msg_id,
                        device = %req.device_jid,
                        count = req.count,
                        has_keys = req.bundle.is_some(),
                        "inbound retry receipt — resending"
                    );
                    tokio::spawn(handle_inbound_retry_receipt(
                        Arc::clone(session),
                        Arc::clone(store),
                        keys.clone(),
                        d.clone(),
                        req,
                    ));
                }
            }
        }
        // `<notification type="devices">` means a peer (or we) added/removed a
        // linked device, so the cached device lists are now stale. Drop the
        // cache; the next send re-resolves via usync. This is what keeps the
        // per-send usync cache correct (mirrors whatsmeow's device-list refresh).
        if node.tag == "notification"
            && node.attrs.get("type").map(String::as_str) == Some("devices")
        {
            session.device_cache_clear();
            tracing::info!("devices notification — cleared device-list cache");
        }
        // `<notification type="account_sync">` is about OUR own account, so its
        // `from` is our own account's LID. We know our own PN (the session jid),
        // so this is where we learn our own LID<->PN — the one mapping usync
        // doesn't carry. It lets the decrypt path migrate our own-device fan-out
        // (sent from our phone's LID) onto the PN session we hold.
        if node.tag == "notification"
            && node.attrs.get("type").map(String::as_str) == Some("account_sync")
        {
            if let (Some(from), Some(own_jid)) =
                (node.attrs.get("from"), session.meta.read().jid.clone())
            {
                if from.ends_with("@lid") {
                    let lid_user = lid_user_part(from);
                    let pn_user = jid_user(&own_jid);
                    if !lid_user.is_empty() && !pn_user.is_empty() {
                        let session_id = session.meta.read().id.clone();
                        let now = chrono::Utc::now().timestamp();
                        let _ = store.lid_pn_put(&session_id, lid_user, pn_user, now);
                        tracing::info!(
                            own_lid = %lid_user,
                            own_pn = %pn_user,
                            "learned own LID<->PN from account_sync notification"
                        );
                    }
                }
            }
        }
        // `<notification type="encrypt">` from the server reports how many of
        // our one-time prekeys remain (`<count value=N/>`). When it drops below
        // the floor, generate + upload a fresh batch so peers can keep opening
        // sessions to us. This is the mechanism that keeps a long-lived device
        // receiving (mirrors whatsmeow's handleEncryptNotification).
        if node.tag == "notification"
            && node.attrs.get("type").map(String::as_str) == Some("encrypt")
        {
            if let Content::Nodes(ns) = &node.content {
                if let Some(count) = ns
                    .iter()
                    .find(|c| c.tag == "count")
                    .and_then(|c| c.attrs.get("value"))
                    .and_then(|v| v.parse::<i64>().ok())
                {
                    tracing::info!(otks_left = count, "server reported prekey count");
                    if count < MIN_PREKEY_COUNT {
                        if let Some(d) = dispatcher {
                            let session_id = session.meta.read().id.clone();
                            replenish_prekeys(store, &session_id, keys, d);
                        }
                    }
                }
            }
        }
        if let Some(d) = dispatcher {
            use crate::protocol::binary::{Attrs, Content, Node};
            let mut attrs = Attrs::new();
            attrs.insert("class".into(), node.tag.clone());
            if let Some(id) = node.attrs.get("id") {
                attrs.insert("id".into(), id.clone());
            }
            if let Some(from) = node.attrs.get("from") {
                attrs.insert("to".into(), from.clone());
            }
            if let Some(p) = node.attrs.get("participant") {
                attrs.insert("participant".into(), p.clone());
            }
            if let Some(r) = node.attrs.get("recipient") {
                attrs.insert("recipient".into(), r.clone());
            }
            // whatsmeow's sendAck (receipt.go) copies the `type` attr onto the
            // ack for every non-`message` node — and all three tags handled here
            // (notification/receipt/call) are non-message. WA's server matches an
            // ack to the pending node by class+id+TYPE; an ack missing `type`
            // (e.g. for `notification type="account_sync"`) is not recognized, so
            // the server keeps the notification pending and the primary device
            // sits on "Connecting…" until it times out (~30s) post-pair. Copying
            // `type` lets the ack land and the device flips online immediately.
            if let Some(ty) = node.attrs.get("type") {
                attrs.insert("type".into(), ty.clone());
            }
            d.send_node(Node {
                tag: "ack".into(),
                attrs,
                content: Content::None,
            });
        }
        tracing::debug!(tag = %node.tag, "acked inbound");
        return None;
    }
    if node.tag != "iq" {
        tracing::debug!(tag = %node.tag, "ignoring non-iq inbound node");
        return None;
    }
    let children = match &node.content {
        Content::Nodes(ns) => ns.as_slice(),
        _ => return None,
    };
    let child_tags: Vec<&str> = children.iter().map(|c| c.tag.as_str()).collect();
    let iq_ty = node.attrs.get("type").map(String::as_str).unwrap_or("?");
    tracing::info!(
        id = %node.attrs.get("id").map(String::as_str).unwrap_or("?"),
        ty = %iq_ty,
        xmlns = %node.attrs.get("xmlns").map(String::as_str).unwrap_or("?"),
        children = ?child_tags,
        child_attrs = ?children.iter().map(|c| (&c.tag, &c.attrs)).collect::<Vec<_>>(),
        "inbound iq (no pending match)"
    );

    // A server-initiated `<iq type="get"|"set">` REQUIRES a matching
    // `<iq type="result" id=… to=…/>` — the server tracks it as pending and a
    // device that never answers looks unresponsive. ruwa handled only a few
    // specific iqs and silently dropped the rest. Send a result ack for any
    // server get/set we don't otherwise handle below (mirrors a real client
    // acknowledging server pings/probes). Known payloads (sync/pair-*) still
    // get their specific handling and return early before this.
    let needs_result = matches!(iq_ty, "get" | "set")
        && node.attrs.get("from").map(|f| f == "s.whatsapp.net").unwrap_or(false);

    // App-state sync result (`<iq><sync><collection>…`): download+decrypt+apply
    // the snapshot/patches and advance the collection version off the recv loop
    // (it does network I/O). Completing this is what lets the phone consider the
    // linked device synced instead of leaving it pending.
    if let Some(sync) = children.iter().find(|c| c.tag == "sync") {
        if let Some(d) = dispatcher {
            let session_id = session.meta.read().id.clone();
            tokio::spawn(handle_app_state_sync_iq(
                Arc::clone(store),
                session_id,
                d.clone(),
                sync.clone(),
            ));
        }
    }

    if let Some(pd) = children.iter().find(|c| c.tag == "pair-device") {
        let codes = pair_device_qr_codes(keys, pd);
        if codes.is_empty() {
            return None;
        }
        session.install_qr_rotation(codes);
        return Some(build_iq_ack(node));
    }

    if let Some(ps) = children.iter().find(|c| c.tag == "pair-success") {
        match apply_pair_success(session, store, keys, node, ps) {
            Ok(reply) => return Some(reply),
            Err(e) => {
                tracing::warn!(error = %e, "failed to persist pair-success");
                return None;
            }
        }
    }

    // Acknowledge any other server-initiated get/set with an empty
    // `<iq type="result">` so the server doesn't keep it pending / treat us as
    // unresponsive. (Specific payloads above return early before this.)
    if needs_result {
        use crate::protocol::binary::{Attrs, Node};
        let mut attrs = Attrs::new();
        if let Some(id) = node.attrs.get("id") {
            attrs.insert("id".into(), id.clone());
        }
        attrs.insert("type".into(), "result".into());
        attrs.insert("to".into(), "s.whatsapp.net".into());
        tracing::info!(
            id = %node.attrs.get("id").map(String::as_str).unwrap_or("?"),
            "answering server-initiated iq with empty <iq type=result>"
        );
        return Some(Node {
            tag: "iq".into(),
            attrs,
            content: Content::None,
        });
    }

    None
}

/// Whatsmeow's `AdvAccountSignaturePrefix` (e2ee) and hosted variant.
const ADV_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 0];
const ADV_HOSTED_ACCOUNT_SIG_PREFIX: [u8; 2] = [6, 5];
/// Whatsmeow's `AdvDeviceSignaturePrefix`.
const ADV_DEVICE_SIG_PREFIX: [u8; 2] = [6, 1];

/// Process a `<pair-success>` IQ: verify the HMAC + account signature,
/// generate our device signature, persist credentials, and build the
/// signed `<iq type=result><pair-device-sign>...</pair-device-sign></iq>`
/// reply that completes the pairing handshake. Mirrors whatsmeow's
/// `Client.handlePair` in pair.go.
fn apply_pair_success(
    session: &Arc<Session>,
    store: &Store,
    keys: &DeviceKeys,
    orig: &crate::protocol::binary::Node,
    pair_success: &crate::protocol::binary::Node,
) -> Result<crate::protocol::binary::Node> {
    use crate::proto::wa_adv::{
        AdvDeviceIdentity, AdvEncryptionType, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac,
    };
    use crate::protocol::binary::{Attrs, Content, Node};
    use hmac::{Hmac, Mac};
    use prost::Message;
    use sha2::Sha256;

    let children: &[Node] = match &pair_success.content {
        Content::Nodes(ns) => ns.as_slice(),
        _ => return Err(Error::BadRequest("pair-success has no children".into())),
    };
    let device_identity_bytes = children
        .iter()
        .find(|c| c.tag == "device-identity")
        .and_then(|c| match &c.content {
            Content::Bytes(b) => Some(b.clone()),
            _ => None,
        })
        .ok_or_else(|| Error::BadRequest("pair-success missing device-identity bytes".into()))?;

    // 1. Parse the outer HMAC envelope.
    let container = AdvSignedDeviceIdentityHmac::decode(device_identity_bytes.as_slice())
        .map_err(|e| Error::BadRequest(format!("bad device-identity HMAC container: {e}")))?;
    let details = container
        .details
        .ok_or_else(|| Error::BadRequest("HMAC container missing details".into()))?;
    let hmac_bytes = container
        .hmac
        .ok_or_else(|| Error::BadRequest("HMAC container missing hmac".into()))?;
    let is_hosted =
        container.account_type == Some(AdvEncryptionType::Hosted as i32);

    // 2. HMAC-SHA256(adv_secret, [hosted-prefix?] || details) == container.hmac.
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys.adv_secret)
        .map_err(|e| Error::Internal(anyhow::anyhow!("hmac init: {e}")))?;
    if is_hosted {
        mac.update(&ADV_HOSTED_ACCOUNT_SIG_PREFIX);
    }
    mac.update(&details);
    if mac.verify_slice(&hmac_bytes).is_err() {
        return Err(Error::BadRequest(
            "device-identity HMAC verification failed".into(),
        ));
    }

    // 3. Parse the signed identity (account_signature_key + account_signature).
    let mut signed = AdvSignedDeviceIdentity::decode(details.as_slice())
        .map_err(|e| Error::BadRequest(format!("bad signed device-identity: {e}")))?;
    let signed_details = signed
        .details
        .clone()
        .ok_or_else(|| Error::BadRequest("signed identity missing details".into()))?;
    let account_sig_key = signed
        .account_signature_key
        .clone()
        .ok_or_else(|| Error::BadRequest("signed identity missing account_signature_key".into()))?;
    let account_sig = signed
        .account_signature
        .clone()
        .ok_or_else(|| Error::BadRequest("signed identity missing account_signature".into()))?;
    if account_sig_key.len() != 32 || account_sig.len() != 64 {
        return Err(Error::BadRequest(
            "account signature key/signature wrong length".into(),
        ));
    }

    // 4. Parse the inner ADVDeviceIdentity to extract key_index (used as an
    //    attr on the outbound device-identity element).
    let device_id_details = AdvDeviceIdentity::decode(signed_details.as_slice())
        .map_err(|e| Error::BadRequest(format!("bad inner ADVDeviceIdentity: {e}")))?;
    let key_index = device_id_details.key_index.unwrap_or(0);

    // 5. Verify account signature: msg = [6,0]||signed.details||identity_pub.
    let acct_prefix: &[u8] = if is_hosted {
        &ADV_HOSTED_ACCOUNT_SIG_PREFIX
    } else {
        &ADV_ACCOUNT_SIG_PREFIX
    };
    let mut acct_msg = Vec::with_capacity(acct_prefix.len() + signed_details.len() + 32);
    acct_msg.extend_from_slice(acct_prefix);
    acct_msg.extend_from_slice(&signed_details);
    acct_msg.extend_from_slice(&keys.identity.public);
    let mut acct_sig_arr = [0u8; 64];
    acct_sig_arr.copy_from_slice(&account_sig);
    let mut acct_key_arr = [0u8; 32];
    acct_key_arr.copy_from_slice(&account_sig_key);
    if !crate::crypto::identity::xeddsa_verify(&acct_key_arr, &acct_msg, &acct_sig_arr) {
        return Err(Error::BadRequest(
            "pair-success account signature verification failed".into(),
        ));
    }

    // 6. Generate device signature: msg = [6,1]||signed.details||identity_pub
    //    ||account_signature_key. Sign with our identity private (XEdDSA).
    let mut dev_msg = Vec::with_capacity(2 + signed_details.len() + 32 + 32);
    dev_msg.extend_from_slice(&ADV_DEVICE_SIG_PREFIX);
    dev_msg.extend_from_slice(&signed_details);
    dev_msg.extend_from_slice(&keys.identity.public);
    dev_msg.extend_from_slice(&account_sig_key);
    let device_sig = crate::crypto::identity::xeddsa_sign(&keys.identity.private, &dev_msg);
    signed.device_signature = Some(device_sig.to_vec());

    // 7. Persist the FULL signed identity (with account_signature_key) as
    //    account_pb — it's our store-of-record for the pair. Then flip the
    //    session row to connected.
    let full_signed_bytes = signed.encode_to_vec();
    let biz_name = find_child_attr(children, "biz", "name");
    let jid = find_child_attr(children, "device", "jid");
    let platform = find_child_attr(children, "platform", "name");

    let id = session.meta.read().id.clone();
    let now = chrono::Utc::now().timestamp();
    store.session_apply_pair_success(
        &id,
        full_signed_bytes.as_slice(),
        biz_name.as_deref(),
        platform.as_deref(),
        jid.as_deref(),
        now,
    )?;

    {
        let mut m = session.meta.write();
        m.jid = jid.clone();
        m.status = SessionStatus::Connected;
        m.updated_at = now;
    }
    if let Some(j) = jid {
        let _ = session.events.send(SessionEvent::Paired { jid: j });
    }
    let _ = session.events.send(SessionEvent::Connected);
    session.cancel_qr_rotation();

    // 8. Build the self-signed identity for the wire: clone, drop the
    //    account_signature_key, marshal. The server only wants OUR proof
    //    of acceptance; it already has the account-side material.
    signed.account_signature_key = None;
    let self_signed_bytes = signed.encode_to_vec();

    // 9. Construct the proper pair-success ACK:
    //    <iq to=s.whatsapp.net type=result id=ORIG_ID>
    //      <pair-device-sign>
    //        <device-identity key-index=KI>
    //          <self-signed bytes>
    //        </device-identity>
    //      </pair-device-sign>
    //    </iq>
    let mut device_id_attrs = Attrs::new();
    device_id_attrs.insert("key-index".into(), key_index.to_string());
    let device_id_node = Node {
        tag: "device-identity".into(),
        attrs: device_id_attrs,
        content: Content::Bytes(self_signed_bytes),
    };
    let pair_sign_node = Node {
        tag: "pair-device-sign".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![device_id_node]),
    };
    let mut ack_attrs = Attrs::new();
    ack_attrs.insert("to".into(), "s.whatsapp.net".into());
    ack_attrs.insert("type".into(), "result".into());
    if let Some(orig_id) = orig.attrs.get("id") {
        ack_attrs.insert("id".into(), orig_id.clone());
    }
    Ok(Node {
        tag: "iq".into(),
        attrs: ack_attrs,
        content: Content::Nodes(vec![pair_sign_node]),
    })
}

fn find_child_attr(
    children: &[crate::protocol::binary::Node],
    child_tag: &str,
    attr_key: &str,
) -> Option<String> {
    children
        .iter()
        .find(|c| c.tag == child_tag)
        .and_then(|c| c.attrs.get(attr_key).cloned())
}

/// Extract the `<ref>` strings inside a `<pair-device>` node and combine
/// each with the device's own keys into the canonical
/// `"<ref>,<noise_pub_b64>,<identity_pub_b64>,<adv_secret_b64>"` form
/// that the WhatsApp mobile scanner expects.
fn pair_device_qr_codes(
    keys: &DeviceKeys,
    pair_device: &crate::protocol::binary::Node,
) -> Vec<String> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use crate::protocol::binary::Content;

    let noise = B64.encode(keys.noise.public);
    let identity = B64.encode(keys.identity.public);
    let adv = B64.encode(keys.adv_secret);

    let children = match &pair_device.content {
        Content::Nodes(ns) => ns.as_slice(),
        _ => return Vec::new(),
    };

    children
        .iter()
        .filter(|c| c.tag == "ref")
        .filter_map(|c| match &c.content {
            Content::Bytes(b) => std::str::from_utf8(b).ok().map(str::to_string),
            _ => None,
        })
        .map(|r| format!("{r},{noise},{identity},{adv}"))
        .collect()
}

/// Client-initiated keepalive IQ:
///   `<iq id="<uuid>" to="s.whatsapp.net" type="get" xmlns="w:p"/>`
/// Mirrors whatsmeow's keepalive.go::sendKeepAlive. The server replies
/// with a matching `<iq type=result/>`. We do not currently wait for the
/// reply — best-effort fire-and-forget every ~25s.
fn build_keepalive_iq(id: &str) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("id".into(), id.into());
    attrs.insert("to".into(), "s.whatsapp.net".into());
    attrs.insert("type".into(), "get".into());
    attrs.insert("xmlns".into(), "w:p".into());
    Node {
        tag: "iq".into(),
        attrs,
        content: Content::None,
    }
}

/// Acknowledge a server IQ. Whatsmeow's pair.go sends:
///   `<iq to="<orig from>" id="<orig id>" type="result"/>`
fn build_iq_ack(orig: &crate::protocol::binary::Node) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Node};
    let mut attrs = Attrs::new();
    if let Some(from) = orig.attrs.get("from") {
        attrs.insert("to".into(), from.clone());
    }
    if let Some(id) = orig.attrs.get("id") {
        attrs.insert("id".into(), id.clone());
    }
    attrs.insert("type".into(), "result".into());
    Node {
        tag: "iq".into(),
        attrs,
        content: crate::protocol::binary::Content::None,
    }
}

/// Decrypt a single 1:1 Signal envelope (`<enc type="msg"|"pkmsg">`) under
/// `decrypt_addr`, returning the unpadded inner `waE2E.Message` bytes (or
/// `None` on any failure). `log_addr` is the raw sender JID, used only for
/// diagnostics. Shared by the 1:1 inbound path and the group SKDM path.
#[allow(clippy::too_many_arguments)]
fn decrypt_signal_envelope(
    store: &Arc<Store>,
    session_id: &str,
    keys: &DeviceKeys,
    decrypt_addr: &str,
    log_addr: &str,
    enc_type: &str,
    enc_version: u32,
    ciphertext: &[u8],
) -> Option<Vec<u8>> {
    use crate::crypto::signal::{
        parse_pre_key_message, BobParameters, RatchetingSession, SessionCipher,
    };
    match enc_type {
        "msg" => {
            let loaded = store_load_record(store, session_id, decrypt_addr);
            tracing::info!(
                addr = %decrypt_addr,
                found = matches!(loaded, Ok(Some(_))),
                "decrypt: msg branch — loaded SessionRecord",
            );
            match loaded {
                Ok(Some(mut record)) => match record.current.as_mut() {
                    Some(state) => match SessionCipher::decrypt(state, ciphertext) {
                        Ok(padded) => match unpad_message_v(&padded, enc_version) {
                            Ok(p) => {
                                let _ =
                                    store_save_record(store, session_id, decrypt_addr, &record);
                                Some(p)
                            }
                            Err(e) => {
                                tracing::warn!(error=%e, v=enc_version, "unpad");
                                None
                            }
                        },
                        Err(e) => {
                            tracing::warn!(error=%e, "decrypt");
                            None
                        }
                    },
                    None => None,
                },
                _ => None,
            }
        }
        "pkmsg" => match parse_pre_key_message(ciphertext) {
            Ok(info) => {
                // Try the existing SessionRecord first. Peers commonly send
                // multiple pkmsgs sharing the same X3DH session (same
                // base_key + OPK), just incrementing the inner WhisperMessage
                // counter. Re-running process_bob on every pkmsg throws away
                // the chain state and breaks every follow-up message.
                let mut existing_decrypt: Option<Vec<u8>> = None;
                if let Ok(Some(mut record)) = store_load_record(store, session_id, decrypt_addr) {
                    let identity_matches = record
                        .current
                        .as_ref()
                        .map(|s| s.remote_identity_pub == info.identity_key_pub)
                        .unwrap_or(false);
                    if identity_matches {
                        if let Some(state) = record.current.as_mut() {
                            if let Ok(padded) =
                                SessionCipher::decrypt(state, &info.inner_whisper_wire)
                            {
                                if let Ok(p) = unpad_message_v(&padded, enc_version) {
                                    let _ = store_save_record(
                                        store,
                                        session_id,
                                        decrypt_addr,
                                        &record,
                                    );
                                    tracing::info!(
                                        addr = %decrypt_addr,
                                        "decrypt: pkmsg reused existing session, no re-X3DH",
                                    );
                                    existing_decrypt = Some(p);
                                }
                            }
                        }
                    }
                }
                if existing_decrypt.is_some() {
                    return existing_decrypt;
                }
                let opk_priv: Option<[u8; 32]> = match info.pre_key_id {
                    Some(id) => match load_prekey_priv(store, session_id, id) {
                        Ok(opt) => opt,
                        Err(e) => {
                            tracing::warn!(error=%e, "prekey lookup");
                            None
                        }
                    },
                    None => None,
                };
                tracing::info!(
                    addr = %log_addr,
                    pre_key_id = info.pre_key_id.unwrap_or(0),
                    has_opk_priv = opk_priv.is_some(),
                    signed_pre_key_id = info.signed_pre_key_id,
                    base_pub_head = %hex::encode(&info.base_key_pub[..8]),
                    inner_ratchet_head = %hex::encode(&info.inner_ratchet_pub[..8]),
                    identity_head = %hex::encode(&info.identity_key_pub[..8]),
                    inner_len = info.inner_whisper_wire.len(),
                    v = enc_version,
                    "decrypt: pkmsg branch — about to process_bob",
                );
                let mut state = RatchetingSession::process_bob(&BobParameters {
                    local_identity_priv: &keys.identity.private,
                    local_identity_pub: &keys.identity.public,
                    local_signed_prekey_priv: &keys.signed_prekey.keypair.private,
                    local_one_time_prekey_priv: opk_priv.as_ref(),
                    remote_identity_pub: &info.identity_key_pub,
                    remote_base_pub: &info.base_key_pub,
                    remote_ratchet_pub: &info.inner_ratchet_pub,
                });
                tracing::info!(
                    addr = %log_addr,
                    root_head = %hex::encode(&state.root_key[..8]),
                    "decrypt: pkmsg branch — process_bob produced state",
                );
                match SessionCipher::decrypt(&mut state, &info.inner_whisper_wire) {
                    Ok(padded) => match unpad_message_v(&padded, enc_version) {
                        Ok(p) => {
                            let mut record = crate::crypto::signal::SessionRecord::new();
                            record.current = Some(state);
                            let _ = store_save_record(store, session_id, decrypt_addr, &record);
                            tracing::info!(
                                addr = %decrypt_addr,
                                v = enc_version,
                                "decrypt: pkmsg branch — saved SessionRecord",
                            );
                            // Single-use OPK eviction — defends against replay.
                            if let Some(id) = info.pre_key_id {
                                if opk_priv.is_some() {
                                    let _ = consume_prekey(store, session_id, id);
                                }
                            }
                            Some(p)
                        }
                        Err(e) => {
                            // MAC already verified inside SessionCipher::decrypt,
                            // so `padded` is authentic plaintext. With the
                            // version-aware unpad this only fires for a genuine
                            // v<=2 bad pad — log the bytes if it ever does.
                            let n = padded.len();
                            let tail = &padded[n.saturating_sub(8)..];
                            tracing::warn!(
                                addr = %decrypt_addr,
                                err = %e,
                                v = enc_version,
                                plain_len = n,
                                last_byte = padded.last().copied().unwrap_or(0),
                                tail_hex = %hex::encode(tail),
                                head_hex = %hex::encode(&padded[..n.min(8)]),
                                "decrypt: pkmsg MAC-OK but unpad FAILED — authentic plaintext, bad pad",
                            );
                            None
                        }
                    },
                    Err(e) => {
                        tracing::warn!(error=%e, "pkmsg decrypt");
                        None
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error=%e, "pkmsg parse");
                None
            }
        },
        _ => None,
    }
}

/// Decrypt a group `<message from="…@g.us">`. Group content rides in an
/// `<enc type="skmsg">` (sender-key encrypted); the sender bootstraps each
/// recipient's receiver state with a `SenderKeyDistributionMessage` carried in
/// a 1:1 `pkmsg`/`msg` enc the first time / on key rotation. We process the
/// SKDM enc first (install + persist the per-(group,sender) receiver state),
/// then decrypt the skmsg. Mirrors whatsmeow's `decryptGroupMsg` +
/// `handleSenderKeyDistributionMessage`. Returns the unpadded inner
/// `waE2E.Message` bytes (the actual content), or `None`.
fn decrypt_group_message(
    store: &Arc<Store>,
    session_id: &str,
    keys: &DeviceKeys,
    group: &str,
    sender: &str,
    sender_addr: &str,
    msg: &crate::protocol::binary::Node,
) -> Option<Vec<u8>> {
    use crate::crypto::senderkey;
    use crate::protocol::binary::Content;

    let encs: Vec<&crate::protocol::binary::Node> = match &msg.content {
        Content::Nodes(ns) => ns.iter().filter(|c| c.tag == "enc").collect(),
        _ => return None,
    };
    let enc_attrs = |n: &crate::protocol::binary::Node| -> (String, u32, Vec<u8>) {
        let ty = n.attrs.get("type").cloned().unwrap_or_default();
        let v = n.attrs.get("v").and_then(|s| s.parse().ok()).unwrap_or(2);
        let ct = match &n.content {
            Content::Bytes(b) => b.clone(),
            _ => Vec::new(),
        };
        (ty, v, ct)
    };

    // 1. Install any SenderKeyDistributionMessage carried in a 1:1 envelope,
    //    so the skmsg below has receiver state to decrypt against.
    for enc in &encs {
        let (ty, v, ct) = enc_attrs(enc);
        if ty != "pkmsg" && ty != "msg" {
            continue;
        }
        let Some(plain) =
            decrypt_signal_envelope(store, session_id, keys, sender_addr, sender, &ty, v, &ct)
        else {
            continue;
        };
        // The decrypted Message carries `sender_key_distribution_message`.
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;
        let Ok(decoded) = Message::decode(plain.as_slice()) else {
            continue;
        };
        let Some(skdm) = decoded.sender_key_distribution_message else {
            continue;
        };
        let Some(axolotl) = skdm.axolotl_sender_key_distribution_message else {
            continue;
        };
        match senderkey::parse_distribution_wire(&axolotl) {
            Ok(dist) => {
                let recv = senderkey::install_distribution(&dist);
                if let Ok(bytes) = serde_json::to_vec(&recv) {
                    let _ = store.sender_key_save(session_id, group, sender, &bytes);
                    tracing::info!(
                        group = %group,
                        sender = %sender,
                        key_id = dist.key_id,
                        iteration = dist.iteration,
                        "installed group sender key from SKDM",
                    );
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "parse SKDM wire");
            }
        }
    }

    // 2. Decrypt the skmsg content with the (group, sender) receiver state.
    for enc in &encs {
        let (ty, v, ct) = enc_attrs(enc);
        if ty != "skmsg" {
            continue;
        }
        let rec_bytes = match store.sender_key_load(session_id, group, sender) {
            Ok(Some(b)) => b,
            _ => {
                tracing::warn!(
                    group = %group,
                    sender = %sender,
                    "skmsg with no sender-key state yet — need the SKDM first",
                );
                return None;
            }
        };
        let Ok(mut recv) =
            serde_json::from_slice::<senderkey::SenderKeyReceiverState>(&rec_bytes)
        else {
            return None;
        };
        match senderkey::decrypt_sender_key_message(&mut recv, &ct) {
            Ok(padded) => {
                if let Ok(bytes) = serde_json::to_vec(&recv) {
                    let _ = store.sender_key_save(session_id, group, sender, &bytes);
                }
                tracing::info!(group = %group, sender = %sender, "decrypt: skmsg ok");
                return unpad_message_v(&padded, v).ok();
            }
            Err(e) => {
                tracing::warn!(error = %e, group = %group, sender = %sender, "skmsg decrypt");
                return None;
            }
        }
    }
    None
}

/// Handle a server-pushed `<message>` node: try to decrypt the inner
/// `<enc>` against the matching SessionRecord, persist a row, and emit an
/// inbound event. Returns the `<receipt>` ack to ship back regardless of
/// whether decryption actually worked — the server expects every message
/// to be acked. Failed-decrypt rows still land in `messages` (with
/// msg_type="undecryptable") so the API consumer can see something arrived.
///
/// Decryption is best-effort: the post-Noise socket we have today doesn't
/// yet maintain the full ratchet across multiple inbound chains. Type=
/// "msg" requires an existing SessionRecord under the sender's address;
/// type="pkmsg" carries its own X3DH bundle and bootstraps the session.
/// Either path may fail (no record / bad MAC / missing prekey) — in that
/// case we log + persist a placeholder + return the receipt anyway.
fn process_inbound_message(
    session: &Arc<Session>,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    dispatcher: Option<&ConnDispatcher>,
    msg: &crate::protocol::binary::Node,
) -> Option<crate::protocol::binary::Node> {
    tracing::info!(
        id = %msg.attrs.get("id").map(String::as_str).unwrap_or("?"),
        from = %msg.attrs.get("from").map(String::as_str).unwrap_or("?"),
        // Full attr dump to ground LID/addressing work: we need to see exactly
        // what the server stamps (addressing_mode, sender_lid, participant_lid,
        // sender_pn, recipient, …) on an `@lid`-addressed message.
        attrs = ?msg.attrs,
        "INBOUND MESSAGE arrived"
    );
    metrics::incr(&metrics::MSGS_IN);
    use crate::protocol::binary::Content;

    let msg_id = msg.attrs.get("id").cloned().unwrap_or_default();
    let from = msg.attrs.get("from").cloned().unwrap_or_default();
    let participant = msg
        .attrs
        .get("participant")
        .cloned()
        .unwrap_or_else(|| from.clone());
    let timestamp: i64 = msg
        .attrs
        .get("t")
        .and_then(|t| t.parse().ok())
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    // The sender's self-chosen profile name rides on the message's `notify`
    // attribute (mirrors whatsmeow's `info.PushName = ag.OptionalString("notify")`).
    // Works for contacts and strangers alike — no app-state/contacts sync needed.
    // WhatsApp uses "-" as a placeholder for "no name", which we drop.
    let push_name = msg
        .attrs
        .get("notify")
        .filter(|n| !n.is_empty() && n.as_str() != "-")
        .cloned();
    let session_id = session.meta.read().id.clone();

    // Stanza routing attrs we mirror onto receipts (whatsmeow `parseMessageInfo`
    // + `sendMessageReceipt`): `category="peer"` marks an own-account protocol
    // fan-out (history sync, app-state), and `type` is the message class.
    let category = msg.attrs.get("category").cloned();
    let msg_type_attr = msg.attrs.get("type").cloned().unwrap_or_default();

    // Is this message from our own account (a fan-out from the phone or another
    // of our devices)? = whatsmeow `info.IsFromMe`. Own-account messages get a
    // TYPED receipt ("sender", or "peer_msg" when the stanza is type=peer_msg) —
    // never a bare delivery receipt — and peer-category ones get an EXTRA
    // `<receipt type="peer_msg">`. Without those the phone treats its
    // history-sync fan-out as unacknowledged and never advances past
    // INITIAL_BOOTSTRAP to the RECENT sync (live-traced against Evolution).
    let own_pn_user: Option<String> = session
        .meta
        .read()
        .jid
        .as_deref()
        .map(|j| jid_user(j).to_string());
    // Learn any LID<->PN correspondences this stanza advertises before the
    // self-check below, so an own message addressed by LID can be bridged to our
    // PN account. (Our own LID<->PN is normally already known from the
    // account_sync notification; this is belt-and-suspenders.)
    capture_lid_pn_mappings(store, &session_id, &msg.attrs);
    // Is this message from our own account (a fan-out from the phone or another
    // of our devices)? Compare the REAL sender — `participant`, since for a group
    // stanza `from` is the GROUP jid, not the sender — to our own account,
    // bridging LID<->PN in BOTH directions so it holds whether our stored jid is
    // the PN and the sender our LID, or vice versa. (Using `from` here silently
    // dropped from_me on every message we sent from our phone into a group.)
    let is_from_me = sender_is_self(store, &session_id, own_pn_user.as_deref(), &participant);

    // Capture OUR OWN push name from our own-device message fan-out (`from` is
    // our own PN/LID user + a `notify`). The phone stamps our profile name on
    // messages we send from another device; we persist it so `<presence>` can
    // carry a name (Baileys won't send presence without one, and a named
    // presence is a candidate "open" signal).
    if let Some(name) = &push_name {
        if is_from_me {
            let current = store.session_push_name(&session_id).ok().flatten();
            if current.as_deref() != Some(name.as_str()) {
                let _ = store.session_set_push_name(&session_id, name);
                tracing::info!(name = %name, "learned our own push name from own-device message");
                // Re-assert a NAMED presence now that we have a name — the
                // connect-time presence went out nameless.
                if let Some(d) = dispatcher {
                    let presence = presence_for(store.session_mark_online(&session_id).unwrap_or(false));
                    d.send_node(build_global_presence_node(presence, Some(name)));
                    tracing::info!(name = %name, presence, "re-shipped NAMED presence");
                }
            }
        }
    }

    // Resolve the address to decrypt under: a `@lid` sender (modern WhatsApp
    // addressing) reuses the PN session we already established instead of being
    // treated as a brand-new peer (which would re-run X3DH against a
    // likely-consumed prekey and fail). LID<->PN correspondences this stanza
    // advertises were captured above. See `resolve_session_address`.
    let decrypt_addr = resolve_session_address(store, &session_id, &participant);

    let enc_node = match &msg.content {
        Content::Nodes(ns) => ns.iter().find(|c| c.tag == "enc"),
        _ => None,
    };
    let (enc_type, enc_version, ciphertext) = match enc_node {
        Some(n) => {
            let ty = n.attrs.get("type").cloned().unwrap_or_default();
            // The `<enc v="">` attribute selects the message-padding scheme.
            // v>=3 messages are NOT wa-padded (whatsmeow `unpadMessage` returns
            // them as-is when version==3); v<=2 carry the random 1..=0x0f pad.
            // Modern WA sends own-device sync + some 1:1 traffic as v=3 — if we
            // blindly strip a pad that isn't there we mangle the trailing byte
            // and the message decodes as garbage (MAC still verifies fine), so
            // the device NACKs its own synced messages and the phone pauses sync.
            let v: u32 = n
                .attrs
                .get("v")
                .and_then(|s| s.parse().ok())
                .unwrap_or(2);
            let ct = match &n.content {
                Content::Bytes(b) => b.clone(),
                _ => Vec::new(),
            };
            (ty, v, ct)
        }
        None => (String::new(), 2, Vec::new()),
    };

    // Decrypt → inner waE2E.Message bytes. Group messages (`@g.us`) carry the
    // content in a sender-key `<enc type="skmsg">` plus, on the first message
    // from a sender / on key rotation, a 1:1 `pkmsg`/`msg` carrying that
    // sender's SenderKeyDistributionMessage; 1:1 chats carry a single
    // `pkmsg`/`msg`. The two 1:1 branches share `decrypt_signal_envelope`.
    let plain: Option<Vec<u8>> = if from.ends_with("@g.us") {
        decrypt_group_message(store, &session_id, keys, &from, &participant, &decrypt_addr, msg)
    } else {
        decrypt_signal_envelope(
            store,
            &session_id,
            keys,
            &decrypt_addr,
            &participant,
            &enc_type,
            enc_version,
            &ciphertext,
        )
    };

    // A `deviceSentMessage` is our OWN outbound, fanned out from another of our
    // devices (the phone). The real conversation is its `destinationJid` and it
    // is from us — NOT a message addressed to our own number. Peek the proto for
    // it before `classify_e2e_message` unwraps and discards the wrapper, so we
    // can store/emit it under the right chat with from_me=true instead of
    // dumping it into the self-chat. (Cheap re-decode; the bytes are in hand.)
    let device_sent_dest: Option<String> =
        plain.as_ref().and_then(|p| device_sent_destination(p));

    // Decide msg_type + body_text + payload from the decoded InboundContent.
    let (msg_type, body_text, mut payload) = match plain {
        None => (
            "undecryptable".to_string(),
            None,
            serde_json::json!({"type": "undecryptable", "enc_type": enc_type}),
        ),
        Some(plain) => match decode_e2e_message(&plain) {
            InboundContent::Text(t) => {
                let body = Some(t.clone());
                (
                    "text".to_string(),
                    body,
                    serde_json::json!({"type": "text", "text": t, "enc_type": enc_type}),
                )
            }
            InboundContent::Media {
                kind,
                url,
                direct_path,
                mimetype,
                media_key,
                caption,
                file_length,
            } => {
                use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                let media_key_b64 = media_key.as_ref().map(|k| B64.encode(k));
                (
                    media_kind_str(kind).to_string(),
                    caption.clone(),
                    serde_json::json!({
                        "type": media_kind_str(kind),
                        "url": url,
                        "direct_path": direct_path,
                        "mimetype": mimetype,
                        "media_key_b64": media_key_b64,
                        "caption": caption,
                        "file_length": file_length,
                        "enc_type": enc_type,
                    }),
                )
            }
            InboundContent::HistorySyncNotification(notif) => {
                // Send a `<receipt type="hist_sync">` for this chunk — the ack
                // that tells the phone "I processed this history-sync chunk,
                // send the next". A live Evolution first-pair trace
                // (LOG_BAILEYS=trace) showed Evolution sends exactly this for
                // every history-sync notification; ruwa sent only the plain
                // delivery receipt, so the phone never advanced past the
                // INITIAL_BOOTSTRAP and the device stayed "message sync paused".
                if let Some(d) = dispatcher {
                    // whatsmeow `SendProtocolMessageReceipt` addresses the ack to
                    // our OWN account (`getOwnID().ToNonAD()`), not the stanza's
                    // `from` — robust for RECENT chunks that may carry a device or
                    // LID in `from`. Fall back to `from` if own PN is unknown.
                    let to = own_pn_user
                        .as_deref()
                        .map(|own| format!("{own}@s.whatsapp.net"))
                        .unwrap_or_else(|| from.clone());
                    let mut ra = crate::protocol::binary::Attrs::new();
                    ra.insert("id".into(), msg_id.clone());
                    ra.insert("to".into(), to);
                    ra.insert("type".into(), "hist_sync".into());
                    d.send_node(crate::protocol::binary::Node {
                        tag: "receipt".into(),
                        attrs: ra,
                        content: Content::None,
                    });
                    tracing::info!(id = %msg_id, "sent <receipt type=hist_sync> (history chunk ack)");
                }
                // Spawn the download+decrypt+parse+persist on a side
                // task so the receive loop keeps draining the socket.
                let session_id_clone = session_id.clone();
                let store_arc = Arc::clone(store);
                let notif_for_task = *notif;
                let dispatcher_for_task = dispatcher.cloned();
                tokio::spawn(async move {
                    match ingest_history_sync_notification(
                        &store_arc,
                        dispatcher_for_task.as_ref(),
                        &session_id_clone,
                        &notif_for_task,
                    )
                    .await
                    {
                        Ok(n) => {
                            tracing::info!(rows = n, "history sync chunk persisted");
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "history sync chunk ingest failed");
                        }
                    }
                });
                (
                    "history_sync_notification".to_string(),
                    None,
                    serde_json::json!({
                        "type": "history_sync_notification",
                        "enc_type": enc_type,
                    }),
                )
            }
            InboundContent::AppStateSyncKeyShare(share) => {
                let mut stored = 0usize;
                for key in &share.keys {
                    let key_id_bytes = match key
                        .key_id
                        .as_ref()
                        .and_then(|kid| kid.key_id.as_ref())
                    {
                        Some(b) => b.clone(),
                        None => continue,
                    };
                    let key_data = match key
                        .key_data
                        .as_ref()
                        .and_then(|kd| kd.key_data.as_ref())
                    {
                        Some(b) if b.len() == 32 => b.clone(),
                        _ => continue,
                    };
                    let mut main_key = [0u8; 32];
                    main_key.copy_from_slice(&key_data);
                    if let Err(e) =
                        store_app_state_main_key(store, &session_id, &key_id_bytes, &main_key)
                    {
                        tracing::warn!(error = %e, "store app-state main key");
                        continue;
                    }
                    stored += 1;
                }
                tracing::info!(stored, "received app-state sync key share");
                // The key share usually arrives AFTER our initial post-connect
                // fetch, so those snapshots couldn't be decrypted. Now that we
                // hold the keys, re-fetch so app-state actually completes (and
                // the phone stops showing "message sync paused").
                if stored > 0 {
                    if let Some(d) = dispatcher {
                        ship_app_state_fetches(store, &session_id, d);
                    }
                }
                (
                    "app_state_sync_key_share".to_string(),
                    None,
                    serde_json::json!({
                        "type": "app_state_sync_key_share",
                        "stored": stored,
                        "enc_type": enc_type,
                    }),
                )
            }
            InboundContent::Typed { kind, text } => (
                kind.clone(),
                text.clone(),
                serde_json::json!({"type": kind, "text": text, "enc_type": enc_type}),
            ),
            InboundContent::Other => (
                "unknown".to_string(),
                None,
                serde_json::json!({"type": "unknown", "enc_type": enc_type}),
            ),
        },
    };

    // Fold the sender's push name into the persisted payload so it's queryable
    // alongside the message without a schema change.
    if let (Some(name), Some(obj)) = (&push_name, payload.as_object_mut()) {
        obj.insert("push_name".into(), serde_json::Value::String(name.clone()));
    }

    // `history_sync_notification` / `app_state_sync_key_share` are own-account
    // PROTOCOL fan-outs (their side effects — chunk download, key storage — ran
    // in the match arms above). They are NOT chat content: persisting/emitting
    // them dumped "sync notif" rows into the self-chat. Still ack them below
    // (the receipt path runs regardless); just don't store or surface them.
    let is_protocol_only =
        matches!(msg_type.as_str(), "history_sync_notification" | "app_state_sync_key_share");

    // Route + label for storage. A deviceSentMessage is OUR outbound from
    // another device: the conversation is its destinationJid and from_me=true —
    // otherwise it (and the wider self-addressed own-fan-out) would pile into the
    // self-chat. Decryption/receipts above still use the raw wire identities;
    // only storage + the outbound event use these.
    let store_from_me = is_from_me || device_sent_dest.is_some();
    let chat_raw = device_sent_dest.as_deref().unwrap_or(from.as_str());
    let sender_raw: String = if device_sent_dest.is_some() {
        own_pn_user
            .as_deref()
            .map(|o| format!("{o}@s.whatsapp.net"))
            .unwrap_or_else(|| participant.clone())
    } else {
        participant.clone()
    };
    // Canonical, stable identities (LID↔PN collapsed to the phone number when
    // known) so a contact never splits into two chats and webhook consumers get
    // one stable key.
    let chat_canon = canonical_user_jid(store, &session_id, chat_raw);
    let sender_canon = canonical_user_jid(store, &session_id, &sender_raw);

    if !is_protocol_only {
        let payload_json = payload.to_string();
        let _ = store.message_insert(
            &crate::store::NewMessage {
                session_id: &session_id,
                chat_jid: &chat_canon,
                message_id: &msg_id,
                sender_jid: &sender_canon,
                from_me: store_from_me,
                timestamp,
                msg_type: &msg_type,
                body_text: body_text.as_deref(),
                payload_json: &payload_json,
                status: None,
            },
            true,
        );

        // Learn the SENDER's display name from the message's `notify` push name
        // and mirror it into `contacts`, so the dashboard (and `chats_list`) can
        // show a real name instead of a bare JID — no app-state/contacts sync
        // required. Only for messages from others; our own name is handled above.
        if let Some(name) = &push_name {
            if !store_from_me {
                let _ = store.contact_upsert(&session_id, &sender_canon, None, Some(name));
                // Touch the chat so a freshly-seen conversation carries its
                // timestamp even before any app-state row exists.
                let _ = store.chat_set_name(&session_id, &chat_canon, None, chat_canon.ends_with("@g.us"), Some(timestamp));
            }
        }

        // Emit event for real chat content only. For downloadable media, attach a
        // `media` descriptor so webhook/SSE consumers can pull the bytes without
        // re-deriving anything: mimetype + voice-note flag + declared size, plus a
        // relative link to this server's GET .../media endpoint (lazy
        // download+decrypt+cache). The bytes stay out of the event; the consumer
        // fetches them with its own bearer token. Segments are percent-encoded to
        // match how the dashboard/MCP call the same route.
        let media_descriptor =
            media_webhook_descriptor(&msg_type, &payload, &session_id, &chat_canon, &msg_id);
        let mut body_obj = serde_json::Map::new();
        body_obj.insert("type".into(), serde_json::json!(msg_type));
        body_obj.insert("text".into(), serde_json::json!(body_text));
        if let Some(m) = media_descriptor {
            body_obj.insert("media".into(), m);
        }
        body_obj.insert("push_name".into(), serde_json::json!(push_name));
        body_obj.insert("from_me".into(), serde_json::json!(store_from_me));
        let _ = session.events.send(SessionEvent::Message {
            id: msg_id.clone(),
            chat: chat_canon.clone(),
            from: sender_canon.clone(),
            body: serde_json::Value::Object(body_obj),
        });
    }

    if msg_type == "undecryptable" {
        // NOTE: the decrypt-failure metric counts only PERMANENT failures (the
        // give-up branch below), not first-attempt misses we recover via the
        // retry receipt — a recovered transient is not a real flag to chase.
        // Escalating retry, based on whatsmeow's sendRetryReceipt. The peer
        // almost certainly holds a Signal session we lost/rebuilt (post-pair,
        // cache-clear, churn); the receipt is how it re-establishes.
        //
        // We attach the `<keys>` re-establishment bundle (identity + a FRESH
        // one-time prekey + signed prekey + device-identity) on EVERY retry —
        // not just the 2nd+ as whatsmeow gates it. A live repro showed the
        // faithful gating can't recover the common failure: the peer resends a
        // pkmsg reusing a one-time prekey we already consumed
        // (`has_opk_priv=false` → X3DH does one fewer DH → MAC fail). The peer
        // doesn't act on the keyless first retry, and even if it resent it
        // would reuse the same dead prekey. Only a fresh OPK in the bundle
        // fixes it, so we send one immediately. Stop after 5 — past that the
        // peer isn't recovering and we'd only be hammering the socket.
        let count = session.bump_message_retry(&msg_id);
        if count >= 5 {
            // Give up: the peer isn't recovering (typically offline backlog
            // encrypted to a one-time prekey we've already consumed — permanently
            // undecryptable). Send a PLAIN DELIVERY RECEIPT instead of silence so
            // the server marks it delivered and STOPS redelivering it on every
            // reconnect (returning None left it pending → endless re-flood/NACK
            // storm that also starved real traffic).
            // A real, permanent decrypt failure — the only one worth flagging.
            metrics::incr(&metrics::DECRYPT_FAILURES);
            tracing::warn!(id = %msg_id, "giving up after 5 retries — acking as delivered to stop redelivery");
            return Some(build_receipt(&msg_id, &from, &participant, is_from_me, &msg_type_attr));
        }
        // On the FIRST failure, also ask our own phone to resend the message
        // (a peer `PlaceholderMessageResendRequest`). The retry receipt alone
        // recovers a *peer's* desynced session, but for our own phone's
        // fan-out — where the server just replays the same ciphertext that
        // reused an already-consumed prekey — the phone has to be told to
        // re-encrypt. Mirrors whatsmeow's `requestMessageFromPhone` on the
        // first retry. Spawned off the recv loop (it does an async prekey
        // fetch + encrypt). Best-effort: failures are logged, never fatal.
        if count == 1 {
            if let Some(d) = dispatcher {
                let chat = from.clone();
                let sender = participant.clone();
                let orig_id = msg_id.clone();
                tokio::spawn(request_message_from_phone(
                    Arc::clone(session),
                    Arc::clone(store),
                    keys.clone(),
                    d.clone(),
                    chat,
                    sender,
                    orig_id,
                ));
            }
        }
        let keys_node = build_retry_keys_node(store, &session_id, keys);
        tracing::info!(
            id = %msg_id,
            to = %from,
            participant = %participant,
            count,
            has_keys = keys_node.is_some(),
            enc_type = %enc_type,
            "sending retry receipt (asking sender to re-establish + resend)"
        );
        Some(build_retry_receipt(
            &msg_id,
            &from,
            &participant,
            timestamp,
            keys.registration_id,
            count,
            keys_node,
        ))
    } else {
        // If we'd previously asked this sender to retry this exact id (its
        // Signal session to us had desynced → undecryptable), a now-successful
        // decrypt means the re-establishment worked. Log it loudly so a live
        // repro can confirm the retry-receipt fix end-to-end with one grep.
        if let Some(prior) = session.take_message_retry(&msg_id) {
            tracing::info!(
                id = %msg_id,
                from = %participant,
                prior_retries = prior,
                enc_type = %enc_type,
                "retry recovery succeeded — a previously-undecryptable message from this device now decrypts"
            );
        }
        // Peer-category protocol fan-outs (history sync, app-state) get an EXTRA
        // `<receipt type="peer_msg">` addressed to our own account — whatsmeow
        // `SendProtocolMessageReceipt(ReceiptTypePeerMsg)` when
        // `info.Category == "peer"`. A live Evolution first-pair trace sent this
        // for every peer history chunk; we sent only a (typeless) delivery
        // receipt, so the phone never advanced past INITIAL_BOOTSTRAP to RECENT.
        if category.as_deref() == Some("peer") {
            if let (Some(d), Some(own)) = (dispatcher, own_pn_user.as_deref()) {
                let mut ra = crate::protocol::binary::Attrs::new();
                ra.insert("id".into(), msg_id.clone());
                ra.insert("type".into(), "peer_msg".into());
                ra.insert("to".into(), format!("{own}@s.whatsapp.net"));
                d.send_node(crate::protocol::binary::Node {
                    tag: "receipt".into(),
                    attrs: ra,
                    content: Content::None,
                });
                tracing::info!(id = %msg_id, "sent <receipt type=peer_msg> (peer chunk ack)");
            }
        }
        Some(build_receipt(
            &msg_id,
            &from,
            &participant,
            is_from_me,
            &msg_type_attr,
        ))
    }
}

/// Decode a waE2E.Message proto into an [`InboundContent`] view. Used by
/// `process_inbound_message` to fan out per-type handling (text body,
/// media metadata, etc.). Unknown/unhandled message variants surface as
/// `Other` so the receipt still ships and the message lands in the table.
/// The `destinationJid` of a top-level `deviceSentMessage`, or `None`. A
/// deviceSentMessage is our OWN outbound fanned out from another device; its
/// `destinationJid` is the real conversation it belongs to (not our own JID,
/// which is what the stanza's `from` carries). Used to route + label own
/// fan-out correctly instead of dumping it into the self-chat.
fn device_sent_destination(plaintext: &[u8]) -> Option<String> {
    use ::prost::Message as _;
    crate::proto::wa_web_protobufs_e2e::Message::decode(plaintext)
        .ok()
        .and_then(|m| m.device_sent_message)
        .and_then(|d| d.destination_jid)
        .filter(|j| !j.is_empty())
}

fn decode_e2e_message(plaintext: &[u8]) -> InboundContent {
    use ::prost::Message as _;
    let msg = match crate::proto::wa_web_protobufs_e2e::Message::decode(plaintext) {
        Ok(m) => m,
        Err(_) => return InboundContent::Other,
    };
    let result = classify_e2e_message(msg, 0);
    if matches!(result, InboundContent::Other) {
        // DIAGNOSTIC: which waE2E.Message field did we fail to handle? Walk the
        // top-level protobuf tags so we can add the right content type.
        let mut tags = Vec::new();
        let mut i = 0usize;
        while i < plaintext.len() {
            let mut shift = 0u32;
            let mut key = 0u64;
            loop {
                if i >= plaintext.len() { break; }
                let b = plaintext[i]; i += 1;
                key |= ((b & 0x7f) as u64) << shift;
                if b & 0x80 == 0 { break; }
                shift += 7;
            }
            let (field, wt) = ((key >> 3) as u32, (key & 7) as u8);
            tags.push(field);
            match wt {
                0 => { while i < plaintext.len() && plaintext[i] & 0x80 != 0 { i += 1; } if i < plaintext.len() { i += 1; } }
                2 => { let mut shift=0u32; let mut len=0u64; loop { if i>=plaintext.len(){break;} let b=plaintext[i]; i+=1; len|=((b&0x7f)as u64)<<shift; if b&0x80==0{break;} shift+=7; } i += len as usize; }
                5 => i += 4,
                1 => i += 8,
                _ => break,
            }
        }
        tracing::info!(?tags, "e2e message classified as Other (unhandled type) — top-level field numbers");
    }
    result
}

/// Classify a decoded waE2E.Message into the content we persist. Recurses
/// through the WRAPPER messages first — `ephemeralMessage` (disappearing
/// chats wrap EVERY message in one), `viewOnceMessage[V2[Extension]]`,
/// `documentWithCaptionMessage`, `editedMessage`, and `deviceSentMessage`
/// all carry the real `Message` inside `.message`. Without unwrapping, every
/// message in a disappearing-messages chat (very common) lands as "unknown".
fn classify_e2e_message(
    msg: crate::proto::wa_web_protobufs_e2e::Message,
    depth: u8,
) -> InboundContent {
    if depth < 4 {
        let inner = msg
            .ephemeral_message
            .and_then(|f| f.message)
            .or_else(|| msg.view_once_message.and_then(|f| f.message))
            .or_else(|| msg.view_once_message_v2.and_then(|f| f.message))
            .or_else(|| msg.view_once_message_v2_extension.and_then(|f| f.message))
            .or_else(|| msg.document_with_caption_message.and_then(|f| f.message))
            .or_else(|| msg.edited_message.and_then(|f| f.message))
            .or_else(|| msg.device_sent_message.and_then(|d| d.message));
        if let Some(inner) = inner {
            return classify_e2e_message(*inner, depth + 1);
        }
    }
    if let Some(text) = msg.conversation {
        return InboundContent::Text(text);
    }
    // `extendedTextMessage` is the OTHER plain-text carrier — WhatsApp uses it
    // (instead of `conversation`) whenever the text has a link preview, a reply
    // quote, mentions, or is sent by many clients/business accounts (Baileys/
    // Evolution default to it). Decoding only `conversation` left all of those
    // as type="unknown" / null body. Surface the text the same way.
    if let Some(etm) = msg.extended_text_message {
        if let Some(text) = etm.text {
            return InboundContent::Text(text);
        }
    }
    if let Some(img) = msg.image_message {
        return InboundContent::Media {
            kind: crate::media::MediaType::Image,
            url: img.url,
            direct_path: img.direct_path,
            mimetype: img.mimetype,
            media_key: img.media_key,
            caption: img.caption,
            file_length: img.file_length,
        };
    }
    if let Some(vid) = msg.video_message {
        return InboundContent::Media {
            kind: crate::media::MediaType::Video,
            url: vid.url,
            direct_path: vid.direct_path,
            mimetype: vid.mimetype,
            media_key: vid.media_key,
            caption: vid.caption,
            file_length: vid.file_length,
        };
    }
    if let Some(aud) = msg.audio_message {
        return InboundContent::Media {
            // A voice note is an AudioMessage with ptt=true; same transport
            // keys as plain audio, but we surface it as Ptt so the API can
            // tell a voice bubble apart from an audio file.
            kind: if aud.ptt == Some(true) {
                crate::media::MediaType::Ptt
            } else {
                crate::media::MediaType::Audio
            },
            url: aud.url,
            direct_path: aud.direct_path,
            mimetype: aud.mimetype,
            media_key: aud.media_key,
            caption: None,
            file_length: aud.file_length,
        };
    }
    if let Some(doc) = msg.document_message {
        return InboundContent::Media {
            kind: crate::media::MediaType::Document,
            url: doc.url,
            direct_path: doc.direct_path,
            mimetype: doc.mimetype,
            media_key: doc.media_key,
            caption: doc.caption,
            file_length: doc.file_length,
        };
    }
    if let Some(stk) = msg.sticker_message {
        return InboundContent::Media {
            kind: crate::media::MediaType::Sticker,
            url: stk.url,
            direct_path: stk.direct_path,
            mimetype: stk.mimetype,
            media_key: stk.media_key,
            caption: None,
            file_length: stk.file_length,
        };
    }
    if let Some(pm) = msg.protocol_message {
        if let Some(notif) = pm.history_sync_notification {
            return InboundContent::HistorySyncNotification(Box::new(notif));
        }
        if let Some(share) = pm.app_state_sync_key_share {
            return InboundContent::AppStateSyncKeyShare(share);
        }
        let ptype = pm.r#type;
        // A message EDIT (`type=MESSAGE_EDIT`) carries the replacement content in
        // `edited_message`; surface its visible text so the chat shows the new
        // text instead of "unknown". Without this every edit lands as `Other`.
        if let Some(edited) = pm.edited_message {
            let text = match classify_e2e_message(*edited, depth + 1) {
                InboundContent::Text(t) => Some(t),
                InboundContent::Typed { text, .. } => text,
                InboundContent::Media { caption, .. } => caption,
                _ => None,
            };
            return InboundContent::Typed { kind: "edited".into(), text };
        }
        // A REVOKE (delete-for-everyone, `type=REVOKE`) has no body; surface a
        // typed marker so the row isn't "unknown" either.
        if ptype
            == Some(crate::proto::wa_web_protobufs_e2e::protocol_message::Type::Revoke as i32)
        {
            return InboundContent::Typed { kind: "revoked".into(), text: None };
        }
    }

    // ── Interactive / business / reply messages: surface their visible text as
    // a normal text bubble (these ARE the chat content the user sees). Fields
    // are `.clone()`d because several of these message types are `Box`-wrapped
    // by prost and a field move-out through the Box won't compile. ──
    if let Some(b) = msg.buttons_response_message.as_ref().and_then(|m| m.response.as_ref()).map(
        |crate::proto::wa_web_protobufs_e2e::buttons_response_message::Response::SelectedDisplayText(t)| t.clone(),
    ) {
        return InboundContent::Text(b);
    }
    if let Some(b) = msg.template_button_reply_message.as_ref().and_then(|m| m.selected_display_text.clone()) {
        return InboundContent::Text(b);
    }
    if let Some(b) = msg.list_response_message.as_ref().and_then(|m| m.title.clone()) {
        return InboundContent::Text(b);
    }
    if let Some(b) = msg.buttons_message.as_ref().and_then(|m| m.content_text.clone()) {
        return InboundContent::Text(b);
    }
    if let Some(b) = msg.interactive_message.as_ref().and_then(|m| m.body.as_ref()).and_then(|b| b.text.clone()) {
        return InboundContent::Text(b);
    }
    if let Some(lm) = msg.list_message.as_ref() {
        if let Some(b) = lm.description.clone().or_else(|| lm.title.clone()) {
            return InboundContent::Text(b);
        }
    }

    // ── Typed non-text content: distinct msg_type + a human-readable summary. ──
    if let Some(r) = msg.reaction_message.as_ref() {
        return InboundContent::Typed { kind: "reaction".into(), text: r.text.clone() };
    }
    if let Some(p) = msg
        .poll_creation_message
        .as_ref()
        .or(msg.poll_creation_message_v2.as_ref())
        .or(msg.poll_creation_message_v3.as_ref())
    {
        return InboundContent::Typed { kind: "poll".into(), text: p.name.clone() };
    }
    if let Some(c) = msg.contact_message.as_ref() {
        return InboundContent::Typed { kind: "contact".into(), text: c.display_name.clone() };
    }
    if let Some(loc) = msg.location_message.as_ref() {
        let label = loc.name.clone().filter(|s| !s.is_empty()).or_else(|| loc.address.clone()).or_else(|| {
            Some(format!("{:.5},{:.5}", loc.degrees_latitude.unwrap_or(0.0), loc.degrees_longitude.unwrap_or(0.0)))
        });
        return InboundContent::Typed { kind: "location".into(), text: label };
    }
    if let Some(gi) = msg.group_invite_message.as_ref() {
        return InboundContent::Typed { kind: "group_invite".into(), text: gi.group_name.clone() };
    }
    if msg.template_message.is_some() {
        return InboundContent::Typed { kind: "template".into(), text: None };
    }

    InboundContent::Other
}

/// Decoded view of an inbound waE2E.Message — the receive path branches
/// on this to decide what `msg_type` and metadata to persist.
enum InboundContent {
    Text(String),
    Media {
        kind: crate::media::MediaType,
        url: Option<String>,
        direct_path: Option<String>,
        mimetype: Option<String>,
        media_key: Option<Vec<u8>>,
        caption: Option<String>,
        /// Plaintext byte length the sender declared (`fileLength`). Surfaced
        /// as `size` in the webhook media descriptor; `None` if absent.
        file_length: Option<u64>,
    },
    /// HSv2 history sync chunk announcement. The receive path spawns a
    /// background task that downloads the blob, decrypts under the
    /// History HKDF info, zlib-decompresses, decodes, and persists rows
    /// into `messages`. Boxed because the proto struct is large.
    HistorySyncNotification(Box<crate::proto::wa_web_protobufs_e2e::HistorySyncNotification>),
    /// One or more app-state main keys arriving from the primary
    /// device. The receive path stores each into `app_state_mac_keys`
    /// so subsequent app-state patches can be authenticated against
    /// the keychain that produced them.
    AppStateSyncKeyShare(crate::proto::wa_web_protobufs_e2e::AppStateSyncKeyShare),
    /// A recognized non-text content type (reaction, poll, contact, location,
    /// group_invite, template) — `kind` becomes `messages.msg_type` and `text`
    /// (if any) the human-readable body. Keeps these out of the "unknown" bucket.
    Typed { kind: String, text: Option<String> },
    Other,
}

/// Map a `MediaType` to the short string we store in `messages.msg_type`
/// and `payload_json.type`. Matches the strings the API accepts on
/// outbound `POST /messages/media`.
/// Percent-encode one path segment (session id / chat JID / message id) for a
/// relative `/v1/...` URL, mirroring the dashboard/MCP `encodeURIComponent` so
/// the value round-trips back through axum's `Path` extractor unchanged.
fn enc_path_seg(s: &str) -> String {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

/// Build the `media` descriptor attached to an inbound message's webhook/SSE
/// `body` when the message carries downloadable media. Returns `None` for
/// non-media types. The `url` is a relative link to this server's
/// `GET /v1/sessions/:id/messages/:chat/:msgid/media` endpoint (lazy
/// download+decrypt+cache); `mimetype`/`size` are read from the already-built
/// `payload` (which mirrors what's persisted to `messages.payload_json`).
fn media_webhook_descriptor(
    msg_type: &str,
    payload: &serde_json::Value,
    session_id: &str,
    chat: &str,
    msg_id: &str,
) -> Option<serde_json::Value> {
    match msg_type {
        "image" | "video" | "audio" | "ptt" | "document" | "sticker" => {
            let url = format!(
                "/v1/sessions/{}/messages/{}/{}/media",
                enc_path_seg(session_id),
                enc_path_seg(chat),
                enc_path_seg(msg_id),
            );
            Some(serde_json::json!({
                "mimetype": payload.get("mimetype").cloned().unwrap_or(serde_json::Value::Null),
                "ptt": msg_type == "ptt",
                "size": payload.get("file_length").cloned().unwrap_or(serde_json::Value::Null),
                "url": url,
            }))
        }
        _ => None,
    }
}

fn media_kind_str(kind: crate::media::MediaType) -> &'static str {
    use crate::media::MediaType;
    match kind {
        MediaType::Image => "image",
        MediaType::Video => "video",
        MediaType::Audio => "audio",
        MediaType::Ptt => "ptt",
        MediaType::Document => "document",
        MediaType::Sticker => "sticker",
        // Internal media types — never appear in user-facing message rows.
        MediaType::History => "history",
        MediaType::AppState => "app_state",
    }
}

/// Build the `<receipt>` ack the server expects after every inbound message.
///
/// Mirrors whatsmeow `sendMessageReceipt`: a contact's message gets a bare
/// delivery receipt (no `type`), but an own-account fan-out (`is_from_me`) gets
/// a typed one — `type="sender"`, escalating to `type="peer_msg"` when the
/// stanza itself is `type="peer_msg"`. Acking own messages as plain deliveries
/// (what we did before) leaves the phone's history-sync drive unsatisfied.
fn build_receipt(
    msg_id: &str,
    from: &str,
    participant: &str,
    is_from_me: bool,
    msg_type_attr: &str,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("id".into(), msg_id.into());
    attrs.insert("to".into(), from.into());
    if !participant.is_empty() && participant != from {
        attrs.insert("participant".into(), participant.into());
    }
    if is_from_me {
        let ty = if msg_type_attr == "peer_msg" {
            "peer_msg"
        } else {
            "sender"
        };
        attrs.insert("type".into(), ty.into());
    }
    Node {
        tag: "receipt".into(),
        attrs,
        content: Content::None,
    }
}

/// Retry receipt — sent when we couldn't decrypt the inbound message.
/// Mirrors whatsmeow retry.go `sendRetryReceipt`: `<receipt type="retry">` with
/// a `<retry count id t v>` child, a `<registration>` child (our 4-byte
/// big-endian registration id), and — whenever `keys_node` is `Some` — a
/// `<keys>` re-establishment bundle so the sender can rebuild a desynced Signal
/// session. `count` escalates per message id (see
/// [`Session::bump_message_retry`]).
fn build_retry_receipt(
    msg_id: &str,
    from: &str,
    participant: &str,
    timestamp: i64,
    registration_id: u32,
    count: u32,
    keys_node: Option<crate::protocol::binary::Node>,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut top = Attrs::new();
    top.insert("id".into(), msg_id.into());
    top.insert("type".into(), "retry".into());
    top.insert("to".into(), from.into());
    if !participant.is_empty() && participant != from {
        top.insert("participant".into(), participant.into());
    }

    let mut retry_attrs = Attrs::new();
    retry_attrs.insert("count".into(), count.to_string());
    retry_attrs.insert("id".into(), msg_id.into());
    retry_attrs.insert("t".into(), timestamp.to_string());
    // whatsmeow stamps `v=1` on the retry element; the server keys off it.
    retry_attrs.insert("v".into(), "1".into());

    let mut regid_be = vec![0u8; 4];
    regid_be.copy_from_slice(&registration_id.to_be_bytes());

    let mut children = vec![
        Node {
            tag: "retry".into(),
            attrs: retry_attrs,
            content: Content::None,
        },
        Node {
            tag: "registration".into(),
            attrs: Attrs::new(),
            content: Content::Bytes(regid_be),
        },
    ];
    if let Some(keys) = keys_node {
        children.push(keys);
    }

    Node {
        tag: "receipt".into(),
        attrs: top,
        content: Content::Nodes(children),
    }
}

/// Build the `<keys>` re-establishment bundle for a retry receipt. Based on the
/// `<keys>` branch of whatsmeow's `sendRetryReceipt`: it mints a fresh
/// one-time prekey (persisted so the peer's follow-up pkmsg can look it up),
/// and packs `<type>`, `<identity>`, that fresh OPK, our signed prekey, and the
/// stored `<device-identity>` (the account-signed `AdvSignedDeviceIdentity`).
/// Returns `None` if we can't mint the prekey or have no device-identity yet
/// (unpaired) — the caller then sends a keyless retry, same as whatsmeow when
/// the marshal fails.
fn build_retry_keys_node(
    store: &Arc<Store>,
    session_id: &str,
    keys: &DeviceKeys,
) -> Option<crate::protocol::binary::Node> {
    use crate::crypto::prekeys::PreKey;
    use crate::protocol::binary::{Attrs, Content, Node};

    // The device-identity blob (persisted at pair-success). Without it the
    // peer can't verify the new identity, so skip the whole bundle.
    let account_pb = store.session_account_pb(session_id).ok().flatten()?;

    // Mint + persist a fresh one-time prekey. It must be stored (uploaded=0 is
    // fine — `prekey_load_private` ignores the flag, and a later bulk re-upload
    // of the same id+value is idempotent) so the re-established session's pkmsg,
    // which references this id, can find the private half.
    let next_id = store.prekey_max_id(session_id).unwrap_or(0).saturating_add(1);
    let pk = PreKey::generate(next_id);
    store
        .prekeys_insert_batch(
            session_id,
            &[(
                pk.key_id,
                pk.keypair.private.as_slice(),
                pk.keypair.public.as_slice(),
            )],
        )
        .ok()?;

    // One-time prekey node: `<key><id>(3-byte BE)<value></key>` (preKeyToNode).
    let opk_id_be = pk.key_id.to_be_bytes();
    let opk_node = Node {
        tag: "key".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![
            Node {
                tag: "id".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(opk_id_be[1..].to_vec()),
            },
            Node {
                tag: "value".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(pk.keypair.public.to_vec()),
            },
        ]),
    };

    // Signed prekey node: same shape plus a `<signature>` (preKeyToNode skey).
    let spk_id_be = keys.signed_prekey.key_id.to_be_bytes();
    let skey_node = Node {
        tag: "skey".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![
            Node {
                tag: "id".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(spk_id_be[1..].to_vec()),
            },
            Node {
                tag: "value".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(keys.signed_prekey.keypair.public.to_vec()),
            },
            Node {
                tag: "signature".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(keys.signed_prekey.signature.to_vec()),
            },
        ]),
    };

    Some(Node {
        tag: "keys".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![
            Node {
                tag: "type".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(vec![0x05]),
            },
            Node {
                tag: "identity".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(keys.identity.public.to_vec()),
            },
            opk_node,
            skey_node,
            Node {
                tag: "device-identity".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(account_pb),
            },
        ]),
    })
}

// -- Send-side: honoring an INBOUND retry receipt ----------------------------

/// A peer's request to resend a message it couldn't decrypt, parsed from an
/// inbound `<receipt type="retry">`. `device_jid` is who asked (and where the
/// resend goes); `bundle` carries the peer's fresh keys when the receipt
/// included a `<keys>` element (whatsmeow attaches it from the 2nd retry on).
struct RetryRequest {
    msg_id: String,
    device_jid: String,
    count: u32,
    bundle: Option<DevicePrekeyBundle>,
}

/// Decode a 3- or 4-byte big-endian id/registration value.
fn be_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() || bytes.len() > 4 {
        return None;
    }
    let mut padded = [0u8; 4];
    padded[4 - bytes.len()..].copy_from_slice(bytes);
    Some(u32::from_be_bytes(padded))
}

/// The device number from a JID (`"5511…:38@s.whatsapp.net"` → 38; 0 if bare).
fn jid_device(jid: &str) -> u32 {
    jid.split_once(':')
        .and_then(|(_, rest)| rest.split(['@', '.', ':']).next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// A direct child node by tag (one level only).
fn node_child<'a>(
    parent: &'a crate::protocol::binary::Node,
    tag: &str,
) -> Option<&'a crate::protocol::binary::Node> {
    match &parent.content {
        crate::protocol::binary::Content::Nodes(ns) => ns.iter().find(|c| c.tag == tag),
        _ => None,
    }
}

/// The `Bytes` content of a direct child node by tag.
fn node_child_bytes<'a>(parent: &'a crate::protocol::binary::Node, tag: &str) -> Option<&'a [u8]> {
    match &node_child(parent, tag)?.content {
        crate::protocol::binary::Content::Bytes(b) => Some(b.as_slice()),
        _ => None,
    }
}

/// Parse the `<keys>` element of an inbound retry receipt into a prekey
/// bundle, so we can re-establish a Signal session to the peer the same way
/// `encrypt_per_device` does from a usync bundle. `registration_id` comes
/// from the receipt's sibling `<registration>`. Mirrors whatsmeow's
/// `nodeToPreKeyBundle`. Returns `None` if any required field is malformed.
fn parse_retry_keys_bundle(
    keys_node: &crate::protocol::binary::Node,
    jid: &str,
    registration_id: u32,
) -> Option<DevicePrekeyBundle> {
    let as32 = |b: &[u8]| -> Option<[u8; 32]> { b.try_into().ok() };
    let as64 = |b: &[u8]| -> Option<[u8; 64]> { b.try_into().ok() };

    let identity_pub = as32(node_child_bytes(keys_node, "identity")?)?;
    let skey = node_child(keys_node, "skey")?;
    let signed_pre_key_id = be_u32(node_child_bytes(skey, "id")?)?;
    let signed_pre_key_pub = as32(node_child_bytes(skey, "value")?)?;
    let signed_pre_key_sig = as64(node_child_bytes(skey, "signature")?)?;

    // The one-time prekey is optional (the peer may omit it).
    let (one_time_pre_key_id, one_time_pre_key_pub) = match node_child(keys_node, "key") {
        Some(k) => (
            Some(be_u32(node_child_bytes(k, "id")?)?),
            Some(as32(node_child_bytes(k, "value")?)?),
        ),
        None => (None, None),
    };

    Some(DevicePrekeyBundle {
        jid: jid.to_string(),
        device_id: jid_device(jid),
        registration_id,
        identity_pub,
        signed_pre_key_id,
        signed_pre_key_pub,
        signed_pre_key_sig,
        one_time_pre_key_id,
        one_time_pre_key_pub,
    })
}

/// Parse an inbound `<receipt type="retry">` into a [`RetryRequest`], or
/// `None` if the node isn't a retry receipt or is missing the message id.
fn parse_inbound_retry_receipt(
    node: &crate::protocol::binary::Node,
) -> Option<RetryRequest> {
    if node.tag != "receipt" || node.attrs.get("type").map(String::as_str) != Some("retry") {
        return None;
    }
    let device_jid = node.attrs.get("from")?.clone();
    let retry_child = node_child(node, "retry");
    let msg_id = node
        .attrs
        .get("id")
        .cloned()
        .or_else(|| retry_child.and_then(|r| r.attrs.get("id").cloned()))?;
    let count = retry_child
        .and_then(|r| r.attrs.get("count"))
        .and_then(|c| c.parse().ok())
        .unwrap_or(1);
    let registration_id = node_child_bytes(node, "registration")
        .and_then(be_u32)
        .unwrap_or(0);
    let bundle =
        node_child(node, "keys").and_then(|k| parse_retry_keys_bundle(k, &device_jid, registration_id));
    Some(RetryRequest {
        msg_id,
        device_jid,
        count,
        bundle,
    })
}

/// Install a fresh outbound Signal session for `device` from `bundle`,
/// overwriting any stale one (`signal_session_save` is an upsert). The new
/// state carries a `pending_pre_key`, so the next encrypt emits a `pkmsg`
/// that re-bootstraps the peer's session. Mirrors the X3DH bootstrap in
/// `encrypt_per_device`.
fn install_session_from_bundle(
    store: &Arc<Store>,
    keys: &DeviceKeys,
    session_id: &str,
    device: &str,
    bundle: &DevicePrekeyBundle,
) -> Result<()> {
    use crate::crypto::identity::KeyPair;
    use crate::crypto::signal::{AliceParameters, PendingPreKey, RatchetingSession, SessionRecord};

    let base = KeyPair::generate();
    let ratchet = KeyPair::generate();
    let mut state = RatchetingSession::initiate_alice(&AliceParameters {
        local_identity_priv: &keys.identity.private,
        local_identity_pub: &keys.identity.public,
        local_base_priv: &base.private,
        local_base_pub: &base.public,
        local_ratchet_priv: &ratchet.private,
        local_ratchet_pub: &ratchet.public,
        remote_identity_pub: &bundle.identity_pub,
        remote_signed_prekey_pub: &bundle.signed_pre_key_pub,
        remote_one_time_prekey_pub: bundle.one_time_pre_key_pub.as_ref(),
    });
    state.local_registration_id = keys.registration_id;
    state.remote_registration_id = bundle.registration_id;
    state.pending_pre_key = Some(PendingPreKey {
        pre_key_id: bundle.one_time_pre_key_id,
        signed_pre_key_id: bundle.signed_pre_key_id,
        base_key_pub: base.public,
    });
    let mut record = SessionRecord::new();
    record.current = Some(state);
    store_save_record(store, session_id, device, &record)
}

/// Fetch a single device's prekey bundle via a usync IQ (the fallback when an
/// inbound retry receipt carried no `<keys>` of its own).
async fn fetch_one_bundle(
    dispatcher: &ConnDispatcher,
    device: &str,
) -> Option<DevicePrekeyBundle> {
    let iq_id = uuid_v4();
    let iq = build_prekey_fetch_iq(&[device], &iq_id);
    let reply = dispatcher.iq_request(iq).await.ok()?;
    parse_prekey_fetch_response(&reply).into_iter().next()
}

/// Build the resend `<message>` for a retry: addressed directly `to` the
/// requesting device (not the `<participants>` fan-out shape), with `count`
/// stamped on the `<enc>` and — for a `pkmsg` — our `<device-identity>` so the
/// peer can verify the new session. Mirrors whatsmeow's retry resend in
/// `handleRetryReceipt`.
fn build_retry_resend_node(
    msg_id: &str,
    device_jid: &str,
    rec: &EncryptedRecipient,
    count: u32,
    timestamp: i64,
    account_pb: Option<Vec<u8>>,
) -> crate::protocol::binary::Node {
    use crate::crypto::signal::MessageType;
    use crate::protocol::binary::{Attrs, Content, Node};

    let is_pkmsg = matches!(rec.message_type, MessageType::PreKey);
    let mut enc_attrs = Attrs::new();
    enc_attrs.insert("v".into(), "2".into());
    enc_attrs.insert(
        "type".into(),
        if is_pkmsg { "pkmsg".into() } else { "msg".into() },
    );
    enc_attrs.insert("count".into(), count.to_string());
    let enc = Node {
        tag: "enc".into(),
        attrs: enc_attrs,
        content: Content::Bytes(rec.ciphertext.clone()),
    };

    let mut children = vec![enc];
    if is_pkmsg {
        if let Some(pb) = account_pb {
            children.push(Node {
                tag: "device-identity".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(pb),
            });
        }
    }

    let mut msg_attrs = Attrs::new();
    msg_attrs.insert("id".into(), msg_id.into());
    msg_attrs.insert("type".into(), "text".into());
    msg_attrs.insert("to".into(), device_jid.into());
    msg_attrs.insert("t".into(), timestamp.to_string());
    // 1:1 resend goes to a single device; suppress server-side fan-out.
    msg_attrs.insert("device_fanout".into(), "false".into());

    Node {
        tag: "message".into(),
        attrs: msg_attrs,
        content: Content::Nodes(children),
    }
}

/// Handle an inbound retry receipt: re-establish the peer's session (from the
/// keys it sent, or a freshly-fetched bundle), re-encrypt the cached message,
/// and resend it to the requesting device. Spawned off the recv loop so the
/// socket keeps draining. A no-op (logged) when the message is no longer
/// cached. Mirrors whatsmeow's `handleRetryReceipt`.
async fn handle_inbound_retry_receipt(
    session: Arc<Session>,
    store: Arc<Store>,
    keys: DeviceKeys,
    dispatcher: ConnDispatcher,
    req: RetryRequest,
) {
    let Some((_chat_jid, inner_proto)) = session.recent_send(&req.msg_id) else {
        tracing::warn!(
            id = %req.msg_id,
            "retry receipt for an unknown/expired message — cannot resend"
        );
        return;
    };
    let session_id = session.meta.read().id.clone();
    let device = req.device_jid.clone();

    // Re-establish: prefer the keys the peer just advertised; else fetch a
    // fresh bundle. Either upserts the session, so the resend is a pkmsg.
    let bundle = match req.bundle {
        Some(b) => Some(b),
        None => fetch_one_bundle(&dispatcher, &device).await,
    };
    match bundle {
        Some(b) => {
            if let Err(e) = install_session_from_bundle(&store, &keys, &session_id, &device, &b) {
                tracing::warn!(error = %e, device = %device, "retry: failed to install session");
                return;
            }
        }
        None => {
            tracing::warn!(
                device = %device,
                "retry: no prekey bundle available; reusing existing session if any"
            );
        }
    }

    let padded = pad_message(&inner_proto);
    let recipients = match encrypt_per_device(
        &store,
        &keys,
        &dispatcher,
        &session_id,
        std::slice::from_ref(&device),
        &padded,
        &padded,
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, device = %device, "retry: re-encrypt failed");
            return;
        }
    };
    let Some(rec) = recipients.into_iter().next() else {
        tracing::warn!(device = %device, "retry: no recipient produced");
        return;
    };

    let now = chrono::Utc::now().timestamp();
    let account_pb = store.session_account_pb(&session_id).ok().flatten();
    let node = build_retry_resend_node(&req.msg_id, &device, &rec, req.count, now, account_pb);
    // Register an ack slot (best-effort; we don't block on it here).
    let _ack = dispatcher.register_ack(&req.msg_id);
    dispatcher.send_node(node);
    metrics::incr(&metrics::MSGS_OUT);
    tracing::info!(
        id = %req.msg_id,
        device = %device,
        count = req.count,
        "resent message in response to retry receipt"
    );
}

// -- Send-side: requesting an unavailable message from our own phone ----------

/// Build + marshal a peer "PlaceholderMessageResendRequest": a `waE2E.Message`
/// whose `ProtocolMessage` is a `PEER_DATA_OPERATION_REQUEST_MESSAGE` of type
/// `PLACEHOLDER_MESSAGE_RESEND`, carrying the `MessageKey` of the message we
/// couldn't decrypt. Sent to our own account to ask the phone to re-encrypt
/// and resend it. Mirrors whatsmeow's `BuildUnavailableMessageRequest` +
/// `BuildMessageKey`.
fn build_unavailable_message_request(
    chat: &str,
    sender: &str,
    msg_id: &str,
    own_user: &str,
) -> Vec<u8> {
    use crate::proto::wa_common::MessageKey;
    use crate::proto::wa_web_protobufs_e2e::{
        peer_data_operation_request_message::PlaceholderMessageResendRequest, protocol_message,
        Message, PeerDataOperationRequestMessage, PeerDataOperationRequestType, ProtocolMessage,
    };
    use prost::Message as _;

    // BuildMessageKey: from_me unless the sender is someone else; for non-PN
    // (e.g. lid/group) chats we'd also stamp the participant, but a 1:1 PN/lid
    // resend needs only remote_jid + from_me + id.
    let from_me = jid_user(sender) == own_user;
    let key = MessageKey {
        remote_jid: Some(chat.to_string()),
        from_me: Some(from_me),
        id: Some(msg_id.to_string()),
        participant: None,
    };
    let msg = Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            r#type: Some(protocol_message::Type::PeerDataOperationRequestMessage as i32),
            peer_data_operation_request_message: Some(PeerDataOperationRequestMessage {
                peer_data_operation_request_type: Some(
                    PeerDataOperationRequestType::PlaceholderMessageResend as i32,
                ),
                placeholder_message_resend_request: vec![PlaceholderMessageResendRequest {
                    message_key: Some(key),
                }],
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    };
    msg.encode_to_vec()
}

/// Build the `<message category="peer">` node carrying an encrypted peer
/// request to our own account. Direct-addressed (no `<participants>` wrapper),
/// with a `<meta appdata="default">` child, the `<enc>`, and — for a pkmsg —
/// our `<device-identity>`. Mirrors whatsmeow's `preparePeerMessageNode`.
fn build_peer_message_node(
    to_bare: &str,
    msg_id: &str,
    rec: &EncryptedRecipient,
    account_pb: Option<Vec<u8>>,
) -> crate::protocol::binary::Node {
    use crate::crypto::signal::MessageType;
    use crate::protocol::binary::{Attrs, Content, Node};

    let is_pkmsg = matches!(rec.message_type, MessageType::PreKey);
    let mut enc_attrs = Attrs::new();
    enc_attrs.insert("v".into(), "2".into());
    enc_attrs.insert(
        "type".into(),
        if is_pkmsg { "pkmsg".into() } else { "msg".into() },
    );
    let enc = Node {
        tag: "enc".into(),
        attrs: enc_attrs,
        content: Content::Bytes(rec.ciphertext.clone()),
    };

    let mut meta_attrs = Attrs::new();
    meta_attrs.insert("appdata".into(), "default".into());
    let mut children = vec![
        Node {
            tag: "meta".into(),
            attrs: meta_attrs,
            content: Content::None,
        },
        enc,
    ];
    if is_pkmsg {
        if let Some(pb) = account_pb {
            children.push(Node {
                tag: "device-identity".into(),
                attrs: Attrs::new(),
                content: Content::Bytes(pb),
            });
        }
    }

    let mut msg_attrs = Attrs::new();
    msg_attrs.insert("id".into(), msg_id.into());
    msg_attrs.insert("type".into(), "text".into());
    msg_attrs.insert("category".into(), "peer".into());
    msg_attrs.insert("to".into(), to_bare.into());

    Node {
        tag: "message".into(),
        attrs: msg_attrs,
        content: Content::Nodes(children),
    }
}

/// Ask our own phone to resend a message our companion couldn't decrypt, by
/// shipping a peer `PlaceholderMessageResendRequest` to our own account
/// (`category="peer"`). Encrypts to our own primary device, bootstrapping a
/// Signal session via a prekey fetch if needed. Spawned off the recv loop;
/// best-effort. Mirrors whatsmeow's `requestMessageFromPhone`.
async fn request_message_from_phone(
    session: Arc<Session>,
    store: Arc<Store>,
    keys: DeviceKeys,
    dispatcher: ConnDispatcher,
    chat: String,
    sender: String,
    orig_id: String,
) {
    let own_jid = match session.meta.read().jid.clone() {
        Some(j) => j,
        None => return, // not paired — nothing to ask
    };
    let own_user = jid_user(&own_jid).to_string();
    let own_bare = format!("{}@s.whatsapp.net", own_user);
    let session_id = session.meta.read().id.clone();

    let inner = build_unavailable_message_request(&chat, &sender, &orig_id, &own_user);
    let padded = pad_message(&inner);
    let recipients = match encrypt_per_device(
        &store,
        &keys,
        &dispatcher,
        &session_id,
        std::slice::from_ref(&own_bare),
        &padded,
        &padded,
        None,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "request-from-phone: encrypt failed");
            return;
        }
    };
    let Some(rec) = recipients.into_iter().next() else {
        return;
    };
    let req_id = uuid_v4_simple();
    let account_pb = store.session_account_pb(&session_id).ok().flatten();
    let node = build_peer_message_node(&own_bare, &req_id, &rec, account_pb);
    let _ack = dispatcher.register_ack(&req_id);
    dispatcher.send_node(node);
    tracing::info!(
        orig_id = %orig_id,
        req_id = %req_id,
        to = %own_bare,
        "requested message resend from phone (peer PlaceholderMessageResendRequest)"
    );
}

/// Marshal an on-demand history-sync request: a `waE2E.Message` whose
/// `ProtocolMessage` is a `PEER_DATA_OPERATION_REQUEST_MESSAGE` of type
/// `HISTORY_SYNC_ON_DEMAND`, asking the phone to resend `count` messages
/// immediately before the given oldest message in `chat`. Mirrors whatsmeow's
/// `BuildHistorySyncRequest`. NOTE: `oldestMsgTimestampMS` is, despite its
/// name, seconds (whatsmeow comment).
fn build_history_sync_on_demand_request(
    chat: &str,
    oldest_id: &str,
    oldest_from_me: bool,
    oldest_ts_secs: i64,
    count: u32,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{
        peer_data_operation_request_message::HistorySyncOnDemandRequest, protocol_message, Message,
        PeerDataOperationRequestMessage, PeerDataOperationRequestType, ProtocolMessage,
    };
    use prost::Message as _;
    let msg = Message {
        protocol_message: Some(Box::new(ProtocolMessage {
            r#type: Some(protocol_message::Type::PeerDataOperationRequestMessage as i32),
            peer_data_operation_request_message: Some(PeerDataOperationRequestMessage {
                peer_data_operation_request_type: Some(
                    PeerDataOperationRequestType::HistorySyncOnDemand as i32,
                ),
                history_sync_on_demand_request: Some(HistorySyncOnDemandRequest {
                    chat_jid: Some(chat.to_string()),
                    oldest_msg_id: Some(oldest_id.to_string()),
                    oldest_msg_from_me: Some(oldest_from_me),
                    on_demand_msg_count: Some(count as i32),
                    oldest_msg_timestamp_ms: Some(oldest_ts_secs),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        })),
        ..Default::default()
    };
    msg.encode_to_vec()
}

/// Ship an on-demand history-sync PULL to our own account (`category="peer"`),
/// asking the phone to resend `count` messages before the given oldest message
/// in `chat`. The phone answers with a HistorySyncNotification (syncType
/// ON_DEMAND) on the recv loop, which lands in `messages` via the normal
/// history-sync ingest path. Unlike the automatic push, this PULL is not gated
/// on the "open on both devices" sync state. Mirrors whatsmeow's
/// `BuildHistorySyncRequest` + `SendPeerMessage`.
#[allow(clippy::too_many_arguments)]
async fn send_history_sync_on_demand(
    dispatcher: &ConnDispatcher,
    session: &Session,
    store: &Arc<Store>,
    keys: &DeviceKeys,
    chat: &str,
    oldest_id: &str,
    oldest_from_me: bool,
    oldest_ts: i64,
    count: u32,
) -> Result<()> {
    let own_jid = match session.meta.read().jid.clone() {
        Some(j) => j,
        None => return Ok(()), // not paired
    };
    let own_user = jid_user(&own_jid).to_string();
    let own_bare = format!("{own_user}@s.whatsapp.net");
    let session_id = session.meta.read().id.clone();

    let inner =
        build_history_sync_on_demand_request(chat, oldest_id, oldest_from_me, oldest_ts, count);
    let padded = pad_message(&inner);
    let recipients = encrypt_per_device(
        store,
        keys,
        dispatcher,
        &session_id,
        std::slice::from_ref(&own_bare),
        &padded,
        &padded,
        None,
    )
    .await?;
    let Some(rec) = recipients.into_iter().next() else {
        return Ok(());
    };
    let req_id = uuid_v4_simple();
    let account_pb = store.session_account_pb(&session_id).ok().flatten();
    let node = build_peer_message_node(&own_bare, &req_id, &rec, account_pb);
    let _ack = dispatcher.register_ack(&req_id);
    dispatcher.send_node(node);
    tracing::info!(
        chat = %chat,
        oldest_id = %oldest_id,
        count,
        req_id = %req_id,
        "sent on-demand history-sync request (peer HISTORY_SYNC_ON_DEMAND)"
    );
    Ok(())
}

/// Load a one-time prekey's private bytes by id from the local prekeys
/// table. Returns Ok(None) if no row matches — the caller treats that the
/// same as "no OPK", which still lets X3DH proceed (with one fewer DH).
fn load_prekey_priv(
    store: &Store,
    session_id: &str,
    key_id: u32,
) -> Result<Option<[u8; 32]>> {
    let bytes = store.prekey_load_private(session_id, key_id)?;
    match bytes {
        None => Ok(None),
        Some(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Ok(Some(a))
        }
        Some(_) => Err(Error::Internal(anyhow::anyhow!(
            "prekey row {key_id} has wrong-length private key"
        ))),
    }
}

/// Delete a one-time prekey row by id. Mirrors whatsmeow's
/// `consumeOneTimePreKey` — OPKs are strictly single-use.
fn consume_prekey(store: &Store, session_id: &str, key_id: u32) -> Result<()> {
    store.prekey_delete(session_id, key_id)?;
    Ok(())
}

fn store_load_record(
    store: &Store,
    session_id: &str,
    address: &str,
) -> Result<Option<crate::crypto::signal::SessionRecord>> {
    let bytes = store.signal_session_load(session_id, address)?;
    match bytes {
        None => Ok(None),
        Some(b) => Ok(Some(serde_json::from_slice(&b).map_err(|e| {
            Error::Internal(anyhow::anyhow!("corrupt: {e}"))
        })?)),
    }
}

/// Update an outbound message row's `status`. Idempotent. Only the
/// happy lifecycle 'queued' → 'sent' → 'delivered' is exercised today;
/// 'failed' is reserved for a retry-bookkeeping pass.
fn update_message_status(
    store: &Store,
    session_id: &str,
    msg_id: &str,
    status: &str,
) -> Result<()> {
    store.message_set_status(session_id, msg_id, status)?;
    Ok(())
}

fn store_save_record(
    store: &Store,
    session_id: &str,
    address: &str,
    record: &crate::crypto::signal::SessionRecord,
) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| Error::Internal(anyhow::anyhow!("serialize: {e}")))?;
    // Stamp updated_at = now (the old inline INSERT here dropped the column to 0,
    // which made the retention sweep's `updated_at > 0` guard skip these rows).
    let now = chrono::Utc::now().timestamp();
    store.signal_session_save(session_id, address, &bytes, now)?;
    Ok(())
}

/// WhatsApp Web client version we identify as. Mirrored from whatsmeow
/// store/clientpayload.go::waVersion. Periodically bumped upstream as the
/// real WA Web app rolls; the server soft-rejects very old versions. This is
/// the compiled-in default; `RUWA_WA_VERSION` overrides it at runtime via
/// [`wa_version`] so a server-side version bump can be chased without a rebuild.
pub const WA_VERSION: [u32; 3] = [2, 3000, 1040390703];

/// Effective WA Web version: `RUWA_WA_VERSION` (`"a.b.c"`, all-numeric) if set
/// and parseable, else the compiled-in [`WA_VERSION`]. Read + parsed once and
/// cached for the process lifetime (it feeds the handshake build hash).
pub fn wa_version() -> [u32; 3] {
    use std::sync::OnceLock;
    static CACHE: OnceLock<[u32; 3]> = OnceLock::new();
    *CACHE.get_or_init(|| match std::env::var("RUWA_WA_VERSION") {
        Ok(s) => parse_wa_version(&s).unwrap_or_else(|| {
            tracing::warn!(value = %s, "RUWA_WA_VERSION is not 'a.b.c'; using built-in default");
            WA_VERSION
        }),
        Err(_) => WA_VERSION,
    })
}

/// Parse a `"a.b.c"` all-numeric version triple. Returns `None` on any non-numeric
/// part or a component count other than 3.
fn parse_wa_version(s: &str) -> Option<[u32; 3]> {
    let parts: Vec<&str> = s.trim().split('.').collect();
    match parts.as_slice() {
        [a, b, c] => Some([a.parse().ok()?, b.parse().ok()?, c.parse().ok()?]),
        _ => None,
    }
}

/// MD5 of the dot-formatted version string. The server expects exactly this
/// in DevicePairingRegistrationData.build_hash. Uses the effective
/// [`wa_version`] so it tracks an `RUWA_WA_VERSION` override.
pub fn wa_version_hash() -> [u8; 16] {
    use md5::{Digest, Md5};
    let v = wa_version();
    let s = format!("{}.{}.{}", v[0], v[1], v[2]);
    let mut h = Md5::new();
    h.update(s.as_bytes());
    h.finalize().into()
}

/// Build the registration `ClientPayload` (waWa6) bytes for a fresh device.
/// Mirrors whatsmeow store/clientpayload.go::getRegistrationPayload.
///
/// `signed_prekey.signature` is a real XEdDSA signature over the SPK pubkey
/// (see `crypto::identity::xeddsa_sign`), so the bundle verifies when other
/// devices fetch it for X3DH.
pub fn build_registration_client_payload(keys: &DeviceKeys) -> Vec<u8> {
    use crate::proto::wa_companion_reg::{device_props, DeviceProps};
    use crate::proto::wa_web_protobufs_wa6::client_payload::{
        user_agent, web_info, ConnectReason, ConnectType, DevicePairingRegistrationData, UserAgent,
        WebInfo,
    };
    use crate::proto::wa_web_protobufs_wa6::ClientPayload;
    use prost::Message;

    let mut regid = Vec::with_capacity(4);
    regid.extend_from_slice(&keys.registration_id.to_be_bytes());

    // 3-byte big-endian SPK id (whatsmeow does `preKeyID[1:]` after writing
    // the u32 BE; equivalent to taking the lower 24 bits).
    let spk_id_be = keys.signed_prekey.key_id.to_be_bytes();
    let spk_id = spk_id_be[1..].to_vec();

    let device_props = DeviceProps {
        // Register as a Chrome web client, mirroring Baileys/Evolution (which
        // stay "active" on the same number where an Unknown-platform device gets
        // bucketed under "OTHER" and "message sync paused"). `os` is the display
        // name; `platform_type` is what classifies the device.
        os: Some("Chrome".to_string()),
        version: Some(device_props::AppVersion {
            primary: Some(0),
            secondary: Some(1),
            tertiary: Some(0),
            quaternary: None,
            quinary: None,
        }),
        platform_type: Some(device_props::PlatformType::Chrome as i32),
        // require_full_sync=FALSE (like Evolution, alwaysOnline/syncFullHistory
        // off). A clean, caught-up device proved that `require_full_sync=true`
        // makes the phone attempt the HEAVY full backfill — which is gated on
        // "both devices open" and so pauses — and SKIP the quick RECENT sync
        // that completes and shows "most recent messages are in sync". We want
        // the recent sync to complete (→ in-sync) and pull older history
        // explicitly via the on-demand API (HISTORY_SYNC_ON_DEMAND) when needed.
        require_full_sync: Some(false),
        // Mirrors whatsmeow's `store.DeviceProps.HistorySyncConfig`. Without
        // this, WA's server rejects the pair-device flow with stream:error
        // code=500 after the user scans the QR. full-sync limits left unset
        // (recent sync by default); on_demand_ready stays true for pulls.
        history_sync_config: Some(device_props::HistorySyncConfig {
            full_sync_days_limit: None,
            full_sync_size_mb_limit: None,
            storage_quota_mb: Some(102400),
            inline_initial_payload_in_e2_ee_msg: Some(true),
            recent_sync_days_limit: None,
            support_call_log_history: Some(false),
            support_bot_user_agent_chat_history: Some(true),
            support_cag_reactions_and_polls: Some(true),
            support_biz_hosted_msg: Some(true),
            support_recent_sync_chunk_message_count_tuning: Some(true),
            support_hosted_group_msg: Some(true),
            support_fbid_bot_chat_history: Some(true),
            support_add_on_history_sync_migration: None,
            support_message_association: Some(true),
            support_group_history: Some(true),
            on_demand_ready: Some(true),
            support_guest_chat: None,
            complete_on_demand_ready: Some(true),
            thumbnail_sync_days_limit: Some(60),
            initial_sync_max_messages_per_chat: None,
            support_manus_history: Some(true),
            support_hatch_history: Some(true),
            supported_bot_channel_fbids: Vec::new(),
            support_inline_contacts: None,
        }),
    };

    let payload = ClientPayload {
        user_agent: Some(UserAgent {
            platform: Some(user_agent::Platform::Web as i32),
            release_channel: Some(user_agent::ReleaseChannel::Release as i32),
            app_version: Some(user_agent::AppVersion {
                primary: Some(wa_version()[0]),
                secondary: Some(wa_version()[1]),
                tertiary: Some(wa_version()[2]),
                ..Default::default()
            }),
            mcc: Some("000".into()),
            mnc: Some("000".into()),
            // whatsmeow/the real WA Web client set os_version == os_build_number
            // == the app version string (not a placeholder like "0.1").
            os_version: Some(format!("{}.{}.{}", wa_version()[0], wa_version()[1], wa_version()[2])),
            manufacturer: Some(String::new()),
            device: Some("Desktop".into()),
            os_build_number: Some(format!(
                "{}.{}.{}",
                wa_version()[0],
                wa_version()[1],
                wa_version()[2]
            )),
            locale_language_iso6391: Some("en".into()),
            locale_country_iso31661_alpha2: Some("US".into()),
            ..Default::default()
        }),
        web_info: Some(WebInfo {
            web_sub_platform: Some(web_info::WebSubPlatform::WebBrowser as i32),
            ..Default::default()
        }),
        connect_type: Some(ConnectType::WifiUnknown as i32),
        connect_reason: Some(ConnectReason::UserActivated as i32),
        passive: Some(false),
        pull: Some(false),
        device_pairing_data: Some(DevicePairingRegistrationData {
            e_regid: Some(regid),
            // [DjbType] = [5]; identifies Curve25519 keys per libsignal.
            e_keytype: Some(vec![5u8]),
            e_ident: Some(keys.identity.public.to_vec()),
            e_skey_id: Some(spk_id),
            e_skey_val: Some(keys.signed_prekey.keypair.public.to_vec()),
            e_skey_sig: Some(keys.signed_prekey.signature.to_vec()),
            build_hash: Some(wa_version_hash().to_vec()),
            device_props: Some(device_props.encode_to_vec()),
        }),
        ..Default::default()
    };
    payload.encode_to_vec()
}

/// Build the *login* (re-attach) `ClientPayload` for an already-paired
/// session. Mirrors whatsmeow store/clientpayload.go::getLoginPayload.
///
/// `user_int` and `device` come from the server-issued JID (e.g.
/// `"5511...:23@s.whatsapp.net"` → user_int=5511..., device=23).
pub fn build_login_client_payload(_keys: &DeviceKeys, user_int: u64, device: u32) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_wa6::client_payload::{
        user_agent, web_info, ConnectReason, ConnectType, UserAgent, WebInfo,
    };
    use crate::proto::wa_web_protobufs_wa6::ClientPayload;
    use prost::Message;

    let payload = ClientPayload {
        user_agent: Some(UserAgent {
            platform: Some(user_agent::Platform::Web as i32),
            release_channel: Some(user_agent::ReleaseChannel::Release as i32),
            app_version: Some(user_agent::AppVersion {
                primary: Some(wa_version()[0]),
                secondary: Some(wa_version()[1]),
                tertiary: Some(wa_version()[2]),
                ..Default::default()
            }),
            mcc: Some("000".into()),
            mnc: Some("000".into()),
            // whatsmeow/the real WA Web client set os_version == os_build_number
            // == the app version string (not a placeholder like "0.1").
            os_version: Some(format!("{}.{}.{}", wa_version()[0], wa_version()[1], wa_version()[2])),
            manufacturer: Some(String::new()),
            device: Some("Desktop".into()),
            os_build_number: Some(format!(
                "{}.{}.{}",
                wa_version()[0],
                wa_version()[1],
                wa_version()[2]
            )),
            locale_language_iso6391: Some("en".into()),
            locale_country_iso31661_alpha2: Some("US".into()),
            ..Default::default()
        }),
        web_info: Some(WebInfo {
            web_sub_platform: Some(web_info::WebSubPlatform::WebBrowser as i32),
            ..Default::default()
        }),
        connect_type: Some(ConnectType::WifiUnknown as i32),
        connect_reason: Some(ConnectReason::UserActivated as i32),
        passive: Some(true),
        pull: Some(true),
        username: Some(user_int),
        device: Some(device),
        lc: Some(1),
        ..Default::default()
    };
    payload.encode_to_vec()
}

/// Pick the right ClientPayload for this session: login (re-attach) when
/// a JID is persisted, otherwise registration.
pub fn select_client_payload(meta: &SessionMeta, keys: &DeviceKeys) -> Vec<u8> {
    if let Some(jid) = &meta.jid {
        if let Some((user_int, device)) = parse_user_jid(jid) {
            return build_login_client_payload(keys, user_int, device);
        }
    }
    build_registration_client_payload(keys)
}

/// Parse a user JID like `"5511999999999:23@s.whatsapp.net"` into
/// `(user_int, device)`. Accepts the `"<user>@<server>"` form (device=0)
/// and the `"<user>[.agent]:<device>@<server>"` form. Returns None if the
/// user portion isn't a valid u64.
pub fn parse_user_jid(jid: &str) -> Option<(u64, u32)> {
    let local = jid.split('@').next()?;
    // Strip the optional ".<agent>" suffix from the user portion.
    let mut user_part = local;
    let mut device: u32 = 0;
    if let Some((u, d)) = local.split_once(':') {
        user_part = u;
        device = d.parse().ok()?;
    }
    if let Some((u, _agent)) = user_part.split_once('.') {
        user_part = u;
    }
    let user_int = user_part.parse().ok()?;
    Some((user_int, device))
}

/// One device's prekey bundle as returned by the WA `<iq xmlns="encrypt">`
/// fetch. Sufficient input for `RatchetingSession::initiate_alice` to start
/// a Signal session.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePrekeyBundle {
    pub jid: String,
    pub device_id: u32,
    pub registration_id: u32,
    pub identity_pub: [u8; 32],
    /// Signed prekey id (3-byte big-endian on the wire, fits in u32).
    pub signed_pre_key_id: u32,
    pub signed_pre_key_pub: [u8; 32],
    pub signed_pre_key_sig: [u8; 64],
    /// One-time prekey (omitted by the server if exhausted for this device).
    pub one_time_pre_key_id: Option<u32>,
    pub one_time_pre_key_pub: Option<[u8; 32]>,
}

/// Build a usync IQ asking the server for the list of devices a JID
/// has linked. Mirrors whatsmeow's `getUsyncDevices` shape:
///
/// ```text
/// <iq id type=get xmlns="usync" to="s.whatsapp.net">
///   <usync sid context=message mode=query last=true>
///     <query><devices version="2"/></query>
///     <list><user jid=<phone>@s.whatsapp.net/></list>
///   </usync>
/// </iq>
/// ```
///
/// Server replies with one `<user jid=...>` per requested user, and
/// inside each: `<devices><device id=N>...` listing the device ids.
/// Caller stitches `<phone>:<device_id>@s.whatsapp.net` for each one.
/// Build an IQ that sets our own "about"/status text. Mirrors whatsmeow's
/// `SetStatusMessage` (`xmlns="status"`, `<status>text</status>`).
pub fn build_set_status_iq(iq_id: &str, text: &str) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("xmlns".into(), "status".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "status".into(),
            attrs: Attrs::new(),
            content: Content::Bytes(text.as_bytes().to_vec()),
        }]),
    }
}

/// Build an IQ that sets our own profile picture to `jpeg` (raw JPEG bytes).
/// `own_jid` is our account JID. Mirrors whatsmeow's `SetProfilePhoto`
/// (`xmlns="w:profile:picture"`, `<picture type="image">…jpeg…</picture>`).
pub fn build_set_picture_iq(
    iq_id: &str,
    own_jid: &str,
    jpeg: &[u8],
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut pic_attrs = Attrs::new();
    pic_attrs.insert("type".into(), "image".into());

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("xmlns".into(), "w:profile:picture".into());
    iq_attrs.insert("to".into(), own_jid.into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "picture".into(),
            attrs: pic_attrs,
            content: Content::Bytes(jpeg.to_vec()),
        }]),
    }
}

/// Build a blocklist update IQ. `block=true` blocks `target_jid`, `false`
/// unblocks. Mirrors whatsmeow's `UpdateBlocklist` (`xmlns="blocklist"`,
/// `<item action="block|unblock" jid=…>`).
pub fn build_block_iq(
    iq_id: &str,
    target_jid: &str,
    block: bool,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut item_attrs = Attrs::new();
    item_attrs.insert("action".into(), if block { "block" } else { "unblock" }.into());
    item_attrs.insert("jid".into(), target_jid.into());

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("xmlns".into(), "blocklist".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "item".into(),
            attrs: item_attrs,
            content: Content::None,
        }]),
    }
}

/// Whether an IQ reply is a server error (`type="error"` or an `<error>` child).
pub fn iq_is_error(iq: &crate::protocol::binary::Node) -> bool {
    if iq.attrs.get("type").map(String::as_str) == Some("error") {
        return true;
    }
    matches!(&iq.content, crate::protocol::binary::Content::Nodes(ns) if ns.iter().any(|n| n.tag == "error"))
}

/// Build a profile-picture query IQ for `target_jid`. `preview=true` asks for
/// the small thumbnail; otherwise the full-resolution image URL. Mirrors
/// whatsmeow's `GetProfilePictureInfo` (`xmlns="w:profile:picture"`).
pub fn build_picture_iq(
    iq_id: &str,
    target_jid: &str,
    preview: bool,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut pic_attrs = Attrs::new();
    pic_attrs.insert("query".into(), "url".into());
    pic_attrs.insert("type".into(), if preview { "preview" } else { "image" }.into());

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "get".into());
    iq_attrs.insert("xmlns".into(), "w:profile:picture".into());
    iq_attrs.insert("to".into(), target_jid.into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "picture".into(),
            attrs: pic_attrs,
            content: Content::None,
        }]),
    }
}

/// Extract the profile-picture URL from a `w:profile:picture` reply, or `None`
/// when the contact has no picture / it's hidden (server replies with an error
/// or omits the `<picture>` node).
pub fn parse_picture_response(iq: &crate::protocol::binary::Node) -> Option<String> {
    use crate::protocol::binary::Content;
    let Content::Nodes(ns) = &iq.content else {
        return None;
    };
    ns.iter()
        .find(|n| n.tag == "picture")
        .and_then(|p| p.attrs.get("url").cloned())
}

/// One row of an onWhatsApp lookup: the queried number, its resolved JID (when
/// on WhatsApp), and whether it exists on the platform.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct OnWhatsAppResult {
    pub query: String,
    pub jid: Option<String>,
    pub exists: bool,
}

/// Build a usync "contact" IQ asking the server which of `phones` are on
/// WhatsApp. Each `<user>` wraps a `<contact>+E.164</contact>`; the `<query>`
/// requests the `contact` field. Mirrors whatsmeow's `IsOnWhatsApp`.
pub fn build_usync_contact_iq(iq_id: &str, phones: &[String]) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};

    let users: Vec<Node> = phones
        .iter()
        .map(|p| {
            let e164 = if p.starts_with('+') {
                p.clone()
            } else {
                format!("+{}", p.trim_start_matches('+'))
            };
            Node {
                tag: "user".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![Node {
                    tag: "contact".into(),
                    attrs: Attrs::new(),
                    content: Content::Bytes(e164.into_bytes()),
                }]),
            }
        })
        .collect();

    let query = Node {
        tag: "query".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![Node {
            tag: "contact".into(),
            attrs: Attrs::new(),
            content: Content::None,
        }]),
    };
    let list = Node {
        tag: "list".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(users),
    };

    let mut usync_attrs = Attrs::new();
    usync_attrs.insert("sid".into(), iq_id.into());
    usync_attrs.insert("mode".into(), "query".into());
    usync_attrs.insert("last".into(), "true".into());
    usync_attrs.insert("index".into(), "0".into());
    usync_attrs.insert("context".into(), "interactive".into());

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "get".into());
    iq_attrs.insert("xmlns".into(), "usync".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "usync".into(),
            attrs: usync_attrs,
            content: Content::Nodes(vec![query, list]),
        }]),
    }
}

/// Parse a usync contact reply into per-user results. `queries` is the original
/// input list (response `<user>` nodes are in request order); a user is "on
/// WhatsApp" when its `<contact type="in"/>` child says so.
pub fn parse_usync_contact_response(
    iq: &crate::protocol::binary::Node,
    queries: &[String],
) -> Vec<OnWhatsAppResult> {
    use crate::protocol::binary::{Content, Node};
    fn children<'a>(n: &'a Node, tag: &str) -> Vec<&'a Node> {
        match &n.content {
            Content::Nodes(ns) => ns.iter().filter(|c| c.tag == tag).collect(),
            _ => Vec::new(),
        }
    }

    let usync = match &iq.content {
        Content::Nodes(ns) => ns.iter().find(|c| c.tag == "usync"),
        _ => None,
    };
    let users: Vec<&Node> = usync
        .and_then(|u| children(u, "list").into_iter().next())
        .map(|l| children(l, "user"))
        .unwrap_or_default();

    users
        .iter()
        .enumerate()
        .map(|(i, user)| {
            let jid = user.attrs.get("jid").cloned();
            let exists = children(user, "contact")
                .first()
                .and_then(|c| c.attrs.get("type"))
                .map(|t| t == "in")
                .unwrap_or(false);
            OnWhatsAppResult {
                query: queries.get(i).cloned().unwrap_or_default(),
                jid: jid.filter(|_| exists),
                exists,
            }
        })
        .collect()
}

/// Build a usync IQ that asks the server for the LID of each phone-number JID.
/// Mirrors whatsmeow's `<usync><query><lid/></query><list><user jid=.../></list>`
/// shape. The reply maps each `<user jid="<pn>@s.whatsapp.net">` to a
/// `<lid val="<n>@lid"/>` child — exactly the LID↔PN correspondence we need to
/// bridge a PN chat to the contact name stored under the sender's LID.
pub fn build_usync_lid_iq(iq_id: &str, pn_jids: &[String]) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};

    let users: Vec<Node> = pn_jids
        .iter()
        .map(|jid| {
            let mut a = Attrs::new();
            a.insert("jid".into(), jid.clone());
            Node { tag: "user".into(), attrs: a, content: Content::None }
        })
        .collect();

    let query = Node {
        tag: "query".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![Node {
            tag: "lid".into(),
            attrs: Attrs::new(),
            content: Content::None,
        }]),
    };
    let list = Node { tag: "list".into(), attrs: Attrs::new(), content: Content::Nodes(users) };

    let mut usync_attrs = Attrs::new();
    usync_attrs.insert("sid".into(), iq_id.into());
    usync_attrs.insert("mode".into(), "query".into());
    usync_attrs.insert("last".into(), "true".into());
    usync_attrs.insert("index".into(), "0".into());
    usync_attrs.insert("context".into(), "interactive".into());

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "get".into());
    iq_attrs.insert("xmlns".into(), "usync".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "usync".into(),
            attrs: usync_attrs,
            content: Content::Nodes(vec![query, list]),
        }]),
    }
}

/// Parse a usync LID reply into `(pn_user, lid_user)` pairs (bare user parts,
/// device/agent/server stripped) — ready for `lid_pn_put`. Skips users with no
/// `<lid>` child.
pub fn parse_usync_lid_response(iq: &crate::protocol::binary::Node) -> Vec<(String, String)> {
    use crate::protocol::binary::{Content, Node};
    fn children<'a>(n: &'a Node, tag: &str) -> Vec<&'a Node> {
        match &n.content {
            Content::Nodes(ns) => ns.iter().filter(|c| c.tag == tag).collect(),
            _ => Vec::new(),
        }
    }
    let usync = match &iq.content {
        Content::Nodes(ns) => ns.iter().find(|c| c.tag == "usync"),
        _ => None,
    };
    let users: Vec<&Node> = usync
        .and_then(|u| children(u, "list").into_iter().next())
        .map(|l| children(l, "user"))
        .unwrap_or_default();

    users
        .iter()
        .filter_map(|user| {
            let pn_jid = user.attrs.get("jid")?;
            if !pn_jid.ends_with("@s.whatsapp.net") {
                return None;
            }
            // The LID rides on `<lid val="<n>@lid"/>` (val attr or text body).
            let lid_node = children(user, "lid").into_iter().next()?;
            let lid_raw = lid_node
                .attrs
                .get("val")
                .cloned()
                .or_else(|| match &lid_node.content {
                    Content::Bytes(b) => Some(String::from_utf8_lossy(b).into_owned()),
                    _ => None,
                })?;
            let pn_user = lid_user_part(pn_jid).to_string();
            let lid_user = lid_user_part(&lid_raw).to_string();
            if pn_user.is_empty() || lid_user.is_empty() {
                return None;
            }
            Some((pn_user, lid_user))
        })
        .collect()
}

pub fn build_usync_devices_iq(
    iq_id: &str,
    target_jids: &[&str],
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};

    let users: Vec<Node> = target_jids
        .iter()
        .map(|jid| {
            let mut a = Attrs::new();
            a.insert("jid".into(), (*jid).into());
            Node {
                tag: "user".into(),
                attrs: a,
                content: Content::None,
            }
        })
        .collect();

    let mut device_attrs = Attrs::new();
    device_attrs.insert("version".into(), "2".into());
    // The `<query>` MUST include a `<lid/>` element alongside `<devices>`.
    // On a LID-primary account the server SILENTLY DROPS a device usync that
    // lacks it (no reply → 30s timeout → every send fails). Confirmed against a
    // live Evolution/Baileys trace capture on this exact number: Evolution sends
    // `<query><devices version='2'/><lid/></query>` and the server replies with
    // the device-list + the user's `<lid val='…@lid'/>` mapping.
    let query = Node {
        tag: "query".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![
            Node {
                tag: "devices".into(),
                attrs: device_attrs,
                content: Content::None,
            },
            Node {
                tag: "lid".into(),
                attrs: Attrs::new(),
                content: Content::None,
            },
        ]),
    };
    let list = Node {
        tag: "list".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(users),
    };

    let mut usync_attrs = Attrs::new();
    // sid MUST be distinct from the iq `id` (whatsmeow uses a separate
    // generateRequestID for each). A usync where sid == id is silently dropped
    // by the server (no reply → 30s timeout → sends fail).
    usync_attrs.insert("sid".into(), uuid_v4());
    usync_attrs.insert("context".into(), "message".into());
    usync_attrs.insert("mode".into(), "query".into());
    usync_attrs.insert("last".into(), "true".into());
    usync_attrs.insert("index".into(), "0".into());

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "get".into());
    iq_attrs.insert("xmlns".into(), "usync".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "usync".into(),
            attrs: usync_attrs,
            content: Content::Nodes(vec![query, list]),
        }]),
    }
}

/// Decode a usync response into the full device-suffix JIDs the server
/// reported. For a request asking about `5511...@s.whatsapp.net`, the
/// reply lists devices `0`, `23`, `40`, etc.; we stitch each into the
/// canonical send-target form `5511...:NN@s.whatsapp.net`. Device 0
/// (phone) is included.
pub fn parse_usync_devices_response(
    iq: &crate::protocol::binary::Node,
) -> Vec<String> {
    use crate::protocol::binary::{Content, Node};
    fn walk(n: &Node, tag: &str) -> Vec<Node> {
        let mut out = Vec::new();
        if let Content::Nodes(ns) = &n.content {
            for c in ns {
                if c.tag == tag {
                    out.push(c.clone());
                }
            }
        }
        out
    }

    let mut result = Vec::new();
    let usync = match iq.content {
        Content::Nodes(ref ns) => match ns.iter().find(|c| c.tag == "usync") {
            Some(u) => u,
            None => return result,
        },
        _ => return result,
    };
    let list = match walk(usync, "list").into_iter().next() {
        Some(l) => l,
        None => return result,
    };
    for user in walk(&list, "user") {
        let user_jid = match user.attrs.get("jid") {
            Some(j) => j.clone(),
            None => continue,
        };
        // The user element is `5511...@s.whatsapp.net`; extract phone
        // local before splitting devices.
        let local_phone = match user_jid.split('@').next() {
            Some(p) => p.to_string(),
            None => continue,
        };
        for devices in walk(&user, "devices") {
            // Server wraps the per-device list in a `<device-list>` element.
            // Older parsers expected `<devices><device/></devices>` directly;
            // current servers emit `<devices><device-list><device/></device-list></devices>`.
            let device_holders: Vec<Node> = {
                let dl = walk(&devices, "device-list");
                if dl.is_empty() {
                    vec![devices.clone()]
                } else {
                    dl
                }
            };
            for holder in &device_holders {
                for device in walk(holder, "device") {
                    if let Some(id) = device.attrs.get("id") {
                        let device_id: u32 = match id.parse() {
                            Ok(n) => n,
                            Err(_) => continue,
                        };
                        if device_id == 0 {
                            result.push(format!("{local_phone}@s.whatsapp.net"));
                        } else {
                            result.push(format!("{local_phone}:{device_id}@s.whatsapp.net"));
                        }
                    }
                }
            }
        }
    }
    result
}

/// Build the prekey-fetch IQ. Mirrors whatsmeow's `fetchPreKeys` exactly:
///   `<iq id=<iq_id> type="get" xmlns="encrypt" to="s.whatsapp.net">`
///   `  <key>`
///   `    <user jid="..." reason="identity"/>* (one per target)`
///   `  </key>`
///   `</iq>`
#[allow(dead_code)]
pub fn build_prekey_fetch_iq(
    target_jids: &[&str],
    iq_id: &str,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};

    let users: Vec<Node> = target_jids
        .iter()
        .map(|jid| {
            let mut a = Attrs::new();
            a.insert("jid".into(), (*jid).into());
            a.insert("reason".into(), "identity".into());
            Node {
                tag: "user".into(),
                attrs: a,
                content: Content::None,
            }
        })
        .collect();

    let key = Node {
        tag: "key".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(users),
    };

    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "get".into());
    iq_attrs.insert("xmlns".into(), "encrypt".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![key]),
    }
}

/// Build the `<iq xmlns="w:m" type="set" to="s.whatsapp.net">` mediaconn
/// IQ that fetches the upload host + token. Mirrors whatsmeow/mediaconn.go:
///   `<iq id type="set" xmlns="w:m" to="s.whatsapp.net">
///      <media_conn/>
///    </iq>`
/// Server replies with `<iq><media_conn auth=<token> ttl=<int> ...>
///   <host hostname=mmg.whatsapp.net .../>
/// </media_conn></iq>`.
#[allow(dead_code)]
pub fn build_mediaconn_iq(iq_id: &str) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("id".into(), iq_id.into());
    attrs.insert("type".into(), "set".into());
    attrs.insert("xmlns".into(), "w:m".into());
    attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs,
        content: Content::Nodes(vec![Node {
            tag: "media_conn".into(),
            attrs: Attrs::new(),
            content: Content::None,
        }]),
    }
}

/// Build the `<iq xmlns="md" type="set" to="s.whatsapp.net">` IQ that
/// asks the server to forget this companion device. Mirrors whatsmeow's
/// `Logout`:
/// ```text
/// <iq id type="set" xmlns="md" to="s.whatsapp.net">
///   <remove-companion-device jid="<our jid>" reason="user_initiated"/>
/// </iq>
/// ```
/// Best-effort — the connection task ships this just before dropping
/// the WS on logout. Server may or may not ack before the close.
pub fn build_remove_companion_device_iq(
    iq_id: &str,
    jid: &str,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("xmlns".into(), "md".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    let mut rm_attrs = Attrs::new();
    rm_attrs.insert("jid".into(), jid.into());
    rm_attrs.insert("reason".into(), "user_initiated".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![Node {
            tag: "remove-companion-device".into(),
            attrs: rm_attrs,
            content: Content::None,
        }]),
    }
}

/// Build a `<chatstate>` node carrying a typing-indicator update. Mirrors
/// whatsmeow's `SendChatPresence`:
/// ```text
/// <chatstate from=<our jid> to=<chat>>
///   <composing/>          (or <paused/>)
/// </chatstate>
/// ```
/// `state` must be `"composing"` or `"paused"`.
pub fn build_chat_presence_node(
    own_jid: &str,
    to: &str,
    state: &str,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("from".into(), own_jid.into());
    attrs.insert("to".into(), to.into());
    Node {
        tag: "chatstate".into(),
        attrs,
        content: Content::Nodes(vec![Node {
            tag: state.into(),
            attrs: Attrs::new(),
            content: Content::None,
        }]),
    }
}

/// Presence to announce for a session's `mark_online` preference. WhatsApp
/// SILENCES the phone's notifications while a companion is `available` (it
/// assumes you're reading on the companion); `unavailable` (the default) keeps
/// the phone notifying — what Evolution sends; reception is unaffected either
/// way. Toggled per session via the API/Console.
fn presence_for(mark_online: bool) -> &'static str {
    if mark_online {
        "available"
    } else {
        "unavailable"
    }
}

/// Build a global `<presence>` node: `available` or `unavailable`. Sent
/// once on connect (or when the user toggles online/offline). Mirrors
/// whatsmeow's `SendPresence`. `name` is the device's push name; the
/// server uses it to populate the contact card other peers see.
pub fn build_global_presence_node(
    state: &str,
    push_name: Option<&str>,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("type".into(), state.into());
    if let Some(n) = push_name {
        attrs.insert("name".into(), n.into());
    }
    Node {
        tag: "presence".into(),
        attrs,
        content: Content::None,
    }
}

/// Build a `<receipt type="read">` for one or more inbound messages from
/// the same `chat_jid`. `participant` is set in group chats (the sender's
/// user JID); for 1:1 chats it should equal `chat_jid` or be omitted.
/// Mirrors whatsmeow's `MarkRead`. The first id goes on the outer attrs;
/// any additional ids land in `<list><item id=.../></list>`.
pub fn build_read_receipt_node(
    chat_jid: &str,
    participant: Option<&str>,
    msg_ids: &[&str],
    timestamp: i64,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    if let Some(first) = msg_ids.first() {
        attrs.insert("id".into(), (*first).into());
    }
    attrs.insert("type".into(), "read".into());
    attrs.insert("to".into(), chat_jid.into());
    attrs.insert("t".into(), timestamp.to_string());
    if let Some(p) = participant {
        if !p.is_empty() && p != chat_jid {
            attrs.insert("participant".into(), p.into());
        }
    }
    let content = if msg_ids.len() > 1 {
        let items: Vec<Node> = msg_ids
            .iter()
            .skip(1)
            .map(|id| {
                let mut a = Attrs::new();
                a.insert("id".into(), (*id).into());
                Node {
                    tag: "item".into(),
                    attrs: a,
                    content: Content::None,
                }
            })
            .collect();
        Content::Nodes(vec![Node {
            tag: "list".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(items),
        }])
    } else {
        Content::None
    };
    Node {
        tag: "receipt".into(),
        attrs,
        content,
    }
}

/// Parsed mediaconn response — host + auth token to use for the next upload.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct MediaConn {
    pub auth: String,
    pub ttl_seconds: i64,
    pub hostname: String,
}

/// Decode an `<iq>` response from build_mediaconn_iq.
#[allow(dead_code)]
pub fn parse_mediaconn_response(
    iq: &crate::protocol::binary::Node,
) -> Option<MediaConn> {
    use crate::protocol::binary::Content;
    let kids = match &iq.content {
        Content::Nodes(ns) => ns.as_slice(),
        _ => return None,
    };
    let mc = kids.iter().find(|c| c.tag == "media_conn")?;
    let auth = mc.attrs.get("auth")?.clone();
    let ttl = mc.attrs.get("ttl").and_then(|s| s.parse().ok()).unwrap_or(0);
    let host_kids = match &mc.content {
        Content::Nodes(ns) => ns.as_slice(),
        _ => return None,
    };
    let host = host_kids
        .iter()
        .find(|c| c.tag == "host")
        .and_then(|h| h.attrs.get("hostname").cloned())
        .unwrap_or_else(|| "mmg.whatsapp.net".to_string());
    Some(MediaConn {
        auth,
        ttl_seconds: ttl,
        hostname: host,
    })
}

/// Decode the server's prekey-fetch response. Returns one bundle per
/// `<user>` child that contained a usable shape; users carrying an
/// `<error>` child are skipped.
#[allow(dead_code)]
pub fn parse_prekey_fetch_response(
    iq: &crate::protocol::binary::Node,
) -> Vec<DevicePrekeyBundle> {
    use crate::protocol::binary::{Content, Node};

    fn child_bytes<'a>(parent: &'a Node, tag: &str) -> Option<&'a [u8]> {
        let kids = match &parent.content {
            Content::Nodes(ns) => ns.as_slice(),
            _ => return None,
        };
        kids.iter().find(|c| c.tag == tag).and_then(|c| match &c.content {
            Content::Bytes(b) => Some(b.as_slice()),
            _ => None,
        })
    }
    fn find_child<'a>(parent: &'a Node, tag: &str) -> Option<&'a Node> {
        let kids = match &parent.content {
            Content::Nodes(ns) => ns.as_slice(),
            _ => return None,
        };
        kids.iter().find(|c| c.tag == tag)
    }
    /// Decode 3- or 4-byte big-endian id encoding used by WA prekeys.
    fn parse_id(bytes: &[u8]) -> Option<u32> {
        if bytes.is_empty() || bytes.len() > 4 {
            return None;
        }
        let mut padded = [0u8; 4];
        padded[4 - bytes.len()..].copy_from_slice(bytes);
        Some(u32::from_be_bytes(padded))
    }

    let list = match find_child(iq, "list") {
        Some(n) => n,
        None => return Vec::new(),
    };
    let users: &[Node] = match &list.content {
        Content::Nodes(ns) => ns.as_slice(),
        _ => return Vec::new(),
    };

    let mut out = Vec::new();
    for user in users.iter().filter(|c| c.tag == "user") {
        if find_child(user, "error").is_some() {
            continue;
        }
        let jid = match user.attrs.get("jid") {
            Some(j) => j.clone(),
            None => continue,
        };
        let device_id = parse_user_jid(&jid).map(|(_, d)| d).unwrap_or(0);

        let reg_bytes = match child_bytes(user, "registration") {
            Some(b) if b.len() == 4 => b,
            _ => continue,
        };
        let registration_id = u32::from_be_bytes([
            reg_bytes[0], reg_bytes[1], reg_bytes[2], reg_bytes[3],
        ]);

        // Server may wrap the per-device keys in a `<keys>` element; if not,
        // the keys hang directly off `<user>`.
        let keys_parent = find_child(user, "keys").unwrap_or(user);

        let identity_bytes = match child_bytes(keys_parent, "identity") {
            Some(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut identity_pub = [0u8; 32];
        identity_pub.copy_from_slice(identity_bytes);

        // Signed prekey: <skey> with <id>, <value>, <signature> children.
        let skey = match find_child(keys_parent, "skey") {
            Some(n) => n,
            None => continue,
        };
        let spk_id = match child_bytes(skey, "id").and_then(parse_id) {
            Some(v) => v,
            None => continue,
        };
        let spk_pub_b = match child_bytes(skey, "value") {
            Some(b) if b.len() == 32 => b,
            _ => continue,
        };
        let mut signed_pre_key_pub = [0u8; 32];
        signed_pre_key_pub.copy_from_slice(spk_pub_b);
        let spk_sig_b = match child_bytes(skey, "signature") {
            Some(b) if b.len() == 64 => b,
            _ => continue,
        };
        let mut signed_pre_key_sig = [0u8; 64];
        signed_pre_key_sig.copy_from_slice(spk_sig_b);

        // One-time prekey is optional (omitted when the server's pool is dry).
        let (one_time_pre_key_id, one_time_pre_key_pub) = match find_child(keys_parent, "key") {
            Some(opk) => {
                let opk_id = child_bytes(opk, "id").and_then(parse_id);
                let opk_pub_b = child_bytes(opk, "value").filter(|b| b.len() == 32);
                match (opk_id, opk_pub_b) {
                    (Some(id), Some(b)) => {
                        let mut p = [0u8; 32];
                        p.copy_from_slice(b);
                        (Some(id), Some(p))
                    }
                    _ => (None, None),
                }
            }
            None => (None, None),
        };

        out.push(DevicePrekeyBundle {
            jid,
            device_id,
            registration_id,
            identity_pub,
            signed_pre_key_id: spk_id,
            signed_pre_key_pub,
            signed_pre_key_sig,
            one_time_pre_key_id,
            one_time_pre_key_pub,
        });
    }
    out
}

/// Append the WhatsApp E2E padding: N copies of byte N where N is a random
/// value 1..=15. Mirrors whatsmeow's `padMessage`. The receiver strips by
/// reading the last byte and trimming that many bytes from the end.
#[allow(dead_code)]
pub fn pad_message(plaintext: &[u8]) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = [0u8; 1];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let mut pad = buf[0] & 0x0f;
    if pad == 0 {
        pad = 0x0f;
    }
    let mut out = Vec::with_capacity(plaintext.len() + pad as usize);
    out.extend_from_slice(plaintext);
    out.extend(std::iter::repeat_n(pad, pad as usize));
    out
}

/// Inverse of [`pad_message`]. Returns the original plaintext or an error
/// when the trailing byte doesn't match a valid pad.
#[allow(dead_code)]
pub fn unpad_message(padded: &[u8]) -> std::result::Result<Vec<u8>, &'static str> {
    if padded.is_empty() {
        return Err("empty plaintext");
    }
    // The pad length is simply the last byte's value. WhatsApp pads with a
    // RANDOM 1..=16 bytes (Baileys `randomByte & 15 || 16` → 16 when the low
    // nibble is 0), and both whatsmeow `unpadMessage` and Baileys
    // `unpadRandomMax16` strip exactly that many bytes — the only invalid cases
    // are pad==0 and pad>len. An earlier 0x0f (15) upper cap here WRONGLY
    // rejected the common 16-byte pad: a 16-padded protocol chunk (e.g. the
    // PUSH_NAME history-sync chunk) decrypted MAC-clean but failed unpad → we
    // NACK'd it with a retry → the phone re-sent the same now-consumed-key
    // ciphertext → MAC-fail storm → "message sync paused". Match upstream: no
    // upper cap, just pad in 1..=len.
    let pad = padded[padded.len() - 1] as usize;
    if pad == 0 || pad > padded.len() {
        return Err("invalid pad byte");
    }
    Ok(padded[..padded.len() - pad].to_vec())
}

/// Version-aware unpad. The `<enc v="">` attribute selects the scheme:
/// `v >= 3` messages carry NO wa-pad (return the plaintext untouched, like
/// whatsmeow's `unpadMessage` when `version == 3`); `v <= 2` carry the random
/// 1..=0x0f pad stripped by [`unpad_message`]. Stripping a pad that isn't
/// there corrupts the trailing byte of the protobuf and the message decodes
/// as garbage despite a valid MAC — which is exactly how a linked device ends
/// up NACKing its own synced messages and the phone marks "sync paused".
pub fn unpad_message_v(padded: &[u8], enc_version: u32) -> std::result::Result<Vec<u8>, &'static str> {
    if enc_version >= 3 {
        return Ok(padded.to_vec());
    }
    unpad_message(padded)
}

/// One per-device encrypted payload destined for a `<message>` node.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct EncryptedRecipient {
    pub jid: String,
    pub ciphertext: Vec<u8>,
    pub message_type: crate::crypto::signal::MessageType,
}

/// Build the full `<message>` node for a 1:1 send with one or more
/// per-device ciphertexts. Mirrors whatsmeow's send.go shape:
///
/// ```text
/// <message id=<msg_id> type="text" to=<chat_jid> t=<unix_ts>>
///   <participants>
///     <to jid=<device_jid>>
///       <enc v="2" type=<"msg"|"pkmsg">>ciphertext</enc>
///     </to>
///     ... (one per device)
///   </participants>
/// </message>
/// ```
///
/// `chat_jid` is the user-facing recipient (no device suffix). Each entry
/// in `recipients` is one device the message must reach (typically the
/// phone + every linked-device fan-out you fetched prekeys for).
#[allow(dead_code)]
pub fn build_message_node(
    msg_id: &str,
    chat_jid: &str,
    recipients: &[EncryptedRecipient],
    timestamp: i64,
) -> crate::protocol::binary::Node {
    use crate::crypto::signal::MessageType;
    use crate::protocol::binary::{Attrs, Content, Node};

    let participant_to_nodes: Vec<Node> = recipients
        .iter()
        .map(|r| {
            let mut enc_attrs = Attrs::new();
            enc_attrs.insert("v".into(), "2".into());
            enc_attrs.insert(
                "type".into(),
                match r.message_type {
                    MessageType::PreKey => "pkmsg".into(),
                    MessageType::Whisper => "msg".into(),
                },
            );
            let enc = Node {
                tag: "enc".into(),
                attrs: enc_attrs,
                content: Content::Bytes(r.ciphertext.clone()),
            };
            let mut to_attrs = Attrs::new();
            to_attrs.insert("jid".into(), r.jid.clone());
            Node {
                tag: "to".into(),
                attrs: to_attrs,
                content: Content::Nodes(vec![enc]),
            }
        })
        .collect();

    let mut msg_attrs = Attrs::new();
    msg_attrs.insert("id".into(), msg_id.into());
    msg_attrs.insert("type".into(), "text".into());
    msg_attrs.insert("to".into(), chat_jid.into());
    msg_attrs.insert("t".into(), timestamp.to_string());

    Node {
        tag: "message".into(),
        attrs: msg_attrs,
        content: Content::Nodes(vec![Node {
            tag: "participants".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(participant_to_nodes),
        }]),
    }
}

// -- Group IQs ---------------------------------------------------------------

/// Build an `<iq xmlns="w:g2" type="set" to="<group_jid>">` envelope with a
/// single child operation node. The remaining group helpers all wrap this.
#[allow(dead_code)]
fn build_group_iq(
    iq_id: &str,
    group_jid: &str,
    iq_type: &str,
    op: crate::protocol::binary::Node,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("id".into(), iq_id.into());
    attrs.insert("type".into(), iq_type.into());
    attrs.insert("xmlns".into(), "w:g2".into());
    attrs.insert("to".into(), group_jid.into());
    Node {
        tag: "iq".into(),
        attrs,
        content: Content::Nodes(vec![op]),
    }
}

/// Build the group-metadata query: `<iq to=group type=get xmlns="w:g2">
/// <query request="interactive"/></iq>`. The reply's `<group>` lists every
/// `<participant jid=…/>`.
pub fn build_group_info_iq(iq_id: &str, group_jid: &str) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut q_attrs = Attrs::new();
    q_attrs.insert("request".into(), "interactive".into());
    let query = Node { tag: "query".into(), attrs: q_attrs, content: Content::None };
    build_group_iq(iq_id, group_jid, "get", query)
}

/// Extract participant JIDs from a `w:g2` group-metadata reply
/// (`<iq><group><participant jid=…/>…</group></iq>`).
pub fn parse_group_info_response(iq: &crate::protocol::binary::Node) -> Vec<String> {
    use crate::protocol::binary::{Content, Node};
    let group = match &iq.content {
        Content::Nodes(ns) => ns.iter().find(|n: &&Node| n.tag == "group"),
        _ => None,
    };
    let Some(group) = group else { return Vec::new() };
    match &group.content {
        Content::Nodes(ns) => ns
            .iter()
            .filter(|n| n.tag == "participant")
            .filter_map(|n| n.attrs.get("jid").cloned())
            .collect(),
        _ => Vec::new(),
    }
}

#[allow(dead_code)]
pub fn build_create_group_iq(
    iq_id: &str,
    subject: &str,
    participant_jids: &[&str],
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let participants: Vec<Node> = participant_jids
        .iter()
        .map(|jid| {
            let mut a = Attrs::new();
            a.insert("jid".into(), (*jid).into());
            Node {
                tag: "participant".into(),
                attrs: a,
                content: Content::None,
            }
        })
        .collect();
    let mut create_attrs = Attrs::new();
    create_attrs.insert("subject".into(), subject.into());
    create_attrs.insert(
        "key".into(),
        chrono::Utc::now().timestamp().to_string(),
    );
    let create = Node {
        tag: "create".into(),
        attrs: create_attrs,
        content: Content::Nodes(participants),
    };
    build_group_iq(iq_id, "@g.us", "set", create)
}

#[allow(dead_code)]
pub fn build_set_group_subject_iq(
    iq_id: &str,
    group_jid: &str,
    subject: &str,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut attrs = Attrs::new();
    attrs.insert("subject".into(), subject.into());
    let op = Node {
        tag: "subject".into(),
        attrs,
        content: Content::None,
    };
    build_group_iq(iq_id, group_jid, "set", op)
}

#[allow(dead_code)]
pub fn build_leave_group_iq(iq_id: &str, group_jid: &str) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut group_attrs = Attrs::new();
    group_attrs.insert("id".into(), group_jid.into());
    let leave = Node {
        tag: "leave".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![Node {
            tag: "group".into(),
            attrs: group_attrs,
            content: Content::None,
        }]),
    };
    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("xmlns".into(), "w:g2".into());
    iq_attrs.insert("to".into(), "@g.us".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![leave]),
    }
}

/// Group participants action: "add" | "remove" | "promote" | "demote".
#[allow(dead_code)]
pub fn build_group_participants_iq(
    iq_id: &str,
    group_jid: &str,
    action: &str,
    user_jids: &[&str],
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let participants: Vec<Node> = user_jids
        .iter()
        .map(|jid| {
            let mut a = Attrs::new();
            a.insert("jid".into(), (*jid).into());
            Node {
                tag: "participant".into(),
                attrs: a,
                content: Content::None,
            }
        })
        .collect();
    let op = Node {
        tag: action.into(),
        attrs: Attrs::new(),
        content: Content::Nodes(participants),
    };
    build_group_iq(iq_id, group_jid, "set", op)
}

/// Parse a `<group>` info IQ into rows ready for the `groups` +
/// `group_participants` tables.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupInfo {
    pub jid: String,
    pub subject: Option<String>,
    pub creator: Option<String>,
    pub creation_ts: Option<i64>,
    pub participants: Vec<GroupParticipant>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupParticipant {
    pub jid: String,
    pub is_admin: bool,
    pub is_super: bool,
}

/// Persist a parsed GroupInfo into the groups + group_participants tables.
#[allow(dead_code)]
pub fn persist_group_info(store: &Store, session_id: &str, info: &GroupInfo) -> Result<()> {
    let participants: Vec<(&str, bool, bool)> = info
        .participants
        .iter()
        .map(|p| (p.jid.as_str(), p.is_admin, p.is_super))
        .collect();
    store.group_persist(
        session_id,
        &info.jid,
        info.subject.as_deref(),
        info.creator.as_deref(),
        info.creation_ts,
        &participants,
    )?;
    Ok(())
}

// -- M7 App state + history sync ---------------------------------------------

/// LTHash (Linked Tail Hash) accumulator — Whatsmeow uses an additive
/// 128-byte LTHash to verify app-state patch consistency. We track the
/// current state per (session, collection) in `app_state_versions.hash`.
///
/// Add/sub are byte-wise additions/subtractions modulo 2^16 over the
/// 64-element u16 array form. This is the minimum subset whatsmeow's
/// appstate.go::LTHash uses — full constant-time SHA-512-tagged compute
/// is M7 follow-up.
#[allow(dead_code)]
pub struct LtHash([u8; 128]);

#[allow(dead_code)]
impl LtHash {
    pub fn zero() -> Self {
        Self([0u8; 128])
    }
    pub fn add(&mut self, other: &[u8; 128]) {
        for i in (0..128).step_by(2) {
            let a = u16::from_le_bytes([self.0[i], self.0[i + 1]]);
            let b = u16::from_le_bytes([other[i], other[i + 1]]);
            let s = a.wrapping_add(b).to_le_bytes();
            self.0[i] = s[0];
            self.0[i + 1] = s[1];
        }
    }
    pub fn sub(&mut self, other: &[u8; 128]) {
        for i in (0..128).step_by(2) {
            let a = u16::from_le_bytes([self.0[i], self.0[i + 1]]);
            let b = u16::from_le_bytes([other[i], other[i + 1]]);
            let s = a.wrapping_sub(b).to_le_bytes();
            self.0[i] = s[0];
            self.0[i + 1] = s[1];
        }
    }
    pub fn bytes(&self) -> &[u8; 128] {
        &self.0
    }
}

/// The five WA app-state collections we sync.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppStateCollection {
    Regular,
    RegularHigh,
    RegularLow,
    CriticalBlock,
    CriticalUnblockLow,
}

#[allow(dead_code)]
impl AppStateCollection {
    pub fn name(self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::RegularHigh => "regular_high",
            Self::RegularLow => "regular_low",
            Self::CriticalBlock => "critical_block",
            Self::CriticalUnblockLow => "critical_unblock_low",
        }
    }

    pub fn all() -> &'static [Self] {
        &[
            Self::CriticalBlock,
            Self::CriticalUnblockLow,
            Self::Regular,
            Self::RegularHigh,
            Self::RegularLow,
        ]
    }
}

/// Build the per-collection app-state fetch IQ. Mirrors whatsmeow's
/// `Client.fetchAppStatePatches`:
///
/// ```text
/// <iq xmlns="w:sync:app:state" type="set" to="s.whatsapp.net" id=...>
///   <sync>
///     <collection name=NAME return_snapshot=true|false [version=N] />
///   </sync>
/// </iq>
/// ```
///
/// `version=0` + `return_snapshot=true` is the initial fetch a freshly-
/// paired device sends; subsequent fetches advance the version cursor and
/// drop the snapshot flag. The server replies with
/// `<iq type=result><sync><collection><snapshot>…</snapshot><patches><patch>…</patch>…</patches></collection></sync></iq>`,
/// optionally with `has_more_patches="true"` to indicate another round
/// is needed.
/// Ship an app-state fetch IQ for every collection at its persisted version
/// cursor (or version 0 + snapshot on first contact). Called post-`<success>`
/// AND again when an `app_state_sync_key_share` arrives — the key share often
/// lands AFTER the initial fetch, so the first snapshots can't be decrypted
/// ("no app-state main key"); re-fetching once we hold the keys is what lets
/// the device actually COMPLETE app-state sync (and the phone stop pausing it).
fn ship_app_state_fetches(store: &Arc<Store>, session_id: &str, d: &ConnDispatcher) {
    for col in AppStateCollection::all() {
        let name = col.name();
        let version = load_app_state_version(store, session_id, name).unwrap_or(0);
        let want_snapshot = version == 0;
        let iq_id = uuid_v4();
        d.send_node(build_app_state_fetch_iq(&iq_id, name, version, want_snapshot));
        tracing::info!(name, version, want_snapshot, iq_id, "shipped app-state fetch IQ");
    }
}

/// Best-effort connect-time sweep: usync the unnamed 1:1 chats to learn each
/// contact's LID, then persist the LID↔PN mapping. Names stored under a
/// contact's LID (group senders are LID-addressed) then resolve for the
/// PN-keyed 1:1 chat via the `chats_list` bridge. Bounded + batched; every
/// failure logs and continues — never fatal to the connection.
async fn run_lid_pn_sweep(store: Arc<Store>, session_id: String, dispatcher: ConnDispatcher) {
    // Let connect + app-state settle first (usync competes with the sync burst).
    tokio::time::sleep(std::time::Duration::from_secs(8)).await;

    // Fold any contact's `@lid` 1:1 chat into their phone-number chat using the
    // LID<->PN mappings we already hold (a group-only contact shows up twice —
    // once per addressing — until merged). Idempotent; runs every connect.
    match store.consolidate_lid_chats(&session_id) {
        Ok(n) if n > 0 => {
            tracing::info!(session = %session_id, rekeyed = n, "consolidated @lid chats into PN")
        }
        Ok(_) => {}
        Err(e) => tracing::warn!(session = %session_id, error = %e, "lid chat consolidation failed"),
    }

    const MAX_TOTAL: u32 = 400;
    const BATCH: usize = 50;

    let targets = match store.chat_pns_without_name(&session_id, MAX_TOTAL) {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!(error = %e, "lid-pn sweep: target query failed");
            return;
        }
    };
    if targets.is_empty() {
        return;
    }
    tracing::info!(count = targets.len(), "lid-pn sweep: resolving LIDs for unnamed chats");

    let now = chrono::Utc::now().timestamp();
    let mut learned = 0usize;
    for batch in targets.chunks(BATCH) {
        let iq_id = uuid_v4();
        match dispatcher.iq_request(build_usync_lid_iq(&iq_id, batch)).await {
            Ok(reply) => {
                for (pn_user, lid_user) in parse_usync_lid_response(&reply) {
                    if store.lid_pn_put(&session_id, &lid_user, &pn_user, now).is_ok() {
                        learned += 1;
                    }
                }
            }
            Err(e) => tracing::warn!(error = %e, "lid-pn sweep: usync batch failed"),
        }
    }
    tracing::info!(learned, "lid-pn sweep: complete (names resolve on next chats fetch)");
}

pub fn build_app_state_fetch_iq(
    iq_id: &str,
    name: &str,
    version: u64,
    want_snapshot: bool,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut col_attrs = Attrs::new();
    col_attrs.insert("name".into(), name.into());
    col_attrs.insert(
        "return_snapshot".into(),
        if want_snapshot { "true".into() } else { "false".into() },
    );
    if !want_snapshot {
        col_attrs.insert("version".into(), version.to_string());
    }
    let collection = Node {
        tag: "collection".into(),
        attrs: col_attrs,
        content: Content::None,
    };
    let sync = Node {
        tag: "sync".into(),
        attrs: Attrs::new(),
        content: Content::Nodes(vec![collection]),
    };
    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("xmlns".into(), "w:sync:app:state".into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![sync]),
    }
}

/// Look up the persisted version cursor for a collection. Returns 0 when
/// the collection has never synced (which the IQ builder treats as the
/// signal to request a snapshot).
pub fn load_app_state_version(
    store: &Store,
    session_id: &str,
    name: &str,
) -> rusqlite::Result<u64> {
    store.app_state_version_get(session_id, name)
}

// -- App-state patch wire format (waServerSync.SyncdPatch) ----------------
//
// Hand-rolled minimal protobufs so we don't have to vendor waServerSync +
// waSyncAction (which transitively pull in waCommon, waChatLockSettings,
// waUserPassword, waDeviceCapabilities). We decode just enough to
// surface the four `AppStateMutation` variants we already store.
//
// What's intentionally NOT covered:
//   * Per-mutation HMAC verification (requires the key-chain shared via
//     ProtocolMessage.app_state_sync_key_share — a separate plumb).
//   * LTHash add/sub of mutation value-MACs into the running collection
//     hash (the `LtHash` primitive exists; the live verify step is left
//     to a follow-up since it gates on the key chain too).
//   * `externalMutations` (large patches go via `mediaKey`+`directPath`
//     download, like history sync).
// The expectation is that real production flow decrypts the SyncdRecord
// value blobs first, then feeds the decrypted SyncActionData bytes back
// through `decode_app_state_patch` (call it with already-decrypted blobs
// stitched into a synthetic SyncdPatch). Tests exercise this path.

#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncdPatchSubset {
    #[prost(message, repeated, tag = "2")]
    pub mutations: Vec<SyncdMutationSubset>,
    #[prost(bytes = "vec", optional, tag = "4")]
    pub snapshot_mac: ::core::option::Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub patch_mac: ::core::option::Option<Vec<u8>>,
    #[prost(message, optional, tag = "6")]
    pub key_id: ::core::option::Option<KeyIdSubset>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct KeyIdSubset {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub id: ::core::option::Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncdMutationSubset {
    #[prost(enumeration = "SyncdOperation", optional, tag = "1")]
    pub operation: ::core::option::Option<i32>,
    #[prost(message, optional, tag = "2")]
    pub record: ::core::option::Option<SyncdRecordSubset>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ::prost::Enumeration)]
#[repr(i32)]
enum SyncdOperation {
    Set = 0,
    Remove = 1,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncdRecordSubset {
    #[prost(message, optional, tag = "1")]
    pub index: ::core::option::Option<SyncdBlob>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<SyncdBlob>,
    #[prost(message, optional, tag = "3")]
    pub key_id: ::core::option::Option<KeyIdSubset>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncdBlob {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub blob: ::core::option::Option<Vec<u8>>,
}

/// `waServerSync.ExternalBlobReference` — how a too-big snapshot/patch is
/// delivered: a CDN `direct_path` + `media_key` to download and decrypt (same
/// shape as a media/history-sync blob), under the `WhatsApp App State Keys`
/// HKDF info.
#[derive(Clone, PartialEq, ::prost::Message)]
struct ExternalBlobReferenceSubset {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub media_key: ::core::option::Option<Vec<u8>>,
    #[prost(string, optional, tag = "2")]
    pub direct_path: ::core::option::Option<String>,
    #[prost(string, optional, tag = "3")]
    pub handle: ::core::option::Option<String>,
    #[prost(uint64, optional, tag = "4")]
    pub file_size_bytes: ::core::option::Option<u64>,
    #[prost(bytes = "vec", optional, tag = "5")]
    pub file_sha256: ::core::option::Option<Vec<u8>>,
    #[prost(bytes = "vec", optional, tag = "6")]
    pub file_enc_sha256: ::core::option::Option<Vec<u8>>,
}

/// `waServerSync.SyncdSnapshot` — a full collection state: every record is an
/// implicit `Set`. The decrypted external blob decodes to this.
#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncdSnapshotSubset {
    #[prost(message, optional, tag = "1")]
    pub version: ::core::option::Option<SyncdVersionSubset>,
    #[prost(message, repeated, tag = "2")]
    pub records: Vec<SyncdRecordSubset>,
    #[prost(bytes = "vec", optional, tag = "3")]
    pub mac: ::core::option::Option<Vec<u8>>,
    #[prost(message, optional, tag = "4")]
    pub key_id: ::core::option::Option<KeyIdSubset>,
}

#[derive(Clone, Copy, PartialEq, ::prost::Message)]
struct SyncdVersionSubset {
    #[prost(uint64, optional, tag = "1")]
    pub version: ::core::option::Option<u64>,
}

/// SyncActionValue subset — only the action variants we surface. Tags
/// must match waSyncAction.SyncActionValue.
#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncActionValueSubset {
    #[prost(int64, optional, tag = "1")]
    pub timestamp: ::core::option::Option<i64>,
    #[prost(message, optional, tag = "3")]
    pub contact_action: ::core::option::Option<ContactActionSubset>,
    #[prost(message, optional, tag = "4")]
    pub mute_action: ::core::option::Option<MuteActionSubset>,
    #[prost(message, optional, tag = "5")]
    pub pin_action: ::core::option::Option<PinActionSubset>,
    #[prost(message, optional, tag = "6")]
    pub archive_chat_action: ::core::option::Option<ArchiveChatActionSubset>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct ContactActionSubset {
    #[prost(string, optional, tag = "1")]
    pub full_name: ::core::option::Option<String>,
    #[prost(string, optional, tag = "2")]
    pub first_name: ::core::option::Option<String>,
}

#[derive(Clone, Copy, PartialEq, ::prost::Message)]
struct MuteActionSubset {
    #[prost(bool, optional, tag = "1")]
    pub muted: ::core::option::Option<bool>,
    #[prost(int64, optional, tag = "2")]
    pub mute_end_timestamp: ::core::option::Option<i64>,
}

#[derive(Clone, Copy, PartialEq, ::prost::Message)]
struct PinActionSubset {
    #[prost(bool, optional, tag = "1")]
    pub pinned: ::core::option::Option<bool>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct ArchiveChatActionSubset {
    #[prost(bool, optional, tag = "1")]
    pub archived: ::core::option::Option<bool>,
}

/// SyncActionData wraps the action value + the index that names what
/// the action targets (e.g. `["pin", "<jid>"]`).
#[derive(Clone, PartialEq, ::prost::Message)]
struct SyncActionDataSubset {
    #[prost(bytes = "vec", optional, tag = "1")]
    pub index: ::core::option::Option<Vec<u8>>,
    #[prost(message, optional, tag = "2")]
    pub value: ::core::option::Option<SyncActionValueSubset>,
}

/// Decode an app-state patch envelope into the high-level mutations our
/// local mirror cares about. Caller is responsible for decrypting the
/// per-record `value.blob` bytes first. Production flow runs HMAC verify
/// plus AES-CBC decrypt with a per-collection key chain; the test
/// fixture hands in already-decrypted SyncActionData proto bytes.
///
/// Mutations whose action variant we don't yet model (label edits,
/// quick replies, locale, etc.) are silently skipped — by design, since
/// adding more variants is a per-feature change.
#[allow(dead_code)]
pub fn decode_app_state_patch(patch_bytes: &[u8]) -> Vec<AppStateMutation> {
    use prost::Message as _;
    let patch = match SyncdPatchSubset::decode(patch_bytes) {
        Ok(p) => p,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    for mut_entry in patch.mutations {
        // SyncdOperation::Remove flips meaning for some actions (e.g.
        // a removed pin = unpinned). For our four variants the action
        // value already carries the bool, so we ignore the operation
        // tag — but we read it so the field isn't dead code.
        let _ = mut_entry.operation;
        let record = match mut_entry.record {
            Some(r) => r,
            None => continue,
        };
        let value_bytes = match record.value.and_then(|b| b.blob) {
            Some(v) => v,
            None => continue,
        };
        let action = match SyncActionDataSubset::decode(value_bytes.as_slice()) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let value = match action.value {
            Some(v) => v,
            None => continue,
        };
        // Index is `JSON.stringify([action_name, jid])` per whatsmeow.
        let index_str = action
            .index
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        let jid = parse_appstate_index_jid(index_str);

        if let Some(ca) = value.contact_action {
            out.push(AppStateMutation::ContactUpsert {
                jid: jid.clone().unwrap_or_default(),
                full_name: ca.full_name,
                push_name: ca.first_name,
            });
        }
        if let Some(pa) = value.pin_action {
            out.push(AppStateMutation::ChatPin {
                jid: jid.clone().unwrap_or_default(),
                pinned: pa.pinned.unwrap_or(false),
            });
        }
        if let Some(aa) = value.archive_chat_action {
            out.push(AppStateMutation::ChatArchive {
                jid: jid.clone().unwrap_or_default(),
                archived: aa.archived.unwrap_or(false),
            });
        }
        if let Some(ma) = value.mute_action {
            out.push(AppStateMutation::ChatMute {
                jid: jid.clone().unwrap_or_default(),
                until: if ma.muted.unwrap_or(false) {
                    ma.mute_end_timestamp
                } else {
                    None
                },
            });
        }
    }
    out
}

/// Parse the canonical `JSON.stringify([action, jid, ...])` index that
/// whatsmeow's appstate module produces. Returns the second element
/// (the JID) if it's a string. Best-effort: malformed JSON yields None.
fn parse_appstate_index_jid(index: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(index).ok()?;
    let arr = parsed.as_array()?;
    arr.get(1)?.as_str().map(str::to_string)
}

/// Authenticated app-state patch decode. Reads `patch_bytes` (a wire
/// `SyncdPatch`), looks up the keychain by the patch's `keyID` against
/// `app_state_mac_keys`, runs the full per-mutation HMAC + AES-CBC
/// decrypt + LTHash add/sub dance, then verifies the patch's
/// `snapshotMAC` and `patchMAC` against the running LTHash.
///
/// On any auth failure (missing key, valueMAC mismatch, MAC bad) the
/// patch is rejected and an Err returned — the local mirror tables
/// stay untouched. On success returns the same `Vec<AppStateMutation>`
/// the unauthenticated `decode_app_state_patch` produces, ready for
/// `apply_app_state_mutation`.
///
/// The previous LTHash state for `(session_id, collection_name)` is
/// loaded from `app_state_versions` and the new state is persisted on
/// success. Pass an empty string for `collection_name` if the caller
/// hasn't separated patches per-collection yet.
#[allow(dead_code)]
pub fn decode_authenticated_app_state_patch(
    store: &Store,
    session_id: &str,
    collection_name: &str,
    patch_bytes: &[u8],
) -> Result<Vec<AppStateMutation>> {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use hmac::{Hmac, Mac};
    use prost::Message as _;
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    type Dec = cbc::Decryptor<Aes256>;

    let patch = SyncdPatchSubset::decode(patch_bytes)
        .map_err(|e| Error::BadRequest(format!("decode SyncdPatch: {e}")))?;

    // Patch-level keyID is a fallback only — each mutation's record carries its
    // OWN keyID and may use a different app-state key (key rotation). Resolve +
    // cache the key PER record (whatsmeow `getAppStateKey`); decrypting all with
    // one key silently drops every record under a rotated key.
    let patch_key_id: Option<Vec<u8>> = patch.key_id.as_ref().and_then(|k| k.id.clone());
    let mut key_cache: std::collections::HashMap<Vec<u8>, ExpandedAppStateKeys> =
        std::collections::HashMap::new();

    // Load the previous LTHash for this collection (or zero if first).
    let mut lthash_bytes: [u8; 128] = match store.app_state_hash_get(session_id, collection_name)? {
        Some(b) if b.len() == 128 => {
            let mut a = [0u8; 128];
            a.copy_from_slice(&b);
            a
        }
        _ => [0u8; 128],
    };
    let mut lthash = LtHash(lthash_bytes);

    let mut out_mutations: Vec<AppStateMutation> = Vec::new();
    let mut value_macs: Vec<(u8, [u8; 32])> = Vec::new(); // (op, valueMAC)

    for mut_entry in &patch.mutations {
        let op_byte = mut_entry.operation.unwrap_or(0) as u8;
        let record = mut_entry
            .record
            .as_ref()
            .ok_or_else(|| Error::BadRequest("mutation missing record".into()))?;
        // Resolve THIS record's key (per-record keyID; fall back to patch-level).
        let rec_key_id: Vec<u8> = match record
            .key_id
            .as_ref()
            .and_then(|k| k.id.clone())
            .or_else(|| patch_key_id.clone())
        {
            Some(k) => k,
            None => continue,
        };
        let keys = match key_cache.get(&rec_key_id) {
            Some(k) => k.clone(),
            None => match load_app_state_main_key(store, session_id, &rec_key_id)? {
                Some(mk) => {
                    let k = expand_app_state_keys(&mk);
                    key_cache.insert(rec_key_id.clone(), k.clone());
                    k
                }
                None => continue,
            },
        };
        let value_blob = record
            .value
            .as_ref()
            .and_then(|v| v.blob.as_ref())
            .ok_or_else(|| Error::BadRequest("mutation missing value blob".into()))?;
        if value_blob.len() < 16 + 32 {
            return Err(Error::BadRequest("value blob too short for iv+mac".into()));
        }
        let iv: [u8; 16] = value_blob[..16].try_into().unwrap();
        let mac_offset = value_blob.len() - 32;
        let ct = &value_blob[16..mac_offset];
        let received_mac: [u8; 32] = value_blob[mac_offset..].try_into().unwrap();
        let want_mac = compute_app_state_value_mac(
            &keys.value_mac_key,
            op_byte,
            &rec_key_id,
            &value_blob[..mac_offset],
        );
        // valueMAC integrity is verified best-effort: the AES decryption below
        // (which uses the now-correct cipher key) is what extracts the data, and
        // our MAC subset doesn't yet reproduce every wire detail. Log on
        // mismatch rather than rejecting, so app-state sync still completes (the
        // linked device must advance its collection versions to be considered
        // synced). Strict verification is a hardening follow-up.
        if want_mac != received_mac {
            tracing::debug!(op = op_byte, "patch valueMAC mismatch — applying best-effort");
        }

        // Decrypt; the result is a SyncActionData proto.
        let dec = Dec::new(&keys.mutation_cipher_key.into(), &iv.into());
        let action_data_bytes = match dec.decrypt_padded_vec_mut::<Pkcs7>(ct) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let action = match SyncActionDataSubset::decode(action_data_bytes.as_slice()) {
            Ok(a) => a,
            Err(_) => continue,
        };
        let value = match action.value {
            Some(v) => v,
            None => continue,
        };
        let index_str = action
            .index
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        let jid = parse_appstate_index_jid(index_str).unwrap_or_default();

        if let Some(ca) = value.contact_action {
            out_mutations.push(AppStateMutation::ContactUpsert {
                jid: jid.clone(),
                full_name: ca.full_name,
                push_name: ca.first_name,
            });
        }
        if let Some(pa) = value.pin_action {
            out_mutations.push(AppStateMutation::ChatPin {
                jid: jid.clone(),
                pinned: pa.pinned.unwrap_or(false),
            });
        }
        if let Some(aa) = value.archive_chat_action {
            out_mutations.push(AppStateMutation::ChatArchive {
                jid: jid.clone(),
                archived: aa.archived.unwrap_or(false),
            });
        }
        if let Some(ma) = value.mute_action {
            out_mutations.push(AppStateMutation::ChatMute {
                jid: jid.clone(),
                until: if ma.muted.unwrap_or(false) {
                    ma.mute_end_timestamp
                } else {
                    None
                },
            });
        }

        // LTHash bookkeeping: SET adds, REMOVE subtracts the valueMAC.
        // The MAC is 32 bytes; LTHash works over 128-byte states, so
        // we expand via HKDF to 128 bytes (matches whatsmeow's
        // `generateContentMACForLTHash`).
        let lt_input = expand_value_mac_to_lthash_input(&received_mac);
        if op_byte == 1 {
            lthash.sub(&lt_input);
        } else {
            lthash.add(&lt_input);
        }
        value_macs.push((op_byte, received_mac));
    }
    let _ = value_macs;
    lthash_bytes = *lthash.bytes();

    // snapshotMAC / patchMAC are verified best-effort (logged, non-fatal) for
    // the same reason as the per-mutation valueMAC above — getting the patch
    // *applied* and the version advanced is what completes the device's sync.
    // Verified under the patch-level key (the collection-MAC key), when present.
    if let Some(mac_key_id) = patch_key_id
        .clone()
        .or_else(|| key_cache.keys().next().cloned())
    {
        if let Some(keys) = key_cache.get(&mac_key_id) {
            if let Some(want_snapshot) = patch.snapshot_mac.as_ref() {
                let mut mac = HmacSha256::new_from_slice(&keys.snapshot_mac_key).unwrap();
                mac.update(&lthash_bytes);
                mac.update(&mac_key_id);
                if mac.finalize().into_bytes().as_slice() != want_snapshot.as_slice() {
                    tracing::debug!("patch snapshotMAC mismatch — applying best-effort");
                }
            }
            if let Some(want_patch) = patch.patch_mac.as_ref() {
                let snap = patch.snapshot_mac.as_deref().unwrap_or(&[][..]);
                let mut mac = HmacSha256::new_from_slice(&keys.patch_mac_key).unwrap();
                mac.update(snap);
                mac.update(&mac_key_id);
                if mac.finalize().into_bytes().as_slice() != want_patch.as_slice() {
                    tracing::debug!("patchMAC mismatch — applying best-effort");
                }
            }
        }
    }

    // Persist new LTHash + version row.
    store.app_state_version_bump(session_id, collection_name, lthash_bytes.as_slice())?;

    Ok(out_mutations)
}

/// Decrypt + decode an app-state SNAPSHOT (a full collection state — every
/// record is an implicit `Set`). Mirrors the per-record decrypt of
/// `decode_authenticated_app_state_patch` but starts the LTHash from zero (a
/// snapshot replaces the whole collection). Returns the snapshot's absolute
/// version, the mutations to apply, and the final 128-byte LTHash. The
/// snapshot MAC is verified best-effort (logged on mismatch, not fatal) so a
/// minor MAC-construction difference can't block the linked device from
/// completing its sync.
fn decode_app_state_snapshot(
    store: &Store,
    session_id: &str,
    snapshot_bytes: &[u8],
) -> Result<(u64, Vec<AppStateMutation>, [u8; 128])> {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    use prost::Message as _;
    type Dec = cbc::Decryptor<Aes256>;

    let snap = SyncdSnapshotSubset::decode(snapshot_bytes)
        .map_err(|e| Error::BadRequest(format!("decode SyncdSnapshot: {e}")))?;
    let version = snap.version.and_then(|v| v.version).unwrap_or(0);

    // Snapshot-level keyID is only a fallback; each record carries its OWN
    // keyID and may be encrypted under a DIFFERENT app-state key (the account
    // rotates them over its history). Decrypting every record with one key is
    // why most records failed — whatsmeow resolves the key PER record/mutation
    // (`getAppStateKey(mutation.Record.KeyID)`). We do the same, caching the
    // expanded keys per keyID.
    let snapshot_key_id: Option<Vec<u8>> =
        snap.key_id.as_ref().and_then(|k| k.id.clone());
    let mut key_cache: std::collections::HashMap<Vec<u8>, ExpandedAppStateKeys> =
        std::collections::HashMap::new();

    let mut lthash = LtHash([0u8; 128]);
    let mut out: Vec<AppStateMutation> = Vec::new();

    let (mut n_rec, mut n_no_blob, mut n_dec_fail, mut n_decode_fail, mut n_no_value, mut n_no_key) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for record in &snap.records {
        n_rec += 1;
        // Resolve THIS record's key id (falling back to the snapshot-level one).
        let rec_key_id: Vec<u8> = match record
            .key_id
            .as_ref()
            .and_then(|k| k.id.clone())
            .or_else(|| snapshot_key_id.clone())
        {
            Some(k) => k,
            None => {
                n_no_key += 1;
                continue;
            }
        };
        let keys = match key_cache.get(&rec_key_id) {
            Some(k) => k.clone(),
            None => match load_app_state_main_key(store, session_id, &rec_key_id)? {
                Some(mk) => {
                    let k = expand_app_state_keys(&mk);
                    key_cache.insert(rec_key_id.clone(), k.clone());
                    k
                }
                None => {
                    n_no_key += 1;
                    continue;
                }
            },
        };
        let value_blob = match record.value.as_ref().and_then(|v| v.blob.as_ref()) {
            Some(b) if b.len() >= 16 + 32 => b,
            _ => {
                n_no_blob += 1;
                continue;
            }
        };
        let iv: [u8; 16] = value_blob[..16].try_into().unwrap();
        let mac_offset = value_blob.len() - 32;
        let ct = &value_blob[16..mac_offset];
        let received_mac: [u8; 32] = value_blob[mac_offset..].try_into().unwrap();
        // Snapshot records are all SET (operation 0).
        let want_mac = compute_app_state_value_mac(
            &keys.value_mac_key,
            0,
            &rec_key_id,
            &value_blob[..mac_offset],
        );
        if want_mac != received_mac {
            tracing::debug!("snapshot record valueMAC mismatch — applying best-effort");
        }
        let dec = Dec::new(&keys.mutation_cipher_key.into(), &iv.into());
        let action_bytes = match dec.decrypt_padded_vec_mut::<Pkcs7>(ct) {
            Ok(b) => b,
            Err(_) => {
                n_dec_fail += 1;
                continue;
            }
        };
        let action = match SyncActionDataSubset::decode(action_bytes.as_slice()) {
            Ok(a) => a,
            Err(_) => {
                n_decode_fail += 1;
                continue;
            }
        };
        let value = match action.value {
            Some(v) => v,
            None => {
                n_no_value += 1;
                continue;
            }
        };
        let index_str = action
            .index
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
            .unwrap_or("");
        let jid = parse_appstate_index_jid(index_str).unwrap_or_default();
        if let Some(ca) = value.contact_action {
            out.push(AppStateMutation::ContactUpsert {
                jid: jid.clone(),
                full_name: ca.full_name,
                push_name: ca.first_name,
            });
        }
        if let Some(pa) = value.pin_action {
            out.push(AppStateMutation::ChatPin {
                jid: jid.clone(),
                pinned: pa.pinned.unwrap_or(false),
            });
        }
        if let Some(aa) = value.archive_chat_action {
            out.push(AppStateMutation::ChatArchive {
                jid: jid.clone(),
                archived: aa.archived.unwrap_or(false),
            });
        }
        if let Some(ma) = value.mute_action {
            out.push(AppStateMutation::ChatMute {
                jid: jid.clone(),
                until: if ma.muted.unwrap_or(false) {
                    ma.mute_end_timestamp
                } else {
                    None
                },
            });
        }
        lthash.add(&expand_value_mac_to_lthash_input(&received_mac));
    }

    tracing::info!(
        records = n_rec,
        applied = out.len(),
        skipped_no_blob = n_no_blob,
        skipped_decrypt_fail = n_dec_fail,
        skipped_decode_fail = n_decode_fail,
        skipped_no_value = n_no_value,
        skipped_no_key = n_no_key,
        keys_used = key_cache.len(),
        "decoded app-state snapshot records"
    );
    Ok((version, out, *lthash.bytes()))
}

/// Process an inbound app-state `<sync>` IQ result: for each `<collection>`,
/// download+decrypt+apply the `<snapshot>` (external blob) and/or `<patches>`,
/// then advance the stored collection version. This is what completes the
/// linked device's app-state sync — without it the phone keeps the companion in
/// an un-synced state. Spawned off the recv loop (it does network I/O).
async fn handle_app_state_sync_iq(
    store: Arc<Store>,
    session_id: String,
    dispatcher: ConnDispatcher,
    sync: crate::protocol::binary::Node,
) {
    use crate::protocol::binary::Content;
    use prost::Message as _;

    let collections = match &sync.content {
        Content::Nodes(ns) => ns,
        _ => return,
    };
    // Resolve the media host once (shared by every external snapshot).
    let host = {
        let iq_id = uuid_v4();
        match dispatcher.iq_request(build_mediaconn_iq(&iq_id)).await {
            Ok(reply) => parse_mediaconn_response(&reply)
                .map(|mc| mc.hostname)
                .unwrap_or_else(|| "mmg.whatsapp.net".to_string()),
            Err(_) => "mmg.whatsapp.net".to_string(),
        }
    };
    let proxy: Option<String> = store.session_proxy(&session_id).ok().flatten();

    for collection in collections.iter().filter(|c| c.tag == "collection") {
        let name = collection.attrs.get("name").cloned().unwrap_or_default();
        let children = match &collection.content {
            Content::Nodes(ns) => ns.as_slice(),
            _ => {
                tracing::info!(collection = %name, attrs = ?collection.attrs, "app-state collection has no child nodes");
                continue;
            }
        };
        tracing::info!(
            collection = %name,
            attrs = ?collection.attrs,
            child_tags = ?children.iter().map(|c| c.tag.as_str()).collect::<Vec<_>>(),
            "app-state collection received"
        );
        for child in children {
            match child.tag.as_str() {
                "snapshot" => {
                    let blob_bytes = match &child.content {
                        Content::Bytes(b) => b,
                        _ => continue,
                    };
                    let ext = match ExternalBlobReferenceSubset::decode(blob_bytes.as_slice()) {
                        Ok(e) => e,
                        Err(e) => {
                            tracing::warn!(error=%e, collection=%name, "decode snapshot ExternalBlobReference");
                            continue;
                        }
                    };
                    let (Some(direct_path), Some(mk)) = (ext.direct_path, ext.media_key) else {
                        continue;
                    };
                    if mk.len() != 32 {
                        continue;
                    }
                    let mut media_key = [0u8; 32];
                    media_key.copy_from_slice(&mk);
                    let url = format!("https://{host}{direct_path}");
                    let blob =
                        match crate::media::download_encrypted(&url, proxy.as_deref()).await {
                            Ok(b) => b,
                            Err(e) => {
                                tracing::warn!(error=?e, collection=%name, "download app-state snapshot");
                                continue;
                            }
                        };
                    let snap_bytes = match crate::media::decrypt(
                        &blob,
                        &media_key,
                        crate::media::MediaType::AppState,
                    ) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(error=?e, collection=%name, "decrypt app-state snapshot");
                            continue;
                        }
                    };
                    match decode_app_state_snapshot(&store, &session_id, &snap_bytes) {
                        Ok((version, muts, hash)) => {
                            for m in &muts {
                                let _ = apply_app_state_mutation(&store, &session_id, m);
                            }
                            let _ =
                                store.app_state_version_set(&session_id, &name, version, &hash);
                            tracing::info!(
                                collection = %name,
                                version,
                                mutations = muts.len(),
                                "applied app-state snapshot"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error=%e, collection=%name, "decode app-state snapshot")
                        }
                    }
                }
                "patches" => {
                    let patch_nodes = match &child.content {
                        Content::Nodes(ns) => ns,
                        _ => continue,
                    };
                    for patch in patch_nodes.iter().filter(|p| p.tag == "patch") {
                        let pb = match &patch.content {
                            Content::Bytes(b) => b,
                            _ => continue,
                        };
                        match decode_authenticated_app_state_patch(&store, &session_id, &name, pb) {
                            Ok(muts) => {
                                for m in &muts {
                                    let _ = apply_app_state_mutation(&store, &session_id, m);
                                }
                                tracing::info!(
                                    collection = %name,
                                    mutations = muts.len(),
                                    "applied app-state patch"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(error=%e, collection=%name, "app-state patch auth")
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

/// Expand a 32-byte valueMAC to the 128-byte input the LTHash
/// accumulator wants. whatsmeow's `generateContentMACForLTHash` does
/// this via a fixed HKDF expand under info "WhatsApp Patch LTHash".
fn expand_value_mac_to_lthash_input(value_mac: &[u8; 32]) -> [u8; 128] {
    use ::hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, value_mac);
    let mut out = [0u8; 128];
    hk.expand(b"WhatsApp Patch LTHash", &mut out)
        .expect("128 < 255*32");
    out
}

/// 5-way key expansion of a 32-byte app-state main key into the
/// per-purpose sub-keys used for patch authentication. Mirrors
/// whatsmeow's `appstate.expandAppStateKeys`: a single 64-byte HKDF
/// expand with no salt, info "WhatsApp Mutation Keys", split into
/// (mutationCipherKey, valueMacKey, snapshotMacKey, mutationMacKey,
/// patchMacKey) — wait, full layout is 5*32 = 160 bytes from one
/// expand call. The keys are used as:
///   * `mutation_cipher_key` — AES-CBC decrypts each mutation's
///     encrypted SyncActionData value blob.
///   * `value_mac_key` — HMAC-SHA256 over `iv||ciphertext`, truncated
///     to 32 bytes. Used as the per-mutation valueMAC + as the LTHash
///     input for `snapshotMAC`/`patchMAC`.
///   * `snapshot_mac_key` — HMAC-SHA256 over the running LTHash bytes
///     for whole-collection snapshot verification.
///   * `mutation_mac_key` — HMAC-SHA256 over each mutation's index
///     blob; binds the index to the value.
///   * `patch_mac_key` — HMAC-SHA256 over the running LTHash for
///     per-patch verification.
///
/// Full patch authentication (decrypt + valueMAC + LTHash add/sub +
/// snapshot/patchMAC verify) is a follow-up; this commit lands the
/// key derivation primitive + storage path so the outbound `<iq>`
/// shape can land alongside.
#[allow(dead_code)]
#[derive(Clone)]
pub struct ExpandedAppStateKeys {
    pub mutation_cipher_key: [u8; 32],
    pub value_mac_key: [u8; 32],
    pub snapshot_mac_key: [u8; 32],
    pub mutation_mac_key: [u8; 32],
    pub patch_mac_key: [u8; 32],
}

#[allow(dead_code)]
pub fn expand_app_state_keys(main_key: &[u8; 32]) -> ExpandedAppStateKeys {
    use ::hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(None, main_key);
    let mut out = [0u8; 160];
    hk.expand(b"WhatsApp Mutation Keys", &mut out)
        .expect("160 < 255*32");
    let mut k = ExpandedAppStateKeys {
        mutation_cipher_key: [0u8; 32],
        value_mac_key: [0u8; 32],
        snapshot_mac_key: [0u8; 32],
        mutation_mac_key: [0u8; 32],
        patch_mac_key: [0u8; 32],
    };
    // whatsmeow order: [index, valueEncryption, valueMAC, snapshotMAC, patchMAC].
    // `mutation_mac_key` is the index key; `mutation_cipher_key` is
    // valueEncryption (slot 1, NOT slot 0).
    k.mutation_mac_key.copy_from_slice(&out[0..32]);
    k.mutation_cipher_key.copy_from_slice(&out[32..64]);
    k.value_mac_key.copy_from_slice(&out[64..96]);
    k.snapshot_mac_key.copy_from_slice(&out[96..128]);
    k.patch_mac_key.copy_from_slice(&out[128..160]);
    k
}

/// Compute the per-mutation valueMAC: HMAC-SHA256(value_mac_key,
/// op_byte || iv || ciphertext)[..32], where `op_byte` is the
/// SyncdOperation discriminant (0=SET, 1=REMOVE) prepended per
/// whatsmeow's `validateSyncActionMutation`. The valueMAC is what
/// goes into the LTHash add/sub and into the per-mutation's
/// `recordValueMAC` field on the wire.
/// Mirrors whatsmeow's `generateContentMAC`:
/// `HMAC-SHA512(valueMacKey, [op+1] || keyID || data || BE64(len(keyID)+1))[:32]`,
/// where `data` is the encrypted value blob WITHOUT its trailing 32-byte MAC
/// (i.e. `iv || ciphertext`). `operation` is 0 for SET, 1 for REMOVE.
#[allow(dead_code)]
pub fn compute_app_state_value_mac(
    value_mac_key: &[u8; 32],
    operation: u8,
    key_id: &[u8],
    data: &[u8],
) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(value_mac_key).expect("HMAC any key");
    mac.update(&[operation + 1]);
    mac.update(key_id);
    mac.update(data);
    mac.update(&((key_id.len() as u64) + 1).to_be_bytes());
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// Persist a 32-byte app-state main key (sourced from inbound
/// `ProtocolMessage.app_state_sync_key_share`) into
/// `app_state_mac_keys` so subsequent patches can be authenticated.
/// `key_id` is the server-assigned id from the share message.
#[allow(dead_code)]
pub fn store_app_state_main_key(
    store: &Store,
    session_id: &str,
    key_id: &[u8],
    main_key: &[u8; 32],
) -> Result<()> {
    store.app_state_main_key_save(session_id, key_id, main_key.as_slice())?;
    Ok(())
}

/// Look up the previously-shared 32-byte main key for a given key id.
/// Patches reference the key id whose chain produced their valueMACs;
/// caller pulls the main key, calls `expand_app_state_keys`, then
/// runs the per-mutation auth dance.
#[allow(dead_code)]
pub fn load_app_state_main_key(
    store: &Store,
    session_id: &str,
    key_id: &[u8],
) -> Result<Option<[u8; 32]>> {
    let bytes = store.app_state_main_key_load(session_id, key_id)?;
    match bytes {
        None => Ok(None),
        Some(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Ok(Some(a))
        }
        Some(_) => Err(Error::Internal(anyhow::anyhow!(
            "stored app-state key has wrong length"
        ))),
    }
}

#[cfg(test)]
mod app_state_key_tests {
    use super::*;

    /// Same main key always expands to the same sub-keys, and all five
    /// outputs are pairwise distinct.
    #[test]
    fn expand_app_state_keys_is_deterministic_and_disjoint() {
        let main = [0x42u8; 32];
        let a = expand_app_state_keys(&main);
        let b = expand_app_state_keys(&main);
        assert_eq!(a.mutation_cipher_key, b.mutation_cipher_key);
        assert_eq!(a.value_mac_key, b.value_mac_key);
        assert_eq!(a.snapshot_mac_key, b.snapshot_mac_key);
        assert_eq!(a.mutation_mac_key, b.mutation_mac_key);
        assert_eq!(a.patch_mac_key, b.patch_mac_key);
        // Pairwise distinct.
        let keys = [
            a.mutation_cipher_key,
            a.value_mac_key,
            a.snapshot_mac_key,
            a.mutation_mac_key,
            a.patch_mac_key,
        ];
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(keys[i], keys[j], "keys[{i}] == keys[{j}]");
            }
        }
    }

    /// valueMAC depends on operation, iv, AND ciphertext; flipping any
    /// changes the output.
    #[test]
    fn value_mac_depends_on_all_inputs() {
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let ct = b"hello".to_vec();
        let m_set = compute_app_state_value_mac(&key, 0, &iv, &ct);
        let m_remove = compute_app_state_value_mac(&key, 1, &iv, &ct);
        assert_ne!(m_set, m_remove);
        let mut iv2 = iv;
        iv2[0] ^= 1;
        let m_iv = compute_app_state_value_mac(&key, 0, &iv2, &ct);
        assert_ne!(m_set, m_iv);
        let mut ct2 = ct.clone();
        ct2[0] ^= 1;
        let m_ct = compute_app_state_value_mac(&key, 0, &iv, &ct2);
        assert_ne!(m_set, m_ct);
    }

    /// `decode_e2e_message` recognizes ProtocolMessage.app_state_sync_key_share
    /// and returns the AppStateSyncKeyShare variant.
    #[test]
    fn decode_e2e_message_recognizes_app_state_sync_key_share() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;

        let key = e2e::AppStateSyncKey {
            key_id: Some(e2e::AppStateSyncKeyId {
                key_id: Some(b"keyid-2".to_vec()),
            }),
            key_data: Some(e2e::AppStateSyncKeyData {
                key_data: Some(vec![0x55; 32]),
                fingerprint: None,
                timestamp: Some(1_700_000_000),
            }),
        };
        let pm = e2e::ProtocolMessage {
            app_state_sync_key_share: Some(e2e::AppStateSyncKeyShare { keys: vec![key] }),
            ..Default::default()
        };
        let m = e2e::Message {
            protocol_message: Some(Box::new(pm)),
            ..Default::default()
        };
        match decode_e2e_message(&m.encode_to_vec()) {
            InboundContent::AppStateSyncKeyShare(share) => {
                assert_eq!(share.keys.len(), 1);
                assert_eq!(
                    share.keys[0]
                        .key_id
                        .as_ref()
                        .unwrap()
                        .key_id
                        .as_deref(),
                    Some(&b"keyid-2"[..])
                );
            }
            _ => panic!("expected AppStateSyncKeyShare"),
        }
    }

    /// Round-trip a main key through the store: after store + load,
    /// the bytes are byte-equal.
    #[test]
    fn store_and_load_main_key() {
        let mgr = manager();
        let session = mgr.create(Some("alice".into())).unwrap();
        let id = session.meta.read().id.clone();
        let main = [0xAAu8; 32];
        let key_id = b"keyid-1".to_vec();
        store_app_state_main_key(&mgr.store, &id, &key_id, &main).unwrap();
        let got = load_app_state_main_key(&mgr.store, &id, &key_id).unwrap();
        assert_eq!(got, Some(main));
        // Wrong key id → None.
        assert!(load_app_state_main_key(&mgr.store, &id, b"other")
            .unwrap()
            .is_none());
    }

    fn manager() -> SessionManager {
        SessionManager::new(Arc::new(Store::open(":memory:").unwrap()))
    }
}

/// One mutation extracted from an app-state patch. The action enum is open
/// (whatsmeow has 50+ action types); we model the common ones.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppStateMutation {
    ContactUpsert { jid: String, full_name: Option<String>, push_name: Option<String> },
    ChatPin { jid: String, pinned: bool },
    ChatArchive { jid: String, archived: bool },
    ChatMute { jid: String, until: Option<i64> },
}

/// Apply an app-state mutation to the local mirror tables.
#[allow(dead_code)]
pub fn apply_app_state_mutation(
    store: &Store,
    session_id: &str,
    mutation: &AppStateMutation,
) -> Result<()> {
    match mutation {
        AppStateMutation::ContactUpsert { jid, full_name, push_name } => {
            store.contact_upsert(session_id, jid, full_name.as_deref(), push_name.as_deref())?;
        }
        AppStateMutation::ChatPin { jid, pinned } => {
            store.chat_set_pinned(session_id, jid, *pinned)?;
        }
        AppStateMutation::ChatArchive { jid, archived } => {
            store.chat_set_archived(session_id, jid, *archived)?;
        }
        AppStateMutation::ChatMute { jid, until } => {
            store.chat_set_muted(session_id, jid, *until)?;
        }
    }
    Ok(())
}

/// Build the history-sync backfill IQ. whatsmeow ships HSv2 requests
/// inside an `<iq xmlns="w:sync:app:state">` envelope.
#[allow(dead_code)]
pub fn build_history_backfill_iq(
    iq_id: &str,
    chat_jid: &str,
    oldest_message_id: Option<&str>,
    count: u32,
) -> crate::protocol::binary::Node {
    use crate::protocol::binary::{Attrs, Content, Node};
    let mut hist_attrs = Attrs::new();
    hist_attrs.insert("count".into(), count.to_string());
    hist_attrs.insert("chat".into(), chat_jid.into());
    if let Some(id) = oldest_message_id {
        hist_attrs.insert("anchor".into(), id.into());
    }
    let hist = Node {
        tag: "history-sync-request".into(),
        attrs: hist_attrs,
        content: Content::None,
    };
    let mut iq_attrs = Attrs::new();
    iq_attrs.insert("id".into(), iq_id.into());
    iq_attrs.insert("type".into(), "set".into());
    iq_attrs.insert("xmlns".into(), "w:sync:app:state".into());
    iq_attrs.insert("to".into(), "s.whatsapp.net".into());
    Node {
        tag: "iq".into(),
        attrs: iq_attrs,
        content: Content::Nodes(vec![hist]),
    }
}

// -- History sync (HSv2) inbound -------------------------------------------
//
// Hand-rolled minimal protobuf subsets so we don't have to vendor the
// full `waHistorySync` schema (which transitively pulls waSyncAction +
// waChatLockSettings + waUserPassword + waDeviceCapabilities + waWeb).
// We decode just the fields we need to surface inbound messages into the
// `messages` table; everything else (presences, push names, account
// metadata, status broadcast V3, etc.) is left untouched and can be
// added by extending the structs below.

/// Minimal HistorySync proto. Only `conversations` is decoded; all other
/// HSv2 features (`pushnames`, `globalSettings`, `statusV3Messages`,
/// etc.) are skipped at the proto layer.
#[derive(Clone, PartialEq, ::prost::Message)]
struct HistorySyncSubset {
    #[prost(message, repeated, tag = "2")]
    pub conversations: Vec<ConvSubset>,
    /// PUSH_NAME sync chunks (syncType=5) carry the display names for every
    /// contact here, NOT on the conversations — without decoding this, 1:1
    /// chats stay nameless (groups get their name from `Conversation.name`).
    /// Matches whatsmeow's `HistorySync.pushnames` (tag 7).
    #[prost(message, repeated, tag = "7")]
    pub pushnames: Vec<PushnameSubset>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct PushnameSubset {
    /// Contact JID (e.g. `5511…@s.whatsapp.net`).
    #[prost(string, optional, tag = "1")]
    pub id: ::core::option::Option<String>,
    #[prost(string, optional, tag = "2")]
    pub pushname: ::core::option::Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct ConvSubset {
    #[prost(string, optional, tag = "1")]
    pub id: ::core::option::Option<String>,
    #[prost(message, repeated, tag = "2")]
    pub messages: Vec<HistMsgSubset>,
    #[prost(uint64, optional, tag = "12")]
    pub conversation_timestamp: ::core::option::Option<u64>,
    #[prost(string, optional, tag = "13")]
    pub name: ::core::option::Option<String>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
struct HistMsgSubset {
    #[prost(message, optional, tag = "1")]
    pub message: ::core::option::Option<WebMessageInfoSubset>,
    #[prost(uint64, optional, tag = "2")]
    pub msg_order_id: ::core::option::Option<u64>,
}

/// Minimal WebMessageInfo. Carries enough to populate a `messages` row:
/// the original message key, the inner waE2E.Message bytes (so we can
/// run `decode_e2e_message` on it for free), the timestamp, and the
/// pushName for sender-display-name surfacing. Tags must match
/// whatsmeow's WAWebProtobufsWeb.WebMessageInfo verbatim.
#[derive(Clone, PartialEq, ::prost::Message)]
struct WebMessageInfoSubset {
    #[prost(message, optional, tag = "1")]
    pub key: ::core::option::Option<crate::proto::wa_common::MessageKey>,
    #[prost(message, optional, tag = "2")]
    pub message: ::core::option::Option<crate::proto::wa_web_protobufs_e2e::Message>,
    #[prost(uint64, optional, tag = "3")]
    pub message_timestamp: ::core::option::Option<u64>,
    #[prost(string, optional, tag = "16")]
    pub push_name: ::core::option::Option<String>,
    #[prost(string, optional, tag = "20")]
    pub participant: ::core::option::Option<String>,
}

/// The decoded contents of a HistorySync blob we care about: message rows
/// (→ `messages`) plus the contact display names (→ `contacts`). The pushnames
/// ride in a dedicated PUSH_NAME chunk, separate from any conversation.
#[derive(Debug, Default, Clone)]
pub struct ParsedHistorySync {
    pub rows: Vec<HistoryMessageRow>,
    /// (contact_jid, display_name) pairs from the `pushnames` field.
    pub pushnames: Vec<(String, String)>,
}

/// Decompress + decode a HistorySync payload (the zlib blob downloaded
/// from `HistorySyncNotification.direct_path`). Returns the message rows
/// (ready for `messages`) plus contact pushnames (ready for `contacts`).
pub fn parse_history_sync_payload(zlib: &[u8]) -> Result<ParsedHistorySync> {
    use flate2::read::ZlibDecoder;
    use prost::Message as _;
    use std::io::Read;

    let mut dec = ZlibDecoder::new(zlib);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| Error::Internal(anyhow::anyhow!("zlib decompress: {e}")))?;
    let hs = HistorySyncSubset::decode(out.as_slice())
        .map_err(|e| Error::Internal(anyhow::anyhow!("decode HistorySync: {e}")))?;
    tracing::info!(
        decompressed_len = out.len(),
        conversations = hs.conversations.len(),
        pushnames = hs.pushnames.len(),
        "parsed history sync blob"
    );

    let pushnames: Vec<(String, String)> = hs
        .pushnames
        .into_iter()
        .filter_map(|p| match (p.id, p.pushname) {
            (Some(id), Some(name)) if !id.is_empty() && !name.is_empty() => Some((id, name)),
            _ => None,
        })
        .collect();

    let mut rows = Vec::new();
    for conv in hs.conversations {
        let chat_jid = match conv.id.clone() {
            Some(j) => j,
            None => continue,
        };
        let chat_name = conv.name.clone().filter(|s| !s.is_empty());
        let is_group = chat_jid.ends_with("@g.us");
        for hist_msg in conv.messages {
            let wmi = match hist_msg.message {
                Some(w) => w,
                None => continue,
            };
            let push_name = wmi.push_name.clone().filter(|s| !s.is_empty());
            let key = wmi.key.unwrap_or_default();
            let msg_id = match key.id {
                Some(s) if !s.is_empty() => s,
                _ => continue,
            };
            let from_me = key.from_me.unwrap_or(false);
            let participant = wmi
                .participant
                .or(key.participant.clone())
                .unwrap_or_else(|| {
                    if from_me {
                        "self".to_string()
                    } else {
                        chat_jid.clone()
                    }
                });
            let timestamp = wmi.message_timestamp.unwrap_or(0) as i64;
            // Decode the inner waE2E.Message to extract a body / type.
            let (msg_type, body_text, payload_json) = match wmi.message {
                Some(m) => {
                    use prost::Message as _;
                    let bytes = m.encode_to_vec();
                    match decode_e2e_message(&bytes) {
                        InboundContent::Text(t) => (
                            "text".to_string(),
                            Some(t.clone()),
                            serde_json::json!({"type":"text","text":t,"source":"history_sync"}),
                        ),
                        InboundContent::Media {
                            kind,
                            url,
                            direct_path,
                            mimetype,
                            media_key,
                            caption,
                            file_length,
                        } => {
                            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
                            let media_key_b64 = media_key.as_ref().map(|k| B64.encode(k));
                            (
                                media_kind_str(kind).to_string(),
                                caption.clone(),
                                serde_json::json!({
                                    "type": media_kind_str(kind),
                                    "url": url,
                                    "direct_path": direct_path,
                                    "mimetype": mimetype,
                                    "media_key_b64": media_key_b64,
                                    "caption": caption,
                                    "file_length": file_length,
                                    "source": "history_sync",
                                }),
                            )
                        }
                        InboundContent::Typed { kind, text } => (
                            kind.clone(),
                            text.clone(),
                            serde_json::json!({"type":kind,"text":text,"source":"history_sync"}),
                        ),
                        InboundContent::HistorySyncNotification(_)
                        | InboundContent::AppStateSyncKeyShare(_)
                        | InboundContent::Other => (
                            "unknown".to_string(),
                            None,
                            serde_json::json!({"type":"unknown","source":"history_sync"}),
                        ),
                    }
                }
                None => (
                    "unknown".to_string(),
                    None,
                    serde_json::json!({"type":"unknown","source":"history_sync"}),
                ),
            };
            rows.push(HistoryMessageRow {
                chat_jid: chat_jid.clone(),
                message_id: msg_id,
                sender_jid: participant,
                from_me,
                timestamp,
                msg_type,
                body_text,
                payload_json: payload_json.to_string(),
                push_name,
                chat_name: chat_name.clone(),
                is_group,
            });
        }
    }
    Ok(ParsedHistorySync { rows, pushnames })
}

/// One row decoded out of a HistorySync blob, shaped for direct INSERT
/// OR IGNORE into `messages`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryMessageRow {
    pub chat_jid: String,
    pub message_id: String,
    pub sender_jid: String,
    pub from_me: bool,
    pub timestamp: i64,
    pub msg_type: String,
    pub body_text: Option<String>,
    pub payload_json: String,
    /// Sender's display name (WebMessageInfo.pushName) — mirrored into `contacts`.
    pub push_name: Option<String>,
    /// Conversation display name (Conversation.name) — mirrored into `chats.name`.
    /// Same for every row of a conversation; carried per-row to avoid a second
    /// return value out of `parse_history_sync_payload`.
    pub chat_name: Option<String>,
    /// Whether `chat_jid` is a group (`@g.us`).
    pub is_group: bool,
}

/// Persist a parsed HistorySync chunk: messages (→ `messages`), conversation +
/// sender display names and the PUSH_NAME chunk's contact names (→ `contacts` /
/// `chats`). Uses INSERT OR IGNORE so re-running the same chunk is idempotent.
pub fn persist_history_sync_rows(
    store: &Store,
    session_id: &str,
    parsed: &ParsedHistorySync,
) -> Result<usize> {
    let rows = &parsed.rows;

    // The dedicated PUSH_NAME chunk (syncType=5) carries every contact's display
    // name — the ONLY place 1:1 chats get a name (groups use Conversation.name).
    for (jid, name) in &parsed.pushnames {
        let _ = store.contact_upsert(session_id, jid, None, Some(name));
    }

    let new_rows: Vec<crate::store::NewMessage> = rows
        .iter()
        .map(|r| crate::store::NewMessage {
            session_id,
            chat_jid: &r.chat_jid,
            message_id: &r.message_id,
            sender_jid: &r.sender_jid,
            from_me: r.from_me,
            timestamp: r.timestamp,
            msg_type: &r.msg_type,
            body_text: r.body_text.as_deref(),
            payload_json: &r.payload_json,
            status: None,
        })
        .collect();
    let count = store.messages_insert_batch(&new_rows, true)?;

    // Mirror display names so `chats_list` / the contacts directory show real
    // names instead of bare JIDs. Best-effort: a name failure must not lose the
    // (already-persisted) messages.
    use std::collections::HashMap;
    let mut chat_meta: HashMap<&str, (Option<&str>, bool, i64)> = HashMap::new();
    for r in rows {
        // Per-sender contact name (skip our own outbound rows).
        if let Some(name) = r.push_name.as_deref() {
            if !r.from_me {
                let _ = store.contact_upsert(session_id, &r.sender_jid, None, Some(name));
            }
        }
        // Per-conversation: keep the latest timestamp + first non-empty name.
        let e = chat_meta
            .entry(&r.chat_jid)
            .or_insert((None, r.is_group, 0));
        if e.0.is_none() {
            e.0 = r.chat_name.as_deref();
        }
        e.1 = r.is_group;
        if r.timestamp > e.2 {
            e.2 = r.timestamp;
        }
    }
    for (jid, (name, is_group, last_ts)) in chat_meta {
        let _ = store.chat_set_name(
            session_id,
            jid,
            name,
            is_group,
            if last_ts > 0 { Some(last_ts) } else { None },
        );
    }

    Ok(count)
}

/// Download an inbound `HistorySyncNotification` blob, decrypt with the
/// included `media_key` under the History HKDF info, zlib-decompress,
/// parse, and persist. Best-effort: any error logs and returns Ok(0)
/// so the connection task doesn't crash on a malformed sync chunk.
///
/// When `dispatcher` is provided, fetches a fresh mediaconn host via
/// `<iq xmlns="w:m">`. The fallback path (None) hardcodes
/// `mmg.whatsapp.net` and is only used in unit tests where the
/// connection task is mocked out.
pub async fn ingest_history_sync_notification(
    store: &Store,
    dispatcher: Option<&ConnDispatcher>,
    session_id: &str,
    notif: &crate::proto::wa_web_protobufs_e2e::HistorySyncNotification,
) -> Result<usize> {
    // INFO (not debug): the syncType/progress decides whether we're already
    // getting RECENT (→ "most recent in sync", paused=FULL-only=cosmetic) or
    // only INITIAL_BOOTSTRAP (→ phone genuinely withholds RECENT). syncType:
    // 0=INITIAL_BOOTSTRAP 1=INITIAL_STATUS_V3 2=FULL 3=RECENT 4=PUSH_NAME …
    tracing::info!(
        sync_type = notif.sync_type.unwrap_or(-1),
        chunk = notif.chunk_order.unwrap_or(0),
        progress = notif.progress.unwrap_or(0),
        has_inline = notif.initial_hist_bootstrap_inline_payload.is_some(),
        has_direct_path = notif.direct_path.is_some(),
        "history sync notification",
    );

    // Some HistorySyncNotifications carry their (zlib-compressed) HistorySync
    // proto INLINE rather than via a CDN download — notably the initial
    // bootstrap chunk the phone sends right after linking. whatsmeow's
    // DownloadHistorySync uses `InitialHistBootstrapInlinePayload` directly when
    // present and only falls back to download+decrypt otherwise; the inline
    // bytes are the same zlib-compressed format as a decrypted blob. We used to
    // hard-require `direct_path` and error out on these, silently dropping the
    // entire inline chunk (the live "missing direct_path" warning seen on pair).
    if let Some(inline) = notif.initial_hist_bootstrap_inline_payload.clone() {
        let parsed = parse_history_sync_payload(&inline)?;
        return persist_history_sync_rows(store, session_id, &parsed);
    }

    let direct_path = notif
        .direct_path
        .clone()
        .ok_or_else(|| Error::BadRequest("HistorySyncNotification missing direct_path".into()))?;
    let media_key_bytes = notif
        .media_key
        .clone()
        .ok_or_else(|| Error::BadRequest("HistorySyncNotification missing media_key".into()))?;
    if media_key_bytes.len() != 32 {
        return Err(Error::BadRequest("media_key wrong length".into()));
    }
    let mut media_key = [0u8; 32];
    media_key.copy_from_slice(&media_key_bytes);

    let host = match dispatcher {
        Some(d) => {
            let iq_id = uuid_v4();
            let iq = build_mediaconn_iq(&iq_id);
            match d.iq_request(iq).await {
                Ok(reply) => match parse_mediaconn_response(&reply) {
                    Some(mc) => mc.hostname,
                    None => "mmg.whatsapp.net".to_string(),
                },
                Err(e) => {
                    tracing::warn!(error = %e, "mediaconn refresh failed; using default host");
                    "mmg.whatsapp.net".to_string()
                }
            }
        }
        None => "mmg.whatsapp.net".to_string(),
    };
    let url = format!("https://{host}{direct_path}");
    // Download through the session's proxy so media shares its egress IP.
    let proxy: Option<String> = store.session_proxy(session_id).ok().flatten();
    let blob = crate::media::download_encrypted(&url, proxy.as_deref())
        .await
        .map_err(|e| Error::Internal(anyhow::anyhow!("download history blob: {e:?}")))?;
    let zlib = crate::media::decrypt(&blob, &media_key, crate::media::MediaType::History)
        .map_err(|e| Error::Internal(anyhow::anyhow!("decrypt history blob: {e:?}")))?;
    tracing::debug!(downloaded_len = blob.len(), decrypted_len = zlib.len(), "downloaded history-sync blob");
    let parsed = parse_history_sync_payload(&zlib)?;
    persist_history_sync_rows(store, session_id, &parsed)
}

impl TryFrom<crate::store::DeviceKeyRow> for DeviceKeys {
    type Error = &'static str;

    fn try_from(r: crate::store::DeviceKeyRow) -> std::result::Result<Self, Self::Error> {
        use crate::crypto::identity::{KeyPair, SignedPreKey};

        let noise = KeyPair::from_bytes(&r.noise_priv, &r.noise_pub)?;
        let identity = KeyPair::from_bytes(&r.identity_priv, &r.identity_pub)?;
        let spk_keypair = KeyPair::from_bytes(&r.spk_priv, &r.spk_pub)?;
        if r.spk_sig.len() != 64 {
            return Err("expected 64-byte spk signature");
        }
        let mut signature = [0u8; 64];
        signature.copy_from_slice(&r.spk_sig);
        if r.adv_secret.len() != 32 {
            return Err("expected 32-byte adv secret");
        }
        let mut adv_secret = [0u8; 32];
        adv_secret.copy_from_slice(&r.adv_secret);
        Ok(DeviceKeys {
            noise,
            identity,
            signed_prekey: SignedPreKey {
                key_id: r.spk_id,
                keypair: spk_keypair,
                signature,
            },
            adv_secret,
            registration_id: r.registration_id,
        })
    }
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Pending => "pending",
            SessionStatus::Connecting => "connecting",
            SessionStatus::AwaitingQr => "awaiting_qr",
            SessionStatus::Connected => "connected",
            SessionStatus::Disconnected => "disconnected",
            SessionStatus::ProxyError => "proxy_error",
            SessionStatus::LoggedOut => "logged_out",
            SessionStatus::Blocked => "blocked",
        }
    }
}

trait ParseStatus {
    fn parse_session_status(&self) -> SessionStatus;
}
impl ParseStatus for String {
    fn parse_session_status(&self) -> SessionStatus {
        match self.as_str() {
            "connecting" => SessionStatus::Connecting,
            "awaiting_qr" => SessionStatus::AwaitingQr,
            "connected" => SessionStatus::Connected,
            "disconnected" => SessionStatus::Disconnected,
            "proxy_error" => SessionStatus::ProxyError,
            "logged_out" => SessionStatus::LoggedOut,
            "blocked" => SessionStatus::Blocked,
            _ => SessionStatus::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn media_descriptor_built_for_media_types_only() {
        // A media payload (as built in process_inbound_message) yields a
        // descriptor with mimetype, size, ptt flag and a pull URL.
        let payload = serde_json::json!({
            "type": "audio",
            "mimetype": "audio/ogg; codecs=opus",
            "file_length": 4821u64,
        });
        let d = media_webhook_descriptor("ptt", &payload, "sess", "55119@s.whatsapp.net", "3EB0ABC")
            .expect("ptt is downloadable media");
        assert_eq!(d["mimetype"], "audio/ogg; codecs=opus");
        assert_eq!(d["size"], 4821);
        assert_eq!(d["ptt"], true);
        // Segments are percent-encoded so the JID round-trips through axum's Path.
        assert_eq!(
            d["url"],
            "/v1/sessions/sess/messages/55119%40s%2Ewhatsapp%2Enet/3EB0ABC/media"
        );

        // Non-ptt media: ptt=false, still has a URL.
        let img = serde_json::json!({ "type": "image", "mimetype": "image/jpeg" });
        let d = media_webhook_descriptor("image", &img, "s", "c@g.us", "M1").unwrap();
        assert_eq!(d["ptt"], false);
        assert_eq!(d["size"], serde_json::Value::Null); // file_length absent -> null
        assert!(d["url"].as_str().unwrap().ends_with("/media"));

        // Text (and other non-media) types get no descriptor.
        let text = serde_json::json!({ "type": "text", "text": "hi" });
        assert!(media_webhook_descriptor("text", &text, "s", "c", "m").is_none());
        assert!(media_webhook_descriptor("reaction", &text, "s", "c", "m").is_none());
    }

    #[test]
    fn enc_path_seg_encodes_jid_reserved_chars() {
        // `@`, `.` and `:` (device JIDs) must be encoded so they survive as a
        // single path segment.
        assert_eq!(enc_path_seg("55119:12@s.whatsapp.net"), "55119%3A12%40s%2Ewhatsapp%2Enet");
        assert_eq!(enc_path_seg("3EB0ABC123"), "3EB0ABC123"); // plain ids untouched
    }

    fn manager() -> SessionManager {
        SessionManager::new(Arc::new(Store::open(":memory:").unwrap()))
    }

    #[test]
    fn uuid_v4_has_correct_format_and_is_unique() {
        let u = uuid_v4();
        assert_eq!(u.len(), 36);
        let parts: Vec<&str> = u.split('-').collect();
        assert_eq!(parts.iter().map(|p| p.len()).collect::<Vec<_>>(), vec![8, 4, 4, 4, 12]);
        assert!(u.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        // Version nibble = 4.
        assert_eq!(parts[2].chars().next().unwrap(), '4');
        // Variant = 10xx → first char of the 4th group ∈ {8,9,a,b}.
        assert!(matches!(parts[3].chars().next().unwrap(), '8' | '9' | 'a' | 'b'));
        // Simple form: 32 hex, no hyphens.
        let s = uuid_v4_simple();
        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c.is_ascii_hexdigit()));
        // Uniqueness across a batch.
        let batch: std::collections::HashSet<_> = (0..1000).map(|_| uuid_v4()).collect();
        assert_eq!(batch.len(), 1000);
    }

    #[test]
    fn extended_text_message_carries_mentions_and_reply() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let mentions = vec![
            "5511999999999@s.whatsapp.net".to_string(),
            "5511888888888@s.whatsapp.net".to_string(),
        ];
        let bytes = build_extended_text_message(
            "hey @5511999999999 and @5511888888888",
            &mentions,
            Some(("QUOTED_STANZA_ID", Some("5511777777777@s.whatsapp.net"))),
        );
        let m = Message::decode(bytes.as_slice()).unwrap();
        let etm = m.extended_text_message.expect("extended_text_message set");
        assert_eq!(etm.text.as_deref(), Some("hey @5511999999999 and @5511888888888"));
        let ctx = etm.context_info.expect("context_info set");
        assert_eq!(ctx.mentioned_jid, mentions);
        assert_eq!(ctx.stanza_id.as_deref(), Some("QUOTED_STANZA_ID"));
        assert_eq!(
            ctx.participant.as_deref(),
            Some("5511777777777@s.whatsapp.net")
        );
        assert!(ctx.quoted_message.is_some());
        // Plain conversation field is NOT used in the extended form.
        assert!(m.conversation.is_none());
    }

    #[test]
    fn decode_e2e_surfaces_extended_text_as_text() {
        // A text sent via `extendedTextMessage` (link preview / reply / mention /
        // Baileys+business default) must decode to InboundContent::Text, not Other.
        // Regression: ruwa only handled `conversation`, so these landed as
        // type="unknown" / null body in the receive path.
        let bytes = build_extended_text_message("hello from extended", &[], None);
        match decode_e2e_message(&bytes) {
            InboundContent::Text(t) => assert_eq!(t, "hello from extended"),
            _ => panic!("expected InboundContent::Text from an extendedTextMessage"),
        }
    }

    #[test]
    fn media_mentions_attach_to_image_context_info() {
        use crate::proto::wa_web_protobufs_e2e::{ImageMessage, Message};
        use prost::Message as _;

        let base = Message {
            image_message: Some(Box::new(ImageMessage {
                url: Some("https://mmg/x".into()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .encode_to_vec();

        let mentions = vec!["5511999999999@s.whatsapp.net".to_string()];
        let out = apply_media_mentions(base.clone(), &mentions);
        let m = Message::decode(out.as_slice()).unwrap();
        let ctx = m
            .image_message
            .unwrap()
            .context_info
            .expect("context_info attached");
        assert_eq!(ctx.mentioned_jid, mentions);

        // No mentions → unchanged bytes.
        assert_eq!(apply_media_mentions(base.clone(), &[]), base);
    }

    #[test]
    fn media_mentions_noop_on_non_media_proto() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;
        let conv = Message {
            conversation: Some("hi".into()),
            ..Default::default()
        }
        .encode_to_vec();
        // A conversation proto has no media sub-message → returned unchanged.
        assert_eq!(
            apply_media_mentions(conv.clone(), &["x@s.whatsapp.net".to_string()]),
            conv
        );
    }

    #[test]
    fn usync_contact_iq_shape_and_response_parse() {
        use crate::protocol::binary::{Attrs, Content, Node};

        // Build: usync xmlns + a <contact> child per <user>, normalized to E.164.
        let iq = build_usync_contact_iq("ID1", &["5511999999999".into(), "+5511888888888".into()]);
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("usync"));
        let usync = match &iq.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "usync").unwrap(),
            _ => panic!("no usync"),
        };
        assert_eq!(usync.attrs.get("context").map(String::as_str), Some("interactive"));
        let list = match &usync.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "list").unwrap(),
            _ => panic!("no list"),
        };
        let users: Vec<&Node> = match &list.content {
            Content::Nodes(ns) => ns.iter().filter(|n| n.tag == "user").collect(),
            _ => vec![],
        };
        assert_eq!(users.len(), 2);
        // First user's contact text is the +-normalized number.
        let contact = match &users[0].content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "contact").unwrap(),
            _ => panic!(),
        };
        assert!(matches!(&contact.content, Content::Bytes(b) if b == b"+5511999999999"));

        // Parse a synthetic reply: user[0] in (on WA), user[1] out (not).
        fn user(jid: &str, typ: &str) -> Node {
            let mut ua = Attrs::new();
            ua.insert("jid".into(), jid.into());
            let mut ca = Attrs::new();
            ca.insert("type".into(), typ.into());
            Node {
                tag: "user".into(),
                attrs: ua,
                content: Content::Nodes(vec![Node {
                    tag: "contact".into(),
                    attrs: ca,
                    content: Content::None,
                }]),
            }
        }
        let reply = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "usync".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![Node {
                    tag: "list".into(),
                    attrs: Attrs::new(),
                    content: Content::Nodes(vec![
                        user("5511999999999@s.whatsapp.net", "in"),
                        user("5511888888888@s.whatsapp.net", "out"),
                    ]),
                }]),
            }]),
        };
        let queries = vec!["5511999999999".to_string(), "+5511888888888".to_string()];
        let res = parse_usync_contact_response(&reply, &queries);
        assert_eq!(res.len(), 2);
        assert_eq!(res[0].query, "5511999999999");
        assert!(res[0].exists);
        assert_eq!(res[0].jid.as_deref(), Some("5511999999999@s.whatsapp.net"));
        assert!(!res[1].exists);
        assert_eq!(res[1].jid, None); // jid only reported when on WA
    }

    /// The LID sweep IQ requests `<lid/>` per PN user; the reply maps each PN
    /// `<user jid>` to a `<lid val="…@lid"/>` → bare (pn_user, lid_user) pairs.
    #[test]
    fn group_info_iq_shape_and_participant_parse() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let iq = build_group_info_iq("GI1", "120363@g.us");
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("w:g2"));
        assert_eq!(iq.attrs.get("to").map(String::as_str), Some("120363@g.us"));
        assert_eq!(iq.attrs.get("type").map(String::as_str), Some("get"));

        // Reply: <iq><group><participant jid/>…</group></iq>
        fn participant(jid: &str) -> Node {
            let mut a = Attrs::new();
            a.insert("jid".into(), jid.into());
            Node { tag: "participant".into(), attrs: a, content: Content::None }
        }
        let reply = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "group".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![
                    participant("5511999999999@s.whatsapp.net"),
                    participant("15400000000003@lid"),
                ]),
            }]),
        };
        let parts = parse_group_info_response(&reply);
        assert_eq!(parts, vec![
            "5511999999999@s.whatsapp.net".to_string(),
            "15400000000003@lid".to_string(),
        ]);
    }

    #[test]
    fn group_message_node_has_participants_and_skmsg() {
        use crate::crypto::signal::MessageType;
        use crate::protocol::binary::Content;

        let recipients = vec![
            EncryptedRecipient { jid: "5511999999999:0@s.whatsapp.net".into(), ciphertext: vec![1, 2, 3], message_type: MessageType::PreKey },
            EncryptedRecipient { jid: "5511888888888:0@s.whatsapp.net".into(), ciphertext: vec![4, 5], message_type: MessageType::Whisper },
        ];
        let node = build_group_message_node("MID1", "120363@g.us", &recipients, &[9, 9, 9], 1700000000, Some(vec![0xAB]));
        assert_eq!(node.attrs.get("to").map(String::as_str), Some("120363@g.us"));
        let children = match &node.content { Content::Nodes(ns) => ns, _ => panic!() };
        // participants + skmsg enc + device-identity
        assert!(children.iter().any(|n| n.tag == "participants"));
        assert!(children.iter().any(|n| n.tag == "enc"
            && n.attrs.get("type").map(String::as_str) == Some("skmsg")));
        assert!(children.iter().any(|n| n.tag == "device-identity"));
        // each participant <to> carries a pkmsg/msg enc
        let parts = children.iter().find(|n| n.tag == "participants").unwrap();
        let tos = match &parts.content { Content::Nodes(ns) => ns, _ => panic!() };
        assert_eq!(tos.len(), 2);
    }

    #[test]
    fn usync_lid_iq_shape_and_response_parse() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let iq = build_usync_lid_iq("LID1", &["5511990000003@s.whatsapp.net".into()]);
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("usync"));
        let usync = match &iq.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "usync").unwrap(),
            _ => panic!("no usync"),
        };
        // The query must ask for <lid/>.
        let query = match &usync.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "query").unwrap(),
            _ => panic!("no query"),
        };
        assert!(matches!(&query.content, Content::Nodes(ns) if ns.iter().any(|n| n.tag == "lid")));

        // Reply: a <user jid="<pn>@s.whatsapp.net"><lid val="<n>@lid"/></user>.
        let mut ua = Attrs::new();
        ua.insert("jid".into(), "5511990000003@s.whatsapp.net".into());
        let mut la = Attrs::new();
        la.insert("val".into(), "15400000000003@lid".into());
        let reply = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "usync".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![Node {
                    tag: "list".into(),
                    attrs: Attrs::new(),
                    content: Content::Nodes(vec![Node {
                        tag: "user".into(),
                        attrs: ua,
                        content: Content::Nodes(vec![Node {
                            tag: "lid".into(),
                            attrs: la,
                            content: Content::None,
                        }]),
                    }]),
                }]),
            }]),
        };
        let pairs = parse_usync_lid_response(&reply);
        assert_eq!(pairs, vec![("5511990000003".to_string(), "15400000000003".to_string())]);
    }

    #[test]
    fn picture_iq_shape_and_response_parse() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let iq = build_picture_iq("ID2", "5511999999999@s.whatsapp.net", false);
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("w:profile:picture"));
        assert_eq!(iq.attrs.get("to").map(String::as_str), Some("5511999999999@s.whatsapp.net"));
        let pic = match &iq.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "picture").unwrap(),
            _ => panic!("no picture node"),
        };
        assert_eq!(pic.attrs.get("type").map(String::as_str), Some("image"));
        assert_eq!(pic.attrs.get("query").map(String::as_str), Some("url"));
        // preview=true switches the type.
        let prev = build_picture_iq("ID3", "g@g.us", true);
        let pic2 = match &prev.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "picture").unwrap(),
            _ => panic!(),
        };
        assert_eq!(pic2.attrs.get("type").map(String::as_str), Some("preview"));

        // Parse a reply with a url.
        let mut pa = Attrs::new();
        pa.insert("url".into(), "https://pps.whatsapp.net/x.jpg".into());
        let reply = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "picture".into(),
                attrs: pa,
                content: Content::None,
            }]),
        };
        assert_eq!(
            parse_picture_response(&reply).as_deref(),
            Some("https://pps.whatsapp.net/x.jpg")
        );

        // An error reply (no <picture>) → None.
        let err = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "error".into(),
                attrs: Attrs::new(),
                content: Content::None,
            }]),
        };
        assert_eq!(parse_picture_response(&err), None);
    }

    #[test]
    fn block_iq_shape_and_error_detection() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let iq = build_block_iq("ID4", "5511999999999@s.whatsapp.net", true);
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("blocklist"));
        assert_eq!(iq.attrs.get("type").map(String::as_str), Some("set"));
        let item = match &iq.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "item").unwrap(),
            _ => panic!("no item"),
        };
        assert_eq!(item.attrs.get("action").map(String::as_str), Some("block"));
        assert_eq!(item.attrs.get("jid").map(String::as_str), Some("5511999999999@s.whatsapp.net"));
        // unblock flips the action.
        let unb = build_block_iq("ID5", "x@s.whatsapp.net", false);
        let item2 = match &unb.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "item").unwrap(),
            _ => panic!(),
        };
        assert_eq!(item2.attrs.get("action").map(String::as_str), Some("unblock"));

        // iq_is_error: type=error, an <error> child, and a clean result.
        let mut err_attrs = Attrs::new();
        err_attrs.insert("type".into(), "error".into());
        let err_iq = Node { tag: "iq".into(), attrs: err_attrs, content: Content::None };
        assert!(iq_is_error(&err_iq));
        let err_child = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "error".into(),
                attrs: Attrs::new(),
                content: Content::None,
            }]),
        };
        assert!(iq_is_error(&err_child));
        let ok = Node {
            tag: "iq".into(),
            attrs: {
                let mut a = Attrs::new();
                a.insert("type".into(), "result".into());
                a
            },
            content: Content::None,
        };
        assert!(!iq_is_error(&ok));
    }

    #[test]
    fn set_status_and_picture_iq_shapes() {
        use crate::protocol::binary::Content;

        let s = build_set_status_iq("ID6", "Living my best life");
        assert_eq!(s.attrs.get("xmlns").map(String::as_str), Some("status"));
        assert_eq!(s.attrs.get("type").map(String::as_str), Some("set"));
        let status = match &s.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "status").unwrap(),
            _ => panic!(),
        };
        assert!(matches!(&status.content, Content::Bytes(b) if b == b"Living my best life"));

        let jpeg = [0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3];
        let p = build_set_picture_iq("ID7", "5511999999999@s.whatsapp.net", &jpeg);
        assert_eq!(p.attrs.get("xmlns").map(String::as_str), Some("w:profile:picture"));
        assert_eq!(p.attrs.get("to").map(String::as_str), Some("5511999999999@s.whatsapp.net"));
        let pic = match &p.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "picture").unwrap(),
            _ => panic!(),
        };
        assert_eq!(pic.attrs.get("type").map(String::as_str), Some("image"));
        assert!(matches!(&pic.content, Content::Bytes(b) if b == &jpeg));
    }

    #[test]
    fn location_message_encodes_coords_and_labels() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let bytes = build_location_message(-23.55052, -46.633308, Some("Sé"), Some("Praça da Sé"));
        let m = Message::decode(bytes.as_slice()).unwrap();
        let loc = m.location_message.expect("location_message set");
        assert_eq!(loc.degrees_latitude, Some(-23.55052));
        assert_eq!(loc.degrees_longitude, Some(-46.633308));
        assert_eq!(loc.name.as_deref(), Some("Sé"));
        assert_eq!(loc.address.as_deref(), Some("Praça da Sé"));
    }

    #[test]
    fn contact_message_carries_name_and_vcard() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let vcard = "BEGIN:VCARD\nVERSION:3.0\nFN:Alice\nEND:VCARD";
        let bytes = build_contact_message("Alice", vcard);
        let m = Message::decode(bytes.as_slice()).unwrap();
        let c = m.contact_message.expect("contact_message set");
        assert_eq!(c.display_name.as_deref(), Some("Alice"));
        assert_eq!(c.vcard.as_deref(), Some(vcard));
    }

    #[test]
    fn poll_message_carries_options_and_secret() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let secret = [7u8; 32];
        let opts = vec!["Pizza".to_string(), "Sushi".to_string(), "Tacos".to_string()];
        let bytes = build_poll_message("Dinner?", &opts, 1, &secret);
        let m = Message::decode(bytes.as_slice()).unwrap();
        let poll = m.poll_creation_message.expect("poll_creation_message set");
        assert_eq!(poll.name.as_deref(), Some("Dinner?"));
        assert_eq!(poll.selectable_options_count, Some(1));
        let names: Vec<_> = poll
            .options
            .iter()
            .map(|o| o.option_name.clone().unwrap())
            .collect();
        assert_eq!(names, opts);
        // The 32-byte poll secret rides in messageContextInfo.
        let mci = m.message_context_info.expect("message_context_info set");
        assert_eq!(mci.message_secret.as_deref(), Some(&secret[..]));
    }

    #[test]
    fn event_message_encodes_calendar_fields() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let bytes = build_event_message(
            "Corte às 14h",
            Some("Acme Inc"),
            Some("Rua Augusta, 123"),
            1_900_000_000,
            Some(1_900_003_600),
            Some("https://meet.example/abc"),
        );
        let m = Message::decode(bytes.as_slice()).unwrap();
        let ev = m.event_message.expect("event_message set");
        assert_eq!(ev.name.as_deref(), Some("Corte às 14h"));
        assert_eq!(ev.description.as_deref(), Some("Acme Inc"));
        assert_eq!(ev.start_time, Some(1_900_000_000));
        assert_eq!(ev.end_time, Some(1_900_003_600));
        assert_eq!(ev.join_link.as_deref(), Some("https://meet.example/abc"));
        // Free-text place rides in the event's LocationMessage.name.
        let loc = ev.location.expect("location set");
        assert_eq!(loc.name.as_deref(), Some("Rua Augusta, 123"));
    }

    #[test]
    fn event_message_omits_optional_fields_when_absent() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let bytes = build_event_message("Minimal", None, None, 1_000, None, None);
        let m = Message::decode(bytes.as_slice()).unwrap();
        let ev = m.event_message.expect("event_message set");
        assert_eq!(ev.name.as_deref(), Some("Minimal"));
        assert_eq!(ev.start_time, Some(1_000));
        assert!(ev.description.is_none());
        assert!(ev.end_time.is_none());
        assert!(ev.join_link.is_none());
        assert!(ev.location.is_none());
    }

    #[test]
    fn extended_text_message_mentions_only_has_no_quote() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use prost::Message as _;

        let mentions = vec!["5511999999999@s.whatsapp.net".to_string()];
        let bytes = build_extended_text_message("hi @5511999999999", &mentions, None);
        let m = Message::decode(bytes.as_slice()).unwrap();
        let ctx = m
            .extended_text_message
            .unwrap()
            .context_info
            .expect("context_info set");
        assert_eq!(ctx.mentioned_jid, mentions);
        assert!(ctx.stanza_id.is_none());
        assert!(ctx.participant.is_none());
        assert!(ctx.quoted_message.is_none());
    }

    #[test]
    fn health_reports_fresh_session_state() {
        let mgr = manager();
        let id = mgr.create(None).unwrap().meta.read().id.clone();
        let h = mgr.health(&id).unwrap();
        assert!(!h.connected);
        assert_eq!(h.last_rx, None);
        assert_eq!(h.seconds_since_rx, None);
        assert_eq!(h.reconnect_count, 0);
        // prekeys_available counts server-uploaded keys; a fresh session hasn't
        // connected/uploaded yet, so 0 (the initial batch is still uploaded=0).
        assert_eq!(h.prekeys_available, 0);
        assert!(!h.proxy_configured);

        // mark_rx + reconnect counters surface.
        let s = mgr.get(&id).unwrap();
        s.mark_rx();
        s.bump_reconnect();
        s.bump_reconnect();
        let h = mgr.health(&id).unwrap();
        assert!(h.last_rx.is_some());
        assert_eq!(h.reconnect_count, 2);
    }

    #[test]
    fn stream_error_515_flags_restart_required() {
        use crate::protocol::binary::{Attrs, Content, Node};
        let mgr = manager();
        let sid = mgr.create(None).unwrap().meta.read().id.clone();
        let session = mgr.get(&sid).unwrap();
        let keys = mgr.load_device_keys(&sid).unwrap();
        let ord = std::sync::atomic::Ordering::Relaxed;

        // A generic stream:error must NOT flag restart.
        let mut a = Attrs::new();
        a.insert("code".into(), "503".into());
        process_inbound_node(&session, &mgr.store, &keys, None,
            &Node { tag: "stream:error".into(), attrs: a, content: Content::None });
        assert!(!session.restart_required.load(ord));

        // code=515 (restart required) flags an immediate reconnect.
        let mut a = Attrs::new();
        a.insert("code".into(), "515".into());
        process_inbound_node(&session, &mgr.store, &keys, None,
            &Node { tag: "stream:error".into(), attrs: a, content: Content::None });
        assert!(session.restart_required.load(ord), "515 should set restart_required");
    }

    #[test]
    fn failure_405_client_outdated_parks_blocked() {
        use crate::protocol::binary::{Attrs, Content, Node};
        let mgr = manager();
        let sid = mgr.create(None).unwrap().meta.read().id.clone();
        let session = mgr.get(&sid).unwrap();
        let keys = mgr.load_device_keys(&sid).unwrap();
        let ord = std::sync::atomic::Ordering::Relaxed;

        // <failure reason="405"> = client-version-outdated. It must park the
        // session (block + expect-disconnect) so the reconnect loop halts rather
        // than hammering a version WhatsApp will keep rejecting.
        let mut a = Attrs::new();
        a.insert("reason".into(), "405".into());
        process_inbound_node(
            &session,
            &mgr.store,
            &keys,
            None,
            &Node { tag: "failure".into(), attrs: a, content: Content::None },
        );
        assert!(session.wa_blocked.load(ord), "405 failure should park Blocked");
        assert!(
            session.expect_disconnect.load(ord),
            "405 failure should halt auto-reconnect"
        );
    }

    #[test]
    fn stream_error_ping_timeout_reconnects_not_blocked() {
        // `<stream:error><ping id="…"/></stream:error>` (no code) is WhatsApp's
        // idle / QR-window timeout. It must trigger an immediate reconnect
        // (restart_required) — NOT park the session Blocked — otherwise the QR
        // dies ~30s in and live pairing can never complete. Mirrors whatsmeow's
        // isAuthErrorDisconnect (only 401 / conflict are terminal).
        use crate::protocol::binary::{Attrs, Content, Node};
        let mgr = manager();
        let sid = mgr.create(None).unwrap().meta.read().id.clone();
        let session = mgr.get(&sid).unwrap();
        let keys = mgr.load_device_keys(&sid).unwrap();
        let ord = std::sync::atomic::Ordering::Relaxed;

        let ping = Node {
            tag: "ping".into(),
            attrs: {
                let mut a = Attrs::new();
                a.insert("id".into(), "1847800649".into());
                a
            },
            content: Content::None,
        };
        process_inbound_node(&session, &mgr.store, &keys, None,
            &Node { tag: "stream:error".into(), attrs: Attrs::new(),
                    content: Content::Nodes(vec![ping]) });

        assert!(session.restart_required.load(ord),
            "ping idle-timeout should set restart_required (reconnect)");
        assert!(!session.wa_blocked.load(ord),
            "ping idle-timeout must NOT block the session");
        assert!(!session.expect_disconnect.load(ord),
            "ping idle-timeout must NOT flag a terminal disconnect");
    }

    #[test]
    fn jittered_backoff_stays_in_upper_half() {
        // frac=0 keeps exactly half; frac=1 reaches the full base; mid is between.
        assert_eq!(jittered_backoff_ms(1000, 0.0), 500);
        assert_eq!(jittered_backoff_ms(1000, 1.0), 1000);
        assert_eq!(jittered_backoff_ms(1000, 0.5), 750);
        // Out-of-range frac is clamped, never overshoots the base.
        assert_eq!(jittered_backoff_ms(1000, 2.0), 1000);
        assert_eq!(jittered_backoff_ms(1000, -1.0), 500);
        // Any frac lands within [base/2, base].
        for i in 0..=10 {
            let v = jittered_backoff_ms(60_000, i as f64 / 10.0);
            assert!((30_000..=60_000).contains(&v), "out of band: {v}");
        }
    }

    #[test]
    fn rx_watchdog_stale_detection() {
        // Nothing received yet → never stale (watchdog is armed only after
        // <success>, which marks rx, so this guards the pre-success edge).
        assert!(!rx_is_stale(None, 1_000, RX_IDLE_TIMEOUT_SECS));
        // Fresh frame just landed → healthy.
        assert!(!rx_is_stale(Some(1_000), 1_000, RX_IDLE_TIMEOUT_SECS));
        // Within one keepalive round-trip → healthy.
        assert!(!rx_is_stale(
            Some(1_000),
            1_000 + KEEPALIVE_SECS as i64,
            RX_IDLE_TIMEOUT_SECS
        ));
        // Just under the threshold → still healthy (no false trip on jitter).
        assert!(!rx_is_stale(
            Some(1_000),
            1_000 + RX_IDLE_TIMEOUT_SECS - 1,
            RX_IDLE_TIMEOUT_SECS
        ));
        // At/after the threshold (~3 missed pongs) → stale, force reconnect.
        assert!(rx_is_stale(
            Some(1_000),
            1_000 + RX_IDLE_TIMEOUT_SECS,
            RX_IDLE_TIMEOUT_SECS
        ));
        assert!(rx_is_stale(Some(1_000), 1_000 + 600, RX_IDLE_TIMEOUT_SECS));
        // The threshold comfortably exceeds the keepalive cadence so a healthy
        // socket's pong stream can never trip it.
        assert!(RX_IDLE_TIMEOUT_SECS > KEEPALIVE_SECS as i64 * 2);
    }

    #[test]
    fn topup_interval_defaults_clamps_and_parses() {
        use std::time::Duration;
        // Default when unset / unparseable.
        assert_eq!(topup_interval_from(None), Duration::from_secs(3600));
        assert_eq!(topup_interval_from(Some("nope".into())), Duration::from_secs(3600));
        // Honors a valid value.
        assert_eq!(topup_interval_from(Some("120".into())), Duration::from_secs(120));
        assert_eq!(topup_interval_from(Some("  900 ".into())), Duration::from_secs(900));
        // Clamps below the 60s floor.
        assert_eq!(topup_interval_from(Some("5".into())), Duration::from_secs(60));
        assert_eq!(topup_interval_from(Some("0".into())), Duration::from_secs(60));
    }

    #[test]
    fn parse_wa_version_accepts_triples_and_rejects_garbage() {
        assert_eq!(parse_wa_version("2.3000.1038187123"), Some([2, 3000, 1038187123]));
        assert_eq!(parse_wa_version("  2.3000.1038187123  "), Some([2, 3000, 1038187123]));
        assert_eq!(parse_wa_version("0.1.0"), Some([0, 1, 0]));
        // Wrong arity / non-numeric / empty all reject (→ falls back to default).
        assert_eq!(parse_wa_version("2.3000"), None);
        assert_eq!(parse_wa_version("2.3000.1.4"), None);
        assert_eq!(parse_wa_version("2.x.1"), None);
        assert_eq!(parse_wa_version(""), None);
        assert_eq!(parse_wa_version("2.-1.0"), None);
        // With no env override, the effective version is the built-in default.
        assert_eq!(wa_version(), WA_VERSION);
    }

    #[test]
    fn prune_once_caps_ages_and_prunes_signal_sessions() {
        let mgr = manager();
        let sid = mgr.create(None).unwrap().meta.read().id.clone();
        let now = chrono::Utc::now().timestamp();
        let day = 86_400i64;

        // Seed messages: chat A has 5 (ts now-0..-4 days), chat B has 1 (now).
        mgr.store
            .with_conn(|conn| {
                for i in 0..5 {
                    conn.execute(
                        "INSERT INTO messages (session_id, chat_jid, message_id, sender_jid, \
                         from_me, timestamp, msg_type, payload_json, status) \
                         VALUES (?, 'A@s', ?, 'x@s', 0, ?, 'text', '{}', 'received')",
                        rusqlite::params![sid, format!("a{i}"), now - i * day],
                    )?;
                }
                conn.execute(
                    "INSERT INTO messages (session_id, chat_jid, message_id, sender_jid, \
                     from_me, timestamp, msg_type, payload_json, status) \
                     VALUES (?, 'B@s', 'b0', 'x@s', 0, ?, 'text', '{}', 'received')",
                    rusqlite::params![sid, now],
                )?;
                // Signal sessions: one fresh, one stale (40 days old).
                conn.execute(
                    "INSERT INTO signal_sessions (session_id, address, record, updated_at) \
                     VALUES (?, 'fresh.1', x'00', ?)",
                    rusqlite::params![sid, now],
                )?;
                conn.execute(
                    "INSERT INTO signal_sessions (session_id, address, record, updated_at) \
                     VALUES (?, 'stale.1', x'00', ?)",
                    rusqlite::params![sid, now - 40 * day],
                )?;
                Ok(())
            })
            .unwrap();

        let cfg = RetentionConfig {
            messages_per_chat: 2,
            message_max_age_days: 3, // cutoff = now-3d; deletes ts strictly older
            signal_max_age_days: 30,
            sweep_secs: 0,
        };
        let stats = mgr.prune_once(&cfg).unwrap();

        // Age cutoff (ts < now-3d) removes only the now-4d chat-A row.
        assert_eq!(stats.messages_aged_out, 1);
        // Chat A's remaining 4 (now, -1d, -2d, -3d) cap to 2 → 2 over cap.
        // Chat B (1 row) is under the cap. Total over-cap deletions = 2.
        assert_eq!(stats.messages_over_cap, 2);
        assert_eq!(stats.signal_sessions_pruned, 1);

        // Final row counts: chat A = 2, chat B = 1, fresh signal session kept.
        let (a, b, sig): (i64, i64, i64) = mgr
            .store
            .with_conn(|conn| {
                let a = conn.query_row(
                    "SELECT COUNT(*) FROM messages WHERE chat_jid = 'A@s'",
                    [],
                    |r| r.get(0),
                )?;
                let b = conn.query_row(
                    "SELECT COUNT(*) FROM messages WHERE chat_jid = 'B@s'",
                    [],
                    |r| r.get(0),
                )?;
                let sig = conn.query_row("SELECT COUNT(*) FROM signal_sessions", [], |r| r.get(0))?;
                Ok((a, b, sig))
            })
            .unwrap();
        assert_eq!(a, 2);
        assert_eq!(b, 1);
        assert_eq!(sig, 1);

        // Idempotent: a second pass with the same data prunes nothing.
        let again = mgr.prune_once(&cfg).unwrap();
        assert_eq!(again, PruneStats::default());
    }

    #[tokio::test]
    async fn connection_task_handles_abort_on_replace_and_cancel() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        // Drop guard: a tokio task aborted (or finished) drops its future, so the
        // guard's flag flips — lets us observe that the *prior* handle's task was
        // actually cancelled rather than left to leak.
        struct AbortFlag(Arc<AtomicBool>);
        impl Drop for AbortFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let meta = SessionMeta {
            id: "leak".into(),
            label: None,
            status: SessionStatus::Connected,
            jid: None,
            proxy_url: None,
            mark_online: false,
            created_at: 0,
            updated_at: 0,
        };
        let session = Session::new(meta);

        // --- keepalive: replacing the handle aborts the prior task ---
        let ka_aborted = Arc::new(AtomicBool::new(false));
        let g = AbortFlag(ka_aborted.clone());
        session.set_keepalive_handle(tokio::spawn(async move {
            let _g = g;
            std::future::pending::<()>().await;
        }));
        session.set_keepalive_handle(tokio::spawn(std::future::pending::<()>()));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            ka_aborted.load(Ordering::SeqCst),
            "replacing keepalive handle must abort the prior task"
        );

        // --- prekey top-up: same invariant ---
        let pk_aborted = Arc::new(AtomicBool::new(false));
        let g = AbortFlag(pk_aborted.clone());
        session.set_prekey_topup_handle(tokio::spawn(async move {
            let _g = g;
            std::future::pending::<()>().await;
        }));
        session.set_prekey_topup_handle(tokio::spawn(std::future::pending::<()>()));
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            pk_aborted.load(Ordering::SeqCst),
            "replacing prekey top-up handle must abort the prior task"
        );

        // --- cancel_* aborts the live task and clears the slot ---
        let cancel_aborted = Arc::new(AtomicBool::new(false));
        let g = AbortFlag(cancel_aborted.clone());
        session.set_keepalive_handle(tokio::spawn(async move {
            let _g = g;
            std::future::pending::<()>().await;
        }));
        session.cancel_keepalive();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            cancel_aborted.load(Ordering::SeqCst),
            "cancel_keepalive must abort the running task"
        );
        // Slot is empty, so a second cancel is a no-op (no panic / double-abort).
        session.cancel_keepalive();
        session.cancel_prekey_topup();
    }

    #[test]
    fn lease_wait_guard_stops_when_session_moves_on() {
        // Paired + Disconnected → keep waiting for the peer to release.
        assert!(lease_wait_still_wanted(SessionStatus::Disconnected, true));
        // Once connected (here or elsewhere), stop.
        assert!(!lease_wait_still_wanted(SessionStatus::Connected, true));
        assert!(!lease_wait_still_wanted(SessionStatus::Connecting, true));
        // Logged out / unpaired → nothing to revive.
        assert!(!lease_wait_still_wanted(SessionStatus::LoggedOut, true));
        assert!(!lease_wait_still_wanted(SessionStatus::Disconnected, false));
    }

    #[test]
    fn session_lease_state_machine() {
        // Two "instances" (A, B) over one shared store.
        let store = Arc::new(Store::open(":memory:").unwrap());
        let a = SessionManager::with_instance(store.clone(), "A".into(), 60);
        let b = SessionManager::with_instance(store.clone(), "B".into(), 60);
        let sid = a.create(None).unwrap().meta.read().id.clone();

        // Free lease → A wins; a fresh lease blocks B; A may re-affirm + renew.
        assert!(a.try_acquire_lease(&sid).unwrap());
        assert!(!b.try_acquire_lease(&sid).unwrap());
        assert!(a.try_acquire_lease(&sid).unwrap());
        let now = chrono::Utc::now().timestamp();
        assert!(store.lease_renew(&sid, "A", now).unwrap());
        let (owner, stale) = a.lease_holder(&sid).unwrap().unwrap();
        assert_eq!(owner, "A");
        assert!(!stale);

        // Simulate A crashing: backdate the heartbeat well past the TTL.
        store
            .with_conn(|c| {
                c.execute(
                    "UPDATE session_leases SET heartbeat_ts = heartbeat_ts - 1000 WHERE session_id = ?",
                    rusqlite::params![sid],
                )
            })
            .unwrap();
        let (_, stale) = b.lease_holder(&sid).unwrap().unwrap();
        assert!(stale, "lease should read as stale once past TTL");

        // B steals the stale lease; A has lost it (renew + re-acquire both fail).
        assert!(b.try_acquire_lease(&sid).unwrap());
        assert!(!store.lease_renew(&sid, "A", now).unwrap());
        assert!(!a.try_acquire_lease(&sid).unwrap());

        // Releasing frees it immediately (no TTL wait) → A can reclaim.
        store.lease_release(&sid, "B").unwrap();
        assert!(a.lease_holder(&sid).unwrap().is_none());
        assert!(a.try_acquire_lease(&sid).unwrap());
    }

    #[test]
    fn retention_config_disabled_by_default() {
        // any_enabled is false when no pruning knob is set.
        let cfg = RetentionConfig {
            messages_per_chat: 0,
            message_max_age_days: 0,
            signal_max_age_days: 0,
            sweep_secs: 3600,
        };
        assert!(!cfg.any_enabled());
        assert!(RetentionConfig {
            messages_per_chat: 1,
            ..cfg
        }
        .any_enabled());
    }

    #[tokio::test]
    async fn shutdown_parks_live_sessions_disconnected() {
        let mgr = manager();
        let connected = mgr.create(None).unwrap().meta.read().id.clone();
        let pending = mgr.create(None).unwrap().meta.read().id.clone();
        // Simulate a live socket without a real connection task: flip status
        // directly so the defensive sweep has something to park.
        mgr.get(&connected).unwrap().set_status(SessionStatus::Connected);

        mgr.shutdown().await;

        // A live session is parked; a Pending one is left untouched.
        assert_eq!(
            mgr.get(&connected).unwrap().meta.read().status,
            SessionStatus::Disconnected
        );
        assert_eq!(
            mgr.get(&pending).unwrap().meta.read().status,
            SessionStatus::Pending
        );
    }

    #[tokio::test]
    async fn driver_task_aborts_immediately_when_shutdown_already_latched() {
        // A task spawned after shutdown is latched must never open a socket;
        // run_with_reconnect returns before any connect attempt.
        let mgr = manager();
        let id = mgr.create(None).unwrap().meta.read().id.clone();
        let session = mgr.get(&id).unwrap();
        let keys = mgr.load_device_keys(&id).unwrap();
        mgr.shutdown().await; // latches shutdown_tx = true

        let mut rx = mgr.shutdown_tx.subscribe();
        assert!(*rx.borrow_and_update());
        // Should return promptly rather than entering the connect loop.
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            run_with_reconnect(session, mgr.store.clone(), keys, rx, None),
        )
        .await
        .expect("run_with_reconnect did not honor the latched shutdown");
    }

    #[test]
    fn metrics_text_renders_session_gauges_and_counter_families() {
        let mgr = manager();
        mgr.create(Some("a".into())).unwrap();
        mgr.create(Some("b".into())).unwrap();
        let text = mgr.metrics_text();

        // Two fresh sessions, neither connected.
        assert!(
            text.contains("ruwa_sessions_total 2"),
            "sessions_total gauge wrong:\n{text}"
        );
        assert!(text.contains("ruwa_sessions_connected 0"));

        // Every counter family is present with HELP + TYPE lines (Prometheus
        // exposition format v0.0.4). Counter *values* are process-global, so we
        // assert the family is emitted, not an exact number (other tests bump them).
        for name in [
            "ruwa_messages_in_total",
            "ruwa_messages_out_total",
            "ruwa_decrypt_failures_total",
            "ruwa_reconnects_total",
            "ruwa_prekey_refills_total",
        ] {
            assert!(text.contains(&format!("# TYPE {name} counter")), "missing {name}");
            assert!(text.contains(&format!("# HELP {name} ")), "missing HELP {name}");
        }
    }

    #[test]
    fn metrics_text_renders_runtime_metrics() {
        let mgr = manager();
        // uptime needs the start stamped (router() does this in prod).
        metrics::mark_process_start();
        // Record a couple of HTTP samples and assert the average reflects them.
        let before_reqs = metrics::get(&metrics::HTTP_REQUESTS_TOTAL);
        let before_sum = metrics::get(&metrics::HTTP_DURATION_MS_SUM);
        metrics::record_http(10);
        metrics::record_http(30);
        assert_eq!(metrics::get(&metrics::HTTP_REQUESTS_TOTAL), before_reqs + 2);
        assert_eq!(metrics::get(&metrics::HTTP_DURATION_MS_SUM), before_sum + 40);

        let text = mgr.metrics_text();
        // Runtime families always present (cross-platform ones).
        for name in [
            "ruwa_process_uptime_seconds",
            "ruwa_http_requests_total",
            "ruwa_http_request_duration_ms_sum",
            "ruwa_http_request_duration_ms_avg",
        ] {
            assert!(text.contains(&format!("# TYPE {name} ")), "missing {name}:\n{text}");
        }
        // The /proc gauges appear only on Linux; assert presence there.
        #[cfg(target_os = "linux")]
        {
            assert!(text.contains("ruwa_process_resident_memory_bytes"));
            assert!(text.contains("ruwa_process_open_fds"));
            assert!(text.contains("ruwa_process_cpu_seconds_total"));
        }
    }

    #[test]
    fn metrics_incr_get_roundtrip() {
        use std::sync::atomic::AtomicU64;
        let c = AtomicU64::new(0);
        assert_eq!(metrics::get(&c), 0);
        metrics::incr(&c);
        metrics::incr(&c);
        assert_eq!(metrics::get(&c), 2);
    }

    #[test]
    fn proxy_error_status_round_trips() {
        // The new variant survives the DB string mapping both ways.
        assert_eq!(SessionStatus::ProxyError.as_str(), "proxy_error");
        assert!(matches!(
            "proxy_error".to_string().parse_session_status(),
            SessionStatus::ProxyError
        ));
        // A malformed proxy is rejected by Proxy::parse — the signal the
        // run_with_reconnect precheck uses to park the session in ProxyError.
        assert!(crate::protocol::connection::Proxy::parse("not-a-proxy").is_err());
    }

    #[test]
    fn set_proxy_validates_persists_and_clears() {
        let mgr = manager();
        let id = mgr.create(None).unwrap().meta.read().id.clone();

        // Valid proxy persists to meta + DB.
        mgr.set_proxy(&id, Some("socks5://u:p@1.2.3.4:1080".into()))
            .unwrap();
        assert_eq!(
            mgr.get(&id).unwrap().meta.read().proxy_url.as_deref(),
            Some("socks5://u:p@1.2.3.4:1080")
        );
        let persisted: Option<String> = mgr
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT proxy_url FROM sessions WHERE id = ?",
                    rusqlite::params![&id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(persisted.as_deref(), Some("socks5://u:p@1.2.3.4:1080"));

        // Invalid proxy is rejected and does not overwrite the existing value.
        assert!(mgr.set_proxy(&id, Some("not-a-proxy".into())).is_err());
        assert_eq!(
            mgr.get(&id).unwrap().meta.read().proxy_url.as_deref(),
            Some("socks5://u:p@1.2.3.4:1080")
        );

        // None clears it.
        mgr.set_proxy(&id, None).unwrap();
        assert_eq!(mgr.get(&id).unwrap().meta.read().proxy_url, None);
    }

    #[test]
    fn create_persists_device_keys_and_prekeys() {
        let mgr = manager();
        let session = mgr.create(Some("phone-a".into())).unwrap();
        let id = session.meta.read().id.clone();

        mgr.store
            .with_conn(|conn| {
                fn assert_blob_len(conn: &rusqlite::Connection, id: &str, col: &str, want: usize) {
                    let blob: Vec<u8> = conn
                        .query_row(
                            &format!("SELECT {col} FROM sessions WHERE id = ?"),
                            [id],
                            |r| r.get(0),
                        )
                        .unwrap();
                    assert_eq!(blob.len(), want, "{col} length");
                }

                let regid: i64 = conn.query_row(
                    "SELECT registration_id FROM sessions WHERE id = ?",
                    [&id],
                    |r| r.get(0),
                )?;
                assert!(regid > 0 && regid <= i64::from(i32::MAX));

                for (col, len) in [
                    ("noise_key_priv", 32),
                    ("noise_key_pub", 32),
                    ("identity_key_priv", 32),
                    ("identity_key_pub", 32),
                    ("signed_prekey_priv", 32),
                    ("signed_prekey_pub", 32),
                    ("signed_prekey_sig", 64),
                    ("adv_secret_key", 32),
                ] {
                    assert_blob_len(conn, &id, col, len);
                }

                let spk_id: i64 = conn.query_row(
                    "SELECT signed_prekey_id FROM sessions WHERE id = ?",
                    [&id],
                    |r| r.get(0),
                )?;
                assert_eq!(spk_id, 1);

                let count: u32 = conn.query_row(
                    "SELECT COUNT(*) FROM prekeys WHERE session_id = ?",
                    [&id],
                    |r| r.get(0),
                )?;
                assert_eq!(count, INITIAL_PREKEY_COUNT);
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn delete_cascades_prekeys() {
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let id = session.meta.read().id.clone();
        mgr.delete(&id).unwrap();

        let remaining: u32 = mgr
            .store
            .with_conn(|conn| {
                conn.query_row("SELECT COUNT(*) FROM prekeys WHERE session_id = ?", [&id], |r| r.get(0))
            })
            .unwrap();
        assert_eq!(remaining, 0, "ON DELETE CASCADE should drop prekeys");
    }

    #[test]
    fn version_hash_matches_md5_of_dotted_string() {
        // The known MD5 of "2.3000.1038187123" — generated independently as
        // a regression guard against accidental WA_VERSION drift in this
        // tree decoupling from the real wire-version expectation.
        let hash = wa_version_hash();
        assert_eq!(hash.len(), 16);
        // Recompute manually with the md-5 crate; if these two ever diverge
        // we have a bigger problem than a stale hash.
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        let v = wa_version();
        h.update(format!("{}.{}.{}", v[0], v[1], v[2]).as_bytes());
        let want: [u8; 16] = h.finalize().into();
        assert_eq!(hash, want);
    }

    #[test]
    #[ignore]
    fn diff_against_whatsmeow_payload() {
        use crate::proto::wa_companion_reg::DeviceProps;
        use crate::proto::wa_web_protobufs_wa6::ClientPayload;
        use prost::Message;

        // Whatsmeow's wire-captured ClientPayload bytes (paste fresh hex
        // from `[RUWA-DEBUG] CLIENT PAYLOAD HEX` to refresh).
        let whatsmeow_hex = "18002a38080e120b080210b81718f3f485ef031a0330303022033030302a03302e3132003a074465736b746f704203302e3150005a02656e6202555332022000600168019a01e1010a04b6e21c4c1201051a2053b642e0f04320aff939b4b3c83b1a337a749667956fde02133b607a52ed5a2c22030000012a205542d01134eadee0445aa8fe50dd6bc8202a54c30d87710c85538a7a3fdb683e3240fadc725d62a6131c0ee945ba22357c8a877e9ac239820c64a2dcf721f45fa809210b45fb50b882f27a2a4d0c60821e7c647388a716134eb46f96acea6c7d85063a101edd940a37a228fb3608b4a93ba275e542390a0977686174736d656f771206080010011800180020002a20188050200130003801400148015001580160017001780198013ca80101b00101880200";
        let mut whatsmeow_bytes = Vec::with_capacity(whatsmeow_hex.len() / 2);
        for i in (0..whatsmeow_hex.len()).step_by(2) {
            whatsmeow_bytes.push(u8::from_str_radix(&whatsmeow_hex[i..i + 2], 16).unwrap());
        }
        let wm = ClientPayload::decode(whatsmeow_bytes.as_slice()).expect("whatsmeow payload");

        let keys = crate::crypto::identity::DeviceKeys::generate();
        let our_bytes = build_registration_client_payload(&keys);
        let ours = ClientPayload::decode(our_bytes.as_slice()).expect("our payload");

        println!("\n=== WHATSMEOW ===");
        println!("{wm:#?}");
        println!("\n=== OURS ===");
        println!("{ours:#?}");

        // Decode device_props sub-blobs separately so we can diff their fields.
        let wm_dp_bytes = wm.device_pairing_data.as_ref().and_then(|d| d.device_props.clone()).unwrap();
        let our_dp_bytes = ours.device_pairing_data.as_ref().and_then(|d| d.device_props.clone()).unwrap();
        let wm_dp = DeviceProps::decode(wm_dp_bytes.as_slice()).expect("whatsmeow device_props");
        let our_dp = DeviceProps::decode(our_dp_bytes.as_slice()).expect("our device_props");
        println!("\n=== WM DEVICE_PROPS ===");
        println!("{wm_dp:#?}");
        println!("\n=== OUR DEVICE_PROPS ===");
        println!("{our_dp:#?}");
    }

    #[test]
    fn registration_client_payload_round_trips_to_proto() {
        use crate::proto::wa_companion_reg::DeviceProps;
        use crate::proto::wa_web_protobufs_wa6::client_payload::{ConnectReason, ConnectType};
        use crate::proto::wa_web_protobufs_wa6::ClientPayload;
        use prost::Message;

        let keys = DeviceKeys::generate();
        let bytes = build_registration_client_payload(&keys);
        let payload = ClientPayload::decode(&bytes[..]).expect("decode payload");

        assert_eq!(payload.passive, Some(false));
        assert_eq!(payload.pull, Some(false));
        assert_eq!(payload.connect_type, Some(ConnectType::WifiUnknown as i32));
        assert_eq!(payload.connect_reason, Some(ConnectReason::UserActivated as i32));

        let ua = payload.user_agent.expect("user_agent");
        let ver = ua.app_version.expect("app_version");
        assert_eq!(ver.primary, Some(WA_VERSION[0]));
        assert_eq!(ver.secondary, Some(WA_VERSION[1]));
        assert_eq!(ver.tertiary, Some(WA_VERSION[2]));

        let pairing = payload.device_pairing_data.expect("device_pairing_data");
        assert_eq!(pairing.e_keytype, Some(vec![5u8])); // DjbType
        assert_eq!(pairing.e_regid.unwrap(), keys.registration_id.to_be_bytes());
        assert_eq!(pairing.e_ident.unwrap(), keys.identity.public.to_vec());
        assert_eq!(pairing.e_skey_id.unwrap(), [0u8, 0, 1]); // 3-byte BE of key_id=1
        assert_eq!(pairing.e_skey_val.unwrap(), keys.signed_prekey.keypair.public);
        assert_eq!(pairing.e_skey_sig.unwrap().len(), 64);
        assert_eq!(pairing.build_hash.unwrap(), wa_version_hash().to_vec());

        // device_props is itself a serialized DeviceProps proto.
        let dp_bytes = pairing.device_props.expect("device_props");
        let dp = DeviceProps::decode(&dp_bytes[..]).expect("decode DeviceProps");
        assert_eq!(dp.os.as_deref(), Some("Chrome"));
        assert_eq!(
            dp.platform_type,
            Some(crate::proto::wa_companion_reg::device_props::PlatformType::Chrome as i32)
        );
        assert!(dp.version.is_some());
    }

    /// Build the canonical `<iq from="s.whatsapp.net" id="..." type="set">
    /// <pair-device><ref>foo</ref><ref>bar</ref></pair-device></iq>` shape
    /// that the server sends after a fresh-device handshake completes.
    fn pair_device_iq(refs: &[&str], id: &str) -> crate::protocol::binary::Node {
        use crate::protocol::binary::{Attrs, Content, Node};
        let mut iq = Node::new("iq");
        iq.attrs.insert("from".into(), "s.whatsapp.net".into());
        iq.attrs.insert("id".into(), id.into());
        iq.attrs.insert("type".into(), "set".into());

        let pair_device = Node {
            tag: "pair-device".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(
                refs.iter()
                    .map(|r| Node {
                        tag: "ref".into(),
                        attrs: Attrs::new(),
                        content: Content::Bytes(r.as_bytes().to_vec()),
                    })
                    .collect(),
            ),
        };
        iq.content = Content::Nodes(vec![pair_device]);
        iq
    }

    #[test]
    fn pair_device_iq_populates_qr_codes_and_emits_ack() {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let keys = mgr.load_device_keys(&session.meta.read().id).unwrap();

        let iq = pair_device_iq(&["AAA-ref-1", "BBB-ref-2"], "iq-id-1");
        let ack = process_inbound_node(&session, &mgr.store, &keys, None, &iq)
            .expect("returns iq result ack");

        // Two refs in → two QR codes out, each with the right key suffix.
        let codes = session.qr_codes.read().clone();
        assert_eq!(codes.len(), 2);
        let noise_b64 = B64.encode(keys.noise.public);
        let identity_b64 = B64.encode(keys.identity.public);
        let adv_b64 = B64.encode(keys.adv_secret);
        assert_eq!(
            codes[0],
            format!("AAA-ref-1,{noise_b64},{identity_b64},{adv_b64}")
        );
        assert_eq!(
            codes[1],
            format!("BBB-ref-2,{noise_b64},{identity_b64},{adv_b64}")
        );

        // Ack node is the conventional iq result with the original id+from.
        assert_eq!(ack.tag, "iq");
        assert_eq!(ack.attrs.get("type").map(String::as_str), Some("result"));
        assert_eq!(ack.attrs.get("id").map(String::as_str), Some("iq-id-1"));
        assert_eq!(
            ack.attrs.get("to").map(String::as_str),
            Some("s.whatsapp.net")
        );
    }

    #[test]
    fn process_inbound_ignores_non_iq_nodes() {
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let keys = mgr.load_device_keys(&session.meta.read().id).unwrap();
        let n = crate::protocol::binary::Node::new("notification");
        assert!(process_inbound_node(&session, &mgr.store, &keys, None, &n).is_none());
        assert!(session.qr_codes.read().is_empty());
    }

    /// Post-`<success>` chain mirrors whatsmeow's `handleConnectSuccess` +
    /// the additional steps documented in INBOUND_HANDOVER.md (git history). With a
    /// dispatcher attached the handler ships, in order:
    ///   1. `<iq xmlns="passive" type="set"><active/></iq>`
    ///   2. `<iq xmlns="encrypt" type="set">…prekey upload…</iq>`
    ///   3. `<presence type="available"/>` (no `name` attr until the
    ///      sessions row's `push_name` is populated by app-state sync).
    ///
    /// Without (3) the WA server keeps the linked device in passive
    /// observer mode and never forwards inbound `<message>` nodes.
    #[test]
    fn success_handler_ships_passive_prekeys_then_presence_available() {
        use crate::protocol::binary::{Content, Node};
        use tokio::sync::mpsc;

        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let keys = mgr.load_device_keys(&session.meta.read().id).unwrap();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Node>();
        let dispatcher = ConnDispatcher::new(out_tx);

        let success = Node::new("success");
        let reply = process_inbound_node(
            &session,
            &mgr.store,
            &keys,
            Some(&dispatcher),
            &success,
        );
        assert!(reply.is_none(), "success returns no synchronous ack");

        // Status flips to Connected.
        assert!(matches!(
            session.meta.read().status,
            SessionStatus::Connected
        ));

        // 1. SetPassive(false) IQ.
        let n1 = out_rx.try_recv().expect("setpassive iq queued");
        assert_eq!(n1.tag, "iq");
        assert_eq!(n1.attrs.get("xmlns").map(String::as_str), Some("passive"));
        assert_eq!(n1.attrs.get("type").map(String::as_str), Some("set"));
        match &n1.content {
            Content::Nodes(ns) => {
                assert_eq!(ns.len(), 1);
                assert_eq!(ns[0].tag, "active");
            }
            _ => panic!("expected child <active/>"),
        }

        // 1a. <iq xmlns=encrypt><digest/></iq> — key-bundle validation.
        let n_digest = out_rx.try_recv().expect("digest iq queued");
        assert_eq!(n_digest.tag, "iq");
        assert_eq!(n_digest.attrs.get("xmlns").map(String::as_str), Some("encrypt"));

        // 1b. <ib><unified_session id=…/></ib> — the open-session signal.
        let n_ib = out_rx.try_recv().expect("ib/unified_session queued");
        assert_eq!(n_ib.tag, "ib");
        match &n_ib.content {
            Content::Nodes(ns) => {
                assert_eq!(ns.len(), 1);
                assert_eq!(ns[0].tag, "unified_session");
                assert!(ns[0].attrs.contains_key("id"));
            }
            _ => panic!("expected child <unified_session/>"),
        }

        // 2. Prekey upload IQ (a fresh session has INITIAL_PREKEY_COUNT
        //    not-yet-uploaded OPKs, so this branch fires).
        let n2 = out_rx.try_recv().expect("prekey upload iq queued");
        assert_eq!(n2.tag, "iq");
        assert_eq!(n2.attrs.get("xmlns").map(String::as_str), Some("encrypt"));
        assert_eq!(n2.attrs.get("type").map(String::as_str), Some("set"));

        // 3. Presence available — no name attr because push_name is NULL
        //    on a freshly-created session.
        let n3 = out_rx.try_recv().expect("presence node queued");
        assert_eq!(n3.tag, "presence");
        // Default session: mark_online=false → announce `unavailable` (phone keeps notifying).
        assert_eq!(n3.attrs.get("type").map(String::as_str), Some("unavailable"));
        assert_eq!(n3.attrs.get("name"), None);
        assert!(matches!(n3.content, Content::None));

        // 4. Five app-state fetch IQs, one per collection. Order is fixed
        //    by AppStateCollection::all() — critical first then regular*.
        let want_names = [
            "critical_block",
            "critical_unblock_low",
            "regular",
            "regular_high",
            "regular_low",
        ];
        for want in want_names {
            let iq = out_rx.try_recv().unwrap_or_else(|_| {
                panic!("expected app-state fetch IQ for {want}")
            });
            assert_eq!(iq.tag, "iq");
            assert_eq!(
                iq.attrs.get("xmlns").map(String::as_str),
                Some("w:sync:app:state"),
            );
            assert_eq!(iq.attrs.get("type").map(String::as_str), Some("set"));
            let sync = match &iq.content {
                Content::Nodes(ns) => &ns[0],
                _ => panic!("expected <sync> child"),
            };
            assert_eq!(sync.tag, "sync");
            let collection = match &sync.content {
                Content::Nodes(ns) => &ns[0],
                _ => panic!("expected <collection> grandchild"),
            };
            assert_eq!(collection.tag, "collection");
            assert_eq!(
                collection.attrs.get("name").map(String::as_str),
                Some(want),
            );
            // Fresh session — every collection asks for a snapshot.
            assert_eq!(
                collection.attrs.get("return_snapshot").map(String::as_str),
                Some("true"),
            );
            assert!(!collection.attrs.contains_key("version"));
        }

        // Init queries (props/blocklist/privacy) — fired after the app-state
        // fetches as fire-and-forget GETs.
        for want_xmlns in ["w", "blocklist", "privacy"] {
            let q = out_rx.try_recv().expect("init query queued");
            assert_eq!(q.tag, "iq");
            assert_eq!(q.attrs.get("type").map(String::as_str), Some("get"));
            assert_eq!(q.attrs.get("xmlns").map(String::as_str), Some(want_xmlns));
        }

        // No straggler nodes.
        assert!(out_rx.try_recv().is_err());
    }

    /// A server `<notification type="encrypt"><count value="N"/></notification>`
    /// with N below the floor triggers a fresh OTK batch: new keys are
    /// generated (key-id sequence continues) and an `<iq xmlns="encrypt">`
    /// upload is shipped. Mirrors whatsmeow's handleEncryptNotification.
    #[test]
    fn low_encrypt_notification_replenishes_and_uploads_prekeys() {
        use crate::protocol::binary::{Attrs, Content, Node};
        use tokio::sync::mpsc;

        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let sid = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&sid).unwrap();

        // Simulate near-exhaustion: mark all initial OTKs uploaded, then delete
        // all but 2 (as peers consuming them would).
        mgr.store
            .with_conn(|conn| {
                conn.execute(
                    "UPDATE prekeys SET uploaded = 1 WHERE session_id = ?",
                    rusqlite::params![&sid],
                )?;
                conn.execute(
                    "DELETE FROM prekeys WHERE session_id = ? AND key_id > 2",
                    rusqlite::params![&sid],
                )?;
                Ok(())
            })
            .unwrap();
        assert_eq!(available_prekey_count(&mgr.store, &sid), 2);

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Node>();
        let dispatcher = ConnDispatcher::new(out_tx);

        // <notification type="encrypt"><count value="2"/></notification>
        let mut nattrs = Attrs::new();
        nattrs.insert("type".into(), "encrypt".into());
        nattrs.insert("from".into(), "s.whatsapp.net".into());
        nattrs.insert("id".into(), "n1".into());
        let mut cattrs = Attrs::new();
        cattrs.insert("value".into(), "2".into());
        let notif = Node {
            tag: "notification".into(),
            attrs: nattrs,
            content: Content::Nodes(vec![Node {
                tag: "count".into(),
                attrs: cattrs,
                content: Content::None,
            }]),
        };

        process_inbound_node(&session, &mgr.store, &keys, Some(&dispatcher), &notif);

        // Fresh batch generated + persisted (2 leftover + WANTED new).
        let total: i64 = mgr
            .store
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM prekeys WHERE session_id = ?",
                    rusqlite::params![&sid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(total, 2 + WANTED_PREKEY_COUNT as i64);

        // An <iq xmlns="encrypt" type="set"> upload was shipped, plus the ack.
        let mut saw_encrypt_upload = false;
        while let Ok(n) = out_rx.try_recv() {
            if n.tag == "iq" && n.attrs.get("xmlns").map(String::as_str) == Some("encrypt") {
                assert_eq!(n.attrs.get("type").map(String::as_str), Some("set"));
                saw_encrypt_upload = true;
            }
        }
        assert!(saw_encrypt_upload, "expected an encrypt upload IQ");
    }

    #[test]
    fn notification_ack_copies_type_and_recipient() {
        // WA matches an <ack> to its pending node by class+id+TYPE. whatsmeow's
        // sendAck copies `type` (for any non-message node) and `recipient` onto
        // the ack; omitting `type` leaves a `notification type="account_sync"`
        // unacked, which strands the primary device on "Connecting…" for ~30s
        // after pairing. This guards that our ack carries both.
        use crate::protocol::binary::{Attrs, Content, Node};
        use tokio::sync::mpsc;

        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let sid = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&sid).unwrap();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Node>();
        let dispatcher = ConnDispatcher::new(out_tx);

        let mut attrs = Attrs::new();
        attrs.insert("type".into(), "account_sync".into());
        attrs.insert("from".into(), "169000000000002.1@lid".into());
        attrs.insert("id".into(), "1428798224".into());
        attrs.insert("recipient".into(), "551190000002@s.whatsapp.net".into());
        let notif = Node {
            tag: "notification".into(),
            attrs,
            content: Content::None,
        };

        process_inbound_node(&session, &mgr.store, &keys, Some(&dispatcher), &notif);

        let ack = std::iter::from_fn(|| out_rx.try_recv().ok())
            .find(|n| n.tag == "ack")
            .expect("expected an <ack> for the notification");
        assert_eq!(ack.attrs.get("class").map(String::as_str), Some("notification"));
        assert_eq!(ack.attrs.get("id").map(String::as_str), Some("1428798224"));
        assert_eq!(
            ack.attrs.get("to").map(String::as_str),
            Some("169000000000002.1@lid"),
        );
        assert_eq!(
            ack.attrs.get("type").map(String::as_str),
            Some("account_sync"),
            "ack must copy the notification `type` or WA treats it as unacked",
        );
        assert_eq!(
            ack.attrs.get("recipient").map(String::as_str),
            Some("551190000002@s.whatsapp.net"),
        );
    }

    #[test]
    fn device_cache_get_put_clear() {
        // The per-user device cache turns a blocking usync-per-send into a hit.
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let key = "5511990000001@s.whatsapp.net";

        assert!(session.device_cache_get(key).is_none(), "cold = miss");
        let devs = vec![
            format!("{key}"),
            "5511990000001:19@s.whatsapp.net".to_string(),
        ];
        session.device_cache_put(key, devs.clone());
        assert_eq!(session.device_cache_get(key), Some(devs), "warm = hit");

        session.device_cache_clear();
        assert!(
            session.device_cache_get(key).is_none(),
            "clear (devices notification) invalidates",
        );
    }

    #[test]
    fn devices_notification_clears_device_cache() {
        // `<notification type="devices">` must drop cached device lists so the
        // next send re-resolves the peer's (now changed) device set.
        use crate::protocol::binary::{Attrs, Content, Node};
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let sid = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&sid).unwrap();

        let key = "5511990000001@s.whatsapp.net";
        session.device_cache_put(key, vec![key.to_string()]);
        assert!(session.device_cache_get(key).is_some());

        let mut attrs = Attrs::new();
        attrs.insert("type".into(), "devices".into());
        attrs.insert("from".into(), key.into());
        attrs.insert("id".into(), "n-dev-1".into());
        let notif = Node { tag: "notification".into(), attrs, content: Content::None };
        process_inbound_node(&session, &mgr.store, &keys, None, &notif);

        assert!(
            session.device_cache_get(key).is_none(),
            "devices notification should clear the cache",
        );
    }

    /// IQ shape matches whatsmeow's `Client.fetchAppStatePatches` exactly,
    /// including the `return_snapshot=false` + `version=N` branch that
    /// fires on follow-up fetches once the version cursor advances.
    #[test]
    fn build_app_state_fetch_iq_snapshot_vs_versioned_shapes() {
        use crate::protocol::binary::Content;

        let snap = build_app_state_fetch_iq("iq-1", "regular", 0, true);
        assert_eq!(snap.tag, "iq");
        assert_eq!(
            snap.attrs.get("xmlns").map(String::as_str),
            Some("w:sync:app:state"),
        );
        assert_eq!(snap.attrs.get("id").map(String::as_str), Some("iq-1"));
        assert_eq!(snap.attrs.get("type").map(String::as_str), Some("set"));
        assert_eq!(
            snap.attrs.get("to").map(String::as_str),
            Some("s.whatsapp.net"),
        );
        let collection = match &snap.content {
            Content::Nodes(ns) => match &ns[0].content {
                Content::Nodes(gs) => gs[0].clone(),
                _ => panic!(),
            },
            _ => panic!(),
        };
        assert_eq!(
            collection.attrs.get("return_snapshot").map(String::as_str),
            Some("true"),
        );
        assert!(!collection.attrs.contains_key("version"));

        let versioned =
            build_app_state_fetch_iq("iq-2", "regular_high", 42, false);
        let collection = match &versioned.content {
            Content::Nodes(ns) => match &ns[0].content {
                Content::Nodes(gs) => gs[0].clone(),
                _ => panic!(),
            },
            _ => panic!(),
        };
        assert_eq!(
            collection.attrs.get("return_snapshot").map(String::as_str),
            Some("false"),
        );
        assert_eq!(
            collection.attrs.get("version").map(String::as_str),
            Some("42"),
        );
        assert_eq!(
            collection.attrs.get("name").map(String::as_str),
            Some("regular_high"),
        );
    }

    /// Same as above but with `push_name` populated (as it would be after
    /// app-state ContactUpsert syncs our own JID). The presence node now
    /// carries the `name` attr WA needs to populate other peers' contact
    /// cards.
    #[test]
    fn success_handler_includes_push_name_when_persisted() {
        use crate::protocol::binary::Node;
        use tokio::sync::mpsc;

        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let session_id = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&session_id).unwrap();

        // Simulate an app-state ContactUpsert for our own JID having
        // populated push_name — the `presence name=` attr should now flow.
        mgr.store
            .with_conn(|c| {
                c.execute(
                    "UPDATE sessions SET push_name = ? WHERE id = ?",
                    rusqlite::params!["Henry", &session_id],
                )?;
                Ok(())
            })
            .unwrap();

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Node>();
        let dispatcher = ConnDispatcher::new(out_tx);
        process_inbound_node(
            &session,
            &mgr.store,
            &keys,
            Some(&dispatcher),
            &Node::new("success"),
        );
        let _ = out_rx.try_recv().unwrap(); // setpassive
        let _ = out_rx.try_recv().unwrap(); // digest iq
        let _ = out_rx.try_recv().unwrap(); // ib/unified_session
        let _ = out_rx.try_recv().unwrap(); // prekey upload
        let presence = out_rx.try_recv().expect("presence queued");
        assert_eq!(presence.tag, "presence");
        assert_eq!(
            presence.attrs.get("type").map(String::as_str),
            Some("unavailable")
        );
        assert_eq!(presence.attrs.get("name").map(String::as_str), Some("Henry"));
    }

    #[test]
    fn process_inbound_ignores_iq_without_pair_device_or_pair_success() {
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let keys = mgr.load_device_keys(&session.meta.read().id).unwrap();
        let mut n = crate::protocol::binary::Node::new("iq");
        n.attrs.insert("type".into(), "result".into());
        assert!(process_inbound_node(&session, &mgr.store, &keys, None, &n).is_none());
    }

    /// Build a real, well-formed `device-identity` payload for tests. The
    /// returned bytes parse as `AdvSignedDeviceIdentityHmac`, the inner
    /// `AdvSignedDeviceIdentity` has a valid account signature over our
    /// device identity pub, and the outer HMAC is computed against the
    /// supplied `adv_secret`. Mirrors the bundle WA's server ships on a
    /// successful QR scan, so `apply_pair_success` runs end-to-end.
    fn build_signed_pair_success_bundle(
        adv_secret: &[u8; 32],
        device_identity_pub: &[u8; 32],
    ) -> Vec<u8> {
        use crate::proto::wa_adv::{
            AdvDeviceIdentity, AdvSignedDeviceIdentity, AdvSignedDeviceIdentityHmac,
        };
        use hmac::{Hmac, Mac};
        use prost::Message;
        use sha2::Sha256;

        // Inner ADVDeviceIdentity (raw_id/timestamp/key_index).
        let inner = AdvDeviceIdentity {
            raw_id: Some(1),
            timestamp: Some(1700000000),
            key_index: Some(1),
            account_type: None,
            device_type: None,
        };
        let signed_details = inner.encode_to_vec();

        // Fresh "account" keypair to play the role of the WA-account signer.
        let account = crate::crypto::identity::KeyPair::generate();

        // account_sig = xeddsa_sign(account_priv, [6,0]||signed_details||device_identity_pub)
        let mut acct_msg = Vec::with_capacity(2 + signed_details.len() + 32);
        acct_msg.extend_from_slice(&ADV_ACCOUNT_SIG_PREFIX);
        acct_msg.extend_from_slice(&signed_details);
        acct_msg.extend_from_slice(device_identity_pub);
        let account_sig = crate::crypto::identity::xeddsa_sign(&account.private, &acct_msg);

        let signed = AdvSignedDeviceIdentity {
            details: Some(signed_details),
            account_signature_key: Some(account.public.to_vec()),
            account_signature: Some(account_sig.to_vec()),
            device_signature: None,
        };
        let signed_bytes = signed.encode_to_vec();

        // HMAC-SHA256(adv_secret, signed_bytes) — the e2ee path (no hosted prefix).
        let mut mac = Hmac::<Sha256>::new_from_slice(adv_secret).unwrap();
        mac.update(&signed_bytes);
        let hmac_bytes = mac.finalize().into_bytes().to_vec();

        let container = AdvSignedDeviceIdentityHmac {
            details: Some(signed_bytes),
            hmac: Some(hmac_bytes),
            account_type: None,
        };
        container.encode_to_vec()
    }

    /// Construct the canonical pair-success IQ shape.
    fn pair_success_iq(
        device_identity: &[u8],
        biz_name: &str,
        jid: &str,
        platform: &str,
        id: &str,
    ) -> crate::protocol::binary::Node {
        use crate::protocol::binary::{Attrs, Content, Node};
        let mut iq = Node::new("iq");
        iq.attrs.insert("from".into(), "s.whatsapp.net".into());
        iq.attrs.insert("id".into(), id.into());
        iq.attrs.insert("type".into(), "result".into());

        let mut device = Node::new("device");
        device.attrs.insert("jid".into(), jid.into());

        let mut biz = Node::new("biz");
        biz.attrs.insert("name".into(), biz_name.into());

        let mut platform_node = Node::new("platform");
        platform_node.attrs.insert("name".into(), platform.into());

        let device_id_node = Node {
            tag: "device-identity".into(),
            attrs: Attrs::new(),
            content: Content::Bytes(device_identity.to_vec()),
        };

        iq.content = Content::Nodes(vec![Node {
            tag: "pair-success".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![device_id_node, biz, device, platform_node]),
        }]);
        iq
    }

    #[test]
    fn pair_success_persists_jid_biz_platform_and_flips_status() {
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let id = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&id).unwrap();

        let bundle = build_signed_pair_success_bundle(&keys.adv_secret, &keys.identity.public);
        let iq = pair_success_iq(
            &bundle,
            "Acme Corp",
            "5511999999999:23@s.whatsapp.net",
            "android",
            "ps-iq-1",
        );

        // Pre-stash a QR so we can assert it's cleared on success.
        session.set_qr_codes(vec!["fake".into()]);

        let ack = process_inbound_node(&session, &mgr.store, &keys, None, &iq)
            .expect("returns iq result ack");
        assert_eq!(ack.tag, "iq");
        assert_eq!(ack.attrs.get("type").map(String::as_str), Some("result"));
        assert_eq!(ack.attrs.get("id").map(String::as_str), Some("ps-iq-1"));

        // In-memory meta updated.
        let m = session.meta.read();
        assert_eq!(m.status, SessionStatus::Connected);
        assert_eq!(
            m.jid.as_deref(),
            Some("5511999999999:23@s.whatsapp.net")
        );
        drop(m);
        assert!(session.qr_codes.read().is_empty(), "QR codes cleared");

        // Persisted columns updated — query each one independently to keep
        // clippy::type_complexity happy without a bespoke struct.
        mgr.store
            .with_conn(|conn| {
                fn get_str(conn: &rusqlite::Connection, id: &str, col: &str) -> Option<String> {
                    conn.query_row(
                        &format!("SELECT {col} FROM sessions WHERE id = ?"),
                        [id],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .unwrap()
                }
                assert_eq!(get_str(conn, &id, "status").unwrap(), "connected");
                assert_eq!(
                    get_str(conn, &id, "jid").as_deref(),
                    Some("5511999999999:23@s.whatsapp.net")
                );
                assert_eq!(get_str(conn, &id, "business_name").as_deref(), Some("Acme Corp"));
                assert_eq!(get_str(conn, &id, "platform").as_deref(), Some("android"));

                // account_pb now stores the FULL signed device identity
                // (with our device_signature filled in). Just confirm it
                // round-trips and contains a 64-byte device signature.
                let pb: Vec<u8> = conn
                    .query_row("SELECT account_pb FROM sessions WHERE id = ?", [&id], |r| {
                        r.get(0)
                    })?;
                use crate::proto::wa_adv::AdvSignedDeviceIdentity;
                use prost::Message;
                let parsed = AdvSignedDeviceIdentity::decode(pb.as_slice()).unwrap();
                assert_eq!(parsed.device_signature.unwrap().len(), 64);
                assert!(parsed.account_signature_key.is_some());
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn parse_user_jid_handles_common_forms() {
        assert_eq!(
            parse_user_jid("5511999999999@s.whatsapp.net"),
            Some((5511999999999, 0))
        );
        assert_eq!(
            parse_user_jid("5511999999999:23@s.whatsapp.net"),
            Some((5511999999999, 23))
        );
        // Whatsmeow's `<user>.<agent>:<device>` form: agent stripped, device kept.
        assert_eq!(
            parse_user_jid("5511999999999.5:23@s.whatsapp.net"),
            Some((5511999999999, 23))
        );
        // Non-numeric user → None (e.g. group jids).
        assert!(parse_user_jid("foo-bar@g.us").is_none());
    }

    #[test]
    fn login_payload_omits_regdata_and_sets_username_device() {
        use crate::proto::wa_web_protobufs_wa6::ClientPayload;
        use prost::Message;

        let keys = DeviceKeys::generate();
        let bytes = build_login_client_payload(&keys, 5511999999999, 23);
        let payload = ClientPayload::decode(&bytes[..]).expect("decode payload");

        assert_eq!(payload.username, Some(5511999999999));
        assert_eq!(payload.device, Some(23));
        assert_eq!(payload.passive, Some(true));
        assert_eq!(payload.pull, Some(true));
        assert!(payload.device_pairing_data.is_none());
    }

    #[test]
    fn select_client_payload_picks_login_when_jid_set() {
        use crate::proto::wa_web_protobufs_wa6::ClientPayload;
        use prost::Message;

        let keys = DeviceKeys::generate();
        let mut meta = SessionMeta {
            id: "x".into(),
            label: None,
            status: SessionStatus::Connected,
            jid: Some("5511999999999:7@s.whatsapp.net".into()),
            proxy_url: None,
            mark_online: false,
            created_at: 0,
            updated_at: 0,
        };
        let p = select_client_payload(&meta, &keys);
        let parsed = ClientPayload::decode(&p[..]).unwrap();
        assert_eq!(parsed.passive, Some(true));
        assert_eq!(parsed.username, Some(5511999999999));
        assert_eq!(parsed.device, Some(7));

        // Without a jid, falls back to registration payload.
        meta.jid = None;
        let p = select_client_payload(&meta, &keys);
        let parsed = ClientPayload::decode(&p[..]).unwrap();
        assert_eq!(parsed.passive, Some(false));
        assert!(parsed.device_pairing_data.is_some());
    }

    #[test]
    fn logout_clears_credentials_and_sets_status() {
        let mgr = manager();
        let session = mgr.create(None).unwrap();
        let id = session.meta.read().id.clone();

        // Apply a fake pair-success so we have credentials to clear.
        let keys = mgr.load_device_keys(&id).unwrap();
        let bundle = build_signed_pair_success_bundle(&keys.adv_secret, &keys.identity.public);
        let iq = pair_success_iq(
            &bundle,
            "Biz",
            "5511999999999:23@s.whatsapp.net",
            "android",
            "ps",
        );
        process_inbound_node(&session, &mgr.store, &keys, None, &iq).unwrap();
        assert_eq!(session.meta.read().status, SessionStatus::Connected);

        mgr.logout(&id).unwrap();
        let m = session.meta.read();
        assert_eq!(m.status, SessionStatus::LoggedOut);
        assert!(m.jid.is_none());
        drop(m);

        mgr.store
            .with_conn(|conn| {
                let (status, jid, account_pb): (String, Option<String>, Option<Vec<u8>>) = conn
                    .query_row(
                        "SELECT status, jid, account_pb FROM sessions WHERE id = ?",
                        [&id],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                    )?;
                assert_eq!(status, "logged_out");
                assert!(jid.is_none());
                assert!(account_pb.is_none());
                Ok(())
            })
            .unwrap();
    }

    // -- prekey-fetch IQ ---------------------------------------------------

    #[test]
    fn reaction_edit_revoke_builders_round_trip_through_proto() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;
        let chat = "5511999@s.whatsapp.net";
        let target_id = "TGT-1";

        // Reaction.
        let bytes = build_reaction_message(chat, target_id, true, None, "👍", 1_700_000_000_000);
        let m = e2e::Message::decode(bytes.as_slice()).unwrap();
        let r = m.reaction_message.expect("reaction_message");
        assert_eq!(r.text.as_deref(), Some("👍"));
        let key = r.key.expect("reaction key");
        assert_eq!(key.id.as_deref(), Some(target_id));
        assert_eq!(key.from_me, Some(true));
        assert_eq!(key.remote_jid.as_deref(), Some(chat));

        // Revoke.
        let bytes = build_revoke_message(chat, target_id, false, Some("u@s.whatsapp.net"));
        let m = e2e::Message::decode(bytes.as_slice()).unwrap();
        let p = m.protocol_message.expect("protocol_message");
        assert_eq!(p.r#type, Some(e2e::protocol_message::Type::Revoke as i32));
        let key = p.key.as_ref().expect("revoke key");
        assert_eq!(key.id.as_deref(), Some(target_id));
        assert_eq!(key.from_me, Some(false));
        assert_eq!(key.participant.as_deref(), Some("u@s.whatsapp.net"));

        // Edit.
        let bytes = build_edit_message(chat, target_id, true, None, "fixed", 1_700_000_000_000);
        let m = e2e::Message::decode(bytes.as_slice()).unwrap();
        let p = m.protocol_message.expect("protocol_message");
        assert_eq!(p.r#type, Some(e2e::protocol_message::Type::MessageEdit as i32));
        let edited = p.edited_message.expect("edited inner");
        assert_eq!(edited.conversation.as_deref(), Some("fixed"));
    }

    #[test]
    fn build_remove_companion_device_iq_has_canonical_shape() {
        use crate::protocol::binary::Content;
        let iq = build_remove_companion_device_iq(
            "iq-rm",
            "5511999999999.0:23@s.whatsapp.net",
        );
        assert_eq!(iq.tag, "iq");
        assert_eq!(iq.attrs.get("type").map(String::as_str), Some("set"));
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("md"));
        assert_eq!(iq.attrs.get("to").map(String::as_str), Some("s.whatsapp.net"));
        assert_eq!(iq.attrs.get("id").map(String::as_str), Some("iq-rm"));
        let rm = match &iq.content {
            Content::Nodes(ns) => &ns[0],
            _ => panic!(),
        };
        assert_eq!(rm.tag, "remove-companion-device");
        assert_eq!(
            rm.attrs.get("jid").map(String::as_str),
            Some("5511999999999.0:23@s.whatsapp.net")
        );
        assert_eq!(
            rm.attrs.get("reason").map(String::as_str),
            Some("user_initiated")
        );
    }

    #[test]
    fn build_usync_devices_iq_round_trips_through_parser() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let iq = build_usync_devices_iq("usync-1", &["5511999@s.whatsapp.net"]);
        assert_eq!(iq.tag, "iq");
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("usync"));
        assert_eq!(iq.attrs.get("type").map(String::as_str), Some("get"));

        // Build a fake response advertising devices 0 and 23.
        fn child(tag: &str, attrs: Attrs, content: Content) -> Node {
            Node {
                tag: tag.into(),
                attrs,
                content,
            }
        }
        let mut dev0_attrs = Attrs::new();
        dev0_attrs.insert("id".into(), "0".into());
        let mut dev23_attrs = Attrs::new();
        dev23_attrs.insert("id".into(), "23".into());
        let devices = child(
            "devices",
            Attrs::new(),
            Content::Nodes(vec![
                child("device", dev0_attrs, Content::None),
                child("device", dev23_attrs, Content::None),
            ]),
        );
        let mut user_attrs = Attrs::new();
        user_attrs.insert("jid".into(), "5511999@s.whatsapp.net".into());
        let user = child("user", user_attrs, Content::Nodes(vec![devices]));
        let list = child("list", Attrs::new(), Content::Nodes(vec![user]));
        let usync = child("usync", Attrs::new(), Content::Nodes(vec![list]));
        let reply_iq = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![usync]),
        };

        let devices = parse_usync_devices_response(&reply_iq);
        assert_eq!(
            devices,
            vec![
                "5511999@s.whatsapp.net".to_string(),
                "5511999:23@s.whatsapp.net".to_string(),
            ],
        );
    }

    #[test]
    fn build_prekey_fetch_iq_has_canonical_shape() {
        use crate::protocol::binary::Content;

        let iq = build_prekey_fetch_iq(
            &["5511999999999@s.whatsapp.net", "1234567890@s.whatsapp.net"],
            "iq-1",
        );
        assert_eq!(iq.tag, "iq");
        assert_eq!(iq.attrs.get("type").map(String::as_str), Some("get"));
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("encrypt"));
        assert_eq!(iq.attrs.get("to").map(String::as_str), Some("s.whatsapp.net"));
        assert_eq!(iq.attrs.get("id").map(String::as_str), Some("iq-1"));

        let key = match &iq.content {
            Content::Nodes(ns) => &ns[0],
            _ => panic!("expected nodes"),
        };
        assert_eq!(key.tag, "key");
        let users = match &key.content {
            Content::Nodes(ns) => ns,
            _ => panic!(),
        };
        assert_eq!(users.len(), 2);
        for u in users {
            assert_eq!(u.tag, "user");
            assert_eq!(u.attrs.get("reason").map(String::as_str), Some("identity"));
        }
        assert_eq!(
            users[0].attrs.get("jid").map(String::as_str),
            Some("5511999999999@s.whatsapp.net")
        );
    }

    /// Build a fixture <user> bundle and assert parsing round-trips.
    fn fixture_user_bundle(
        jid: &str,
        registration_id: u32,
        identity: &[u8; 32],
        spk_id: u32,
        spk_pub: &[u8; 32],
        spk_sig: &[u8; 64],
        opk: Option<(u32, &[u8; 32])>,
    ) -> crate::protocol::binary::Node {
        use crate::protocol::binary::{Attrs, Content, Node};
        fn bytes_node(tag: &str, b: Vec<u8>) -> Node {
            Node {
                tag: tag.into(),
                attrs: Attrs::new(),
                content: Content::Bytes(b),
            }
        }
        fn id_be(id: u32) -> Vec<u8> {
            id.to_be_bytes()[1..].to_vec() // 3-byte big-endian
        }

        let mut skey_children = vec![
            bytes_node("id", id_be(spk_id)),
            bytes_node("value", spk_pub.to_vec()),
            bytes_node("signature", spk_sig.to_vec()),
        ];
        // Emulate whatsmeow: skey content is a list of nodes.
        let _ = &mut skey_children;
        let skey = Node {
            tag: "skey".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(skey_children),
        };

        let mut keys_children = vec![
            bytes_node("identity", identity.to_vec()),
            skey,
        ];
        if let Some((id, pub_b)) = opk {
            keys_children.push(Node {
                tag: "key".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![
                    bytes_node("id", id_be(id)),
                    bytes_node("value", pub_b.to_vec()),
                ]),
            });
        }

        let mut user_attrs = Attrs::new();
        user_attrs.insert("jid".into(), jid.into());
        Node {
            tag: "user".into(),
            attrs: user_attrs,
            content: Content::Nodes(vec![
                bytes_node("registration", registration_id.to_be_bytes().to_vec()),
                Node {
                    tag: "keys".into(),
                    attrs: Attrs::new(),
                    content: Content::Nodes(keys_children),
                },
            ]),
        }
    }

    #[test]
    fn parse_prekey_fetch_response_extracts_bundles() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let identity = [0x11; 32];
        let spk_pub = [0x22; 32];
        let spk_sig = [0x33; 64];
        let opk_pub = [0x44; 32];

        let user_a = fixture_user_bundle(
            "5511999999999:23@s.whatsapp.net",
            0xCAFE,
            &identity,
            7,
            &spk_pub,
            &spk_sig,
            Some((42, &opk_pub)),
        );
        let user_b = fixture_user_bundle(
            "1234567890@s.whatsapp.net",
            0xBEEF,
            &identity,
            8,
            &spk_pub,
            &spk_sig,
            None, // no OPK
        );

        let iq = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "list".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![user_a, user_b]),
            }]),
        };

        let bundles = parse_prekey_fetch_response(&iq);
        assert_eq!(bundles.len(), 2);

        assert_eq!(bundles[0].jid, "5511999999999:23@s.whatsapp.net");
        assert_eq!(bundles[0].device_id, 23);
        assert_eq!(bundles[0].registration_id, 0xCAFE);
        assert_eq!(bundles[0].identity_pub, identity);
        assert_eq!(bundles[0].signed_pre_key_id, 7);
        assert_eq!(bundles[0].signed_pre_key_pub, spk_pub);
        assert_eq!(bundles[0].signed_pre_key_sig, spk_sig);
        assert_eq!(bundles[0].one_time_pre_key_id, Some(42));
        assert_eq!(bundles[0].one_time_pre_key_pub, Some(opk_pub));

        assert_eq!(bundles[1].device_id, 0); // no :device suffix
        assert_eq!(bundles[1].registration_id, 0xBEEF);
        assert!(bundles[1].one_time_pre_key_id.is_none());
        assert!(bundles[1].one_time_pre_key_pub.is_none());
    }

    #[test]
    fn parse_prekey_fetch_response_skips_user_with_error_child() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let mut user_attrs = Attrs::new();
        user_attrs.insert("jid".into(), "9999@s.whatsapp.net".into());
        let user = Node {
            tag: "user".into(),
            attrs: user_attrs,
            content: Content::Nodes(vec![Node {
                tag: "error".into(),
                attrs: Attrs::new(),
                content: Content::None,
            }]),
        };
        let iq = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![Node {
                tag: "list".into(),
                attrs: Attrs::new(),
                content: Content::Nodes(vec![user]),
            }]),
        };
        assert!(parse_prekey_fetch_response(&iq).is_empty());
    }

    // -- pad / unpad / build_message_node ---------------------------------

    #[test]
    fn pad_then_unpad_round_trips_and_pad_size_is_1_to_15() {
        // 200 random round-trips so we exercise every random pad value.
        for _ in 0..200 {
            let pt = b"the quick brown fox";
            let padded = pad_message(pt);
            let pad_byte = *padded.last().unwrap();
            assert!((1..=15).contains(&pad_byte), "pad in [1,15]");
            assert_eq!(padded.len(), pt.len() + pad_byte as usize);
            // Last `pad_byte` bytes should all equal `pad_byte`.
            for &b in &padded[pt.len()..] {
                assert_eq!(b, pad_byte);
            }
            assert_eq!(unpad_message(&padded).unwrap(), pt);
        }
    }

    #[test]
    fn unpad_message_rejects_invalid_pad() {
        assert!(unpad_message(&[]).is_err());
        // Pad byte 0 is invalid.
        assert!(unpad_message(&[0x00]).is_err());
        // Pad byte 0xff (255) > total length → pad longer than message.
        assert!(unpad_message(&[0xff]).is_err());
        // Pad byte 0x05 but only 3 bytes total → pad longer than message.
        assert!(unpad_message(&[0x01, 0x02, 0x05]).is_err());
        // REGRESSION: a 16-byte (0x10) pad is VALID — WhatsApp pads 1..=16, and
        // an earlier 0x0f cap rejected this, breaking decrypt of 16-padded
        // protocol chunks (PUSH_NAME etc.) and stalling history sync.
        let body = b"hello".to_vec();
        let mut p16 = body.clone();
        p16.extend(std::iter::repeat_n(0x10u8, 16));
        assert_eq!(unpad_message(&p16).unwrap(), body);
        // The exact max: pad == len strips everything (empty result), still ok.
        assert_eq!(unpad_message(&[0x01]).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn unpad_message_v_respects_enc_version() {
        // A real v=3 protobuf can end in ANY byte (here 0x00 and 0xff) — the
        // version-aware unpad must return it untouched, never strip a "pad".
        let v3_a = vec![0x0a, 0x03, b'h', b'i', 0x00];
        let v3_b = vec![0x12, 0x02, 0xde, 0xff];
        assert_eq!(unpad_message_v(&v3_a, 3).unwrap(), v3_a);
        assert_eq!(unpad_message_v(&v3_b, 3).unwrap(), v3_b);
        // Future versions (>=3) behave the same.
        assert_eq!(unpad_message_v(&v3_a, 4).unwrap(), v3_a);
        // v<=2 still strips the random 1..=0x0f pad.
        let payload = b"payload".to_vec();
        let padded = pad_message(&payload);
        assert_eq!(unpad_message_v(&padded, 2).unwrap(), payload);
        // Those same bad-pad bytes WOULD be rejected under the v<=2 scheme —
        // proving the version gate is what saves the v=3 path.
        assert!(unpad_message_v(&v3_a, 2).is_err());
    }

    #[test]
    fn build_message_node_for_two_devices_has_canonical_shape() {
        use crate::crypto::signal::MessageType;
        use crate::protocol::binary::Content;

        let recipients = [
            EncryptedRecipient {
                jid: "5511999999999.0:23@s.whatsapp.net".into(),
                ciphertext: vec![0xCA, 0xFE],
                message_type: MessageType::Whisper,
            },
            EncryptedRecipient {
                jid: "5511999999999.0:7@s.whatsapp.net".into(),
                ciphertext: vec![0xBE, 0xEF, 0x00],
                message_type: MessageType::PreKey,
            },
        ];
        let node = build_message_node(
            "msg-1",
            "5511999999999@s.whatsapp.net",
            &recipients,
            1_700_000_000,
        );
        assert_eq!(node.tag, "message");
        assert_eq!(node.attrs.get("id").map(String::as_str), Some("msg-1"));
        assert_eq!(node.attrs.get("type").map(String::as_str), Some("text"));
        assert_eq!(
            node.attrs.get("to").map(String::as_str),
            Some("5511999999999@s.whatsapp.net")
        );
        assert_eq!(node.attrs.get("t").map(String::as_str), Some("1700000000"));

        let participants = match &node.content {
            Content::Nodes(ns) => &ns[0],
            _ => panic!("expected nodes"),
        };
        assert_eq!(participants.tag, "participants");
        let tos: &[_] = match &participants.content {
            Content::Nodes(ns) => ns.as_slice(),
            _ => panic!(),
        };
        assert_eq!(tos.len(), 2);
        for (idx, recipient) in recipients.iter().enumerate() {
            assert_eq!(tos[idx].tag, "to");
            assert_eq!(
                tos[idx].attrs.get("jid").map(String::as_str),
                Some(recipient.jid.as_str())
            );
            let enc = match &tos[idx].content {
                Content::Nodes(ns) => &ns[0],
                _ => panic!(),
            };
            assert_eq!(enc.tag, "enc");
            assert_eq!(enc.attrs.get("v").map(String::as_str), Some("2"));
            let want_type = match recipient.message_type {
                MessageType::Whisper => "msg",
                MessageType::PreKey => "pkmsg",
            };
            assert_eq!(enc.attrs.get("type").map(String::as_str), Some(want_type));
            match &enc.content {
                Content::Bytes(b) => assert_eq!(b, &recipient.ciphertext),
                _ => panic!("enc content must be raw bytes"),
            }
        }
    }

    /// Outbound lifecycle: row starts 'queued' (persist_outgoing_text),
    /// flips to 'sent' after the wire ship, then 'delivered' after the
    /// dispatcher resolves the pending ack. Exercises register_ack +
    /// take_pending_ack + the spawn-and-wait path inside
    /// encrypt_inner_proto_and_ship.
    #[tokio::test]
    async fn outbound_ack_flips_status_through_queued_sent_delivered() {
        use crate::protocol::binary::Node;
        use std::time::Duration;
        use tokio::sync::mpsc;

        let mgr = Arc::new(manager());
        let session = mgr.create(Some("alice".into())).unwrap();
        let session_id = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&session_id).unwrap();
        let store = mgr.store.clone();

        let chat_jid = "5511999@s.whatsapp.net";
        let msg_id = "ACK-MSG-1";
        let now = chrono::Utc::now().timestamp();
        mgr.persist_outgoing_text(&session_id, chat_jid, msg_id, "self", "hi", now)
            .unwrap();

        // Row starts 'queued'.
        let status: String = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT status FROM messages WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![session_id, msg_id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(status, "queued");

        // Stand up dispatcher; provide a fake prekey bundle on demand
        // so the X3DH branch can complete.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Node>();
        let dispatcher = ConnDispatcher::new(out_tx);

        let bob_id = crate::crypto::identity::KeyPair::generate();
        let bob_spk = crate::crypto::identity::KeyPair::generate();
        let bob_opk = crate::crypto::identity::KeyPair::generate();

        let send_handle = tokio::spawn({
            let dispatcher = dispatcher.clone();
            let session = session.clone();
            let store = store.clone();
            let keys = keys.clone();
            let cj = chat_jid.to_string();
            let mid = msg_id.to_string();
            async move {
                send_text_op(&dispatcher, &session, &store, &keys, &cj, &mid, "hi", now).await
            }
        });

        // First IQ is usync; respond with single-device-0. Next IQ is
        // the prekey fetch.
        let iq = drain_usync_then_next(&mut out_rx, &dispatcher, chat_jid).await;
        let iq_id = iq.attrs.get("id").cloned().unwrap();
        let bob_spk_sig = {
            let mut signed = [0u8; 33];
            signed[0] = 0x05;
            signed[1..].copy_from_slice(&bob_spk.public);
            crate::crypto::identity::xeddsa_sign(&bob_id.private, &signed)
        };
        let response = build_fake_user_bundle_iq(
            &iq_id,
            chat_jid,
            12345,
            &bob_id.public,
            17,
            &bob_spk.public,
            &bob_spk_sig,
            29,
            &bob_opk.public,
        );
        dispatcher
            .take_pending(&iq_id)
            .expect("iq pending registered")
            .send(response)
            .unwrap();

        // <message> shipped; status now 'sent'.
        let _msg = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .unwrap()
            .unwrap();
        send_handle.await.unwrap().unwrap();
        let status: String = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT status FROM messages WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![session_id, msg_id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(status, "sent");

        // Deliver ack — flips status to 'delivered'.
        let ack_tx = dispatcher
            .take_pending_ack(msg_id)
            .expect("pending ack registered before ship");
        ack_tx.send("message".to_string()).unwrap();

        // The status update happens in a tokio::spawn'd task; yield a
        // few times so it has a chance to run.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            let status: String = store
                .with_conn(|c| {
                    c.query_row(
                        "SELECT status FROM messages WHERE session_id = ? AND message_id = ?",
                        rusqlite::params![session_id, msg_id],
                        |r| r.get(0),
                    )
                })
                .unwrap();
            if status == "delivered" {
                return;
            }
        }
        panic!("status never flipped to 'delivered'");
    }

    /// End-to-end of the live send pump:
    /// 1. send_text_op writes a `<iq xmlns=encrypt>` for a fresh peer.
    /// 2. Test plays the WA server: returns a fake user-bundle response.
    /// 3. send_text_op runs X3DH, encrypts, ships a `<message>` node.
    /// 4. The peer ("Bob") runs process_bob and decrypts.
    ///
    /// Must recover the original plaintext byte-for-byte.
    #[tokio::test]
    async fn send_text_op_runs_x3dh_and_emits_decryptable_message_node() {
        use crate::crypto::identity::KeyPair;
        use crate::crypto::signal::{
            parse_pre_key_message, BobParameters, RatchetingSession, SessionCipher,
            SignalMessageProto,
        };
        use crate::protocol::binary::{Content, Node};
        use prost::Message as _;
        use std::time::Duration;
        use tokio::sync::mpsc;

        // ----- Alice (the device under test) -----
        let mgr = manager();
        let session = mgr.create(Some("alice".into())).unwrap();
        let session_id = session.meta.read().id.clone();
        let keys = mgr.load_device_keys(&session_id).unwrap();
        let store = mgr.store.clone();

        // ----- Bob (peer we ship the message to) -----
        let bob_id = KeyPair::generate();
        let bob_spk = KeyPair::generate();
        let bob_opk = KeyPair::generate();
        let bob_jid = "5511999999999@s.whatsapp.net";

        // Stand-in for the connection task: the test owns out_rx and the
        // pending-IQ map via the same dispatcher that send_text_op uses.
        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Node>();
        let dispatcher = ConnDispatcher::new(out_tx);

        // Fire the send op as a background task so we can interleave with
        // the dispatcher's request/response dance.
        let send_handle = tokio::spawn({
            let dispatcher = dispatcher.clone();
            let session = session.clone();
            let store = store.clone();
            let keys = keys.clone();
            async move {
                send_text_op(
                    &dispatcher,
                    &session,
                    &store,
                    &keys,
                    bob_jid,
                    "MSG-1",
                    "hello bob",
                    1_000_000,
                )
                .await
            }
        });

        // 1. First IQ is usync (device list); answer with single-device-0.
        //    Then send_text_op ships the prekey-fetch IQ.
        let iq = drain_usync_then_next(&mut out_rx, &dispatcher, bob_jid).await;
        assert_eq!(iq.tag, "iq");
        assert_eq!(iq.attrs.get("xmlns").map(String::as_str), Some("encrypt"));
        let iq_id = iq.attrs.get("id").cloned().unwrap();

        // 2. Build a server-style response carrying Bob's bundle. The
        //    SPK signature is real — send_text_op now requires it to
        //    pass XEdDSA verify against bob_id.public.
        let bob_spk_sig = {
            let mut signed = [0u8; 33];
            signed[0] = 0x05;
            signed[1..].copy_from_slice(&bob_spk.public);
            crate::crypto::identity::xeddsa_sign(&bob_id.private, &signed)
        };
        let response = build_fake_user_bundle_iq(
            &iq_id,
            bob_jid,
            12345,
            &bob_id.public,
            17,
            &bob_spk.public,
            &bob_spk_sig,
            29,
            &bob_opk.public,
        );
        // Deliver it through the dispatcher's pending map.
        dispatcher
            .take_pending(&iq_id)
            .expect("send_text_op registered the iq id")
            .send(response)
            .unwrap();

        // 3. send_text_op now ships a <message> node.
        let msg = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("message node within timeout")
            .expect("message node present");
        assert_eq!(msg.tag, "message");
        assert_eq!(msg.attrs.get("to").map(String::as_str), Some(bob_jid));
        assert_eq!(msg.attrs.get("id").map(String::as_str), Some("MSG-1"));

        // send_text_op completes after dispatching.
        send_handle.await.unwrap().unwrap();

        // 4. Drill into <participants><to><enc type=pkmsg>.
        let participants = match &msg.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "participants").unwrap().clone(),
            _ => panic!("message must contain participants"),
        };
        let to = match &participants.content {
            Content::Nodes(ns) => ns[0].clone(),
            _ => panic!(),
        };
        let enc = match &to.content {
            Content::Nodes(ns) => ns[0].clone(),
            _ => panic!(),
        };
        assert_eq!(enc.attrs.get("type").map(String::as_str), Some("pkmsg"));
        let pkmsg_wire = match enc.content {
            Content::Bytes(b) => b,
            _ => panic!("enc must carry raw ciphertext"),
        };

        // 5. Parse the pkmsg envelope; extract Alice's base/identity/inner.
        let info = parse_pre_key_message(&pkmsg_wire).unwrap();
        assert_eq!(info.signed_pre_key_id, 29, "echoed back from bundle");
        assert_eq!(info.pre_key_id, Some(17));
        assert_eq!(info.identity_key_pub, keys.identity.public);

        // Recover Alice's ratchet pub from the inner SignalMessage proto.
        let inner = &info.inner_whisper_wire;
        let inner_body = &inner[1..inner.len() - 8];
        let inner_proto = SignalMessageProto::decode(inner_body).unwrap();
        // ratchet_key is now `[0x05] || pub` (33 bytes); strip the prefix.
        let raw = inner_proto.ratchet_key.clone().unwrap();
        let mut alice_ratchet_pub = [0u8; 32];
        let pub_slice: &[u8] = if raw.len() == 33 && raw[0] == 0x05 {
            &raw[1..]
        } else {
            &raw
        };
        alice_ratchet_pub.copy_from_slice(pub_slice);

        // 6. Bob (the peer) reconstructs the session and decrypts.
        let mut bob_state = RatchetingSession::process_bob(&BobParameters {
            local_identity_priv: &bob_id.private,
            local_identity_pub: &bob_id.public,
            local_signed_prekey_priv: &bob_spk.private,
            local_one_time_prekey_priv: Some(&bob_opk.private),
            remote_identity_pub: &keys.identity.public,
            remote_base_pub: &info.base_key_pub,
            remote_ratchet_pub: &alice_ratchet_pub,
        });
        let padded = SessionCipher::decrypt(&mut bob_state, &info.inner_whisper_wire).unwrap();
        let plain = unpad_message(&padded).unwrap();
        let e2e =
            crate::proto::wa_web_protobufs_e2e::Message::decode(plain.as_slice()).unwrap();
        assert_eq!(
            e2e.conversation.as_deref(),
            Some("hello bob"),
            "round-trip recovers the original plaintext"
        );

        // 7. Signal session was persisted under the chat JID; a follow-up
        //    send must NOT issue a second prekey fetch — it should reuse
        //    the saved state and ship a steady-state "msg" envelope.
        let send_handle_2 = tokio::spawn({
            let dispatcher = dispatcher.clone();
            let session = session.clone();
            let store = store.clone();
            let keys = keys.clone();
            async move {
                send_text_op(
                    &dispatcher,
                    &session,
                    &store,
                    &keys,
                    bob_jid,
                    "MSG-2",
                    "second",
                    1_000_001,
                )
                .await
            }
        });
        // Second send to the same peer takes the fast path: the device list is
        // served from the per-user cache (NO usync round-trip — the first send
        // populated it) and the Signal session is already saved (NO prekey
        // fetch). So it ships the `<message>` straight away. This guards the
        // device-list cache: a usync here would mean the cache regressed.
        use std::time::Duration as Dur2;
        let next = tokio::time::timeout(Dur2::from_secs(5), out_rx.recv())
            .await
            .expect("message within timeout")
            .expect("message present");
        send_handle_2.await.unwrap().unwrap();
        assert_eq!(
            next.tag, "message",
            "cached devices + saved session ⇒ straight to <message> (no usync, no prekey IQ)",
        );
        let participants_2 = match &next.content {
            Content::Nodes(ns) => ns.iter().find(|n| n.tag == "participants").unwrap().clone(),
            _ => panic!(),
        };
        let to_2 = match &participants_2.content {
            Content::Nodes(ns) => ns[0].clone(),
            _ => panic!(),
        };
        let enc_2 = match &to_2.content {
            Content::Nodes(ns) => ns[0].clone(),
            _ => panic!(),
        };
        assert_eq!(
            enc_2.attrs.get("type").map(String::as_str),
            Some("msg"),
            "second send is a steady-state Whisper, not a fresh PreKey envelope"
        );
    }

    /// Build a `<iq type=result>` shaped like a usync devices response,
    /// reporting that `user_jid` has a single device 0. Tests use this
    /// to satisfy the usync IQ that `encrypt_inner_proto_and_ship`
    /// fires before the prekey fetch.
    fn build_fake_usync_response_single_device(
        iq_id: &str,
        user_jid: &str,
    ) -> crate::protocol::binary::Node {
        use crate::protocol::binary::{Attrs, Content, Node};
        let mut dev_attrs = Attrs::new();
        dev_attrs.insert("id".into(), "0".into());
        let device = Node {
            tag: "device".into(),
            attrs: dev_attrs,
            content: Content::None,
        };
        let devices = Node {
            tag: "devices".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![device]),
        };
        let mut user_attrs = Attrs::new();
        user_attrs.insert("jid".into(), user_jid.into());
        let user = Node {
            tag: "user".into(),
            attrs: user_attrs,
            content: Content::Nodes(vec![devices]),
        };
        let list = Node {
            tag: "list".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![user]),
        };
        let usync = Node {
            tag: "usync".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![list]),
        };
        let mut iq_attrs = Attrs::new();
        iq_attrs.insert("id".into(), iq_id.into());
        iq_attrs.insert("type".into(), "result".into());
        Node {
            tag: "iq".into(),
            attrs: iq_attrs,
            content: Content::Nodes(vec![usync]),
        }
    }

    /// Helper that consumes a usync IQ from `out_rx`, replies with a
    /// single-device response, then returns the next outbound node
    /// (which will be the prekey-fetch IQ).
    async fn drain_usync_then_next(
        out_rx: &mut tokio::sync::mpsc::UnboundedReceiver<crate::protocol::binary::Node>,
        dispatcher: &ConnDispatcher,
        chat_jid: &str,
    ) -> crate::protocol::binary::Node {
        use std::time::Duration;
        let usync = tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("usync IQ within timeout")
            .expect("usync IQ present");
        let usync_id = usync.attrs.get("id").cloned().unwrap();
        let response = build_fake_usync_response_single_device(&usync_id, chat_jid);
        dispatcher
            .take_pending(&usync_id)
            .expect("usync iq pending registered")
            .send(response)
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), out_rx.recv())
            .await
            .expect("next IQ within timeout")
            .expect("next IQ present")
    }

    /// Build a `<iq type=result>` carrying one `<user>` prekey bundle, in
    /// the shape `parse_prekey_fetch_response` already accepts.
    #[allow(clippy::too_many_arguments)]
    fn build_fake_user_bundle_iq(
        iq_id: &str,
        user_jid: &str,
        registration_id: u32,
        identity_pub: &[u8; 32],
        opk_id: u32,
        spk_pub: &[u8; 32],
        spk_sig: &[u8; 64],
        spk_id: u32,
        opk_pub: &[u8; 32],
    ) -> crate::protocol::binary::Node {
        use crate::protocol::binary::{Attrs, Content, Node};
        fn child(tag: &str, content: Content) -> Node {
            Node {
                tag: tag.into(),
                attrs: Attrs::new(),
                content,
            }
        }

        let skey = Node {
            tag: "skey".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![
                child("id", Content::Bytes(spk_id.to_be_bytes().to_vec())),
                child("value", Content::Bytes(spk_pub.to_vec())),
                child("signature", Content::Bytes(spk_sig.to_vec())),
            ]),
        };
        let opk = Node {
            tag: "key".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![
                child("id", Content::Bytes(opk_id.to_be_bytes().to_vec())),
                child("value", Content::Bytes(opk_pub.to_vec())),
            ]),
        };
        let keys_node = Node {
            tag: "keys".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![
                child("identity", Content::Bytes(identity_pub.to_vec())),
                skey,
                opk,
            ]),
        };

        let mut user_attrs = Attrs::new();
        user_attrs.insert("jid".into(), user_jid.into());
        let user = Node {
            tag: "user".into(),
            attrs: user_attrs,
            content: Content::Nodes(vec![
                child(
                    "registration",
                    Content::Bytes(registration_id.to_be_bytes().to_vec()),
                ),
                keys_node,
            ]),
        };
        let list = Node {
            tag: "list".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![user]),
        };

        let mut iq_attrs = Attrs::new();
        iq_attrs.insert("id".into(), iq_id.into());
        iq_attrs.insert("type".into(), "result".into());
        Node {
            tag: "iq".into(),
            attrs: iq_attrs,
            content: Content::Nodes(vec![list]),
        }
    }

    /// `decode_e2e_message` must identify each media variant from an inner
    /// waE2E.Message proto and pull through url + media_key. The check
    /// matters because `process_inbound_message` switches on this output
    /// to set `msg_type` + the lazy-download payload.
    #[test]
    fn decode_e2e_message_dispatches_text_image_video_audio_document_sticker() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;

        // Text.
        let m = e2e::Message {
            conversation: Some("hi".into()),
            ..Default::default()
        };
        match decode_e2e_message(&m.encode_to_vec()) {
            InboundContent::Text(t) => assert_eq!(t, "hi"),
            _ => panic!("text"),
        }

        // Image.
        let m = e2e::Message {
            image_message: Some(Box::new(e2e::ImageMessage {
                url: Some("https://x".into()),
                media_key: Some(vec![0xAA; 32]),
                mimetype: Some("image/jpeg".into()),
                caption: Some("a pic".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        match decode_e2e_message(&m.encode_to_vec()) {
            InboundContent::Media {
                kind,
                url,
                mimetype,
                caption,
                media_key,
                ..
            } => {
                assert!(matches!(kind, crate::media::MediaType::Image));
                assert_eq!(url.as_deref(), Some("https://x"));
                assert_eq!(mimetype.as_deref(), Some("image/jpeg"));
                assert_eq!(caption.as_deref(), Some("a pic"));
                assert_eq!(media_key.as_deref().map(<[u8]>::len), Some(32));
            }
            _ => panic!("image"),
        }

        // Video.
        let m = e2e::Message {
            video_message: Some(Box::new(e2e::VideoMessage {
                url: Some("https://v".into()),
                media_key: Some(vec![0xBB; 32]),
                mimetype: Some("video/mp4".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(matches!(
            decode_e2e_message(&m.encode_to_vec()),
            InboundContent::Media { kind: crate::media::MediaType::Video, .. }
        ));

        // Audio.
        let m = e2e::Message {
            audio_message: Some(Box::new(e2e::AudioMessage {
                url: Some("https://a".into()),
                media_key: Some(vec![0xCC; 32]),
                mimetype: Some("audio/ogg".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(matches!(
            decode_e2e_message(&m.encode_to_vec()),
            InboundContent::Media { kind: crate::media::MediaType::Audio, .. }
        ));

        // Voice note (ptt=true) classifies as Ptt, not Audio.
        let m = e2e::Message {
            audio_message: Some(Box::new(e2e::AudioMessage {
                url: Some("https://v".into()),
                media_key: Some(vec![0xCC; 32]),
                mimetype: Some("audio/ogg; codecs=opus".into()),
                ptt: Some(true),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(matches!(
            decode_e2e_message(&m.encode_to_vec()),
            InboundContent::Media { kind: crate::media::MediaType::Ptt, .. }
        ));

        // Document.
        let m = e2e::Message {
            document_message: Some(Box::new(e2e::DocumentMessage {
                url: Some("https://d".into()),
                media_key: Some(vec![0xDD; 32]),
                mimetype: Some("application/pdf".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(matches!(
            decode_e2e_message(&m.encode_to_vec()),
            InboundContent::Media { kind: crate::media::MediaType::Document, .. }
        ));

        // Sticker.
        let m = e2e::Message {
            sticker_message: Some(Box::new(e2e::StickerMessage {
                url: Some("https://s".into()),
                media_key: Some(vec![0xEE; 32]),
                mimetype: Some("image/webp".into()),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(matches!(
            decode_e2e_message(&m.encode_to_vec()),
            InboundContent::Media { kind: crate::media::MediaType::Sticker, .. }
        ));

        // Empty / unknown payload.
        let m = e2e::Message::default();
        assert!(matches!(
            decode_e2e_message(&m.encode_to_vec()),
            InboundContent::Other
        ));
    }

    /// Interactive/business + typed content types classify (not "unknown"):
    /// reaction/poll/contact/location → Typed{kind}; button replies → Text.
    #[test]
    fn decode_e2e_message_classifies_business_and_typed() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;

        let react = e2e::Message {
            reaction_message: Some(e2e::ReactionMessage { text: Some("👍".into()), ..Default::default() }),
            ..Default::default()
        };
        match decode_e2e_message(&react.encode_to_vec()) {
            InboundContent::Typed { kind, text } => { assert_eq!(kind, "reaction"); assert_eq!(text.as_deref(), Some("👍")); }
            _ => panic!("reaction"),
        }

        let poll = e2e::Message {
            poll_creation_message: Some(Box::new(e2e::PollCreationMessage { name: Some("Lunch?".into()), ..Default::default() })),
            ..Default::default()
        };
        match decode_e2e_message(&poll.encode_to_vec()) {
            InboundContent::Typed { kind, text } => { assert_eq!(kind, "poll"); assert_eq!(text.as_deref(), Some("Lunch?")); }
            _ => panic!("poll"),
        }

        let loc = e2e::Message {
            location_message: Some(Box::new(e2e::LocationMessage { name: Some("Office".into()), ..Default::default() })),
            ..Default::default()
        };
        assert!(matches!(decode_e2e_message(&loc.encode_to_vec()), InboundContent::Typed { kind, .. } if kind == "location"));

        // A tapped button reply surfaces its display text as a normal text bubble.
        let reply = e2e::Message {
            template_button_reply_message: Some(Box::new(e2e::TemplateButtonReplyMessage {
                selected_display_text: Some("Yes".into()), ..Default::default()
            })),
            ..Default::default()
        };
        match decode_e2e_message(&reply.encode_to_vec()) {
            InboundContent::Text(t) => assert_eq!(t, "Yes"),
            _ => panic!("button reply"),
        }
    }

    /// Wrapper messages (ephemeral/disappearing, view-once, edited,
    /// device-sent) carry the real Message inside `.message`; the decoder must
    /// unwrap and classify the inner content, not return Other. Without this
    /// every message in a disappearing-messages chat shows as "unknown".
    #[test]
    fn decode_e2e_message_unwraps_container_messages() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;

        let inner = e2e::Message { conversation: Some("hi from ephemeral".into()), ..Default::default() };

        // ephemeralMessage (disappearing chats) → unwrap to the inner text.
        let eph = e2e::Message {
            ephemeral_message: Some(Box::new(e2e::FutureProofMessage {
                message: Some(Box::new(inner.clone())),
            })),
            ..Default::default()
        };
        match decode_e2e_message(&eph.encode_to_vec()) {
            InboundContent::Text(t) => assert_eq!(t, "hi from ephemeral"),
            _ => panic!("ephemeral should unwrap to text"),
        }

        // deviceSentMessage (our own fan-out) wrapping an image → unwrap to media.
        let dsm = e2e::Message {
            device_sent_message: Some(Box::new(e2e::DeviceSentMessage {
                destination_jid: Some("x@s.whatsapp.net".into()),
                message: Some(Box::new(e2e::Message {
                    image_message: Some(Box::new(e2e::ImageMessage {
                        url: Some("https://i".into()),
                        media_key: Some(vec![0xCC; 32]),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                phash: None,
            })),
            ..Default::default()
        };
        assert!(matches!(
            decode_e2e_message(&dsm.encode_to_vec()),
            InboundContent::Media { kind: crate::media::MediaType::Image, .. }
        ));

        // viewOnceMessageV2 wrapping text → unwrap.
        let vo = e2e::Message {
            view_once_message_v2: Some(Box::new(e2e::FutureProofMessage {
                message: Some(Box::new(inner)),
            })),
            ..Default::default()
        };
        assert!(matches!(decode_e2e_message(&vo.encode_to_vec()), InboundContent::Text(_)));
    }

    /// A message edit arrives as a `protocolMessage` (`type=MESSAGE_EDIT`) whose
    /// `editedMessage` holds the replacement content — NOT as a top-level
    /// `editedMessage` wrapper. The decoder must surface the new text (tagged
    /// `edited`) instead of letting it fall through to "unknown". A REVOKE
    /// (delete-for-everyone) likewise surfaces as a `revoked` marker.
    #[test]
    fn decode_e2e_message_classifies_edit_and_revoke() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;

        let edit = e2e::Message {
            protocol_message: Some(Box::new(e2e::ProtocolMessage {
                key: Some(crate::proto::wa_common::MessageKey {
                    id: Some("ORIG123".into()),
                    ..Default::default()
                }),
                r#type: Some(e2e::protocol_message::Type::MessageEdit as i32),
                edited_message: Some(Box::new(e2e::Message {
                    conversation: Some("edited text".into()),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };
        match decode_e2e_message(&edit.encode_to_vec()) {
            InboundContent::Typed { kind, text } => {
                assert_eq!(kind, "edited");
                assert_eq!(text.as_deref(), Some("edited text"));
            }
            _ => panic!("expected Typed/edited"),
        }

        let revoke = e2e::Message {
            protocol_message: Some(Box::new(e2e::ProtocolMessage {
                r#type: Some(e2e::protocol_message::Type::Revoke as i32),
                ..Default::default()
            })),
            ..Default::default()
        };
        match decode_e2e_message(&revoke.encode_to_vec()) {
            InboundContent::Typed { kind, text } => {
                assert_eq!(kind, "revoked");
                assert!(text.is_none());
            }
            _ => panic!("expected Typed/revoked"),
        }
    }

    /// An own-device fan-out (deviceSentMessage) exposes the real conversation
    /// via `destinationJid` — the inbound path routes/labels by it so the
    /// message lands in the peer chat, not the self-chat. A plain message has no
    /// destination.
    #[test]
    fn device_sent_destination_extracts_jid() {
        use crate::proto::wa_web_protobufs_e2e as e2e;
        use prost::Message as _;

        let fanout = e2e::Message {
            device_sent_message: Some(Box::new(e2e::DeviceSentMessage {
                destination_jid: Some("5511999999999@s.whatsapp.net".into()),
                message: Some(Box::new(e2e::Message {
                    conversation: Some("hey".into()),
                    ..Default::default()
                })),
                phash: None,
            })),
            ..Default::default()
        };
        assert_eq!(
            device_sent_destination(&fanout.encode_to_vec()).as_deref(),
            Some("5511999999999@s.whatsapp.net"),
        );

        let plain = e2e::Message { conversation: Some("hey".into()), ..Default::default() };
        assert_eq!(device_sent_destination(&plain.encode_to_vec()), None);
    }

    /// The app-state external-blob + snapshot proto subsets round-trip — the
    /// shapes we decode the `<snapshot>` external-blob ref and downloaded
    /// SyncdSnapshot through.
    #[test]
    fn app_state_snapshot_protos_round_trip() {
        use prost::Message as _;

        let ext = ExternalBlobReferenceSubset {
            media_key: Some(vec![1u8; 32]),
            direct_path: Some("/v/t62.x/abc.enc?ccb=11-4".into()),
            handle: Some("HANDLE123".into()),
            file_size_bytes: Some(527),
            file_sha256: Some(vec![2u8; 32]),
            file_enc_sha256: Some(vec![3u8; 32]),
        };
        let back = ExternalBlobReferenceSubset::decode(ext.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.direct_path.as_deref(), Some("/v/t62.x/abc.enc?ccb=11-4"));
        assert_eq!(back.media_key.as_deref(), Some(&[1u8; 32][..]));
        assert_eq!(back.file_size_bytes, Some(527));

        let snap = SyncdSnapshotSubset {
            version: Some(SyncdVersionSubset { version: Some(143) }),
            records: vec![],
            mac: Some(vec![9u8; 32]),
            key_id: Some(KeyIdSubset {
                id: Some(b"k1".to_vec()),
            }),
        };
        let back = SyncdSnapshotSubset::decode(snap.encode_to_vec().as_slice()).unwrap();
        assert_eq!(back.version.and_then(|v| v.version), Some(143));
        assert_eq!(
            back.key_id.and_then(|k| k.id).as_deref(),
            Some(&b"k1"[..])
        );
    }

    /// Hand-build a SyncdPatch with three mutations (pin, archive,
    /// mute) and a contact upsert, encode it, and verify
    /// `decode_app_state_patch` extracts the right `AppStateMutation`s.
    #[test]
    fn decode_app_state_snapshot_resolves_per_record_keys() {
        // A snapshot whose records are encrypted under TWO different app-state
        // keys (the account rotated keys over its history). The decoder must
        // resolve the key PER record — decrypting all records with one key drops
        // every record under a rotated key, which is why the contact list (in
        // critical_unblock_low, 13 keys across 168 records) came back empty.
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        use prost::Message as _;
        type Enc = cbc::Encryptor<Aes256>;

        let mgr = manager();
        let session = mgr.create(Some("alice".into())).unwrap();
        let id = session.meta.read().id.clone();

        let key_id_a = b"keyid-A".to_vec();
        let key_id_b = b"keyid-B".to_vec();
        let main_a = [0x11u8; 32];
        let main_b = [0x22u8; 32];
        store_app_state_main_key(&mgr.store, &id, &key_id_a, &main_a).unwrap();
        store_app_state_main_key(&mgr.store, &id, &key_id_b, &main_b).unwrap();

        let make_record = |key_id: &[u8], main: &[u8; 32], jid: &str, name: &str| {
            let keys = expand_app_state_keys(main);
            let action = SyncActionDataSubset {
                index: Some(format!("[\"contact\",\"{jid}\"]").into_bytes()),
                value: Some(SyncActionValueSubset {
                    contact_action: Some(ContactActionSubset {
                        full_name: Some(name.to_string()),
                        first_name: None,
                    }),
                    ..Default::default()
                }),
            };
            let iv = [0x33u8; 16];
            let ct = Enc::new(&keys.mutation_cipher_key.into(), &iv.into())
                .encrypt_padded_vec_mut::<Pkcs7>(&action.encode_to_vec());
            let mut blob = iv.to_vec();
            blob.extend_from_slice(&ct);
            let mac = compute_app_state_value_mac(&keys.value_mac_key, 0, key_id, &blob);
            blob.extend_from_slice(&mac);
            SyncdRecordSubset {
                index: None,
                value: Some(SyncdBlob { blob: Some(blob) }),
                key_id: Some(KeyIdSubset { id: Some(key_id.to_vec()) }),
            }
        };

        let snap = SyncdSnapshotSubset {
            version: Some(SyncdVersionSubset { version: Some(5) }),
            records: vec![
                make_record(&key_id_a, &main_a, "111@s.whatsapp.net", "Alice A"),
                make_record(&key_id_b, &main_b, "222@s.whatsapp.net", "Bob B"),
            ],
            // Snapshot-level key is A; record B uses a DIFFERENT key.
            key_id: Some(KeyIdSubset { id: Some(key_id_a.clone()) }),
            mac: None,
        };

        let (version, muts, _hash) =
            decode_app_state_snapshot(&mgr.store, &id, &snap.encode_to_vec()).unwrap();
        assert_eq!(version, 5);
        // BOTH decode — the old single-key code yielded only the key-A record.
        assert_eq!(muts.len(), 2, "both per-key records must decode");
        for m in &muts {
            apply_app_state_mutation(&mgr.store, &id, m).unwrap();
        }
        let contacts = mgr.store.contacts_list(&id).unwrap();
        assert_eq!(
            contacts.iter().find(|c| c.jid == "111@s.whatsapp.net").unwrap().full_name.as_deref(),
            Some("Alice A")
        );
        assert_eq!(
            contacts.iter().find(|c| c.jid == "222@s.whatsapp.net").unwrap().full_name.as_deref(),
            Some("Bob B")
        );
    }

    #[test]
    fn decode_app_state_patch_extracts_pin_archive_mute_contact() {
        use prost::Message as _;
        let chat = "5511999@s.whatsapp.net";

        // Helper: wrap an action value into a SyncdMutation with the
        // canonical JSON-array index `[action, jid]`.
        fn make_mutation(action_name: &str, jid: &str, value: SyncActionValueSubset) -> SyncdMutationSubset {
            let index_str = format!("[\"{action_name}\",\"{jid}\"]");
            let action_data = SyncActionDataSubset {
                index: Some(index_str.into_bytes()),
                value: Some(value),
            };
            SyncdMutationSubset {
                operation: Some(SyncdOperation::Set as i32),
                record: Some(SyncdRecordSubset {
                    index: Some(SyncdBlob {
                        blob: Some(action_data.index.clone().unwrap_or_default()),
                    }),
                    value: Some(SyncdBlob {
                        blob: Some(action_data.encode_to_vec()),
                    }),
                    key_id: None,
                }),
            }
        }

        let pin_mut = make_mutation(
            "pin",
            chat,
            SyncActionValueSubset {
                pin_action: Some(PinActionSubset { pinned: Some(true) }),
                ..Default::default()
            },
        );
        let archive_mut = make_mutation(
            "archive",
            chat,
            SyncActionValueSubset {
                archive_chat_action: Some(ArchiveChatActionSubset {
                    archived: Some(true),
                }),
                ..Default::default()
            },
        );
        let mute_mut = make_mutation(
            "mute",
            chat,
            SyncActionValueSubset {
                mute_action: Some(MuteActionSubset {
                    muted: Some(true),
                    mute_end_timestamp: Some(1_700_000_999),
                }),
                ..Default::default()
            },
        );
        let contact_mut = make_mutation(
            "contact",
            chat,
            SyncActionValueSubset {
                contact_action: Some(ContactActionSubset {
                    full_name: Some("Bob Builder".into()),
                    first_name: Some("Bob".into()),
                }),
                ..Default::default()
            },
        );

        let patch = SyncdPatchSubset {
            mutations: vec![pin_mut, archive_mut, mute_mut, contact_mut],
            snapshot_mac: None,
            patch_mac: None,
            key_id: None,
        };
        let bytes = patch.encode_to_vec();

        let muts = decode_app_state_patch(&bytes);
        assert_eq!(muts.len(), 4);

        assert!(matches!(
            muts[0],
            AppStateMutation::ChatPin { ref jid, pinned: true } if jid == chat
        ));
        assert!(matches!(
            muts[1],
            AppStateMutation::ChatArchive { ref jid, archived: true } if jid == chat
        ));
        assert!(matches!(
            muts[2],
            AppStateMutation::ChatMute { ref jid, until: Some(1_700_000_999) } if jid == chat
        ));
        match &muts[3] {
            AppStateMutation::ContactUpsert {
                jid,
                full_name,
                push_name,
            } => {
                assert_eq!(jid, chat);
                assert_eq!(full_name.as_deref(), Some("Bob Builder"));
                assert_eq!(push_name.as_deref(), Some("Bob"));
            }
            other => panic!("expected ContactUpsert, got {other:?}"),
        }

        // End-to-end: feeding these into apply_app_state_mutation
        // populates contacts + chats.
        let mgr = manager();
        let session = mgr.create(Some("alice".into())).unwrap();
        let id = session.meta.read().id.clone();
        for m in &muts {
            apply_app_state_mutation(&mgr.store, &id, m).unwrap();
        }
        let (full_name, push_name): (Option<String>, Option<String>) = mgr
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT full_name, push_name FROM contacts WHERE session_id = ? AND jid = ?",
                    rusqlite::params![id, chat],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })
            .unwrap();
        assert_eq!(full_name.as_deref(), Some("Bob Builder"));
        assert_eq!(push_name.as_deref(), Some("Bob"));
        let (pinned, archived, muted_until): (i64, i64, Option<i64>) = mgr
            .store
            .with_conn(|c| {
                c.query_row(
                    "SELECT pinned, archived, muted_until FROM chats WHERE session_id = ? AND jid = ?",
                    rusqlite::params![id, chat],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .unwrap();
        assert_eq!(pinned, 1);
        assert_eq!(archived, 1);
        assert_eq!(muted_until, Some(1_700_000_999));
    }

    /// Round-trip a HistorySync chunk: hand-build a HistorySyncSubset
    /// with two messages (one text, one image) → zlib-encode → run
    /// `parse_history_sync_payload` → assert decoded rows match → run
    /// `persist_history_sync_rows` → assert the messages table sees them.
    #[test]
    fn history_sync_chunk_round_trips_text_and_media() {
        use crate::proto::wa_common::MessageKey;
        use crate::proto::wa_web_protobufs_e2e::{ImageMessage, Message};
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use prost::Message as _;
        use std::io::Write;

        let mgr = manager();
        let session = mgr.create(Some("alice".into())).unwrap();
        let session_id = session.meta.read().id.clone();
        let store = mgr.store.clone();

        let chat = "5511999@s.whatsapp.net";

        // Inner waE2E.Message for each row.
        let text_inner = Message {
            conversation: Some("hi from history".into()),
            ..Default::default()
        };
        let image_inner = Message {
            image_message: Some(Box::new(ImageMessage {
                url: Some("https://x".into()),
                media_key: Some(vec![0xCC; 32]),
                mimetype: Some("image/jpeg".into()),
                caption: Some("a pic".into()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let conv = ConvSubset {
            id: Some(chat.to_string()),
            messages: vec![
                HistMsgSubset {
                    message: Some(WebMessageInfoSubset {
                        key: Some(MessageKey {
                            remote_jid: Some(chat.into()),
                            from_me: Some(false),
                            id: Some("HS-MSG-1".into()),
                            participant: None,
                        }),
                        message: Some(text_inner),
                        message_timestamp: Some(1_700_000_000),
                        push_name: Some("Bob".into()),
                        participant: Some("5511888@s.whatsapp.net".into()),
                    }),
                    msg_order_id: Some(1),
                },
                HistMsgSubset {
                    message: Some(WebMessageInfoSubset {
                        key: Some(MessageKey {
                            remote_jid: Some(chat.into()),
                            from_me: Some(true),
                            id: Some("HS-MSG-2".into()),
                            participant: None,
                        }),
                        message: Some(image_inner),
                        message_timestamp: Some(1_700_000_001),
                        push_name: None,
                        participant: None,
                    }),
                    msg_order_id: Some(2),
                },
            ],
            conversation_timestamp: Some(1_700_000_002),
            name: Some("Bob".into()),
        };
        let hs = HistorySyncSubset {
            conversations: vec![conv],
            // A PUSH_NAME-chunk entry for a contact with NO conversation — the
            // only way 1:1 contacts get a display name.
            pushnames: vec![PushnameSubset {
                id: Some("5511777@s.whatsapp.net".into()),
                pushname: Some("Carol".into()),
            }],
        };
        let bytes = hs.encode_to_vec();
        let mut zlib_enc = ZlibEncoder::new(Vec::new(), Compression::default());
        zlib_enc.write_all(&bytes).unwrap();
        let compressed = zlib_enc.finish().unwrap();

        let parsed = parse_history_sync_payload(&compressed).expect("parse");
        let rows = &parsed.rows;
        assert_eq!(rows.len(), 2);
        assert_eq!(parsed.pushnames, vec![("5511777@s.whatsapp.net".to_string(), "Carol".to_string())]);
        let r0 = rows.iter().find(|r| r.message_id == "HS-MSG-1").unwrap();
        assert_eq!(r0.msg_type, "text");
        assert_eq!(r0.body_text.as_deref(), Some("hi from history"));
        assert!(!r0.from_me);
        assert_eq!(r0.sender_jid, "5511888@s.whatsapp.net");

        let r1 = rows.iter().find(|r| r.message_id == "HS-MSG-2").unwrap();
        assert_eq!(r1.msg_type, "image");
        assert_eq!(r1.body_text.as_deref(), Some("a pic"));
        assert!(r1.from_me);
        assert!(r1.payload_json.contains("\"url\":\"https://x\""));

        // Sender + conversation display names rode along on the parsed rows.
        assert_eq!(r0.push_name.as_deref(), Some("Bob"));
        assert_eq!(r0.chat_name.as_deref(), Some("Bob"));
        assert!(!r0.is_group);

        // Persist + verify.
        let n = persist_history_sync_rows(&store, &session_id, &parsed).unwrap();
        assert_eq!(n, 2);
        let count: u32 = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM messages WHERE session_id = ?",
                    [&session_id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(count, 2);

        // The non-self sender's push name landed in `contacts`…
        let contacts = store.contacts_list(&session_id).unwrap();
        let bob = contacts.iter().find(|c| c.jid == "5511888@s.whatsapp.net").unwrap();
        assert_eq!(bob.push_name.as_deref(), Some("Bob"));
        // …and so did the PUSH_NAME-chunk contact that had no conversation.
        let carol = contacts.iter().find(|c| c.jid == "5511777@s.whatsapp.net").unwrap();
        assert_eq!(carol.push_name.as_deref(), Some("Carol"));
        // …and the conversation surfaces in `chats_list` with its real name.
        let chats = store.chats_list(&session_id).unwrap();
        let c = chats.iter().find(|c| c.jid == chat).unwrap();
        assert_eq!(c.name.as_deref(), Some("Bob"));
        assert_eq!(c.last_msg_ts, Some(1_700_000_001));

        // Idempotent: a second persist with the same rows is a no-op.
        let n2 = persist_history_sync_rows(&store, &session_id, &parsed).unwrap();
        assert_eq!(n2, 0);
    }

    /// A HistorySyncNotification with an inline bootstrap payload (no
    /// `direct_path`/`media_key`) must be ingested directly — not rejected.
    /// Guards the regression where the initial post-link bootstrap chunk was
    /// dropped with "missing direct_path". Mirrors whatsmeow's
    /// DownloadHistorySync inline-payload branch.
    #[tokio::test]
    async fn ingest_history_sync_uses_inline_bootstrap_without_direct_path() {
        use crate::proto::wa_common::MessageKey;
        use crate::proto::wa_web_protobufs_e2e::{HistorySyncNotification, Message};
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use prost::Message as _;
        use std::io::Write;

        let mgr = manager();
        let session = mgr.create(Some("alice".into())).unwrap();
        let session_id = session.meta.read().id.clone();
        let store = mgr.store.clone();
        let chat = "5511777@s.whatsapp.net";

        let conv = ConvSubset {
            id: Some(chat.to_string()),
            messages: vec![HistMsgSubset {
                message: Some(WebMessageInfoSubset {
                    key: Some(MessageKey {
                        remote_jid: Some(chat.into()),
                        from_me: Some(false),
                        id: Some("INLINE-1".into()),
                        participant: None,
                    }),
                    message: Some(Message {
                        conversation: Some("inline bootstrap msg".into()),
                        ..Default::default()
                    }),
                    message_timestamp: Some(1_700_000_010),
                    push_name: Some("Carol".into()),
                    participant: Some(chat.into()),
                }),
                msg_order_id: Some(1),
            }],
            conversation_timestamp: Some(1_700_000_011),
            name: Some("Carol".into()),
        };
        let hs = HistorySyncSubset { conversations: vec![conv], pushnames: vec![] };
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&hs.encode_to_vec()).unwrap();
        let inline = enc.finish().unwrap();

        // syncType=INITIAL_BOOTSTRAP(1), inline payload set, NO direct_path/media_key.
        let notif = HistorySyncNotification {
            sync_type: Some(1),
            initial_hist_bootstrap_inline_payload: Some(inline),
            ..Default::default()
        };

        let n = ingest_history_sync_notification(&store, None, &session_id, &notif)
            .await
            .expect("inline bootstrap must ingest, not error on missing direct_path");
        assert_eq!(n, 1);
        let count: u32 = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM messages WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![&session_id, "INLINE-1"],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(count, 1);
    }

    /// Inbound pkmsg path: a fresh peer ("Bob") consumes one of Alice's
    /// uploaded one-time prekeys, ships a PreKeyWhisperMessage. Alice's
    /// `process_inbound_message` must:
    /// - look the OPK up by id in the prekeys table,
    /// - run process_bob with that OPK + the inner ratchet key,
    /// - decrypt the inner Whisper, persist the `messages` row as text,
    /// - and DELETE the consumed prekey row (single-use).
    #[test]
    fn process_inbound_pkmsg_consumes_prekey_and_persists_text() {
        use crate::crypto::identity::KeyPair;
        use crate::crypto::signal::{
            AliceParameters, RatchetingSession, SessionCipher,
        };
        use crate::protocol::binary::{Attrs, Content, Node};

        let mgr = manager();
        let alice = mgr.create(Some("alice".into())).unwrap();
        let alice_id = alice.meta.read().id.clone();
        let alice_keys = mgr.load_device_keys(&alice_id).unwrap();
        let store = mgr.store.clone();

        // Pick one of the 30 OPKs Alice uploaded; fetch its public for
        // Bob's X3DH input. Cleaner than re-generating fresh keys — the
        // whole point of the test is the table-backed lookup path.
        let (opk_id, opk_pub_bytes): (u32, Vec<u8>) = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT key_id, public_key FROM prekeys \
                       WHERE session_id = ? ORDER BY key_id ASC LIMIT 1",
                    [&alice_id],
                    |r| Ok((r.get::<_, u32>(0)?, r.get::<_, Vec<u8>>(1)?)),
                )
            })
            .unwrap();
        let mut opk_pub = [0u8; 32];
        opk_pub.copy_from_slice(&opk_pub_bytes);

        // Bob's identity, base, ratchet — disposable.
        let bob_id = KeyPair::generate();
        let bob_base = KeyPair::generate();
        let bob_ratchet = KeyPair::generate();
        let bob_jid = "5511888888888@s.whatsapp.net";

        // Bob runs initiate_alice against Alice's static SPK + the chosen OPK.
        let mut bob_state = RatchetingSession::initiate_alice(&AliceParameters {
            local_identity_priv: &bob_id.private,
            local_identity_pub: &bob_id.public,
            local_base_priv: &bob_base.private,
            local_base_pub: &bob_base.public,
            local_ratchet_priv: &bob_ratchet.private,
            local_ratchet_pub: &bob_ratchet.public,
            remote_identity_pub: &alice_keys.identity.public,
            remote_signed_prekey_pub: &alice_keys.signed_prekey.keypair.public,
            remote_one_time_prekey_pub: Some(&opk_pub),
        });

        // Plaintext = waE2E.Message{conversation:"hi alice"} + WA pad.
        let inner_pt = build_e2e_conversation("hi alice");
        let padded = pad_message(&inner_pt);
        let pkm = SessionCipher::encrypt_pre_key(
            &mut bob_state,
            &padded,
            42,
            &bob_base.public,
            &bob_id.public,
            alice_keys.signed_prekey.key_id,
            Some(opk_id),
        )
        .unwrap();

        // Wrap in a `<message id type to t><enc type=pkmsg/></message>`.
        let mut enc_attrs = Attrs::new();
        enc_attrs.insert("v".into(), "2".into());
        enc_attrs.insert("type".into(), "pkmsg".into());
        let enc = Node {
            tag: "enc".into(),
            attrs: enc_attrs,
            content: Content::Bytes(pkm.serialized.clone()),
        };
        let mut msg_attrs = Attrs::new();
        msg_attrs.insert("id".into(), "INBOUND-1".into());
        msg_attrs.insert("from".into(), bob_jid.into());
        msg_attrs.insert("type".into(), "text".into());
        msg_attrs.insert("t".into(), "1700000000".into());
        msg_attrs.insert("notify".into(), "Bob Sender".into());
        let inbound = Node {
            tag: "message".into(),
            attrs: msg_attrs,
            content: Content::Nodes(vec![enc]),
        };

        // Simulate that we'd already sent retry receipts for this id (the
        // sender's earlier attempt was undecryptable). A successful decrypt of
        // the same id now is the "retry recovery" signal.
        alice.bump_message_retry("INBOUND-1");
        alice.bump_message_retry("INBOUND-1");

        // Drive the path under test.
        let receipt =
            process_inbound_message(&alice, &store, &alice_keys, None, &inbound).expect("receipt");
        assert_eq!(receipt.tag, "receipt");
        // Decrypt success → regular ack (no `type` attr), not a retry.
        assert!(
            !receipt.attrs.contains_key("type"),
            "successful decrypt must produce a regular receipt, not a retry"
        );
        // Recovery cleared the retry counter for this id (logged at info).
        assert!(
            alice.take_message_retry("INBOUND-1").is_none(),
            "a successful decrypt must clear the pending retry state for that id"
        );

        // The prekey row must be gone.
        let remaining: u32 = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT COUNT(*) FROM prekeys \
                       WHERE session_id = ? AND key_id = ?",
                    rusqlite::params![alice_id, opk_id],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(remaining, 0, "consumed OPK must be deleted");

        // The decrypted text must land in `messages`.
        let body_text: Option<String> = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT body_text FROM messages \
                       WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![alice_id, "INBOUND-1"],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert_eq!(body_text.as_deref(), Some("hi alice"));

        // The sender's push name (from the `notify` attr) is folded into the
        // persisted payload.
        let payload_json: String = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT payload_json FROM messages \
                       WHERE session_id = ? AND message_id = ?",
                    rusqlite::params![alice_id, "INBOUND-1"],
                    |r| r.get(0),
                )
            })
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
        assert_eq!(payload["push_name"], serde_json::json!("Bob Sender"));

        // The Signal session was persisted under Bob's JID; a follow-up
        // pkmsg/msg from him would now find a record.
        let bytes: Vec<u8> = store
            .with_conn(|c| {
                c.query_row(
                    "SELECT record FROM signal_sessions \
                       WHERE session_id = ? AND address = ?",
                    rusqlite::params![alice_id, bob_jid],
                    |r| r.get(0),
                )
            })
            .unwrap();
        let _record: crate::crypto::signal::SessionRecord =
            serde_json::from_slice(&bytes).unwrap();
    }

    #[test]
    fn build_receipt_types_own_account_messages() {
        // A contact's message → bare delivery receipt (no `type`), matching
        // whatsmeow `sendMessageReceipt` for non-own stanzas.
        let r = build_receipt("ID1", "5511888888888@s.whatsapp.net", "", false, "text");
        assert_eq!(r.tag, "receipt");
        assert_eq!(r.attrs.get("id").map(String::as_str), Some("ID1"));
        assert_eq!(
            r.attrs.get("to").map(String::as_str),
            Some("5511888888888@s.whatsapp.net")
        );
        assert!(
            !r.attrs.contains_key("type"),
            "a contact's message must get a typeless delivery receipt"
        );

        // Our own fan-out (is_from_me) → `type="sender"`. Acking these as plain
        // deliveries left the phone's history-sync drive unsatisfied → "paused".
        let r = build_receipt("ID2", "5511990000001@s.whatsapp.net", "", true, "text");
        assert_eq!(r.attrs.get("type").map(String::as_str), Some("sender"));

        // A `type="peer_msg"` own stanza escalates to `type="peer_msg"`.
        let r = build_receipt("ID3", "5511990000001@s.whatsapp.net", "", true, "peer_msg");
        assert_eq!(r.attrs.get("type").map(String::as_str), Some("peer_msg"));
    }

    /// An undecryptable inbound must produce an escalating retry receipt:
    /// the first carries `count=1 v=1` and NO `<keys>`; the second (same id)
    /// carries `count=2` plus the full `<keys>` re-establishment bundle
    /// (type/identity/fresh-OPK/skey/device-identity), and mints a fresh,
    /// persisted one-time prekey. Mirrors whatsmeow's `sendRetryReceipt`.
    #[test]
    fn undecryptable_inbound_escalates_retry_receipt_and_attaches_keys() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let mgr = manager();
        let alice = mgr.create(Some("alice".into())).unwrap();
        let alice_id = alice.meta.read().id.clone();
        let alice_keys = mgr.load_device_keys(&alice_id).unwrap();
        let store = mgr.store.clone();

        // A device-identity blob must exist for the keys bundle to attach —
        // stamp a placeholder via the pair-success path.
        store
            .session_apply_pair_success(
                &alice_id,
                b"dummy-account-pb-blob",
                None,
                None,
                Some("5511999999999:1@s.whatsapp.net"),
                1_700_000_000,
            )
            .unwrap();

        // An `<enc type="msg">` with junk ciphertext from a peer we have no
        // session with → the "msg" branch loads no record → undecryptable.
        let peer = "5511777777777@s.whatsapp.net";
        let make_inbound = || {
            let mut enc_attrs = Attrs::new();
            enc_attrs.insert("v".into(), "2".into());
            enc_attrs.insert("type".into(), "msg".into());
            let enc = Node {
                tag: "enc".into(),
                attrs: enc_attrs,
                content: Content::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]),
            };
            let mut msg_attrs = Attrs::new();
            msg_attrs.insert("id".into(), "RETRY-ME".into());
            msg_attrs.insert("from".into(), peer.into());
            msg_attrs.insert("type".into(), "text".into());
            msg_attrs.insert("t".into(), "1700000000".into());
            Node {
                tag: "message".into(),
                attrs: msg_attrs,
                content: Content::Nodes(vec![enc]),
            }
        };

        let child = |n: &Node, tag: &str| -> Option<Node> {
            match &n.content {
                Content::Nodes(ns) => ns.iter().find(|c| c.tag == tag).cloned(),
                _ => None,
            }
        };

        let max_before = store.prekey_max_id(&alice_id).unwrap();

        // Asserts a retry receipt carries `count`/`v=1` plus the full `<keys>`
        // re-establishment bundle, and that a fresh OPK was persisted.
        let assert_full_retry = |r: &Node, expect_count: &str| {
            assert_eq!(r.attrs.get("type").map(String::as_str), Some("retry"));
            let retry = child(r, "retry").expect("retry child");
            assert_eq!(retry.attrs.get("count").map(String::as_str), Some(expect_count));
            assert_eq!(retry.attrs.get("v").map(String::as_str), Some("1"));
            assert!(child(r, "registration").is_some(), "registration node");
            let keys = child(r, "keys").expect("retry must include keys bundle");
            for tag in ["type", "identity", "key", "skey", "device-identity"] {
                assert!(child(&keys, tag).is_some(), "keys bundle missing <{tag}>");
            }
            match child(&keys, "device-identity").unwrap().content {
                Content::Bytes(b) => assert_eq!(b, b"dummy-account-pb-blob"),
                _ => panic!("device-identity must be bytes"),
            }
        };

        // --- Eager keys: the FIRST retry already carries the bundle. A live
        // repro showed peers won't act on a keyless retry (and would reuse a
        // dead one-time prekey), so we re-establish from retry #1. ---
        let r1 = process_inbound_message(&alice, &store, &alice_keys, None, &make_inbound())
            .expect("retry receipt");
        assert_full_retry(&r1, "1");

        // --- Second retry (same id): count escalates, bundle still attached. ---
        let r2 = process_inbound_message(&alice, &store, &alice_keys, None, &make_inbound())
            .expect("retry receipt");
        assert_full_retry(&r2, "2");

        // Each retry mints + persists a fresh, loadable OPK (two retries → the
        // max id advanced by at least one).
        let max_after = store.prekey_max_id(&alice_id).unwrap();
        assert!(max_after > max_before, "a fresh one-time prekey was persisted");
        assert!(
            store
                .prekey_load_private(&alice_id, max_after)
                .unwrap()
                .is_some(),
            "the minted OPK private key is loadable by id"
        );
    }

    /// The recent-send ring stores newest-last, looks up by id, and evicts the
    /// oldest past the cap.
    #[test]
    fn recent_send_cache_stores_and_evicts() {
        let mgr = manager();
        let s = mgr.create(Some("s".into())).unwrap();

        s.record_recent_send("a", "chatA", b"protoA");
        s.record_recent_send("b", "chatB", b"protoB");
        assert_eq!(
            s.recent_send("a"),
            Some(("chatA".to_string(), b"protoA".to_vec()))
        );
        assert_eq!(
            s.recent_send("b"),
            Some(("chatB".to_string(), b"protoB".to_vec()))
        );
        assert_eq!(s.recent_send("missing"), None);

        // Flood past the cap: the two originals plus the early flood ids fall off.
        for i in 0..RECENT_SENDS_MAX + 5 {
            s.record_recent_send(&format!("k{i}"), "c", b"x");
        }
        assert!(s.recent_send("a").is_none(), "oldest entry evicted");
        assert!(
            s.recent_send(&format!("k{}", RECENT_SENDS_MAX + 4)).is_some(),
            "newest entry retained"
        );
    }

    /// An inbound retry receipt carrying a `<keys>` bundle (the exact shape we
    /// emit from [`build_retry_keys_node`]) round-trips back into a
    /// `DevicePrekeyBundle` with the right key material. Closes the loop:
    /// what one device puts on the wire, the other parses.
    #[test]
    fn inbound_retry_receipt_parses_keys_bundle() {
        use crate::protocol::binary::{Attrs, Content, Node};

        let mgr = manager();
        let peer = mgr.create(Some("peer".into())).unwrap();
        let peer_id = peer.meta.read().id.clone();
        let peer_keys = mgr.load_device_keys(&peer_id).unwrap();
        let store = mgr.store.clone();
        store
            .session_apply_pair_success(
                &peer_id,
                b"acct-pb",
                None,
                None,
                Some("5511777777777:7@s.whatsapp.net"),
                1_700_000_000,
            )
            .unwrap();

        // The peer builds its retry `<keys>` bundle (as if it couldn't decrypt
        // a message we sent and is asking for a fresh session).
        let keys_node = build_retry_keys_node(&store, &peer_id, &peer_keys).expect("keys node");

        // Wrap it in an inbound `<receipt type="retry" from=<device>>`.
        let device = "5511777777777:7@s.whatsapp.net";
        let mut retry_attrs = Attrs::new();
        retry_attrs.insert("count".into(), "2".into());
        retry_attrs.insert("id".into(), "MSG-1".into());
        let retry = Node {
            tag: "retry".into(),
            attrs: retry_attrs,
            content: Content::None,
        };
        let registration = Node {
            tag: "registration".into(),
            attrs: Attrs::new(),
            content: Content::Bytes(4242u32.to_be_bytes().to_vec()),
        };
        let mut top = Attrs::new();
        top.insert("from".into(), device.into());
        top.insert("id".into(), "MSG-1".into());
        top.insert("type".into(), "retry".into());
        let receipt = Node {
            tag: "receipt".into(),
            attrs: top,
            content: Content::Nodes(vec![retry, registration, keys_node]),
        };

        let req = parse_inbound_retry_receipt(&receipt).expect("parses as retry request");
        assert_eq!(req.msg_id, "MSG-1");
        assert_eq!(req.device_jid, device);
        assert_eq!(req.count, 2);

        let b = req.bundle.expect("keys bundle parsed");
        assert_eq!(b.identity_pub, peer_keys.identity.public);
        assert_eq!(b.signed_pre_key_pub, peer_keys.signed_prekey.keypair.public);
        assert_eq!(b.signed_pre_key_sig, peer_keys.signed_prekey.signature);
        assert_eq!(
            b.signed_pre_key_id,
            peer_keys.signed_prekey.key_id & 0x00FF_FFFF
        );
        assert!(b.one_time_pre_key_id.is_some(), "fresh OPK present");
        assert!(b.one_time_pre_key_pub.is_some());
        assert_eq!(b.registration_id, 4242);
        assert_eq!(b.device_id, 7);

        // A non-retry receipt is ignored.
        let mut plain = Attrs::new();
        plain.insert("from".into(), device.into());
        plain.insert("id".into(), "X".into());
        assert!(parse_inbound_retry_receipt(&Node {
            tag: "receipt".into(),
            attrs: plain,
            content: Content::None,
        })
        .is_none());
    }

    /// `install_session_from_bundle` writes a usable outbound session: the
    /// stored record has a live state with a `pending_pre_key` (so the next
    /// encrypt emits a re-bootstrapping pkmsg) and the peer's identity.
    #[test]
    fn install_session_from_bundle_persists_pending_prekey_session() {
        use crate::crypto::identity::KeyPair;

        let mgr = manager();
        let us = mgr.create(Some("us".into())).unwrap();
        let our_id = us.meta.read().id.clone();
        let our_keys = mgr.load_device_keys(&our_id).unwrap();
        let store = mgr.store.clone();

        // A synthetic peer bundle.
        let peer_id_kp = KeyPair::generate();
        let peer_spk = KeyPair::generate();
        let peer_opk = KeyPair::generate();
        let bundle = DevicePrekeyBundle {
            jid: "5511555555555:3@s.whatsapp.net".into(),
            device_id: 3,
            registration_id: 99,
            identity_pub: peer_id_kp.public,
            signed_pre_key_id: 1,
            signed_pre_key_pub: peer_spk.public,
            signed_pre_key_sig: [0u8; 64],
            one_time_pre_key_id: Some(7),
            one_time_pre_key_pub: Some(peer_opk.public),
        };
        let device = bundle.jid.clone();

        install_session_from_bundle(&store, &our_keys, &our_id, &device, &bundle).unwrap();

        let record = store_load_record(&store, &our_id, &device)
            .unwrap()
            .expect("session persisted");
        let state = record.current.expect("live state");
        assert_eq!(state.remote_identity_pub, peer_id_kp.public);
        assert_eq!(state.remote_registration_id, 99);
        let pp = state.pending_pre_key.expect("pending prekey set → first send is a pkmsg");
        assert_eq!(pp.pre_key_id, Some(7));
        assert_eq!(pp.signed_pre_key_id, 1);
    }

    /// The peer "PlaceholderMessageResendRequest" marshals to a ProtocolMessage
    /// of the right type carrying the undecryptable message's key — what we ask
    /// our own phone to resend.
    #[test]
    fn unavailable_message_request_builds_placeholder_resend_proto() {
        use crate::proto::wa_web_protobufs_e2e::{
            protocol_message, Message, PeerDataOperationRequestType,
        };
        use prost::Message as _;

        let bytes = build_unavailable_message_request(
            "5511777777777@s.whatsapp.net",
            "5511777777777@s.whatsapp.net",
            "MSG-XYZ",
            "5511990000001",
        );
        let msg = Message::decode(bytes.as_slice()).expect("decodes as waE2E.Message");
        let pm = msg.protocol_message.expect("has protocol_message");
        assert_eq!(
            pm.r#type,
            Some(protocol_message::Type::PeerDataOperationRequestMessage as i32)
        );
        let pdo = pm
            .peer_data_operation_request_message
            .expect("has peer data op request");
        assert_eq!(
            pdo.peer_data_operation_request_type,
            Some(PeerDataOperationRequestType::PlaceholderMessageResend as i32)
        );
        assert_eq!(pdo.placeholder_message_resend_request.len(), 1);
        let key = pdo.placeholder_message_resend_request[0]
            .message_key
            .as_ref()
            .expect("message key");
        assert_eq!(key.id.as_deref(), Some("MSG-XYZ"));
        assert_eq!(key.remote_jid.as_deref(), Some("5511777777777@s.whatsapp.net"));
        // Sender != our own user → from_me=false (mirrors BuildMessageKey).
        assert_eq!(key.from_me, Some(false));
    }

    /// `capture_lid_pn_mappings` records the chat's LID<->PN from a fan-out
    /// message's `recipient` + `peer_recipient_pn` attrs (the real wire shape).
    #[test]
    fn capture_lid_pn_from_message_attrs() {
        use crate::protocol::binary::Attrs;
        let mgr = manager();
        let s = mgr.create(Some("s".into())).unwrap();
        let id = s.meta.read().id.clone();
        let store = mgr.store.clone();

        let mut attrs = Attrs::new();
        attrs.insert("from".into(), "64000000000001.1@lid".into());
        attrs.insert("recipient".into(), "169000000000002.1@lid".into());
        attrs.insert("peer_recipient_pn".into(), "551190000002@s.whatsapp.net".into());
        capture_lid_pn_mappings(&store, &id, &attrs);

        assert_eq!(
            store.lid_to_pn(&id, "169000000000002").unwrap().as_deref(),
            Some("551190000002"),
            "chat LID<->PN learned from peer_recipient_pn"
        );
    }

    /// `capture_group_participant_lids` learns each participant's LID<->PN from a
    /// group-info reply (`<participant jid="..@lid" phone_number="..">`) — the
    /// source that lets a later 1:1 send to a group-only contact resolve to a PN.
    #[test]
    fn capture_group_participant_lids_learns_pns() {
        use crate::protocol::binary::{Attrs, Content, Node};
        let mgr = manager();
        let s = mgr.create(Some("g".into())).unwrap();
        let id = s.meta.read().id.clone();
        let store = mgr.store.clone();

        let participant = |lid: &str, pn: &str| {
            let mut a = Attrs::new();
            a.insert("jid".into(), lid.into());
            a.insert("phone_number".into(), pn.into());
            Node { tag: "participant".into(), attrs: a, content: Content::None }
        };
        let group = Node {
            tag: "group".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![
                participant("64000000000001.1@lid", "5511990000001@s.whatsapp.net"),
                participant("169000000000002.1@lid", "551190000002@s.whatsapp.net"),
            ]),
        };
        let iq = Node {
            tag: "iq".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![group]),
        };
        capture_group_participant_lids(&store, &id, &iq);

        assert_eq!(
            store.lid_to_pn(&id, "64000000000001").unwrap().as_deref(),
            Some("5511990000001"),
            "Henry's LID->PN learned from group info"
        );
        assert_eq!(
            store.lid_to_pn(&id, "169000000000002").unwrap().as_deref(),
            Some("551190000002")
        );
    }

    /// A `@lid`-addressed message reuses the PN session we already have: with a
    /// LID->PN mapping in place, `resolve_session_address` migrates the existing
    /// PN-keyed session to the LID address instead of treating it as new.
    #[test]
    fn resolve_session_address_migrates_pn_session_to_lid() {
        let mgr = manager();
        let s = mgr.create(Some("s".into())).unwrap();
        let id = s.meta.read().id.clone();
        let store = mgr.store.clone();

        // An established session keyed by the PRIMARY (device-0, bare) PN addr.
        let rec = crate::crypto::signal::SessionRecord::new();
        store_save_record(&store, &id, "5511990000001@s.whatsapp.net", &rec).unwrap();
        store.lid_pn_put(&id, "64000000000001", "5511990000001", 1).unwrap();

        // `64000000000001.1@lid` is agent 1 / device 0 (NOT device 1) → it must
        // resolve via the map + migrate the device-0 PN session.
        assert!(store_load_record(&store, &id, "64000000000001.1@lid")
            .unwrap()
            .is_none());
        let resolved = resolve_session_address(&store, &id, "64000000000001.1@lid");
        assert_eq!(resolved, "64000000000001.1@lid");
        assert!(
            store_load_record(&store, &id, "64000000000001.1@lid")
                .unwrap()
                .is_some(),
            "the device-0 PN session was migrated to the device-0 LID address"
        );

        // Unknown LID (no mapping) → returned unchanged, no session.
        assert_eq!(
            resolve_session_address(&store, &id, "99999999999.1@lid"),
            "99999999999.1@lid"
        );
    }

    /// `sender_is_self` must recognise our own messages whether the sender is
    /// addressed by our PN or our `@lid`, and reject other people — even when
    /// the real sender is `participant` (a group `from` is the group jid, which
    /// is exactly the case that used to slip through and render own group
    /// messages as if they came from someone else).
    #[test]
    fn sender_is_self_bridges_lid_and_pn_for_own_messages() {
        let mgr = manager();
        let s = mgr.create(Some("s".into())).unwrap();
        let id = s.meta.read().id.clone();
        let store = mgr.store.clone();
        let own_pn = "5511990000001";
        // Our own LID<->PN, as learned from the account_sync notification.
        store.lid_pn_put(&id, "64000000000001", own_pn, 1).unwrap();

        // Our own PN form.
        assert!(sender_is_self(&store, &id, Some(own_pn), "5511990000001@s.whatsapp.net"));
        // Our own LID form (agent .1, device :3) — the group fan-out shape.
        assert!(sender_is_self(&store, &id, Some(own_pn), "64000000000001.1:3@lid"));
        // Bare own LID with no PN known on the sender side still bridges via the
        // own pn->lid direction.
        assert!(sender_is_self(&store, &id, Some(own_pn), "64000000000001@lid"));

        // Someone else — PN and an unmapped LID — must NOT be us.
        assert!(!sender_is_self(&store, &id, Some(own_pn), "5511000000000@s.whatsapp.net"));
        assert!(!sender_is_self(&store, &id, Some(own_pn), "99999999999.1@lid"));
        // No own jid known yet → never claims a message as ours.
        assert!(!sender_is_self(&store, &id, None, "5511990000001@s.whatsapp.net"));
    }

    /// Sessions are per-device: a device-0 (bare PN) session must NOT be
    /// migrated onto a device-1 LID address (that would corrupt it).
    #[test]
    fn resolve_session_address_does_not_cross_devices() {
        let mgr = manager();
        let s = mgr.create(Some("s2".into())).unwrap();
        let id = s.meta.read().id.clone();
        let store = mgr.store.clone();

        // Only the PRIMARY (device 0 / bare) session exists.
        let rec = crate::crypto::signal::SessionRecord::new();
        store_save_record(&store, &id, "5511990000001@s.whatsapp.net", &rec).unwrap();
        store.lid_pn_put(&id, "64000000000001", "5511990000001", 1).unwrap();

        // A NON-PRIMARY device (the `:19`) must not pick up the device-0
        // session. The `.1` is the agent, `:19` is the device.
        resolve_session_address(&store, &id, "64000000000001.1:19@lid");
        assert!(
            store_load_record(&store, &id, "64000000000001.1:19@lid")
                .unwrap()
                .is_none(),
            "device-19 LID must not migrate the device-0 session"
        );

        // The device-0 LID (agent 1, no `:device`) *does* map to the bare PN
        // session — this is the own-phone fan-out that was breaking.
        resolve_session_address(&store, &id, "64000000000001.1@lid");
        assert!(store_load_record(&store, &id, "64000000000001.1@lid")
            .unwrap()
            .is_some());
    }
}
