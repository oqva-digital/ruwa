//! Meta WhatsApp Cloud API (Graph API) backend for `kind = "cloud"` sessions.
//!
//! Pure transport module: Graph client, neutral payload builders, webhook
//! parsing + `X-Hub-Signature-256` verification, Graph error mapping. It has no
//! dependency on `session.rs` / `store.rs`; the wiring lives there and in
//! `api.rs`.
//!
//! Everything here is expressed in terms of plain strings / `serde_json::Value`
//! so it can be unit-tested without a network and so that no Graph-specific
//! type ever leaks into the public HTTP API.

use std::time::Duration;

use anyhow::anyhow;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::Sha256;

use crate::error::{Error, Result};

/// Graph API version used when a session does not pin one.
pub const DEFAULT_GRAPH_VERSION: &str = "v25.0";

/// Graph API host. Every Cloud API call is `{GRAPH_BASE}/{version}/{path}`.
pub const GRAPH_BASE: &str = "https://graph.facebook.com";

/// Kapso's Meta-compatible proxy host. Kapso mirrors the Graph surface 1:1 at
/// `{KAPSO_WA_BASE}/{version}/{path}` (same paths, same request/response bodies),
/// so the whole [`CloudClient`] send/upload/template code path is shared — only
/// the base host and the auth header differ (see [`CloudClient::api_base`] /
/// [`CloudClient::auth`]).
pub const KAPSO_WA_BASE: &str = "https://api.kapso.ai/meta/whatsapp";

/// Which upstream a cloud session talks to. `Meta` = Graph directly (bearer
/// token). `Kapso` = Kapso's Meta-compatible proxy (platform `X-API-Key`),
/// used when the number was onboarded through the Kapso Business Platform.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    #[default]
    Meta,
    Kapso,
}

impl CloudProvider {
    /// Parse the persisted `sessions.cloud_provider` column; anything
    /// unrecognized (including the empty string / NULL) is `Meta`.
    // `parse` / `as_str` land with the store column that feeds them (WP-D).
    #[allow(dead_code)]
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "kapso" => CloudProvider::Kapso,
            _ => CloudProvider::Meta,
        }
    }

    /// Value for the `sessions.cloud_provider` column.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            CloudProvider::Meta => "meta",
            CloudProvider::Kapso => "kapso",
        }
    }
}

/// Total timeout for the small JSON Graph calls (send, validate, templates,
/// media metadata) — and the connect timeout for every call.
const GRAPH_TIMEOUT_SECS: u64 = 30;

/// Total timeout for the media transfers (`POST /{pnid}/media` uploads,
/// download of inbound media). Meta accepts documents up to 100 MB, so the
/// budget must cover a large body on a modest uplink; the 30 s connect timeout
/// still bounds a dead host.
const MEDIA_TIMEOUT_SECS: u64 = 15 * 60;

const USER_AGENT: &str = concat!("ruwa/", env!("CARGO_PKG_VERSION"));

// ---------------------------------------------------------------------------
// Credentials + client
// ---------------------------------------------------------------------------

/// Everything needed to talk to Graph on behalf of one business phone number.
///
/// `access_token` / `app_secret` are secrets: they are stored sealed by the
/// store layer and must never be serialized into an API response.
#[derive(Clone, Debug)]
pub struct CloudCreds {
    /// Upstream this session talks to (`meta` direct, or `kapso` proxy).
    pub provider: CloudProvider,
    /// Graph node id of the business phone number (`/{phone_number_id}/messages`).
    pub phone_number_id: String,
    /// WhatsApp Business Account id; required for template management only.
    pub waba_id: Option<String>,
    /// System-user (or business) access token, sent as `Authorization: Bearer`.
    /// Empty for `provider = kapso` (Kapso holds the Meta token; ruwa
    /// authenticates with the platform key in `api_key`).
    pub access_token: String,
    /// Kapso platform `X-API-Key` — server-wide (`RUWA_KAPSO_API_KEY`), injected
    /// when the client is built. Only read for `provider = kapso`.
    pub api_key: Option<String>,
    /// Override for the upstream base host. `None` → the provider default
    /// ([`GRAPH_BASE`] / [`KAPSO_WA_BASE`]).
    pub base_url: Option<String>,
    /// Meta app secret used to verify `X-Hub-Signature-256` on inbound webhooks.
    /// Unused for `provider = kapso` (Kapso signs with a per-number secret; see
    /// [`verify_kapso_signature`]).
    pub app_secret: Option<String>,
    /// Token echoed on the webhook `GET` verification handshake.
    pub verify_token: Option<String>,
    /// Graph API version (`v25.0`), see [`DEFAULT_GRAPH_VERSION`]. Kapso pins its
    /// own supported version in the proxy path (e.g. `v24.0`).
    pub graph_version: String,
}

/// Result of a successful credential validation (`GET /{phone_number_id}`).
#[derive(Debug, Clone, Serialize)]
pub struct PhoneInfo {
    /// Graph id of the phone number node (equals `phone_number_id`).
    pub id: String,
    /// Human-formatted number as shown by Meta (e.g. `"+55 11 99999-9999"`).
    pub display_phone_number: Option<String>,
    /// Verified business display name.
    pub verified_name: Option<String>,
    /// `GREEN` / `YELLOW` / `RED` / `NA` / `UNKNOWN`.
    pub quality_rating: Option<String>,
}

/// Outcome of `POST /{phone_number_id}/messages`.
#[derive(Debug, Clone)]
pub struct SendResult {
    /// The `wamid.…` message id later referenced by status webhooks.
    pub wamid: String,
    /// `contacts[0].wa_id` — the recipient id as WhatsApp sees it (may differ
    /// from the input number, e.g. Brazilian 9th digit).
    pub wa_id: Option<String>,
}

/// Metadata for an uploaded / received media asset (`GET /{media_id}`).
#[derive(Debug, Clone, Serialize)]
pub struct MediaInfo {
    /// Short-lived (≈5 min) download URL; requires the bearer token.
    pub url: String,
    pub mime_type: Option<String>,
    pub sha256: Option<String>,
    pub file_size: Option<u64>,
}

/// One page of `GET /{waba_id}/message_templates`.
#[derive(Debug, Clone, Serialize)]
pub struct TemplatePage {
    /// Each item is `{id, name, language, status, category, components}` as
    /// returned by Graph.
    pub templates: Vec<Value>,
    /// Cursor to pass as `after` for the next page, `None` on the last page.
    pub next: Option<String>,
}

/// Thin Graph API client bound to one set of [`CloudCreds`].
pub struct CloudClient {
    http: reqwest::Client,
    creds: CloudCreds,
}

impl std::fmt::Debug for CloudClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudClient")
            .field("phone_number_id", &self.creds.phone_number_id)
            .field("waba_id", &self.creds.waba_id)
            .field("graph_version", &self.creds.graph_version)
            .finish_non_exhaustive()
    }
}

impl CloudClient {
    /// Build a client with a 30 s connect + JSON-call timeout (media transfers
    /// get their own, larger per-request budget) and an optional egress proxy
    /// (`http://`, `https://`, `socks5://` — anything `reqwest::Proxy::all`
    /// accepts).
    pub fn new(creds: CloudCreds, proxy: Option<&str>) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(GRAPH_TIMEOUT_SECS))
            .timeout(Duration::from_secs(GRAPH_TIMEOUT_SECS))
            .user_agent(USER_AGENT);
        if let Some(url) = proxy.map(str::trim).filter(|s| !s.is_empty()) {
            let p = reqwest::Proxy::all(url)
                .map_err(|e| Error::BadRequest(format!("cloud: invalid proxy url: {e}")))?;
            b = b.proxy(p);
        }
        let http = b
            .build()
            .map_err(|e| Error::Internal(anyhow!("cloud: http client: {e}")))?;
        Ok(Self { http, creds })
    }

    /// Business phone number id this client sends from.
    pub fn phone_number_id(&self) -> &str {
        &self.creds.phone_number_id
    }

    /// Upstream base host for this session — the provider default unless the
    /// session pins an override in `base_url`. No trailing slash.
    pub fn api_base(&self) -> &str {
        if let Some(b) = self.creds.base_url.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            return b.trim_end_matches('/');
        }
        match self.creds.provider {
            CloudProvider::Meta => GRAPH_BASE,
            CloudProvider::Kapso => KAPSO_WA_BASE,
        }
    }

    /// Absolute upstream URL for `path` (no leading slash), e.g.
    /// `graph_url("123/messages")`. Structure is identical for Meta and Kapso
    /// (`{base}/{version}/{path}`).
    pub fn graph_url(&self, path: &str) -> String {
        let version = if self.creds.graph_version.trim().is_empty() {
            DEFAULT_GRAPH_VERSION
        } else {
            self.creds.graph_version.trim()
        };
        format!("{}/{version}/{path}", self.api_base())
    }

    /// Attach the provider's auth to a request: `Authorization: Bearer <token>`
    /// for Meta, `X-API-Key: <platform key>` for Kapso.
    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.creds.provider {
            CloudProvider::Meta => req.bearer_auth(&self.creds.access_token),
            CloudProvider::Kapso => {
                req.header("X-API-Key", self.creds.api_key.as_deref().unwrap_or_default())
            }
        }
    }

    fn waba_id(&self) -> Result<&str> {
        self.creds
            .waba_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::BadRequest("cloud: waba_id is required for template management".into())
            })
    }

    /// Execute a prepared request, mapping transport failures and non-2xx
    /// Graph error envelopes; returns the parsed JSON body.
    async fn exec_json(&self, req: reqwest::RequestBuilder) -> Result<Value> {
        let resp = self
            .auth(req)
            .send()
            .await
            .map_err(|e| Error::Internal(anyhow!("cloud: graph request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Internal(anyhow!("cloud: graph read failed: {e}")))?;
        if !status.is_success() {
            return Err(map_graph_error(status.as_u16(), &body));
        }
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&body)
            .map_err(|e| Error::Internal(anyhow!("cloud: graph returned invalid json: {e}")))
    }

    /// `GET /{phone_number_id}?fields=id,display_phone_number,verified_name,quality_rating`
    /// — the cheapest way to check that token + phone number id are valid.
    pub async fn validate(&self) -> Result<PhoneInfo> {
        let url = self.graph_url(&self.creds.phone_number_id);
        let v = self
            .exec_json(self.http.get(&url).query(&[(
                "fields",
                "id,display_phone_number,verified_name,quality_rating",
            )]))
            .await?;
        Ok(PhoneInfo {
            id: str_of(&v, "id").unwrap_or_else(|| self.creds.phone_number_id.clone()),
            display_phone_number: str_of(&v, "display_phone_number"),
            verified_name: str_of(&v, "verified_name"),
            quality_rating: str_of(&v, "quality_rating"),
        })
    }

    /// `POST /{phone_number_id}/messages` with a payload produced by one of the
    /// builders below. Returns the wamid Meta assigned.
    pub async fn send(&self, payload: Value) -> Result<SendResult> {
        let url = self.graph_url(&format!("{}/messages", self.creds.phone_number_id));
        let v = self.exec_json(self.http.post(&url).json(&payload)).await?;
        let wamid = v
            .get("messages")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|m| m.get("id"))
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                Error::Internal(anyhow!("cloud: send response without messages[0].id"))
            })?;
        let wa_id = v
            .get("contacts")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("wa_id"))
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(SendResult { wamid, wa_id })
    }

    /// `POST /{phone_number_id}/media` (multipart: `messaging_product`, `type`,
    /// `file`) → the media id to reference from a media/template payload.
    pub async fn upload_media(&self, bytes: Vec<u8>, mime: &str, filename: &str) -> Result<String> {
        let url = self.graph_url(&format!("{}/media", self.creds.phone_number_id));
        let name = if filename.trim().is_empty() {
            "file".to_string()
        } else {
            filename.to_string()
        };
        let part = reqwest::multipart::Part::bytes(bytes)
            .file_name(name)
            .mime_str(mime)
            .map_err(|e| Error::BadRequest(format!("cloud: invalid mime type {mime:?}: {e}")))?;
        let form = reqwest::multipart::Form::new()
            .text("messaging_product", "whatsapp")
            .text("type", mime.to_string())
            .part("file", part);
        let v = self
            .exec_json(
                self.http
                    .post(&url)
                    .timeout(Duration::from_secs(MEDIA_TIMEOUT_SECS))
                    .multipart(form),
            )
            .await?;
        str_of(&v, "id")
            .ok_or_else(|| Error::Internal(anyhow!("cloud: media upload response without id")))
    }

    /// `GET /{media_id}` → short-lived download URL + metadata. `media_id`
    /// must be a numeric Graph id (it is interpolated into the URL path and,
    /// for inbound media, originates from a webhook body).
    pub async fn media_info(&self, media_id: &str) -> Result<MediaInfo> {
        let media_id = media_id.trim();
        if !is_graph_id(media_id) {
            return Err(Error::BadRequest(format!(
                "cloud: invalid media id {media_id:?} (expected a numeric Graph id)"
            )));
        }
        let url = self.graph_url(media_id);
        let v = self
            .exec_json(
                self.http
                    .get(&url)
                    .query(&[("phone_number_id", self.creds.phone_number_id.as_str())]),
            )
            .await?;
        // Kapso returns both Meta's `url` (which still expects a Meta bearer
        // token) and its own short-lived `download_url`. Prefer the latter:
        // its credential is embedded in the URL and a Kapso session has no
        // Meta bearer token to use against the former.
        let dl = (self.creds.provider == CloudProvider::Kapso)
            .then(|| str_of(&v, "download_url"))
            .flatten()
            .or_else(|| str_of(&v, "url"))
            .ok_or_else(|| {
                Error::NotFound(format!("cloud: media {media_id} has no download url"))
            })?;
        Ok(MediaInfo {
            url: dl,
            mime_type: str_of(&v, "mime_type"),
            sha256: str_of(&v, "sha256"),
            file_size: v.get("file_size").and_then(u64_of),
        })
    }

    /// Is `url` a host we may send this session's credentials to when fetching
    /// media? Meta sessions: Meta-operated hosts only ([`is_meta_media_url`]).
    /// Kapso sessions: also the Kapso API host / `*.kapso.ai` (Kapso re-hosts
    /// inbound media and hands back a ready `media_url`).
    fn media_url_allowed(&self, url: &str) -> bool {
        if is_meta_media_url(url) {
            return true;
        }
        if self.creds.provider != CloudProvider::Kapso {
            return false;
        }
        let Ok(u) = reqwest::Url::parse(url) else {
            return false;
        };
        if u.scheme() != "https" {
            return false;
        }
        let Some(host) = u.host_str().map(|h| h.to_ascii_lowercase()) else {
            return false;
        };
        let base_host = reqwest::Url::parse(self.api_base())
            .ok()
            .and_then(|b| b.host_str().map(|h| h.to_ascii_lowercase()));
        host == "kapso.ai"
            || host.ends_with(".kapso.ai")
            || base_host.as_deref() == Some(host.as_str())
    }

    /// Download media bytes from a URL obtained via [`CloudClient::media_info`]
    /// (or the `url` carried in a webhook). The auth header is mandatory, so the
    /// URL must point at a host [`media_url_allowed`](Self::media_url_allowed)
    /// accepts — the credential is never sent anywhere else.
    pub async fn download(&self, url: &str) -> Result<Vec<u8>> {
        if !self.media_url_allowed(url) {
            return Err(Error::BadRequest(format!(
                "cloud: refusing to download media from an untrusted url ({})",
                url_host(url).unwrap_or_default()
            )));
        }
        // Kapso's `download_url` carries a short-lived credential in its
        // query string. Sending the project API key too is unnecessary and
        // some Kapso media endpoints reject that mixed authentication.
        let req = self
            .http
            .get(url)
            .timeout(Duration::from_secs(MEDIA_TIMEOUT_SECS));
        let req = if self.creds.provider == CloudProvider::Kapso && is_kapso_signed_media_url(url) {
            req
        } else {
            self.auth(req)
        };
        let resp = req
            .send()
            .await
            .map_err(|e| Error::Internal(anyhow!("cloud: media download failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Internal(anyhow!("cloud: media download read failed: {e}")))?;
        if !status.is_success() {
            return Err(map_graph_error(status.as_u16(), &body));
        }
        Ok(body.to_vec())
    }

    /// `GET /{waba_id}/message_templates?fields=id,name,language,status,category,components`.
    /// Requires `waba_id` (else `BadRequest`).
    pub async fn list_templates(
        &self,
        status: Option<&str>,
        limit: Option<u32>,
        after: Option<&str>,
    ) -> Result<TemplatePage> {
        let waba = self.waba_id()?;
        let url = self.graph_url(&format!("{waba}/message_templates"));
        let mut q: Vec<(&str, String)> = vec![(
            "fields",
            "id,name,language,status,category,components".to_string(),
        )];
        if let Some(s) = status.map(str::trim).filter(|s| !s.is_empty()) {
            q.push(("status", s.to_ascii_uppercase()));
        }
        if let Some(l) = limit {
            q.push(("limit", l.max(1).to_string()));
        }
        if let Some(a) = after.map(str::trim).filter(|s| !s.is_empty()) {
            q.push(("after", a.to_string()));
        }
        let v = self.exec_json(self.http.get(&url).query(&q)).await?;
        let templates = v
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let paging = v.get("paging");
        let has_next = paging
            .and_then(|p| p.get("next"))
            .and_then(Value::as_str)
            .is_some();
        let next = if has_next {
            paging
                .and_then(|p| p.get("cursors"))
                .and_then(|c| c.get("after"))
                .and_then(Value::as_str)
                .map(str::to_string)
        } else {
            None
        };
        Ok(TemplatePage { templates, next })
    }

    /// `POST /{waba_id}/message_templates` with a Cloud-native template
    /// definition (`{name, language, category, components, …}`). Returns the
    /// Graph response (`{id, status, category}`).
    pub async fn create_template(&self, body: Value) -> Result<Value> {
        let waba = self.waba_id()?;
        let url = self.graph_url(&format!("{waba}/message_templates"));
        self.exec_json(self.http.post(&url).json(&body)).await
    }

    /// `DELETE /{waba_id}/message_templates?name=…[&hsm_id=…]` — deletes every
    /// language of `name`, or a single one when `hsm_id` is given.
    pub async fn delete_template(&self, name: &str, hsm_id: Option<&str>) -> Result<()> {
        let waba = self.waba_id()?;
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::BadRequest("cloud: template name is required".into()));
        }
        let url = self.graph_url(&format!("{waba}/message_templates"));
        let mut q: Vec<(&str, &str)> = vec![("name", name)];
        if let Some(id) = hsm_id.map(str::trim).filter(|s| !s.is_empty()) {
            q.push(("hsm_id", id));
        }
        let v = self.exec_json(self.http.delete(&url).query(&q)).await?;
        if v.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(Error::Internal(anyhow!(
                "cloud: template delete reported success=false"
            )));
        }
        Ok(())
    }

    /// Mark an inbound message as read, optionally showing the 25 s typing
    /// indicator (see [`read_payload`]).
    pub async fn mark_read(&self, message_id: &str, typing: bool) -> Result<()> {
        let url = self.graph_url(&format!("{}/messages", self.creds.phone_number_id));
        let v = self
            .exec_json(self.http.post(&url).json(&read_payload(message_id, typing)))
            .await?;
        if v.get("success").and_then(Value::as_bool) == Some(false) {
            return Err(Error::Internal(anyhow!(
                "cloud: mark-read reported success=false"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Payload builders
// ---------------------------------------------------------------------------

/// Media kinds sendable through the Cloud API. `Ptt` is `audio` with
/// `voice: true` (renders as a voice note; must be OGG/OPUS).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Image,
    Video,
    Audio,
    Document,
    Sticker,
    /// Voice note: Graph `type: audio` + `audio.voice = true`.
    Ptt,
}

impl MediaKind {
    /// Graph `type` value (and media object key) for this kind.
    pub fn graph_type(self) -> &'static str {
        match self {
            MediaKind::Image => "image",
            MediaKind::Video => "video",
            MediaKind::Audio | MediaKind::Ptt => "audio",
            MediaKind::Document => "document",
            MediaKind::Sticker => "sticker",
        }
    }
}

/// Minimal neutral contact card used by [`contacts_payload`] and produced by
/// webhook parsing (`InboundKind::Contacts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactCard {
    pub name: String,
    #[serde(default)]
    pub phones: Vec<String>,
}

/// Header spec shared by template and interactive sends.
///
/// `type` ∈ `text | image | video | document`. Text headers need `text`;
/// media headers need `media_id` (uploaded asset) or `link` (public https URL);
/// documents may add `filename`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HeaderSpec {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub media_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filename: Option<String>,
}

/// One button parameter of a template send (`components[].type == "button"`).
///
/// `sub_type` ∈ `quick_reply` (needs `payload`), `url` (needs `text` = the
/// dynamic URL suffix), `copy_code` (needs `coupon_code`, `text` accepted as
/// alias).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TemplateButton {
    #[serde(default)]
    pub index: u32,
    pub sub_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_code: Option<String>,
}

/// Neutral request for `POST /messages/template` (minus `to`, which the API
/// layer passes separately). Mirrors PLAN §1.3.
///
/// * `body_params` — positional body parameters; strings/numbers become
///   `{"type":"text","text":…}`, objects are passed through verbatim (e.g.
///   `{"type":"currency",…}` or named `{"type":"text","parameter_name":…}`).
/// * `components` — escape hatch: a Cloud-native `components` array used
///   verbatim; when present `body_params` / `header` / `buttons` are ignored.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TemplateSend {
    pub name: String,
    pub language: String,
    #[serde(default)]
    pub body_params: Vec<Value>,
    #[serde(default)]
    pub header: Option<HeaderSpec>,
    #[serde(default)]
    pub buttons: Vec<TemplateButton>,
    #[serde(default)]
    pub components: Option<Vec<Value>>,
    #[serde(default)]
    pub reply_to: Option<String>,
}

/// Reply button of an interactive `button` message (≤3, title ≤20 chars).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InteractiveButton {
    pub id: String,
    pub title: String,
}

/// Row of an interactive `list` section.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InteractiveRow {
    pub id: String,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Section of an interactive `list` message.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct InteractiveSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default)]
    pub rows: Vec<InteractiveRow>,
}

/// Call-to-action of an interactive `cta_url` message.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CtaUrl {
    pub display_text: String,
    pub url: String,
}

/// Neutral request for `POST /messages/interactive` (minus `to`). Mirrors
/// PLAN §1.3: `type` ∈ `button | list | cta_url`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct InteractiveSend {
    #[serde(rename = "type")]
    pub kind: String,
    pub body: String,
    #[serde(default)]
    pub header: Option<HeaderSpec>,
    #[serde(default)]
    pub footer: Option<String>,
    /// `type = button`.
    #[serde(default)]
    pub buttons: Vec<InteractiveButton>,
    /// `type = list`: label of the button that opens the list (≤20 chars).
    #[serde(default)]
    pub button: Option<String>,
    /// `type = list`.
    #[serde(default)]
    pub sections: Vec<InteractiveSection>,
    /// `type = cta_url`.
    #[serde(default)]
    pub cta: Option<CtaUrl>,
    #[serde(default)]
    pub reply_to: Option<String>,
}

fn base_payload(to: &str, msg_type: &str, reply_to: Option<&str>) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("messaging_product".into(), json!("whatsapp"));
    m.insert("recipient_type".into(), json!("individual"));
    m.insert("to".into(), json!(to_digits(to)));
    if let Some(id) = reply_to.map(str::trim).filter(|s| !s.is_empty()) {
        m.insert("context".into(), json!({ "message_id": id }));
    }
    m.insert("type".into(), json!(msg_type));
    m
}

/// Text message. `preview_url` is set when the text carries an `http(s)://`
/// link (Graph previews the first one).
pub fn text_payload(to: &str, text: &str, reply_to: Option<&str>) -> Value {
    let preview = text.contains("http://") || text.contains("https://");
    let mut m = base_payload(to, "text", reply_to);
    m.insert(
        "text".into(),
        json!({ "preview_url": preview, "body": text }),
    );
    Value::Object(m)
}

/// Media message referencing an already-uploaded asset (`media_id`).
/// `caption` applies to image/video/document, `filename` to document only;
/// `MediaKind::Ptt` adds `voice: true`.
pub fn media_payload(
    to: &str,
    kind: MediaKind,
    media_id: &str,
    caption: Option<&str>,
    filename: Option<&str>,
    reply_to: Option<&str>,
) -> Value {
    let key = kind.graph_type();
    let mut obj = Map::new();
    obj.insert("id".into(), json!(media_id));
    match kind {
        MediaKind::Image | MediaKind::Video | MediaKind::Document => {
            if let Some(c) = caption.filter(|c| !c.is_empty()) {
                obj.insert("caption".into(), json!(c));
            }
        }
        MediaKind::Audio | MediaKind::Ptt | MediaKind::Sticker => {}
    }
    if kind == MediaKind::Document {
        if let Some(f) = filename.filter(|f| !f.is_empty()) {
            obj.insert("filename".into(), json!(f));
        }
    }
    if kind == MediaKind::Ptt {
        obj.insert("voice".into(), json!(true));
    }
    let mut m = base_payload(to, key, reply_to);
    m.insert(key.into(), Value::Object(obj));
    Value::Object(m)
}

/// Static location message.
pub fn location_payload(
    to: &str,
    lat: f64,
    lng: f64,
    name: Option<&str>,
    address: Option<&str>,
    reply_to: Option<&str>,
) -> Value {
    let mut loc = Map::new();
    loc.insert("latitude".into(), json!(lat));
    loc.insert("longitude".into(), json!(lng));
    if let Some(n) = name.filter(|s| !s.is_empty()) {
        loc.insert("name".into(), json!(n));
    }
    if let Some(a) = address.filter(|s| !s.is_empty()) {
        loc.insert("address".into(), json!(a));
    }
    let mut m = base_payload(to, "location", reply_to);
    m.insert("location".into(), Value::Object(loc));
    Value::Object(m)
}

/// Contact cards. Each phone becomes `{phone, type: "CELL", wa_id?}` where
/// `wa_id` is the digits of the phone (lets the recipient tap-to-chat).
pub fn contacts_payload(to: &str, contacts: &[ContactCard], reply_to: Option<&str>) -> Value {
    let cards: Vec<Value> = contacts
        .iter()
        .map(|c| {
            let phones: Vec<Value> = c
                .phones
                .iter()
                .filter(|p| !p.trim().is_empty())
                .map(|p| {
                    let digits = to_digits(p);
                    let mut ph = Map::new();
                    ph.insert("phone".into(), json!(p.trim()));
                    ph.insert("type".into(), json!("CELL"));
                    if !digits.is_empty() {
                        ph.insert("wa_id".into(), json!(digits));
                    }
                    Value::Object(ph)
                })
                .collect();
            json!({
                "name": { "formatted_name": c.name, "first_name": c.name },
                "phones": phones,
            })
        })
        .collect();
    let mut m = base_payload(to, "contacts", reply_to);
    m.insert("contacts".into(), Value::Array(cards));
    Value::Object(m)
}

/// Reaction to `message_id`; an empty `emoji` removes the reaction.
pub fn reaction_payload(to: &str, message_id: &str, emoji: &str) -> Value {
    let mut m = base_payload(to, "reaction", None);
    m.insert(
        "reaction".into(),
        json!({ "message_id": message_id, "emoji": emoji }),
    );
    Value::Object(m)
}

/// Mark-as-read payload; `typing` adds the `typing_indicator` (also marks read).
pub fn read_payload(message_id: &str, typing: bool) -> Value {
    let mut m = Map::new();
    m.insert("messaging_product".into(), json!("whatsapp"));
    m.insert("status".into(), json!("read"));
    m.insert("message_id".into(), json!(message_id));
    if typing {
        m.insert("typing_indicator".into(), json!({ "type": "text" }));
    }
    Value::Object(m)
}

/// Build the Graph media object for a header (`{"id":…}` / `{"link":…}` +
/// optional `filename` for documents).
fn header_media_object(h: &HeaderSpec, what: &str) -> Result<Value> {
    let mut obj = Map::new();
    match (
        h.media_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty()),
        h.link.as_deref().map(str::trim).filter(|s| !s.is_empty()),
    ) {
        (Some(id), _) => {
            obj.insert("id".into(), json!(id));
        }
        (None, Some(link)) => {
            obj.insert("link".into(), json!(link));
        }
        (None, None) => {
            return Err(Error::BadRequest(format!(
                "{what}: {} header needs media_id or link",
                h.kind
            )))
        }
    }
    if h.kind.trim().eq_ignore_ascii_case("document") {
        if let Some(f) = h.filename.as_deref().filter(|s| !s.is_empty()) {
            obj.insert("filename".into(), json!(f));
        }
    }
    Ok(Value::Object(obj))
}

/// Template `header` component from a [`HeaderSpec`].
fn template_header_component(h: &HeaderSpec) -> Result<Value> {
    let kind = h.kind.trim().to_ascii_lowercase();
    let param = match kind.as_str() {
        "text" => {
            let t = h
                .text
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::BadRequest("template: text header needs text".into()))?;
            json!({ "type": "text", "text": t })
        }
        "image" | "video" | "document" => {
            let media = header_media_object(h, "template")?;
            json!({ "type": kind, kind.clone(): media })
        }
        other => {
            return Err(Error::BadRequest(format!(
                "template: unsupported header type {other:?} (text|image|video|document)"
            )))
        }
    };
    Ok(json!({ "type": "header", "parameters": [param] }))
}

/// Template `button` component from a [`TemplateButton`].
fn template_button_component(b: &TemplateButton) -> Result<Value> {
    let sub = b.sub_type.trim().to_ascii_lowercase();
    let param = match sub.as_str() {
        "quick_reply" => {
            let p = b
                .payload
                .as_deref()
                .or(b.text.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    Error::BadRequest("template: quick_reply button needs payload".into())
                })?;
            json!({ "type": "payload", "payload": p })
        }
        "url" => {
            let t = b
                .text
                .as_deref()
                .or(b.payload.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::BadRequest("template: url button needs text".into()))?;
            json!({ "type": "text", "text": t })
        }
        "copy_code" => {
            let c = b
                .coupon_code
                .as_deref()
                .or(b.text.as_deref())
                .or(b.payload.as_deref())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    Error::BadRequest("template: copy_code button needs coupon_code".into())
                })?;
            json!({ "type": "coupon_code", "coupon_code": c })
        }
        other => {
            return Err(Error::BadRequest(format!(
                "template: unsupported button sub_type {other:?} (quick_reply|url|copy_code)"
            )))
        }
    };
    Ok(json!({
        "type": "button",
        "sub_type": sub,
        "index": b.index.to_string(),
        "parameters": [param],
    }))
}

/// Template message. Components are built from `header` / `body_params` /
/// `buttons` unless `req.components` is given (used verbatim).
pub fn template_payload(to: &str, req: &TemplateSend) -> Result<Value> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(Error::BadRequest("template: name is required".into()));
    }
    let lang = req.language.trim();
    if lang.is_empty() {
        return Err(Error::BadRequest("template: language is required".into()));
    }
    let components: Vec<Value> = match &req.components {
        Some(c) => c.clone(),
        None => {
            let mut out = Vec::new();
            if let Some(h) = &req.header {
                out.push(template_header_component(h)?);
            }
            if !req.body_params.is_empty() {
                let params: Vec<Value> = req
                    .body_params
                    .iter()
                    .map(|p| match p {
                        Value::Object(_) => p.clone(),
                        Value::String(s) => json!({ "type": "text", "text": s }),
                        Value::Null => json!({ "type": "text", "text": "" }),
                        other => json!({ "type": "text", "text": other.to_string() }),
                    })
                    .collect();
                out.push(json!({ "type": "body", "parameters": params }));
            }
            for b in &req.buttons {
                out.push(template_button_component(b)?);
            }
            out
        }
    };
    let mut tpl = Map::new();
    tpl.insert("name".into(), json!(name));
    tpl.insert("language".into(), json!({ "code": lang }));
    if !components.is_empty() {
        tpl.insert("components".into(), Value::Array(components));
    }
    let mut m = base_payload(to, "template", req.reply_to.as_deref());
    m.insert("template".into(), Value::Object(tpl));
    Ok(Value::Object(m))
}

const MAX_REPLY_BUTTONS: usize = 3;
const MAX_BUTTON_TITLE: usize = 20;
const MAX_BUTTON_ID: usize = 256;
const MAX_LIST_SECTIONS: usize = 10;
const MAX_LIST_ROWS: usize = 10;
const MAX_LIST_BUTTON: usize = 20;
const MAX_ROW_TITLE: usize = 24;
const MAX_ROW_DESCRIPTION: usize = 72;
const MAX_SECTION_TITLE: usize = 24;
const MAX_HEADER_TEXT: usize = 60;
const MAX_FOOTER_TEXT: usize = 60;
const MAX_BODY_BUTTON: usize = 1024;
const MAX_BODY_LIST: usize = 4096;

fn chars(s: &str) -> usize {
    s.chars().count()
}

/// Interactive `header` object from a [`HeaderSpec`].
fn interactive_header(h: &HeaderSpec, list: bool) -> Result<Value> {
    let kind = h.kind.trim().to_ascii_lowercase();
    match kind.as_str() {
        "text" => {
            let t = h
                .text
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error::BadRequest("interactive: text header needs text".into()))?;
            if chars(t) > MAX_HEADER_TEXT {
                return Err(Error::BadRequest(format!(
                    "interactive: header text exceeds {MAX_HEADER_TEXT} chars"
                )));
            }
            Ok(json!({ "type": "text", "text": t }))
        }
        "image" | "video" | "document" if !list => {
            let media = header_media_object(h, "interactive")?;
            Ok(json!({ "type": kind, kind.clone(): media }))
        }
        "image" | "video" | "document" => Err(Error::BadRequest(
            "interactive: list messages only support text headers".into(),
        )),
        other => Err(Error::BadRequest(format!(
            "interactive: unsupported header type {other:?} (text|image|video|document)"
        ))),
    }
}

/// Interactive message (`button` / `list` / `cta_url`) with Graph limit
/// validation (≤3 reply buttons, titles ≤20 chars; ≤10 sections and ≤10 rows
/// total; `cta_url` needs `display_text` + `url`).
pub fn interactive_payload(to: &str, req: &InteractiveSend) -> Result<Value> {
    let kind = req.kind.trim().to_ascii_lowercase();
    let body = req.body.trim();
    if body.is_empty() {
        return Err(Error::BadRequest("interactive: body is required".into()));
    }
    let mut inter = Map::new();
    inter.insert("type".into(), json!(kind));
    let is_list = kind == "list";
    if let Some(h) = &req.header {
        inter.insert("header".into(), interactive_header(h, is_list)?);
    }
    let body_max = if is_list {
        MAX_BODY_LIST
    } else {
        MAX_BODY_BUTTON
    };
    if chars(body) > body_max {
        return Err(Error::BadRequest(format!(
            "interactive: body exceeds {body_max} chars"
        )));
    }
    inter.insert("body".into(), json!({ "text": body }));
    if let Some(f) = req
        .footer
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if chars(f) > MAX_FOOTER_TEXT {
            return Err(Error::BadRequest(format!(
                "interactive: footer exceeds {MAX_FOOTER_TEXT} chars"
            )));
        }
        inter.insert("footer".into(), json!({ "text": f }));
    }
    let action = match kind.as_str() {
        "button" => {
            if req.buttons.is_empty() {
                return Err(Error::BadRequest(
                    "interactive: button message needs at least one button".into(),
                ));
            }
            if req.buttons.len() > MAX_REPLY_BUTTONS {
                return Err(Error::BadRequest(format!(
                    "interactive: at most {MAX_REPLY_BUTTONS} buttons allowed"
                )));
            }
            let mut buttons = Vec::with_capacity(req.buttons.len());
            for b in &req.buttons {
                let id = b.id.trim();
                let title = b.title.trim();
                if id.is_empty() || title.is_empty() {
                    return Err(Error::BadRequest(
                        "interactive: every button needs id and title".into(),
                    ));
                }
                if chars(title) > MAX_BUTTON_TITLE {
                    return Err(Error::BadRequest(format!(
                        "interactive: button title {title:?} exceeds {MAX_BUTTON_TITLE} chars"
                    )));
                }
                if chars(id) > MAX_BUTTON_ID {
                    return Err(Error::BadRequest(format!(
                        "interactive: button id exceeds {MAX_BUTTON_ID} chars"
                    )));
                }
                buttons.push(json!({ "type": "reply", "reply": { "id": id, "title": title } }));
            }
            json!({ "buttons": buttons })
        }
        "list" => {
            let button = req
                .button
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    Error::BadRequest("interactive: list message needs `button` text".into())
                })?;
            if chars(button) > MAX_LIST_BUTTON {
                return Err(Error::BadRequest(format!(
                    "interactive: list button text exceeds {MAX_LIST_BUTTON} chars"
                )));
            }
            if req.sections.is_empty() {
                return Err(Error::BadRequest(
                    "interactive: list message needs at least one section".into(),
                ));
            }
            if req.sections.len() > MAX_LIST_SECTIONS {
                return Err(Error::BadRequest(format!(
                    "interactive: at most {MAX_LIST_SECTIONS} sections allowed"
                )));
            }
            let mut total_rows = 0usize;
            let mut sections = Vec::with_capacity(req.sections.len());
            for s in &req.sections {
                if s.rows.is_empty() {
                    return Err(Error::BadRequest(
                        "interactive: every list section needs at least one row".into(),
                    ));
                }
                let mut sec = Map::new();
                if let Some(t) = s.title.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    if chars(t) > MAX_SECTION_TITLE {
                        return Err(Error::BadRequest(format!(
                            "interactive: section title exceeds {MAX_SECTION_TITLE} chars"
                        )));
                    }
                    sec.insert("title".into(), json!(t));
                }
                let mut rows = Vec::with_capacity(s.rows.len());
                for r in &s.rows {
                    total_rows += 1;
                    if total_rows > MAX_LIST_ROWS {
                        return Err(Error::BadRequest(format!(
                            "interactive: at most {MAX_LIST_ROWS} rows allowed across all sections"
                        )));
                    }
                    let id = r.id.trim();
                    let title = r.title.trim();
                    if id.is_empty() || title.is_empty() {
                        return Err(Error::BadRequest(
                            "interactive: every list row needs id and title".into(),
                        ));
                    }
                    if chars(title) > MAX_ROW_TITLE {
                        return Err(Error::BadRequest(format!(
                            "interactive: row title {title:?} exceeds {MAX_ROW_TITLE} chars"
                        )));
                    }
                    let mut row = Map::new();
                    row.insert("id".into(), json!(id));
                    row.insert("title".into(), json!(title));
                    if let Some(d) = r
                        .description
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        if chars(d) > MAX_ROW_DESCRIPTION {
                            return Err(Error::BadRequest(format!(
                                "interactive: row description exceeds {MAX_ROW_DESCRIPTION} chars"
                            )));
                        }
                        row.insert("description".into(), json!(d));
                    }
                    rows.push(Value::Object(row));
                }
                sec.insert("rows".into(), Value::Array(rows));
                sections.push(Value::Object(sec));
            }
            json!({ "button": button, "sections": sections })
        }
        "cta_url" => {
            let cta = req.cta.as_ref().ok_or_else(|| {
                Error::BadRequest("interactive: cta_url message needs `cta`".into())
            })?;
            let text = cta.display_text.trim();
            let url = cta.url.trim();
            if text.is_empty() || url.is_empty() {
                return Err(Error::BadRequest(
                    "interactive: cta needs display_text and url".into(),
                ));
            }
            if chars(text) > MAX_BUTTON_TITLE {
                return Err(Error::BadRequest(format!(
                    "interactive: cta display_text exceeds {MAX_BUTTON_TITLE} chars"
                )));
            }
            json!({ "name": "cta_url", "parameters": { "display_text": text, "url": url } })
        }
        other => {
            return Err(Error::BadRequest(format!(
                "interactive: unsupported type {other:?} (button|list|cta_url)"
            )))
        }
    };
    inter.insert("action".into(), action);
    let mut m = base_payload(to, "interactive", req.reply_to.as_deref());
    m.insert("interactive".into(), Value::Object(inter));
    Ok(Value::Object(m))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reduce a JID / phone number to bare digits: `"5511999999999@s.whatsapp.net"`,
/// `"5511999999999:12@s.whatsapp.net"`, `"5511999999999@lid"`,
/// `"+55 (11) 99999-9999"` all → `"5511999999999"`.
pub fn to_digits(jid_or_number: &str) -> String {
    let user = jid_or_number.split('@').next().unwrap_or("");
    let user = user.split(':').next().unwrap_or("");
    user.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// `"<digits>@s.whatsapp.net"` for a phone number (input is normalized with
/// [`to_digits`] first, so passing a full JID is harmless).
pub fn to_jid(digits: &str) -> String {
    format!("{}@s.whatsapp.net", to_digits(digits))
}

/// Validate a cloud send recipient BEFORE it is digit-stripped by
/// [`to_digits`]: the Cloud API addresses phone numbers only, so a JID on any
/// server other than the user server (`@lid`, `@g.us`, `@broadcast`,
/// `@newsletter`, …) must be refused rather than silently rewritten into a
/// syntactically valid — but unrelated — E.164 number. Returns the digits.
pub fn check_recipient(to: &str) -> Result<String> {
    let t = to.trim();
    if let Some((_, server)) = t.split_once('@') {
        if !matches!(server, "s.whatsapp.net" | "c.us") {
            return Err(Error::BadRequest(format!(
                "cloud sessions can only address phone numbers (got a @{server} id); \
                 pass an E.164 number or a <number>@s.whatsapp.net jid"
            )));
        }
    }
    let digits = to_digits(t);
    if digits.is_empty() {
        return Err(Error::BadRequest(
            "cloud: recipient must contain a phone number".into(),
        ));
    }
    Ok(digits)
}

/// Whether `s` looks like a Graph node id (`phone_number_id`, `waba_id`,
/// media id, template id): non-empty ASCII digits only. These are interpolated
/// into Graph URL paths, so anything else is refused.
pub fn is_graph_id(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `v` is a well-formed Graph API version (`v25.0`).
pub fn is_graph_version(v: &str) -> bool {
    let Some(rest) = v.strip_prefix('v') else {
        return false;
    };
    let Some((major, minor)) = rest.split_once('.') else {
        return false;
    };
    is_graph_id(major) && is_graph_id(minor)
}

/// Host part of an absolute URL (lower-cased), if it parses.
fn url_host(url: &str) -> Option<String> {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
}

/// Kapso's short-lived `download_url` embeds its authorization as a `token`
/// query parameter. It must be fetched as-is, without adding `X-API-Key`.
fn is_kapso_signed_media_url(url: &str) -> bool {
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    let Some(host) = u.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    (host == "kapso.ai" || host.ends_with(".kapso.ai"))
        && u.query_pairs()
            .any(|(key, value)| key == "token" && !value.is_empty())
}

/// Whether a media download URL points at a Meta-operated host over HTTPS —
/// the only places the session's bearer token may be sent. Meta serves
/// media from `lookaside.fbsbx.com`, `mmg.whatsapp.net`, `*.fbcdn.net` and
/// `graph.facebook.com`.
pub fn is_meta_media_url(url: &str) -> bool {
    const SUFFIXES: [&str; 6] = [
        "facebook.com",
        "fbcdn.net",
        "fbsbx.com",
        "whatsapp.net",
        "whatsapp.com",
        "meta.com",
    ];
    let Ok(u) = reqwest::Url::parse(url) else {
        return false;
    };
    if u.scheme() != "https" {
        return false;
    }
    let Some(host) = u.host_str().map(|h| h.to_ascii_lowercase()) else {
        return false;
    };
    SUFFIXES
        .iter()
        .any(|suf| host == *suf || host.ends_with(&format!(".{suf}")))
}

/// Hex-encoded HMAC-SHA256 of `msg` under `key`.
pub fn hmac_sha256_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

/// Verify Meta's `X-Hub-Signature-256: sha256=<hex>` header over the RAW
/// request body (constant-time compare). `false` on a missing or malformed
/// header.
pub fn verify_signature(app_secret: &str, raw_body: &[u8], header_value: Option<&str>) -> bool {
    let Some(header) = header_value.map(str::trim) else {
        return false;
    };
    let Some(hex_sig) = header
        .strip_prefix("sha256=")
        .or_else(|| header.strip_prefix("SHA256="))
    else {
        return false;
    };
    let Ok(sig) = hex::decode(hex_sig.trim()) else {
        return false;
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(raw_body);
    mac.verify_slice(&sig).is_ok()
}

fn str_of(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| match x {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })
}

fn f64_of(v: &Value) -> Option<f64> {
    v.as_f64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn i64_of(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_f64().map(|f| f as i64))
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

fn u64_of(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Seconds in the WhatsApp customer-service window.
pub(crate) const CS_WINDOW_SECS: i64 = 24 * 3600;

/// `v[key]` as an RFC-3339 timestamp → unix seconds (e.g. Kapso's
/// `"2025-10-28T17:25:01.000000Z"`).
fn rfc3339_secs(v: &Value, key: &str) -> Option<i64> {
    let s = v.get(key).and_then(Value::as_str)?.trim();
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.timestamp())
}

// ---------------------------------------------------------------------------
// Webhook parsing
// ---------------------------------------------------------------------------

/// One `entry[].changes[]` with `field == "messages"`, normalized.
#[derive(Debug, Clone, Default)]
pub struct WebhookBatch {
    /// `value.metadata.phone_number_id` — routes the batch to a session.
    pub phone_number_id: String,
    pub display_phone_number: Option<String>,
    pub messages: Vec<InboundMessage>,
    pub statuses: Vec<StatusUpdate>,
    /// `value.errors[]` (account / system level), passed through verbatim.
    pub errors: Vec<Value>,
    /// Unix seconds when this conversation's 24 h customer-service window
    /// closes, when the provider reports it: Meta's
    /// `statuses[].conversation.expiration_timestamp`, or Kapso's
    /// `conversation.kapso.last_inbound_at + 24 h`. `None` = not in this batch —
    /// callers fall back to (latest inbound message timestamp + 24 h).
    pub window_expires_at: Option<i64>,
    /// Kapso only: business-originated messages echoed on an outbound webhook
    /// that ruwa did not send itself. The Meta parser never populates this.
    pub outbound: Vec<OutboundEcho>,
}

/// A user → business message from `value.messages[]`.
#[derive(Debug, Clone)]
pub struct InboundMessage {
    pub wamid: String,
    /// Sender phone digits (`from`, falling back to `contacts[].wa_id`, then to
    /// the BSUID `from_user_id` when Meta omits the phone number entirely).
    pub from: String,
    /// Business-scoped user id (BSUID), when present.
    pub from_user_id: Option<String>,
    /// Unix seconds.
    pub timestamp: i64,
    /// `contacts[].profile.name` — the sender's push name.
    pub push_name: Option<String>,
    /// `contacts[].wa_id` for this sender.
    pub wa_id: Option<String>,
    pub kind: InboundKind,
    /// `context.id` — the quoted message when the user replied.
    pub context_id: Option<String>,
    /// The original `messages[i]` object.
    pub raw: Value,
}

/// Normalized inbound message content.
#[derive(Debug, Clone, PartialEq)]
pub enum InboundKind {
    Text {
        body: String,
    },
    Media {
        /// `image | video | audio | ptt | document | sticker`
        /// (`audio` with `voice: true` → `ptt`).
        msg_type: &'static str,
        media_id: String,
        mime: Option<String>,
        sha256: Option<String>,
        caption: Option<String>,
        filename: Option<String>,
        /// Direct download URL when Meta includes one (bearer still required).
        url: Option<String>,
        voice: bool,
    },
    Location {
        latitude: f64,
        longitude: f64,
        name: Option<String>,
        address: Option<String>,
    },
    Contacts(Vec<ContactCard>),
    Reaction {
        message_id: String,
        /// `None` = reaction removed.
        emoji: Option<String>,
    },
    /// Template quick-reply tap.
    Button {
        payload: Option<String>,
        text: Option<String>,
    },
    /// Interactive reply: `kind` ∈ `button_reply | list_reply`.
    Interactive {
        kind: String,
        id: String,
        title: Option<String>,
        description: Option<String>,
    },
    /// `order`, `system`, `unsupported`, `edit`, `revoke`, … — see `raw`.
    Unknown {
        type_name: String,
    },
}

/// A delivery status for a business → user message from `value.statuses[]`.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusUpdate {
    pub wamid: String,
    /// Recipient phone digits (`recipient_id`).
    pub recipient: String,
    /// `sent | delivered | read | failed` (`played` is folded into `read`).
    pub status: String,
    /// Unix seconds.
    pub timestamp: i64,
    /// `"<code>: <title>[ — <details>]"` from `errors[0]` (failed statuses).
    pub error: Option<String>,
}

/// A business → user message echoed back on a Kapso `whatsapp.message.sent`
/// webhook (`message.kapso.direction == "outbound"`). Covers sends ruwa did
/// NOT originate: typed in the WhatsApp Business App (`origin: business_app`)
/// or dispatched by another system against the same number.
#[derive(Debug, Clone)]
pub struct OutboundEcho {
    /// Meta's `wamid.…` — correlates with `statuses[]` in the same batch and
    /// with later standalone `whatsapp.message.{delivered,read}` webhooks.
    pub wamid: String,
    /// Recipient phone digits (`message.to`).
    pub to: String,
    pub timestamp: i64,
    pub kind: InboundKind,
    /// Raw `message` object, kept for `InboundKind::Unknown` passthrough.
    pub raw: Value,
}

/// Parse a raw Meta webhook POST body into normalized batches — one per
/// `entry[].changes[]` whose `field == "messages"`. Unknown fields are
/// ignored; other change fields (`message_template_status_update`, …) are
/// skipped. Returns `BadRequest` only when the body is not JSON.
pub fn parse_webhook(raw: &[u8]) -> Result<Vec<WebhookBatch>> {
    let root: Value = serde_json::from_slice(raw)
        .map_err(|e| Error::BadRequest(format!("cloud webhook: invalid json: {e}")))?;
    let mut out = Vec::new();
    let Some(entries) = root.get("entry").and_then(Value::as_array) else {
        return Ok(out);
    };
    for entry in entries {
        let Some(changes) = entry.get("changes").and_then(Value::as_array) else {
            continue;
        };
        for change in changes {
            let field = change.get("field").and_then(Value::as_str).unwrap_or("");
            if field != "messages" {
                tracing::debug!(field, "cloud webhook: ignoring non-messages change");
                continue;
            }
            let Some(value) = change.get("value") else {
                continue;
            };
            let Some(pnid) = value
                .get("metadata")
                .and_then(|m| str_of(m, "phone_number_id"))
                .filter(|s| !s.is_empty())
            else {
                tracing::warn!("cloud webhook: messages change without metadata.phone_number_id");
                continue;
            };
            let display_phone_number = value
                .get("metadata")
                .and_then(|m| str_of(m, "display_phone_number"));
            let contacts: Vec<&Value> = value
                .get("contacts")
                .and_then(Value::as_array)
                .map(|a| a.iter().collect())
                .unwrap_or_default();
            let messages = value
                .get("messages")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|m| parse_inbound_message(m, &contacts))
                        .collect()
                })
                .unwrap_or_default();
            let status_arr = value.get("statuses").and_then(Value::as_array);
            let statuses = status_arr
                .map(|a| a.iter().filter_map(parse_status).collect())
                .unwrap_or_default();
            // Meta reports the window close on status webhooks
            // (`statuses[].conversation.expiration_timestamp`, unix seconds).
            let window_expires_at = status_arr
                .into_iter()
                .flatten()
                .filter_map(|s| s.get("conversation").and_then(|c| i64_of(c.get("expiration_timestamp")?)))
                .max();
            let errors = value
                .get("errors")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            out.push(WebhookBatch {
                phone_number_id: pnid,
                display_phone_number,
                messages,
                statuses,
                errors,
                window_expires_at,
                outbound: Vec::new(),
            });
        }
    }
    Ok(out)
}

fn parse_media_kind(m: &Value, type_name: &str) -> Option<InboundKind> {
    let obj = m.get(type_name)?;
    let voice = obj.get("voice").and_then(Value::as_bool).unwrap_or(false);
    let msg_type: &'static str = match type_name {
        "image" => "image",
        "video" => "video",
        "audio" if voice => "ptt",
        "audio" => "audio",
        "document" => "document",
        "sticker" => "sticker",
        _ => return None,
    };
    Some(InboundKind::Media {
        msg_type,
        media_id: str_of(obj, "id").unwrap_or_default(),
        mime: str_of(obj, "mime_type"),
        sha256: str_of(obj, "sha256"),
        caption: str_of(obj, "caption"),
        filename: str_of(obj, "filename"),
        url: str_of(obj, "url"),
        voice,
    })
}

fn parse_contact_card(c: &Value) -> ContactCard {
    let name_obj = c.get("name");
    let name = name_obj
        .and_then(|n| str_of(n, "formatted_name"))
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            name_obj.map(|n| {
                ["first_name", "middle_name", "last_name"]
                    .iter()
                    .filter_map(|k| str_of(n, k))
                    .filter(|s| !s.trim().is_empty())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_default();
    let phones = c
        .get("phones")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|p| str_of(p, "phone").or_else(|| str_of(p, "wa_id")))
                .filter(|s| !s.trim().is_empty())
                .collect()
        })
        .unwrap_or_default();
    ContactCard { name, phones }
}

fn parse_inbound_kind(m: &Value, type_name: &str) -> InboundKind {
    match type_name {
        "text" => InboundKind::Text {
            body: m
                .get("text")
                .and_then(|t| str_of(t, "body"))
                .unwrap_or_default(),
        },
        "image" | "video" | "audio" | "document" | "sticker" => parse_media_kind(m, type_name)
            .unwrap_or(InboundKind::Unknown {
                type_name: type_name.to_string(),
            }),
        "location" => {
            let loc = m.get("location").cloned().unwrap_or(Value::Null);
            InboundKind::Location {
                latitude: loc.get("latitude").and_then(f64_of).unwrap_or(0.0),
                longitude: loc.get("longitude").and_then(f64_of).unwrap_or(0.0),
                name: str_of(&loc, "name"),
                address: str_of(&loc, "address"),
            }
        }
        "contacts" => InboundKind::Contacts(
            m.get("contacts")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(parse_contact_card).collect())
                .unwrap_or_default(),
        ),
        "reaction" => {
            let r = m.get("reaction").cloned().unwrap_or(Value::Null);
            InboundKind::Reaction {
                message_id: str_of(&r, "message_id").unwrap_or_default(),
                emoji: str_of(&r, "emoji").filter(|e| !e.is_empty()),
            }
        }
        "button" => {
            let b = m.get("button").cloned().unwrap_or(Value::Null);
            InboundKind::Button {
                payload: str_of(&b, "payload"),
                text: str_of(&b, "text"),
            }
        }
        "interactive" => {
            let i = m.get("interactive").cloned().unwrap_or(Value::Null);
            let kind = str_of(&i, "type").unwrap_or_default();
            let inner = i.get(kind.as_str());
            match (kind.as_str(), inner) {
                ("button_reply" | "list_reply", Some(inner)) => InboundKind::Interactive {
                    kind,
                    id: str_of(inner, "id").unwrap_or_default(),
                    title: str_of(inner, "title"),
                    description: str_of(inner, "description"),
                },
                _ => InboundKind::Unknown {
                    type_name: if kind.is_empty() {
                        "interactive".to_string()
                    } else {
                        format!("interactive/{kind}")
                    },
                },
            }
        }
        other => InboundKind::Unknown {
            type_name: if other.is_empty() {
                "unknown".to_string()
            } else {
                other.to_string()
            },
        },
    }
}

/// Overlay Kapso's ready media URL + file metadata (carried on `message.kapso`,
/// not the type sub-object) onto a freshly parsed `InboundKind::Media`.
fn overlay_kapso_media(kind: &mut InboundKind, kapso: Option<&Value>) {
    let InboundKind::Media { url, mime, filename, .. } = kind else {
        return;
    };
    if url.is_none() {
        *url = kapso
            .and_then(|k| str_of(k, "download_url"))
            .or_else(|| kapso.and_then(|k| str_of(k, "media_url")));
    }
    if let Some(md) = kapso.and_then(|k| k.get("media_data")) {
        if url.is_none() {
            *url = str_of(md, "download_url").or_else(|| str_of(md, "url"));
        }
        if mime.is_none() {
            *mime = str_of(md, "content_type");
        }
        if filename.is_none() {
            *filename = str_of(md, "filename");
        }
    }
}

fn parse_inbound_message(m: &Value, contacts: &[&Value]) -> Option<InboundMessage> {
    let wamid = str_of(m, "id").filter(|s| !s.is_empty())?;
    let from_raw = str_of(m, "from").filter(|s| !s.trim().is_empty());
    let from_user_id_msg = str_of(m, "from_user_id");
    // Match the sender against contacts[]: by `wa_id == from` digits, or —
    // when Meta hides the phone number (BSUID era) — by `user_id ==
    // from_user_id`. Only a single-contact batch may fall back to that one
    // contact; with several contacts and no match we don't guess (a wrong
    // guess would misattribute chat + push_name to another sender).
    let from_digits = from_raw.as_deref().map(to_digits).unwrap_or_default();
    let contact = contacts
        .iter()
        .find(|c| {
            let by_wa_id = str_of(c, "wa_id")
                .map(|w| !from_digits.is_empty() && to_digits(&w) == from_digits)
                .unwrap_or(false);
            let by_user_id = match (str_of(c, "user_id"), from_user_id_msg.as_deref()) {
                (Some(u), Some(f)) => !u.trim().is_empty() && u.trim() == f.trim(),
                _ => false,
            };
            by_wa_id || by_user_id
        })
        .or_else(|| if contacts.len() == 1 { contacts.first() } else { None })
        .copied();
    let wa_id = contact.and_then(|c| str_of(c, "wa_id"));
    let push_name = contact
        .and_then(|c| c.get("profile"))
        .and_then(|p| str_of(p, "name"))
        .filter(|s| !s.trim().is_empty());
    let from_user_id = from_user_id_msg.or_else(|| contact.and_then(|c| str_of(c, "user_id")));
    let from = if !from_digits.is_empty() {
        from_digits
    } else if let Some(w) = wa_id.as_deref().map(to_digits).filter(|s| !s.is_empty()) {
        w
    } else {
        from_user_id.clone().unwrap_or_default()
    };
    let timestamp = m
        .get("timestamp")
        .and_then(i64_of)
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let type_name = str_of(m, "type").unwrap_or_default();
    let kind = parse_inbound_kind(m, &type_name);
    let context_id = m
        .get("context")
        .and_then(|c| str_of(c, "id"))
        .filter(|s| !s.is_empty());
    Some(InboundMessage {
        wamid,
        from,
        from_user_id,
        timestamp,
        push_name,
        wa_id,
        kind,
        context_id,
        raw: m.clone(),
    })
}

/// `"<code>: <title>[ — <details>]"` for one Graph error entry.
fn format_error_entry(e: &Value) -> String {
    let code = str_of(e, "code").unwrap_or_else(|| "?".into());
    let title = str_of(e, "title")
        .or_else(|| str_of(e, "message"))
        .unwrap_or_else(|| "error".into());
    let details = e
        .get("error_data")
        .and_then(|d| str_of(d, "details"))
        .filter(|s| !s.trim().is_empty());
    match details {
        Some(d) => format!("{code}: {title} — {d}"),
        None => format!("{code}: {title}"),
    }
}

fn parse_status(s: &Value) -> Option<StatusUpdate> {
    let wamid = str_of(s, "id").filter(|s| !s.is_empty())?;
    let recipient = str_of(s, "recipient_id")
        .map(|r| to_digits(&r))
        .filter(|r| !r.is_empty())
        .or_else(|| str_of(s, "recipient_user_id"))
        .unwrap_or_default();
    let mut status = str_of(s, "status").unwrap_or_default().to_ascii_lowercase();
    if status == "played" {
        status = "read".to_string();
    }
    let timestamp = s
        .get("timestamp")
        .and_then(i64_of)
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let error = s
        .get("errors")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .map(format_error_entry);
    Some(StatusUpdate {
        wamid,
        recipient,
        status,
        timestamp,
        error,
    })
}

// ---------------------------------------------------------------------------
// Kapso webhook parsing (native envelope)
// ---------------------------------------------------------------------------
// `verify_kapso_signature` / `parse_kapso_webhook` are wired into the HTTP
// layer by WP-F (`POST /v1/cloud/kapso/webhook`).

/// Verify Kapso's `X-Webhook-Signature` header (hex HMAC-SHA256 of the RAW
/// request body under the per-number `secret_key`; constant-time). Accepts the
/// bare hex or a `sha256=` prefix. `false` on a missing / malformed header.
pub fn verify_kapso_signature(secret: &str, raw_body: &[u8], header_value: Option<&str>) -> bool {
    let Some(header) = header_value.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let hex_sig = header
        .strip_prefix("sha256=")
        .or_else(|| header.strip_prefix("SHA256="))
        .unwrap_or(header)
        .trim();
    let Ok(sig) = hex::decode(hex_sig) else {
        return false;
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac accepts any key length");
    mac.update(raw_body);
    mac.verify_slice(&sig).is_ok()
}

/// Parse a Kapso native message webhook body (`whatsapp.message.received` and the
/// `whatsapp.message.{sent,delivered,read,failed}` status events) into the same
/// normalized [`WebhookBatch`] vec the Meta parser produces — so `cloud_ingest`
/// is shared. Handles the buffered `{ "batch": true, "data": [ … ] }` envelope
/// and a single top-level item alike. Returns `BadRequest` only when the body is
/// not JSON; anything unrecognized yields an empty vec.
pub fn parse_kapso_webhook(raw: &[u8]) -> Result<Vec<WebhookBatch>> {
    let root: Value = serde_json::from_slice(raw)
        .map_err(|e| Error::BadRequest(format!("kapso webhook: invalid json: {e}")))?;
    let items: Vec<&Value> = if root.get("batch").and_then(Value::as_bool) == Some(true) {
        root.get("data")
            .and_then(Value::as_array)
            .map(|a| a.iter().collect())
            .unwrap_or_default()
    } else if root.get("message").is_some() {
        vec![&root]
    } else {
        tracing::debug!("kapso webhook: body has neither `message` nor a `data` batch");
        Vec::new()
    };
    Ok(items.into_iter().filter_map(kapso_item_to_batch).collect())
}

/// One `{ message, conversation, is_new_conversation, phone_number_id }` item →
/// a single-element `WebhookBatch` (inbound message OR that message's status
/// updates, keyed by `phone_number_id`).
fn kapso_item_to_batch(item: &Value) -> Option<WebhookBatch> {
    let msg = item.get("message")?;
    let convo = item.get("conversation");
    let pnid = str_of(item, "phone_number_id")
        .or_else(|| convo.and_then(|c| str_of(c, "phone_number_id")))
        .filter(|s| !s.is_empty())?;
    let kapso = msg.get("kapso");
    let direction = kapso
        .and_then(|k| str_of(k, "direction"))
        .unwrap_or_default();

    let mut batch = WebhookBatch {
        phone_number_id: pnid,
        display_phone_number: convo.and_then(|c| str_of(c, "phone_number")),
        // Kapso gives `conversation.kapso.last_inbound_at`; the window closes
        // 24 h after the customer's last inbound.
        window_expires_at: convo
            .and_then(|c| c.get("kapso"))
            .and_then(|k| rfc3339_secs(k, "last_inbound_at"))
            .map(|t| t + CS_WINDOW_SECS),
        ..Default::default()
    };

    if direction == "outbound" {
        // Status event — `message.kapso.statuses[]` has Meta's exact shape.
        if let Some(arr) = kapso.and_then(|k| k.get("statuses")).and_then(Value::as_array) {
            batch.statuses = arr.iter().filter_map(parse_status).collect();
        }
        if batch.statuses.is_empty() {
            // Fall back to the single `message.kapso.status` + top-level ids.
            if let (Some(st), Some(id)) = (
                kapso.and_then(|k| str_of(k, "status")),
                str_of(msg, "id").filter(|s| !s.is_empty()),
            ) {
                let mut status = st.to_ascii_lowercase();
                if status == "played" {
                    status = "read".into();
                }
                batch.statuses.push(StatusUpdate {
                    wamid: id,
                    recipient: str_of(msg, "to").map(|r| to_digits(&r)).unwrap_or_default(),
                    status,
                    timestamp: msg
                        .get("timestamp")
                        .and_then(i64_of)
                        .unwrap_or_else(|| chrono::Utc::now().timestamp()),
                    error: kapso
                        .and_then(|k| k.get("errors"))
                        .and_then(Value::as_array)
                        .and_then(|a| a.first())
                        .map(format_error_entry),
                });
            }
        }
        // Also surface the message body when the echo carries content (a
        // `whatsapp.message.sent` for a Business-App / external send). A bare
        // status-only echo has no usable `type` — skip those.
        let type_name = str_of(msg, "type").unwrap_or_default();
        if let Some(id) = str_of(msg, "id").filter(|s| !s.is_empty()) {
            if !type_name.is_empty() {
                let mut kind = parse_inbound_kind(msg, &type_name);
                overlay_kapso_media(&mut kind, kapso);
                batch.outbound.push(OutboundEcho {
                    wamid: id,
                    to: str_of(msg, "to").map(|t| to_digits(&t)).unwrap_or_default(),
                    timestamp: msg
                        .get("timestamp")
                        .and_then(i64_of)
                        .unwrap_or_else(|| chrono::Utc::now().timestamp()),
                    kind,
                    raw: msg.clone(),
                });
            }
        }
        return Some(batch);
    }

    // Inbound message.
    let wamid = str_of(msg, "id").filter(|s| !s.is_empty())?;
    let type_name = str_of(msg, "type").unwrap_or_default();
    let mut kind = parse_inbound_kind(msg, &type_name);
    overlay_kapso_media(&mut kind, kapso);

    let from_digits = str_of(msg, "from").map(|f| to_digits(&f)).unwrap_or_default();
    let from_user_id = str_of(msg, "from_user_id").filter(|s| !s.is_empty());
    let wa_id = convo
        .and_then(|c| str_of(c, "phone_number"))
        .filter(|s| !s.is_empty())
        .or_else(|| str_of(msg, "from"));
    let from = if !from_digits.is_empty() {
        from_digits
    } else if let Some(w) = wa_id.as_deref().map(to_digits).filter(|s| !s.is_empty()) {
        w
    } else {
        from_user_id.clone().unwrap_or_default()
    };

    batch.messages.push(InboundMessage {
        wamid,
        from,
        from_user_id,
        timestamp: msg
            .get("timestamp")
            .and_then(i64_of)
            .unwrap_or_else(|| chrono::Utc::now().timestamp()),
        push_name: convo
            .and_then(|c| str_of(c, "contact_name"))
            .filter(|s| !s.trim().is_empty()),
        wa_id,
        kind,
        context_id: msg
            .get("context")
            .and_then(|c| str_of(c, "id"))
            .filter(|s| !s.is_empty()),
        raw: msg.clone(),
    });
    Some(batch)
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a non-2xx Graph response (`{error:{message,type,code,error_subcode,
/// error_data{details}}}`) to an [`Error`]:
///
/// * `190` / `0` / HTTP 401 → `Unauthorized`
/// * `3` / `10` / `200` (missing permission or asset access) → `Forbidden`
/// * `100`, `131008`, `131009`, `131021`, `131053`, `132000`, `132001`,
///   `132012`, `132018` → `BadRequest("cloud: <code> <msg> — <details>")`
/// * `131047` → `BadRequest` (outside the 24 h customer-service window)
/// * `131026` → `BadRequest` (undeliverable / not a WhatsApp number)
/// * `131030` → `BadRequest` (recipient not in the sandbox allowed list)
/// * `4`, `80007`, `130429`, `131056` → `Conflict("cloud: rate limited …")`
/// * anything else → `Internal("cloud: <code> <msg>")`
///
/// A body that is not a Graph error envelope is mapped by HTTP status
/// (401 → Unauthorized, 403 → Forbidden, 404 → NotFound, 400 → BadRequest,
/// 429 → Conflict, else Internal).
pub fn map_graph_error(status: u16, body: &[u8]) -> Error {
    let parsed: Option<Value> = serde_json::from_slice(body).ok();
    let err = parsed.as_ref().and_then(|v| v.get("error")).cloned();
    let Some(err) = err.filter(|e| e.is_object()) else {
        let snippet = String::from_utf8_lossy(body);
        let snippet: String = snippet.chars().take(200).collect();
        let text = format!("cloud: http {status}: {}", snippet.trim());
        return match status {
            401 => Error::Unauthorized,
            403 => Error::Forbidden(text),
            404 => Error::NotFound(text),
            400 => Error::BadRequest(text),
            // 402 = Kapso "insufficient credits"; 409 = Kapso "message already
            // in-flight". Both are account/state conditions the caller can act
            // on, not ruwa bugs — surface as Conflict, not 500.
            402 => Error::Conflict(format!("{text} (insufficient Kapso credits)")),
            409 | 429 => Error::Conflict(text),
            _ => Error::Internal(anyhow!(text)),
        };
    };
    let code = err.get("code").and_then(i64_of).unwrap_or(0);
    let msg = str_of(&err, "message").unwrap_or_default();
    let details = err
        .get("error_data")
        .and_then(|d| str_of(d, "details"))
        .filter(|s| !s.trim().is_empty());
    let text = match &details {
        Some(d) => format!("cloud: {code} {msg} — {d}"),
        None => format!("cloud: {code} {msg}"),
    };
    match code {
        190 | 0 => Error::Unauthorized,
        _ if status == 401 => Error::Unauthorized,
        _ if status == 402 => Error::Conflict(format!("{text} (insufficient Kapso credits)")),
        _ if status == 409 => Error::Conflict(text),
        3 | 10 | 200 => Error::Forbidden(text),
        131047 => Error::BadRequest(
            "cloud: 131047 outside 24h customer-service window — send a template".into(),
        ),
        131026 => Error::BadRequest(format!("{text} (undeliverable)")),
        131030 => Error::BadRequest(format!("{text} (recipient not in allowed list)")),
        100 | 131008 | 131009 | 131021 | 131053 | 132000 | 132001 | 132012 | 132018 => {
            Error::BadRequest(text)
        }
        4 | 80007 | 130429 | 131056 => {
            Error::Conflict(format!("cloud: rate limited — {code} {msg}"))
        }
        _ => Error::Internal(anyhow!(text)),
    }
}

// ---------------------------------------------------------------------------
// Kapso Business Platform API (onboarding / provisioning)
// ---------------------------------------------------------------------------
// `KapsoPlatform` + `parse_kapso_project_event` are wired into the HTTP layer
// and the embedded-signup callback flow by WP-E / WP-F.

/// Base URL for the Kapso Business Platform API (customers, setup-links,
/// phone-number + webhook provisioning). Distinct from [`KAPSO_WA_BASE`], which
/// is the Meta-compatible *send* proxy.
pub const KAPSO_PLATFORM_BASE: &str = "https://api.kapso.ai/platform/v1";

/// Platform API path for webhook CRUD. Both project-scoped (no `phone_number_id`)
/// and number-scoped (with `phone_number_id` in the body) webhooks POST here.
/// Kapso spells its WhatsApp resources `whatsapp/…` (slash + underscore), not
/// `whatsapp-…` — a hyphen here 404s.
const KAPSO_WEBHOOKS_PATH: &str = "whatsapp/webhooks";

/// Platform API path for the connected-number collection
/// (`GET …?customer_id=…`). Same `whatsapp/…` spelling caveat as above.
const KAPSO_PHONE_NUMBERS_PATH: &str = "whatsapp/phone_numbers";

/// Platform API path for the broadcast (bulk-template campaign) collection.
/// Same `whatsapp/…` spelling caveat as [`KAPSO_WEBHOOKS_PATH`] — a hyphen 404s.
const KAPSO_BROADCASTS_PATH: &str = "whatsapp/broadcasts";

/// Default `events` for a per-number webhook (number-scoped `whatsapp/webhooks`).
const KAPSO_NUMBER_WEBHOOK_EVENTS: [&str; 5] = [
    "whatsapp.message.received",
    "whatsapp.message.sent",
    "whatsapp.message.delivered",
    "whatsapp.message.read",
    "whatsapp.message.failed",
];

/// Default `events` for a project-level webhook (lifecycle of the numbers
/// onboarded under the Kapso project).
const KAPSO_PROJECT_WEBHOOK_EVENTS: [&str; 5] = [
    "whatsapp.phone_number.created",
    "whatsapp.phone_number.deleted",
    "whatsapp.phone_number.offboarded",
    "whatsapp.phone_number.disconnected",
    "whatsapp.phone_number.reconnected",
];

/// A customer record in the Kapso platform (`POST /customers`).
#[derive(Debug, Clone, Serialize)]
pub struct KapsoCustomer {
    pub id: String,
    pub external_customer_id: Option<String>,
}

/// A hosted embedded-signup setup link (`POST /customers/{id}/setup_links`).
#[derive(Debug, Clone, Serialize)]
pub struct KapsoSetupLink {
    pub id: String,
    pub url: String,
    pub status: String,
    pub whatsapp_setup_status: String,
    pub whatsapp_setup_error: Option<String>,
    pub expires_at: Option<String>,
}

/// A provisioned WhatsApp business phone number
/// (`GET /whatsapp/phone_numbers?customer_id=…`).
#[derive(Debug, Clone, Serialize)]
pub struct KapsoPhoneNumber {
    pub id: String,
    pub internal_id: String,
    pub phone_number_id: String,
    /// Meta WABA id the number belongs to — needed for template management.
    pub business_account_id: Option<String>,
    pub display_phone_number: Option<String>,
    pub verified_name: Option<String>,
    pub quality_rating: Option<String>,
    pub customer_id: Option<String>,
    pub status: Option<String>,
}

// ---------------------------------------------------------------------------
// Kapso Broadcasts (bulk-template campaigns) — neutral views
// ---------------------------------------------------------------------------

/// The approved template a broadcast fans out (`broadcast.whatsapp_template`).
#[derive(Debug, Clone, Serialize)]
pub struct BroadcastTemplateView {
    pub id: Option<String>,
    pub name: Option<String>,
    pub language_code: Option<String>,
    pub category: Option<String>,
    pub status: Option<String>,
    pub meta_template_id: Option<String>,
}

/// A broadcast campaign (`POST/GET /whatsapp/broadcasts…`), translated out of
/// the Kapso `data` envelope. Count fields default to `0`; timestamps pass
/// through as the verbatim ISO-8601 strings Kapso returns.
#[derive(Debug, Clone, Serialize)]
pub struct BroadcastView {
    pub id: Option<String>,
    pub name: Option<String>,
    /// draft | scheduled | copying | sending | stopped | completed | failed
    pub status: Option<String>,
    pub total_recipients: u64,
    pub pending_count: u64,
    pub sent_count: u64,
    pub delivered_count: u64,
    pub read_count: u64,
    pub failed_count: u64,
    pub suppressed_count: u64,
    pub responded_count: u64,
    pub response_rate: Option<f64>,
    pub phone_number_id: Option<String>,
    pub scheduled_at: Option<String>,
    pub started_at: Option<String>,
    pub stopped_at: Option<String>,
    pub completed_at: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub template: Option<BroadcastTemplateView>,
}

/// One recipient of a broadcast (`GET /whatsapp/broadcasts/{id}/recipients`).
#[derive(Debug, Clone, Serialize)]
pub struct BroadcastRecipientView {
    pub id: Option<String>,
    pub phone_number: Option<String>,
    /// pending | sent | failed | suppressed
    pub status: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub sent_at: Option<String>,
    pub failed_at: Option<String>,
    pub delivered_at: Option<String>,
    pub read_at: Option<String>,
    pub responded_at: Option<String>,
    pub error_message: Option<String>,
    /// Meta component objects rendered for this recipient — passed through 1:1.
    pub template_components: Value,
    /// Provider error envelope, or `null`.
    pub error_details: Value,
}

/// A page of broadcasts with Kapso's `meta` pagination flattened in.
#[derive(Debug, Clone, Serialize)]
pub struct BroadcastList {
    pub items: Vec<BroadcastView>,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
    pub total_count: u64,
}

/// A page of broadcast recipients with Kapso's `meta` pagination flattened in.
#[derive(Debug, Clone, Serialize)]
pub struct BroadcastRecipientList {
    pub items: Vec<BroadcastRecipientView>,
    pub page: u64,
    pub per_page: u64,
    pub total_pages: u64,
    pub total_count: u64,
}

/// Outcome of `POST /whatsapp/broadcasts/{id}/recipients`.
#[derive(Debug, Clone, Serialize)]
pub struct AddRecipientsResult {
    pub added: u64,
    pub duplicates: u64,
    pub errors: Vec<String>,
}

/// `meta.{page,per_page,total_pages,total_count}` as `u64` (each defaults to 0).
fn parse_broadcast_meta(v: &Value) -> (u64, u64, u64, u64) {
    let m = v.get("meta").unwrap_or(&Value::Null);
    let read = |k: &str| m.get(k).and_then(u64_of).unwrap_or(0);
    (
        read("page"),
        read("per_page"),
        read("total_pages"),
        read("total_count"),
    )
}

/// Translate a Kapso broadcast object (bare or `{data:{…}}`) into [`BroadcastView`].
fn parse_broadcast(v: &Value) -> BroadcastView {
    let d = v.get("data").unwrap_or(v);
    let count = |k: &str| d.get(k).and_then(u64_of).unwrap_or(0);
    let template = d.get("whatsapp_template").filter(|t| t.is_object()).map(|t| {
        BroadcastTemplateView {
            id: str_of(t, "id"),
            name: str_of(t, "name"),
            language_code: str_of(t, "language_code"),
            category: str_of(t, "category"),
            status: str_of(t, "status"),
            meta_template_id: str_of(t, "meta_template_id"),
        }
    });
    BroadcastView {
        id: str_of(d, "id"),
        name: str_of(d, "name"),
        status: str_of(d, "status"),
        total_recipients: count("total_recipients"),
        pending_count: count("pending_count"),
        sent_count: count("sent_count"),
        delivered_count: count("delivered_count"),
        read_count: count("read_count"),
        failed_count: count("failed_count"),
        suppressed_count: count("suppressed_count"),
        responded_count: count("responded_count"),
        response_rate: d.get("response_rate").and_then(f64_of),
        phone_number_id: str_of(d, "phone_number_id"),
        scheduled_at: str_of(d, "scheduled_at"),
        started_at: str_of(d, "started_at"),
        stopped_at: str_of(d, "stopped_at"),
        completed_at: str_of(d, "completed_at"),
        created_at: str_of(d, "created_at"),
        updated_at: str_of(d, "updated_at"),
        template,
    }
}

/// Translate one Kapso broadcast-recipient object into [`BroadcastRecipientView`].
fn parse_broadcast_recipient(v: &Value) -> BroadcastRecipientView {
    let d = v.get("data").unwrap_or(v);
    BroadcastRecipientView {
        id: str_of(d, "id"),
        phone_number: str_of(d, "phone_number"),
        status: str_of(d, "status"),
        created_at: str_of(d, "created_at"),
        updated_at: str_of(d, "updated_at"),
        sent_at: str_of(d, "sent_at"),
        failed_at: str_of(d, "failed_at"),
        delivered_at: str_of(d, "delivered_at"),
        read_at: str_of(d, "read_at"),
        responded_at: str_of(d, "responded_at"),
        error_message: str_of(d, "error_message"),
        template_components: d
            .get("template_components")
            .cloned()
            .unwrap_or(Value::Null),
        error_details: d.get("error_details").cloned().unwrap_or(Value::Null),
    }
}

/// Options for [`KapsoPlatform::create_setup_link`]. Every optional field is
/// omitted from the request body when unset / blank.
#[derive(Debug, Clone, Default)]
pub struct SetupLinkOpts {
    pub provision_phone_number: bool,
    /// `"coexistence"` | `"dedicated"` → `allowed_connection_types: [<it>]`.
    pub connection_type: Option<String>,
    /// `"partner_managed"` (default when `None`) | `"customer_managed"`.
    pub meta_billing_mode: Option<String>,
    pub success_redirect_url: Option<String>,
    pub failure_redirect_url: Option<String>,
    /// ISO-3166-1 alpha-2 codes for `phone_number_country_isos`.
    pub country_isos: Vec<String>,
    pub language: Option<String>,
}

/// Build the `POST /setup-links` request body from [`SetupLinkOpts`], omitting
/// null / empty optionals. Factored out so the mapping is unit-testable without
/// a network; `meta_billing_mode` defaults to `"partner_managed"`.
pub(crate) fn setup_link_body(opts: &SetupLinkOpts) -> Value {
    let mut m = Map::new();
    m.insert(
        "provision_phone_number".into(),
        json!(opts.provision_phone_number),
    );
    if let Some(ct) = opts
        .connection_type
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        m.insert("allowed_connection_types".into(), json!([ct]));
    }
    let billing = opts
        .meta_billing_mode
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("partner_managed");
    m.insert("meta_billing_mode".into(), json!(billing));
    if let Some(u) = opts
        .success_redirect_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        m.insert("success_redirect_url".into(), json!(u));
    }
    if let Some(u) = opts
        .failure_redirect_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        m.insert("failure_redirect_url".into(), json!(u));
    }
    let isos: Vec<&str> = opts
        .country_isos
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if !isos.is_empty() {
        m.insert("phone_number_country_isos".into(), json!(isos));
    }
    if let Some(l) = opts
        .language
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        m.insert("language".into(), json!(l));
    }
    json!({ "setup_link": Value::Object(m) })
}

/// Whether `s` is a plausible Kapso resource id to interpolate into a URL path:
/// a numeric Graph id, or a non-empty `[A-Za-z0-9_-]` token (UUIDs). Anything
/// with a slash, space, dot or query char is refused.
fn is_kapso_id(s: &str) -> bool {
    is_graph_id(s)
        || (!s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

fn parse_kapso_setup_link(d: &Value) -> Option<KapsoSetupLink> {
    Some(KapsoSetupLink {
        id: str_of(d, "id")?,
        url: str_of(d, "url").unwrap_or_default(),
        status: str_of(d, "status").unwrap_or_default(),
        whatsapp_setup_status: str_of(d, "whatsapp_setup_status").unwrap_or_default(),
        whatsapp_setup_error: str_of(d, "whatsapp_setup_error"),
        expires_at: str_of(d, "expires_at"),
    })
}

fn parse_kapso_phone_number(d: &Value) -> Option<KapsoPhoneNumber> {
    let internal_id = str_of(d, "internal_id")?;
    Some(KapsoPhoneNumber {
        id: str_of(d, "id").unwrap_or_default(),
        internal_id,
        phone_number_id: str_of(d, "phone_number_id").unwrap_or_default(),
        business_account_id: str_of(d, "business_account_id")
            .or_else(|| str_of(d, "whatsapp_business_account_id")),
        display_phone_number: str_of(d, "display_phone_number"),
        verified_name: str_of(d, "verified_name"),
        quality_rating: str_of(d, "quality_rating"),
        customer_id: str_of(d, "customer_id"),
        status: str_of(d, "status"),
    })
}

/// A project-level lifecycle webhook event (`whatsapp.phone_number.*`), parsed
/// from the Kapso `POST` body plus the `X-Webhook-Event` header.
#[derive(Debug, Clone, Serialize)]
pub struct KapsoProjectEvent {
    pub event: String,
    pub phone_number_id: Option<String>,
    pub customer_id: Option<String>,
    pub project_id: Option<String>,
    pub business_account_id: Option<String>,
    pub occurred_at: Option<String>,
}

/// Parse a Kapso project-webhook body. The event name is taken from the
/// `X-Webhook-Event` header when present, else the body `event` / `type` field.
/// Pure; `BadRequest` only when the body is not JSON. Wired by WP-F.
pub fn parse_kapso_project_event(
    raw: &[u8],
    event_header: Option<&str>,
) -> Result<KapsoProjectEvent> {
    let root: Value = serde_json::from_slice(raw)
        .map_err(|e| Error::BadRequest(format!("kapso project webhook: invalid json: {e}")))?;
    let event = event_header
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(|| str_of(&root, "event"))
        .or_else(|| str_of(&root, "type"))
        .unwrap_or_default();
    Ok(KapsoProjectEvent {
        event,
        phone_number_id: str_of(&root, "phone_number_id"),
        customer_id: root.get("customer").and_then(|c| str_of(c, "id")),
        project_id: root.get("project").and_then(|p| str_of(p, "id")),
        business_account_id: root
            .get("source")
            .and_then(|s| str_of(s, "business_account_id")),
        occurred_at: str_of(&root, "occurred_at"),
    })
}

/// Thin client for the Kapso Business Platform API (customer + setup-link +
/// phone-number provisioning). Separate from [`CloudClient`] (which speaks the
/// Meta-compatible *send* surface): different base host, always `X-API-Key`
/// auth, JSON-only. Wired by WP-E / WP-F.
pub struct KapsoPlatform {
    http: reqwest::Client,
    api_key: String,
    base: String,
}

impl std::fmt::Debug for KapsoPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KapsoPlatform")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

#[allow(dead_code)]
impl KapsoPlatform {
    /// Build a client with the same 30 s connect + call timeout and optional
    /// egress proxy as [`CloudClient::new`]. `base` defaults to
    /// [`KAPSO_PLATFORM_BASE`]; a trailing slash is trimmed.
    pub fn new(api_key: impl Into<String>, base: Option<&str>, proxy: Option<&str>) -> Result<Self> {
        let mut b = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(GRAPH_TIMEOUT_SECS))
            .timeout(Duration::from_secs(GRAPH_TIMEOUT_SECS))
            .user_agent(USER_AGENT);
        if let Some(url) = proxy.map(str::trim).filter(|s| !s.is_empty()) {
            let p = reqwest::Proxy::all(url).map_err(|e| {
                Error::BadRequest(format!("kapso platform: invalid proxy url: {e}"))
            })?;
            b = b.proxy(p);
        }
        let http = b
            .build()
            .map_err(|e| Error::Internal(anyhow!("kapso platform: http client: {e}")))?;
        let base = base
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or(KAPSO_PLATFORM_BASE)
            .trim_end_matches('/')
            .to_string();
        Ok(Self {
            http,
            api_key: api_key.into(),
            base,
        })
    }

    /// Absolute URL for `path` (leading slash optional): `{base}/{path}`.
    fn url(&self, path: &str) -> String {
        format!("{}/{}", self.base, path.trim_start_matches('/'))
    }

    /// Send a prepared request with `X-API-Key`, mapping transport failures and
    /// non-2xx bodies via [`map_graph_error`] (Kapso returns the Meta error
    /// envelope, plus 402/409). Empty body → `Value::Null`.
    async fn exec_json(&self, req: reqwest::RequestBuilder) -> Result<Value> {
        let resp = req
            .header("X-API-Key", &self.api_key)
            .send()
            .await
            .map_err(|e| Error::Internal(anyhow!("kapso platform: request failed: {e}")))?;
        let status = resp.status();
        let body = resp
            .bytes()
            .await
            .map_err(|e| Error::Internal(anyhow!("kapso platform: read failed: {e}")))?;
        if !status.is_success() {
            return Err(map_graph_error(status.as_u16(), &body));
        }
        if body.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&body)
            .map_err(|e| Error::Internal(anyhow!("kapso platform: invalid json: {e}")))
    }

    /// `POST /customers` — create (or upsert by `external_customer_id`) a customer.
    pub async fn create_customer(
        &self,
        name: &str,
        external_id: Option<&str>,
    ) -> Result<KapsoCustomer> {
        let body = json!({
            "customer": { "name": name, "external_customer_id": external_id },
        });
        let v = self
            .exec_json(self.http.post(self.url("customers")).json(&body))
            .await?;
        let d = v.get("data").unwrap_or(&v);
        let id = str_of(d, "id").ok_or_else(|| {
            Error::Internal(anyhow!("kapso platform: create-customer response without data.id"))
        })?;
        Ok(KapsoCustomer {
            id,
            external_customer_id: str_of(d, "external_customer_id"),
        })
    }

    /// `POST /customers/{customer_id}/setup_links` — mint a hosted embedded-signup
    /// link for `customer_id`.
    // TODO(kapso-verify): docs show POST /setup-links; customer-scoped path assumed
    pub async fn create_setup_link(
        &self,
        customer_id: &str,
        opts: SetupLinkOpts,
    ) -> Result<KapsoSetupLink> {
        let cid = customer_id.trim();
        if !is_kapso_id(cid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid customer id {cid:?}"
            )));
        }
        let path = format!("customers/{cid}/setup_links");
        let v = self
            .exec_json(self.http.post(self.url(&path)).json(&setup_link_body(&opts)))
            .await?;
        let d = v.get("data").unwrap_or(&v);
        parse_kapso_setup_link(d).ok_or_else(|| {
            Error::Internal(anyhow!("kapso platform: setup-link response without data.id"))
        })
    }

    /// `GET /customers/{customer_id}/setup_links` — list a customer's setup links.
    pub async fn list_setup_links(&self, customer_id: &str) -> Result<Vec<KapsoSetupLink>> {
        let cid = customer_id.trim();
        if !is_kapso_id(cid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid customer id {cid:?}"
            )));
        }
        let path = format!("customers/{cid}/setup_links");
        let v = self.exec_json(self.http.get(self.url(&path))).await?;
        let arr = v
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(arr.iter().filter_map(parse_kapso_setup_link).collect())
    }

    /// `GET /whatsapp/phone_numbers?customer_id={customer_id}` — the numbers
    /// provisioned for a customer (used after the onboarding callback to resolve
    /// `internal_id` + display fields).
    pub async fn list_customer_phone_numbers(
        &self,
        customer_id: &str,
    ) -> Result<Vec<KapsoPhoneNumber>> {
        let cid = customer_id.trim();
        if !is_kapso_id(cid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid customer id {cid:?}"
            )));
        }
        let v = self
            .exec_json(
                self.http
                    .get(self.url(KAPSO_PHONE_NUMBERS_PATH))
                    .query(&[("customer_id", cid)]),
            )
            .await?;
        let arr = v
            .get("data")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(arr.iter().filter_map(parse_kapso_phone_number).collect())
    }

    /// `POST /whatsapp/webhooks` with `phone_number_id` in the body — register a
    /// number-scoped `kind: "kapso"` webhook (message + conversation events).
    /// Keyed by the Meta `phone_number_id` (not the Kapso `internal_id`).
    /// Returns the webhook id. `events` defaults to the message-lifecycle list.
    pub async fn register_number_webhook(
        &self,
        phone_number_id: &str,
        url: &str,
        secret: &str,
        events: Option<&[&str]>,
    ) -> Result<String> {
        let pnid = phone_number_id.trim();
        if !is_kapso_id(pnid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid phone_number_id {pnid:?}"
            )));
        }
        let events: &[&str] = events.unwrap_or(&KAPSO_NUMBER_WEBHOOK_EVENTS);
        let body = json!({
            "whatsapp_webhook": {
                "url": url,
                "kind": "kapso",
                "phone_number_id": pnid,
                "secret_key": secret,
                "active": true,
                "events": events,
            }
        });
        let v = self
            .exec_json(self.http.post(self.url(KAPSO_WEBHOOKS_PATH)).json(&body))
            .await?;
        let d = v.get("data").unwrap_or(&v);
        str_of(d, "id").ok_or_else(|| {
            Error::Internal(anyhow!("kapso platform: webhook response without data.id"))
        })
    }

    /// `POST /whatsapp/webhooks` with no `phone_number_id` — register a
    /// project-scoped `kind: "kapso"` webhook (number-lifecycle events only).
    /// Returns the webhook id. `events` defaults to the phone-number-lifecycle list.
    pub async fn register_project_webhook(
        &self,
        url: &str,
        secret: &str,
        events: Option<&[&str]>,
    ) -> Result<String> {
        let events: &[&str] = events.unwrap_or(&KAPSO_PROJECT_WEBHOOK_EVENTS);
        let body = json!({
            "whatsapp_webhook": {
                "url": url,
                "kind": "kapso",
                "secret_key": secret,
                "active": true,
                "events": events,
            }
        });
        let v = self
            .exec_json(self.http.post(self.url(KAPSO_WEBHOOKS_PATH)).json(&body))
            .await?;
        let d = v.get("data").unwrap_or(&v);
        str_of(d, "id").ok_or_else(|| {
            Error::Internal(anyhow!("kapso platform: webhook response without data.id"))
        })
    }

    /// `DELETE /whatsapp/phone_numbers/{phone_number_id}` — offboard a connected
    /// number (also drops its number-scoped webhooks on the Kapso side). Keyed by
    /// the Meta `phone_number_id`. A 404 (already gone) is treated as success.
    pub async fn delete_phone_number(&self, phone_number_id: &str) -> Result<()> {
        let pnid = phone_number_id.trim();
        if !is_kapso_id(pnid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid phone_number_id {pnid:?}"
            )));
        }
        let path = format!("{KAPSO_PHONE_NUMBERS_PATH}/{pnid}");
        match self.exec_json(self.http.delete(self.url(&path))).await {
            Ok(_) | Err(Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// `DELETE /customers/{customer_id}` — remove the customer record ruwa
    /// created for this session (cascades its numbers/setup-links on Kapso).
    /// A 404 (already gone) is treated as success.
    pub async fn delete_customer(&self, customer_id: &str) -> Result<()> {
        let cid = customer_id.trim();
        if !is_kapso_id(cid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid customer id {cid:?}"
            )));
        }
        let path = format!("customers/{cid}");
        match self.exec_json(self.http.delete(self.url(&path))).await {
            Ok(_) | Err(Error::NotFound(_)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    // ---- Broadcasts (bulk-template campaigns) ---------------------------------

    /// `POST /whatsapp/broadcasts` — create a draft broadcast for `phone_number_id`
    /// off the approved template `template_id` (a Meta template id).
    pub async fn create_broadcast(
        &self,
        phone_number_id: &str,
        name: &str,
        template_id: &str,
    ) -> Result<BroadcastView> {
        let pnid = phone_number_id.trim();
        if !is_graph_id(pnid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid phone_number_id {pnid:?}"
            )));
        }
        let name = name.trim();
        let template_id = template_id.trim();
        if name.is_empty() {
            return Err(Error::BadRequest("broadcast name is required".into()));
        }
        if template_id.is_empty() {
            return Err(Error::BadRequest("broadcast template_id is required".into()));
        }
        let body = json!({
            "whatsapp_broadcast": {
                "name": name,
                "phone_number_id": pnid,
                "whatsapp_template_id": template_id,
            }
        });
        let v = self
            .exec_json(self.http.post(self.url(KAPSO_BROADCASTS_PATH)).json(&body))
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// `GET /whatsapp/broadcasts` — list broadcasts for `phone_number_id`,
    /// optionally filtered by `status` and paginated.
    pub async fn list_broadcasts(
        &self,
        phone_number_id: &str,
        status: Option<&str>,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<BroadcastList> {
        let pnid = phone_number_id.trim();
        if !is_graph_id(pnid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid phone_number_id {pnid:?}"
            )));
        }
        let mut q: Vec<(&str, String)> = vec![("phone_number_id", pnid.to_string())];
        if let Some(s) = status.map(str::trim).filter(|s| !s.is_empty()) {
            q.push(("status", s.to_string()));
        }
        if let Some(p) = page {
            q.push(("page", p.to_string()));
        }
        if let Some(pp) = per_page {
            q.push(("per_page", pp.to_string()));
        }
        let v = self
            .exec_json(self.http.get(self.url(KAPSO_BROADCASTS_PATH)).query(&q))
            .await?;
        let items = v
            .get("data")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(parse_broadcast).collect())
            .unwrap_or_default();
        let (page, per_page, total_pages, total_count) = parse_broadcast_meta(&v);
        Ok(BroadcastList {
            items,
            page,
            per_page,
            total_pages,
            total_count,
        })
    }

    /// `GET /whatsapp/broadcasts/{bid}`.
    pub async fn get_broadcast(&self, bid: &str) -> Result<BroadcastView> {
        let bid = self.broadcast_id(bid)?;
        let v = self
            .exec_json(
                self.http
                    .get(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}"))),
            )
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// `POST /whatsapp/broadcasts/{bid}/recipients` — `recipients` is the caller's
    /// already-validated JSON array of `{phone_number|whatsapp_contact_id,
    /// components:[…]}` objects (≤1000), enveloped here as
    /// `{whatsapp_broadcast:{recipients:[…]}}`.
    pub async fn add_broadcast_recipients(
        &self,
        bid: &str,
        recipients: Value,
    ) -> Result<AddRecipientsResult> {
        let bid = self.broadcast_id(bid)?;
        let body = json!({ "whatsapp_broadcast": { "recipients": recipients } });
        let v = self
            .exec_json(
                self.http
                    .post(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}/recipients")))
                    .json(&body),
            )
            .await?;
        let d = v.get("data").unwrap_or(&v);
        Ok(AddRecipientsResult {
            added: d.get("added").and_then(u64_of).unwrap_or(0),
            duplicates: d.get("duplicates").and_then(u64_of).unwrap_or(0),
            errors: d
                .get("errors")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .map(|e| e.as_str().map(str::to_string).unwrap_or_else(|| e.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }

    /// `DELETE /whatsapp/broadcasts/{bid}/recipients` — clear the recipient list
    /// (a scheduled broadcast returns to `draft`).
    pub async fn clear_broadcast_recipients(&self, bid: &str) -> Result<BroadcastView> {
        let bid = self.broadcast_id(bid)?;
        let v = self
            .exec_json(
                self.http
                    .delete(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}/recipients"))),
            )
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// `GET /whatsapp/broadcasts/{bid}/recipients` — per-recipient status, paginated.
    pub async fn list_broadcast_recipients(
        &self,
        bid: &str,
        page: Option<u32>,
        per_page: Option<u32>,
    ) -> Result<BroadcastRecipientList> {
        let bid = self.broadcast_id(bid)?;
        let mut q: Vec<(&str, String)> = Vec::new();
        if let Some(p) = page {
            q.push(("page", p.to_string()));
        }
        if let Some(pp) = per_page {
            q.push(("per_page", pp.to_string()));
        }
        let v = self
            .exec_json(
                self.http
                    .get(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}/recipients")))
                    .query(&q),
            )
            .await?;
        let items = v
            .get("data")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(parse_broadcast_recipient).collect())
            .unwrap_or_default();
        let (page, per_page, total_pages, total_count) = parse_broadcast_meta(&v);
        Ok(BroadcastRecipientList {
            items,
            page,
            per_page,
            total_pages,
            total_count,
        })
    }

    /// `POST /whatsapp/broadcasts/{bid}/send` — start sending now (Kapso 202).
    pub async fn send_broadcast(&self, bid: &str) -> Result<BroadcastView> {
        let bid = self.broadcast_id(bid)?;
        let v = self
            .exec_json(
                self.http
                    .post(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}/send"))),
            )
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// `POST /whatsapp/broadcasts/{bid}/schedule` — schedule for a future
    /// ISO-8601 `scheduled_at` (Kapso 202).
    pub async fn schedule_broadcast(
        &self,
        bid: &str,
        scheduled_at: &str,
    ) -> Result<BroadcastView> {
        let bid = self.broadcast_id(bid)?;
        let scheduled_at = scheduled_at.trim();
        if scheduled_at.is_empty() {
            return Err(Error::BadRequest("scheduled_at is required".into()));
        }
        let body = json!({ "scheduled_at": scheduled_at });
        let v = self
            .exec_json(
                self.http
                    .post(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}/schedule")))
                    .json(&body),
            )
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// `POST /whatsapp/broadcasts/{bid}/cancel` — cancel a schedule (→ `draft`).
    pub async fn cancel_broadcast(&self, bid: &str) -> Result<BroadcastView> {
        let bid = self.broadcast_id(bid)?;
        let v = self
            .exec_json(
                self.http
                    .post(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}/cancel"))),
            )
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// `PATCH /whatsapp/broadcasts/{bid}` `{whatsapp_broadcast:{status:"stopped"}}`
    /// — halt a sending broadcast.
    pub async fn stop_broadcast(&self, bid: &str) -> Result<BroadcastView> {
        let bid = self.broadcast_id(bid)?;
        let body = json!({ "whatsapp_broadcast": { "status": "stopped" } });
        let v = self
            .exec_json(
                self.http
                    .patch(self.url(&format!("{KAPSO_BROADCASTS_PATH}/{bid}")))
                    .json(&body),
            )
            .await?;
        Ok(parse_broadcast(&v))
    }

    /// Validate a broadcast id for path interpolation.
    fn broadcast_id<'a>(&self, bid: &'a str) -> Result<&'a str> {
        let bid = bid.trim();
        if !is_kapso_id(bid) {
            return Err(Error::BadRequest(format!(
                "kapso platform: invalid broadcast id {bid:?}"
            )));
        }
        Ok(bid)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn creds() -> CloudCreds {
        CloudCreds {
            provider: CloudProvider::Meta,
            phone_number_id: "106540352242922".into(),
            waba_id: Some("102290129340398".into()),
            access_token: "EAAG-fake-token".into(),
            api_key: None,
            base_url: None,
            app_secret: Some("fake-app-secret".into()),
            verify_token: Some("my-verify".into()),
            graph_version: DEFAULT_GRAPH_VERSION.into(),
        }
    }

    fn kapso_creds() -> CloudCreds {
        CloudCreds {
            provider: CloudProvider::Kapso,
            phone_number_id: "106540352242922".into(),
            waba_id: None,
            access_token: String::new(),
            api_key: Some("kapso-platform-key".into()),
            base_url: None,
            app_secret: None,
            verify_token: None,
            graph_version: "v24.0".into(),
        }
    }

    // ---- helpers -----------------------------------------------------------

    #[test]
    fn to_digits_normalizes_every_input_shape() {
        assert_eq!(to_digits("5511999999999"), "5511999999999");
        assert_eq!(to_digits("+55 (11) 99999-9999"), "5511999999999");
        assert_eq!(to_digits("5511999999999@s.whatsapp.net"), "5511999999999");
        assert_eq!(
            to_digits("5511999999999:12@s.whatsapp.net"),
            "5511999999999"
        );
        assert_eq!(to_digits("5511999999999@lid"), "5511999999999");
        assert_eq!(to_digits("+1 631-555-5555"), "16315555555");
        assert_eq!(to_digits(""), "");
    }

    #[test]
    fn check_recipient_accepts_numbers_and_user_jids_only() {
        assert_eq!(check_recipient("5511999999999").unwrap(), "5511999999999");
        assert_eq!(check_recipient("+55 (11) 99999-9999").unwrap(), "5511999999999");
        assert_eq!(check_recipient("5511999999999@s.whatsapp.net").unwrap(), "5511999999999");
        assert_eq!(check_recipient("5511999999999:3@s.whatsapp.net").unwrap(), "5511999999999");
        assert_eq!(check_recipient("5511999999999@c.us").unwrap(), "5511999999999");
        // Non-phone servers must be refused, not digit-stripped into a stranger's number.
        for bad in [
            "123456789012345@lid",
            "120363123456789012@g.us",
            "status@broadcast",
            "120363123456789012@newsletter",
        ] {
            assert!(matches!(check_recipient(bad), Err(Error::BadRequest(_))), "{bad}");
        }
        assert!(matches!(check_recipient(""), Err(Error::BadRequest(_))));
        assert!(matches!(check_recipient("abc"), Err(Error::BadRequest(_))));
    }

    #[test]
    fn graph_id_and_version_validators() {
        assert!(is_graph_id("106540352242922"));
        assert!(!is_graph_id(""));
        assert!(!is_graph_id("../../me"));
        assert!(!is_graph_id("123?fields=x"));
        assert!(!is_graph_id("12 34"));
        assert!(is_graph_version("v25.0"));
        assert!(is_graph_version("v100.12"));
        assert!(!is_graph_version("25.0"));
        assert!(!is_graph_version("v25"));
        assert!(!is_graph_version("v25.0/../x"));
        assert!(!is_graph_version(""));
    }

    #[test]
    fn provider_api_base_and_graph_url() {
        // Meta: unchanged — Graph host, pinned version.
        let m = CloudClient::new(creds(), None).unwrap();
        assert_eq!(m.api_base(), GRAPH_BASE);
        assert_eq!(
            m.graph_url("106540352242922/messages"),
            "https://graph.facebook.com/v25.0/106540352242922/messages"
        );
        // Kapso: proxy host, its own version, identical path structure.
        let k = CloudClient::new(kapso_creds(), None).unwrap();
        assert_eq!(k.api_base(), KAPSO_WA_BASE);
        assert_eq!(
            k.graph_url("106540352242922/messages"),
            "https://api.kapso.ai/meta/whatsapp/v24.0/106540352242922/messages"
        );
        // Per-session base_url override wins for either provider (trailing slash trimmed).
        let mut c = kapso_creds();
        c.base_url = Some("https://proxy.example.test/wa/".into());
        let o = CloudClient::new(c, None).unwrap();
        assert_eq!(o.api_base(), "https://proxy.example.test/wa");
        assert_eq!(
            o.graph_url("1/messages"),
            "https://proxy.example.test/wa/v24.0/1/messages"
        );
    }

    #[test]
    fn kapso_signed_media_url_is_detected_without_matching_lookalikes() {
        assert!(is_kapso_signed_media_url(
            "https://api.kapso.ai/meta/whatsapp/media_download?token=short-lived"
        ));
        assert!(!is_kapso_signed_media_url(
            "https://api.kapso.ai/meta/whatsapp/media_download?other=short-lived"
        ));
        assert!(!is_kapso_signed_media_url(
            "https://kapso.ai.evil.example/media_download?token=short-lived"
        ));
    }

    #[test]
    fn provider_parse_roundtrip() {
        assert_eq!(CloudProvider::parse("kapso"), CloudProvider::Kapso);
        assert_eq!(CloudProvider::parse("  KAPSO "), CloudProvider::Kapso);
        assert_eq!(CloudProvider::parse("meta"), CloudProvider::Meta);
        assert_eq!(CloudProvider::parse(""), CloudProvider::Meta);
        assert_eq!(CloudProvider::parse("nonsense"), CloudProvider::Meta);
        assert_eq!(CloudProvider::Kapso.as_str(), "kapso");
        assert_eq!(CloudProvider::Meta.as_str(), "meta");
    }

    #[test]
    fn kapso_media_url_allow_list() {
        let k = CloudClient::new(kapso_creds(), None).unwrap();
        // Kapso-hosted media + the API host itself are allowed for a Kapso session…
        assert!(k.media_url_allowed("https://api.kapso.ai/meta/whatsapp/media/abc"));
        assert!(k.media_url_allowed("https://cdn.kapso.ai/m/xyz.jpg"));
        // …Meta hosts stay allowed (passthrough-ish deliveries)…
        assert!(k.media_url_allowed("https://lookaside.fbsbx.com/whatsapp_business/attachments/?mid=1"));
        // …but look-alikes, plain http, and unrelated hosts are refused.
        assert!(!k.media_url_allowed("https://kapso.ai.evil.example/x"));
        assert!(!k.media_url_allowed("http://cdn.kapso.ai/x"));
        assert!(!k.media_url_allowed("https://example.com/x"));
        // A Meta session must NOT trust Kapso hosts.
        let m = CloudClient::new(creds(), None).unwrap();
        assert!(!m.media_url_allowed("https://cdn.kapso.ai/m/xyz.jpg"));
    }

    #[test]
    fn kapso_status_codes_map_to_conflict() {
        assert!(matches!(
            map_graph_error(402, b"{\"error\":{\"code\":100,\"message\":\"no credits\"}}"),
            Error::Conflict(_)
        ));
        assert!(matches!(
            map_graph_error(409, b"not json"),
            Error::Conflict(_)
        ));
    }

    #[test]
    fn kapso_signature_roundtrip() {
        let secret = "kapso-webhook-secret";
        let body = br#"{"message":{"id":"wamid.1"}}"#;
        let good = hmac_sha256_hex(secret.as_bytes(), body);
        assert!(verify_kapso_signature(secret, body, Some(&good)));
        assert!(verify_kapso_signature(secret, body, Some(&format!("sha256={good}"))));
        assert!(!verify_kapso_signature(secret, body, Some("deadbeef")));
        assert!(!verify_kapso_signature(secret, body, None));
        assert!(!verify_kapso_signature("wrong", body, Some(&good)));
    }

    #[test]
    fn kapso_webhook_inbound_text() {
        let raw = br#"{
          "message": { "id": "wamid.123", "timestamp": "1730092800", "type": "text",
            "from": "16315551181", "from_user_id": "US.134912",
            "text": { "body": "Hello" },
            "kapso": { "direction": "inbound", "has_media": false, "content": "Hello" } },
          "conversation": { "id": "conv_1", "contact_name": "John Doe",
            "phone_number": "16315551181", "phone_number_id": "123456789012345" },
          "is_new_conversation": true,
          "phone_number_id": "123456789012345"
        }"#;
        let batches = parse_kapso_webhook(raw).unwrap();
        assert_eq!(batches.len(), 1);
        let b = &batches[0];
        assert_eq!(b.phone_number_id, "123456789012345");
        assert_eq!(b.messages.len(), 1);
        assert!(b.statuses.is_empty());
        let m = &b.messages[0];
        assert_eq!(m.wamid, "wamid.123");
        assert_eq!(m.from, "16315551181");
        assert_eq!(m.push_name.as_deref(), Some("John Doe"));
        assert_eq!(m.kind, InboundKind::Text { body: "Hello".into() });
    }

    #[test]
    fn kapso_webhook_extracts_cs_window_from_last_inbound_at() {
        let raw = br#"{
          "message": { "id": "wamid.9", "timestamp": "1730092800", "type": "text",
            "from": "1", "text": { "body": "hi" },
            "kapso": { "direction": "inbound" } },
          "conversation": { "phone_number_id": "PN",
            "kapso": { "last_inbound_at": "2024-10-28T05:20:00.000000Z" } },
          "phone_number_id": "PN"
        }"#;
        let anchor = chrono::DateTime::parse_from_rfc3339("2024-10-28T05:20:00.000000Z")
            .unwrap()
            .timestamp();
        let b = &parse_kapso_webhook(raw).unwrap()[0];
        assert_eq!(b.window_expires_at, Some(anchor + CS_WINDOW_SECS));

        // No `conversation.kapso` → parser reports nothing (caller falls back).
        let raw2 = br#"{ "message": { "id": "w", "timestamp": "1", "type": "text",
            "from": "1", "text": { "body": "x" }, "kapso": { "direction": "inbound" } },
          "conversation": { "phone_number_id": "PN" }, "phone_number_id": "PN" }"#;
        assert_eq!(parse_kapso_webhook(raw2).unwrap()[0].window_expires_at, None);
    }

    #[test]
    fn meta_webhook_extracts_cs_window_from_status_conversation() {
        let raw = br#"{ "entry": [ { "changes": [ { "field": "messages", "value": {
            "metadata": { "phone_number_id": "PN" },
            "statuses": [ { "id": "wamid.1", "status": "delivered",
              "recipient_id": "5511999999999", "timestamp": "1730000000",
              "conversation": { "id": "c1", "expiration_timestamp": "1730116480" } } ]
        } } ] } ] }"#;
        let b = &parse_webhook(raw).unwrap()[0];
        assert_eq!(b.window_expires_at, Some(1730116480));
    }

    #[test]
    fn kapso_webhook_inbound_image_uses_kapso_media_url() {
        let raw = br#"{
          "message": { "id": "wamid.789", "timestamp": "1730093000", "type": "image",
            "from": "16315551181",
            "image": { "caption": "Photo description", "id": "media_id_123" },
            "kapso": { "direction": "inbound", "has_media": true,
              "media_url": "https://api.kapso.ai/media/abc",
              "media_data": { "url": "https://api.kapso.ai/media/abc",
                "filename": "photo.jpg", "content_type": "image/jpeg", "byte_size": 204800 } } },
          "conversation": { "phone_number": "16315551181", "phone_number_id": "123456789012345" },
          "phone_number_id": "123456789012345"
        }"#;
        let b = &parse_kapso_webhook(raw).unwrap()[0];
        match &b.messages[0].kind {
            InboundKind::Media { msg_type, media_id, url, mime, filename, caption, .. } => {
                assert_eq!(*msg_type, "image");
                assert_eq!(media_id, "media_id_123");
                assert_eq!(url.as_deref(), Some("https://api.kapso.ai/media/abc"));
                assert_eq!(mime.as_deref(), Some("image/jpeg"));
                assert_eq!(filename.as_deref(), Some("photo.jpg"));
                assert_eq!(caption.as_deref(), Some("Photo description"));
            }
            other => panic!("expected media, got {other:?}"),
        }
    }

    #[test]
    fn kapso_webhook_outbound_status_and_failure() {
        let raw = br#"{
          "message": { "id": "wamid.456", "type": "text", "to": "15551234567",
            "kapso": { "direction": "outbound", "status": "delivered", "statuses": [
              { "id": "wamid.456", "status": "sent", "timestamp": "1730092860", "recipient_id": "15551234567" },
              { "id": "wamid.456", "status": "delivered", "timestamp": "1730092888", "recipient_id": "15551234567" },
              { "id": "wamid.456", "status": "failed", "timestamp": "1730093200", "recipient_id": "15551234567",
                "errors": [ { "code": 131047, "title": "Re-engagement message" } ] } ] } },
          "conversation": { "phone_number": "15551234567", "phone_number_id": "123456789012345" },
          "phone_number_id": "123456789012345"
        }"#;
        let b = &parse_kapso_webhook(raw).unwrap()[0];
        assert!(b.messages.is_empty());
        assert_eq!(b.statuses.len(), 3);
        assert_eq!(b.statuses[0].status, "sent");
        assert_eq!(b.statuses[2].status, "failed");
        assert!(b.statuses[2].error.as_deref().unwrap().contains("131047"));
        assert_eq!(b.outbound.len(), 1);
        assert_eq!(b.outbound[0].wamid, "wamid.456");
        assert_eq!(b.outbound[0].to, "15551234567");
    }

    #[test]
    fn kapso_webhook_outbound_echo_carries_content() {
        let raw = r#"{
          "message": {
            "id": "wamid.OUT99", "type": "text", "to": "5500000000001",
            "timestamp": "1730092860",
            "text": { "body": "Já estou a caminho" },
            "kapso": {
              "direction": "outbound", "status": "sent", "origin": "business_app",
              "statuses": [
                { "id": "wamid.OUT99", "status": "sent", "timestamp": "1730092860", "recipient_id": "5500000000001" }
              ]
            }
          },
          "conversation": { "phone_number": "5500000000001", "phone_number_id": "123456789012345" },
          "phone_number_id": "123456789012345"
        }"#;
        let b = &parse_kapso_webhook(raw.as_bytes()).unwrap()[0];
        assert!(b.messages.is_empty(), "echo is not an inbound message");
        assert_eq!(b.statuses.len(), 1);
        assert_eq!(b.outbound.len(), 1);
        let e = &b.outbound[0];
        assert_eq!(e.wamid, "wamid.OUT99");
        assert_eq!(e.to, "5500000000001");
        assert_eq!(e.timestamp, 1_730_092_860);
        match &e.kind {
            InboundKind::Text { body } => assert_eq!(body, "Já estou a caminho"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn kapso_webhook_batch_envelope() {
        let raw = br#"{
          "type": "whatsapp.message.received", "batch": true, "batch_info": {},
          "data": [
            { "message": { "id": "wamid.a", "type": "text", "from": "1", "text": {"body": "one"},
                "kapso": { "direction": "inbound" } },
              "conversation": { "phone_number": "1", "phone_number_id": "PN" }, "phone_number_id": "PN" },
            { "message": { "id": "wamid.b", "type": "text", "from": "2", "text": {"body": "two"},
                "kapso": { "direction": "inbound" } },
              "conversation": { "phone_number": "2", "phone_number_id": "PN" }, "phone_number_id": "PN" }
          ]
        }"#;
        let batches = parse_kapso_webhook(raw).unwrap();
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].messages[0].wamid, "wamid.a");
        assert_eq!(batches[1].messages[0].wamid, "wamid.b");
    }

    #[test]
    fn kapso_webhook_tolerates_odd_bodies() {
        assert!(parse_kapso_webhook(b"not json").is_err());
        assert_eq!(parse_kapso_webhook(b"{}").unwrap().len(), 0);
        assert_eq!(parse_kapso_webhook(br#"{"batch":true,"data":[]}"#).unwrap().len(), 0);
        // message without id → dropped, not a panic.
        assert_eq!(
            parse_kapso_webhook(br#"{"message":{"type":"text"},"phone_number_id":"PN"}"#)
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn meta_media_url_allow_list() {
        assert!(is_meta_media_url("https://lookaside.fbsbx.com/whatsapp_business/attachments/?mid=1&ext=2&hash=3"));
        assert!(is_meta_media_url("https://mmg.whatsapp.net/v/t62.7118-24/abc?ccb=11-4"));
        assert!(is_meta_media_url("https://scontent.xx.fbcdn.net/v/t1.0/x.jpg"));
        assert!(is_meta_media_url("https://graph.facebook.com/v25.0/123"));
        // Wrong scheme, look-alike hosts, or garbage → refused (bearer token never leaks).
        assert!(!is_meta_media_url("http://lookaside.fbsbx.com/x"));
        assert!(!is_meta_media_url("https://fbsbx.com.evil.example/x"));
        assert!(!is_meta_media_url("https://notfacebook.com/x"));
        assert!(!is_meta_media_url("https://example.com/whatsapp.net"));
        assert!(!is_meta_media_url("not a url"));
    }

    #[test]
    fn to_jid_appends_server_and_normalizes() {
        assert_eq!(to_jid("5511999999999"), "5511999999999@s.whatsapp.net");
        assert_eq!(to_jid("+55 11 99999-9999"), "5511999999999@s.whatsapp.net");
        assert_eq!(
            to_jid("5511999999999@s.whatsapp.net"),
            "5511999999999@s.whatsapp.net"
        );
    }

    #[test]
    fn hmac_and_signature_verify() {
        let secret = "fake-app-secret";
        let body = br#"{"object":"whatsapp_business_account","entry":[]}"#;
        // Independent computation with the hmac crate.
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let expected = hex::encode(mac.finalize().into_bytes());
        assert_eq!(hmac_sha256_hex(secret.as_bytes(), body), expected);

        let header = format!("sha256={expected}");
        assert!(verify_signature(secret, body, Some(&header)));
        assert!(verify_signature(
            secret,
            body,
            Some(&format!("sha256={}", expected.to_uppercase()))
        ));
        // Wrong secret / body / header shapes.
        assert!(!verify_signature("other-secret", body, Some(&header)));
        assert!(!verify_signature(secret, b"{}", Some(&header)));
        assert!(!verify_signature(secret, body, None));
        assert!(!verify_signature(secret, body, Some("")));
        assert!(!verify_signature(secret, body, Some(&expected)));
        assert!(!verify_signature(secret, body, Some("sha1=abcd")));
        assert!(!verify_signature(secret, body, Some("sha256=zz-not-hex")));
        assert!(!verify_signature(secret, body, Some("sha256=abcd")));
    }

    // ---- client construction -------------------------------------------------

    #[test]
    fn client_builds_graph_urls() {
        let c = CloudClient::new(creds(), None).unwrap();
        assert_eq!(
            c.graph_url("106540352242922/messages"),
            "https://graph.facebook.com/v25.0/106540352242922/messages"
        );
        let mut cr = creds();
        cr.graph_version = "".into();
        let c = CloudClient::new(cr, Some("  ")).unwrap();
        assert_eq!(
            c.graph_url("x"),
            format!("{GRAPH_BASE}/{DEFAULT_GRAPH_VERSION}/x")
        );
        assert_eq!(c.phone_number_id(), "106540352242922");
        assert!(format!("{c:?}").contains("106540352242922"));
        assert!(!format!("{c:?}").contains("EAAG-fake-token"));
    }

    #[test]
    fn client_accepts_proxy_and_rejects_garbage() {
        assert!(CloudClient::new(creds(), Some("socks5://127.0.0.1:1080")).is_ok());
        assert!(CloudClient::new(creds(), Some("http://user:pw@127.0.0.1:3128")).is_ok());
        let err = CloudClient::new(creds(), Some("::not a url::")).unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)), "{err}");
    }

    #[test]
    fn client_requires_waba_for_templates() {
        let mut cr = creds();
        cr.waba_id = None;
        let c = CloudClient::new(cr, None).unwrap();
        assert!(matches!(c.waba_id(), Err(Error::BadRequest(_))));
    }

    // ---- builders ------------------------------------------------------------

    #[test]
    fn text_payload_exact() {
        assert_eq!(
            text_payload("5511999999999@s.whatsapp.net", "Hello there", None),
            json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": "5511999999999",
                "type": "text",
                "text": { "preview_url": false, "body": "Hello there" }
            })
        );
        assert_eq!(
            text_payload(
                "+55 11 99999-9999",
                "See https://example.com/x",
                Some("wamid.HBgLMTY0NjcwNDM1OTUVAgARGBI1RjQyNUE3NEYxMzAzMzQ5MkEA")
            ),
            json!({
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": "5511999999999",
                "context": { "message_id": "wamid.HBgLMTY0NjcwNDM1OTUVAgARGBI1RjQyNUE3NEYxMzAzMzQ5MkEA" },
                "type": "text",
                "text": { "preview_url": true, "body": "See https://example.com/x" }
            })
        );
    }

    #[test]
    fn media_payload_exact_per_kind() {
        assert_eq!(
            media_payload(
                "5511999999999",
                MediaKind::Image,
                "1479537139650973",
                Some("The best succulent ever?"),
                None,
                None
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "image", "image": { "id": "1479537139650973", "caption": "The best succulent ever?" }
            })
        );
        assert_eq!(
            media_payload(
                "5511999999999",
                MediaKind::Video,
                "731675419373506",
                None,
                None,
                Some("wamid.HBgLquoted")
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "context": { "message_id": "wamid.HBgLquoted" },
                "type": "video", "video": { "id": "731675419373506" }
            })
        );
        assert_eq!(
            media_payload(
                "5511999999999",
                MediaKind::Audio,
                "1013859600285441",
                Some("ignored"),
                None,
                None
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "audio", "audio": { "id": "1013859600285441" }
            })
        );
        assert_eq!(
            media_payload(
                "5511999999999",
                MediaKind::Ptt,
                "1013859600285441",
                None,
                None,
                None
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "audio", "audio": { "id": "1013859600285441", "voice": true }
            })
        );
        assert_eq!(
            media_payload(
                "5511999999999",
                MediaKind::Document,
                "1376223850470843",
                Some("Your order confirmation (PDF)"),
                Some("order_abc123.pdf"),
                None
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "document",
                "document": { "id": "1376223850470843", "filename": "order_abc123.pdf", "caption": "Your order confirmation (PDF)" }
            })
        );
        assert_eq!(
            media_payload(
                "5511999999999",
                MediaKind::Sticker,
                "798882015472548",
                Some("no caption"),
                Some("x.webp"),
                None
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "sticker", "sticker": { "id": "798882015472548" }
            })
        );
    }

    #[test]
    fn location_payload_exact() {
        assert_eq!(
            location_payload(
                "5511999999999",
                37.44216251868683,
                -122.16153582049394,
                Some("Philz Coffee"),
                Some("101 Forest Ave, Palo Alto, CA 94301"),
                None
            ),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "location",
                "location": { "latitude": 37.44216251868683, "longitude": -122.16153582049394,
                              "name": "Philz Coffee", "address": "101 Forest Ave, Palo Alto, CA 94301" }
            })
        );
        assert_eq!(
            location_payload("5511999999999", -23.5, -46.6, None, Some(""), None),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "location", "location": { "latitude": -23.5, "longitude": -46.6 }
            })
        );
    }

    #[test]
    fn contacts_payload_exact() {
        let cards = vec![ContactCard {
            name: "Barbara J. Johnson".into(),
            phones: vec!["+1 650 555 9999".into(), "".into()],
        }];
        assert_eq!(
            contacts_payload("5511999999999", &cards, None),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "contacts",
                "contacts": [ {
                    "name": { "formatted_name": "Barbara J. Johnson", "first_name": "Barbara J. Johnson" },
                    "phones": [ { "phone": "+1 650 555 9999", "type": "CELL", "wa_id": "16505559999" } ]
                } ]
            })
        );
    }

    #[test]
    fn reaction_and_read_payloads_exact() {
        assert_eq!(
            reaction_payload("5511999999999", "wamid.HBgLtarget", "😀"),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "reaction", "reaction": { "message_id": "wamid.HBgLtarget", "emoji": "😀" }
            })
        );
        // Empty emoji = remove.
        assert_eq!(
            reaction_payload("5511999999999", "wamid.HBgLtarget", "")["reaction"]["emoji"],
            json!("")
        );
        assert_eq!(
            read_payload("wamid.HBgLinbound", false),
            json!({ "messaging_product": "whatsapp", "status": "read", "message_id": "wamid.HBgLinbound" })
        );
        assert_eq!(
            read_payload("wamid.HBgLinbound", true),
            json!({ "messaging_product": "whatsapp", "status": "read", "message_id": "wamid.HBgLinbound",
                    "typing_indicator": { "type": "text" } })
        );
    }

    #[test]
    fn template_payload_from_convenience_fields() {
        let req: TemplateSend = serde_json::from_value(json!({
            "name": "order_update",
            "language": "pt_BR",
            "body_params": ["Alex", 1234, { "type": "currency", "currency": { "fallback_value": "$100.99", "code": "USD", "amount_1000": 100990 } }],
            "header": { "type": "image", "media_id": "2871834006348767" },
            "buttons": [
                { "index": 0, "sub_type": "quick_reply", "payload": "YES" },
                { "index": 1, "sub_type": "url", "text": "abc123" },
                { "index": 2, "sub_type": "copy_code", "coupon_code": "WINTER25" }
            ],
            "reply_to": "wamid.HBgLquoted"
        }))
        .unwrap();
        assert_eq!(
            template_payload("5511999999999", &req).unwrap(),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "context": { "message_id": "wamid.HBgLquoted" },
                "type": "template",
                "template": {
                    "name": "order_update",
                    "language": { "code": "pt_BR" },
                    "components": [
                        { "type": "header", "parameters": [ { "type": "image", "image": { "id": "2871834006348767" } } ] },
                        { "type": "body", "parameters": [
                            { "type": "text", "text": "Alex" },
                            { "type": "text", "text": "1234" },
                            { "type": "currency", "currency": { "fallback_value": "$100.99", "code": "USD", "amount_1000": 100990 } }
                        ] },
                        { "type": "button", "sub_type": "quick_reply", "index": "0", "parameters": [ { "type": "payload", "payload": "YES" } ] },
                        { "type": "button", "sub_type": "url", "index": "1", "parameters": [ { "type": "text", "text": "abc123" } ] },
                        { "type": "button", "sub_type": "copy_code", "index": "2", "parameters": [ { "type": "coupon_code", "coupon_code": "WINTER25" } ] }
                    ]
                }
            })
        );
    }

    #[test]
    fn template_payload_headers_text_document_link() {
        let req: TemplateSend = serde_json::from_value(json!({
            "name": "t", "language": "en_US",
            "header": { "type": "text", "text": "December 1st" }
        }))
        .unwrap();
        assert_eq!(
            template_payload("5511999999999", &req).unwrap()["template"]["components"],
            json!([ { "type": "header", "parameters": [ { "type": "text", "text": "December 1st" } ] } ])
        );
        let req: TemplateSend = serde_json::from_value(json!({
            "name": "t", "language": "en_US",
            "header": { "type": "document", "link": "https://example.com/invoice.pdf", "filename": "invoice.pdf" }
        }))
        .unwrap();
        assert_eq!(
            template_payload("5511999999999", &req).unwrap()["template"]["components"],
            json!([ { "type": "header", "parameters": [ { "type": "document",
                "document": { "link": "https://example.com/invoice.pdf", "filename": "invoice.pdf" } } ] } ])
        );
        // The header type is case-insensitive everywhere — including the
        // document `filename`, which used to be dropped for "Document".
        let req: TemplateSend = serde_json::from_value(json!({
            "name": "t", "language": "en_US",
            "header": { "type": "Document", "media_id": "1376223850470843", "filename": "invoice.pdf" }
        }))
        .unwrap();
        assert_eq!(
            template_payload("5511999999999", &req).unwrap()["template"]["components"],
            json!([ { "type": "header", "parameters": [ { "type": "document",
                "document": { "id": "1376223850470843", "filename": "invoice.pdf" } } ] } ])
        );
    }

    #[test]
    fn template_payload_without_params_omits_components() {
        let req: TemplateSend =
            serde_json::from_value(json!({ "name": "hello_world", "language": "en_US" })).unwrap();
        assert_eq!(
            template_payload("5511999999999", &req).unwrap(),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "template",
                "template": { "name": "hello_world", "language": { "code": "en_US" } }
            })
        );
    }

    #[test]
    fn template_payload_components_verbatim_wins() {
        let comps = json!([ { "type": "body", "parameters": [ { "type": "text", "parameter_name": "first_name", "text": "Jessica" } ] } ]);
        let req: TemplateSend = serde_json::from_value(json!({
            "name": "order_confirmation", "language": "en_US",
            "body_params": ["ignored"], "header": { "type": "text", "text": "ignored" },
            "components": comps
        }))
        .unwrap();
        let v = template_payload("5511999999999", &req).unwrap();
        assert_eq!(v["template"]["components"], comps);
    }

    #[test]
    fn template_payload_validation_errors() {
        let bad = |v: Value| {
            let req: TemplateSend = serde_json::from_value(v).unwrap();
            template_payload("5511999999999", &req).unwrap_err()
        };
        assert!(matches!(
            bad(json!({ "name": "", "language": "en" })),
            Error::BadRequest(_)
        ));
        assert!(matches!(
            bad(json!({ "name": "t", "language": " " })),
            Error::BadRequest(_)
        ));
        assert!(matches!(
            bad(json!({ "name": "t", "language": "en", "header": { "type": "text" } })),
            Error::BadRequest(_)
        ));
        assert!(matches!(
            bad(json!({ "name": "t", "language": "en", "header": { "type": "image" } })),
            Error::BadRequest(_)
        ));
        assert!(matches!(
            bad(json!({ "name": "t", "language": "en", "header": { "type": "gif", "link": "x" } })),
            Error::BadRequest(_)
        ));
        assert!(matches!(
            bad(
                json!({ "name": "t", "language": "en", "buttons": [ { "index": 0, "sub_type": "quick_reply" } ] })
            ),
            Error::BadRequest(_)
        ));
        assert!(matches!(
            bad(
                json!({ "name": "t", "language": "en", "buttons": [ { "index": 0, "sub_type": "flow" } ] })
            ),
            Error::BadRequest(_)
        ));
    }

    #[test]
    fn interactive_button_exact() {
        let req: InteractiveSend = serde_json::from_value(json!({
            "type": "button",
            "header": { "type": "image", "media_id": "2762702990552401" },
            "body": "Hi Pablo! Use the buttons if you need to reschedule.",
            "footer": "Lucky Shrub: Your gateway to succulents!™",
            "buttons": [ { "id": "change-button", "title": "Change" }, { "id": "cancel-button", "title": "Cancel" } ]
        }))
        .unwrap();
        assert_eq!(
            interactive_payload("5511999999999", &req).unwrap(),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "interactive",
                "interactive": {
                    "type": "button",
                    "header": { "type": "image", "image": { "id": "2762702990552401" } },
                    "body": { "text": "Hi Pablo! Use the buttons if you need to reschedule." },
                    "footer": { "text": "Lucky Shrub: Your gateway to succulents!™" },
                    "action": { "buttons": [
                        { "type": "reply", "reply": { "id": "change-button", "title": "Change" } },
                        { "type": "reply", "reply": { "id": "cancel-button", "title": "Cancel" } }
                    ] }
                }
            })
        );
    }

    #[test]
    fn interactive_list_exact() {
        let req: InteractiveSend = serde_json::from_value(json!({
            "type": "list",
            "header": { "type": "text", "text": "Choose Shipping Option" },
            "body": "Which shipping option do you prefer?",
            "footer": "Lucky Shrub: Your gateway to succulents™",
            "button": "Shipping Options",
            "sections": [
                { "title": "I want it ASAP!", "rows": [
                    { "id": "priority_express", "title": "Priority Mail Express", "description": "Next Day to 2 Days" },
                    { "id": "priority_mail", "title": "Priority Mail", "description": "1–3 Days" } ] },
                { "title": "I can wait a bit", "rows": [
                    { "id": "usps_ground_advantage", "title": "USPS Ground Advantage", "description": "2–5 Days" },
                    { "id": "media_mail", "title": "Media Mail" } ] }
            ],
            "reply_to": "wamid.HBgLquoted"
        }))
        .unwrap();
        assert_eq!(
            interactive_payload("5511999999999", &req).unwrap(),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "context": { "message_id": "wamid.HBgLquoted" },
                "type": "interactive",
                "interactive": {
                    "type": "list",
                    "header": { "type": "text", "text": "Choose Shipping Option" },
                    "body": { "text": "Which shipping option do you prefer?" },
                    "footer": { "text": "Lucky Shrub: Your gateway to succulents™" },
                    "action": {
                        "button": "Shipping Options",
                        "sections": [
                            { "title": "I want it ASAP!", "rows": [
                                { "id": "priority_express", "title": "Priority Mail Express", "description": "Next Day to 2 Days" },
                                { "id": "priority_mail", "title": "Priority Mail", "description": "1–3 Days" } ] },
                            { "title": "I can wait a bit", "rows": [
                                { "id": "usps_ground_advantage", "title": "USPS Ground Advantage", "description": "2–5 Days" },
                                { "id": "media_mail", "title": "Media Mail" } ] }
                        ]
                    }
                }
            })
        );
    }

    #[test]
    fn interactive_cta_url_exact() {
        let req: InteractiveSend = serde_json::from_value(json!({
            "type": "cta_url",
            "header": { "type": "image", "link": "https://example.com/banner.png" },
            "body": "Tap the button below to see available dates.",
            "footer": "Dates subject to change.",
            "cta": { "display_text": "See Dates", "url": "https://example.com/dates?clickID=abc" }
        }))
        .unwrap();
        assert_eq!(
            interactive_payload("5511999999999", &req).unwrap(),
            json!({
                "messaging_product": "whatsapp", "recipient_type": "individual", "to": "5511999999999",
                "type": "interactive",
                "interactive": {
                    "type": "cta_url",
                    "header": { "type": "image", "image": { "link": "https://example.com/banner.png" } },
                    "body": { "text": "Tap the button below to see available dates." },
                    "footer": { "text": "Dates subject to change." },
                    "action": { "name": "cta_url", "parameters": { "display_text": "See Dates", "url": "https://example.com/dates?clickID=abc" } }
                }
            })
        );
    }

    #[test]
    fn interactive_validation_errors() {
        let bad = |v: Value| {
            let req: InteractiveSend = serde_json::from_value(v).unwrap();
            let err = interactive_payload("5511999999999", &req).unwrap_err();
            assert!(matches!(err, Error::BadRequest(_)), "{err}");
            err.to_string()
        };
        // Too many buttons.
        let e = bad(json!({ "type": "button", "body": "b", "buttons": [
            {"id":"1","title":"A"},{"id":"2","title":"B"},{"id":"3","title":"C"},{"id":"4","title":"D"} ] }));
        assert!(e.contains("at most 3 buttons"), "{e}");
        // Title too long (21 chars).
        let e = bad(
            json!({ "type": "button", "body": "b", "buttons": [ {"id":"1","title":"abcdefghijklmnopqrstu"} ] }),
        );
        assert!(e.contains("exceeds 20 chars"), "{e}");
        // No buttons / empty body / unknown type.
        bad(json!({ "type": "button", "body": "b" }));
        bad(json!({ "type": "button", "body": " ", "buttons": [ {"id":"1","title":"A"} ] }));
        bad(json!({ "type": "carousel", "body": "b" }));
        // List: >10 rows total, >10 sections, missing button text, long button, media header.
        let rows: Vec<Value> = (0..11)
            .map(|i| json!({ "id": format!("r{i}"), "title": format!("Row {i}") }))
            .collect();
        let e = bad(
            json!({ "type": "list", "body": "b", "button": "Menu", "sections": [ { "rows": rows } ] }),
        );
        assert!(e.contains("at most 10 rows"), "{e}");
        let sections: Vec<Value> = (0..11)
            .map(|i| json!({ "rows": [ { "id": format!("r{i}"), "title": "x" } ] }))
            .collect();
        let e = bad(json!({ "type": "list", "body": "b", "button": "Menu", "sections": sections }));
        assert!(e.contains("at most 10 sections"), "{e}");
        bad(
            json!({ "type": "list", "body": "b", "sections": [ { "rows": [ { "id": "r", "title": "x" } ] } ] }),
        );
        bad(
            json!({ "type": "list", "body": "b", "button": "abcdefghijklmnopqrstu", "sections": [ { "rows": [ { "id": "r", "title": "x" } ] } ] }),
        );
        bad(
            json!({ "type": "list", "body": "b", "button": "Menu", "header": { "type": "image", "media_id": "1" },
                    "sections": [ { "rows": [ { "id": "r", "title": "x" } ] } ] }),
        );
        // cta_url needs display_text + url.
        bad(json!({ "type": "cta_url", "body": "b" }));
        bad(json!({ "type": "cta_url", "body": "b", "cta": { "display_text": "Go", "url": "" } }));
        bad(
            json!({ "type": "cta_url", "body": "b", "cta": { "display_text": "", "url": "https://x" } }),
        );
        // Footer / header text limits.
        bad(
            json!({ "type": "button", "body": "b", "footer": "f".repeat(61), "buttons": [ {"id":"1","title":"A"} ] }),
        );
        bad(
            json!({ "type": "button", "body": "b", "header": { "type": "text", "text": "h".repeat(61) }, "buttons": [ {"id":"1","title":"A"} ] }),
        );
    }

    // ---- webhook parsing -----------------------------------------------------

    fn envelope(value: Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "object": "whatsapp_business_account",
            "entry": [ { "id": "102290129340398", "changes": [ { "field": "messages", "value": value } ] } ]
        }))
        .unwrap()
    }

    fn inbound(msg: Value) -> InboundMessage {
        let mut value = json!({
            "messaging_product": "whatsapp",
            "metadata": { "display_phone_number": "15550783881", "phone_number_id": "106540352242922" },
            "contacts": [ { "profile": { "name": "Sheena Nelson" }, "wa_id": "16505551234" } ],
            "messages": [ msg ]
        });
        // Messages of type "system" carry no contacts[].
        if value["messages"][0]["type"] == "system" {
            value.as_object_mut().unwrap().remove("contacts");
        }
        let mut batches = parse_webhook(&envelope(value)).unwrap();
        assert_eq!(batches.len(), 1);
        let b = batches.remove(0);
        assert_eq!(b.phone_number_id, "106540352242922");
        assert_eq!(b.display_phone_number.as_deref(), Some("15550783881"));
        assert_eq!(b.messages.len(), 1);
        assert!(b.statuses.is_empty());
        b.messages.into_iter().next().unwrap()
    }

    #[test]
    fn webhook_text() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLMTY1MDM4Nzk0MzkVAgASGBQzQTRBNjU5OUFFRTAzODEwMTQ0RgA=",
            "timestamp": "1749416383", "type": "text", "text": { "body": "Does it come in another color?" }
        }));
        assert_eq!(
            m.wamid,
            "wamid.HBgLMTY1MDM4Nzk0MzkVAgASGBQzQTRBNjU5OUFFRTAzODEwMTQ0RgA="
        );
        assert_eq!(m.from, "16505551234");
        assert_eq!(m.timestamp, 1749416383);
        assert_eq!(m.push_name.as_deref(), Some("Sheena Nelson"));
        assert_eq!(m.wa_id.as_deref(), Some("16505551234"));
        assert_eq!(m.from_user_id, None);
        assert_eq!(m.context_id, None);
        assert_eq!(
            m.kind,
            InboundKind::Text {
                body: "Does it come in another color?".into()
            }
        );
        assert_eq!(m.raw["type"], "text");
    }

    #[test]
    fn webhook_image_with_url_and_caption() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLimg", "timestamp": "1744344496", "type": "image",
            "image": { "caption": "Taj Mahal", "mime_type": "image/jpeg", "sha256": "SfInY0gGKTsJlUWbwxC1k+FAD0FZHvzwfpvO0zX0GUI=",
                       "id": "1003383421387256", "url": "https://lookaside.fbsbx.com/whatsapp_business/attachments/?mid=133" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Media {
                msg_type: "image",
                media_id: "1003383421387256".into(),
                mime: Some("image/jpeg".into()),
                sha256: Some("SfInY0gGKTsJlUWbwxC1k+FAD0FZHvzwfpvO0zX0GUI=".into()),
                caption: Some("Taj Mahal".into()),
                filename: None,
                url: Some(
                    "https://lookaside.fbsbx.com/whatsapp_business/attachments/?mid=133".into()
                ),
                voice: false,
            }
        );
    }

    #[test]
    fn webhook_audio_voice_is_ptt_and_plain_audio_is_audio() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLptt", "timestamp": "1744344496", "type": "audio",
            "audio": { "mime_type": "audio/ogg; codecs=opus", "sha256": "wvqX", "id": "1908647269898587", "voice": true }
        }));
        match m.kind {
            InboundKind::Media {
                msg_type,
                media_id,
                mime,
                voice,
                url,
                ..
            } => {
                assert_eq!(msg_type, "ptt");
                assert_eq!(media_id, "1908647269898587");
                assert_eq!(mime.as_deref(), Some("audio/ogg; codecs=opus"));
                assert!(voice);
                assert_eq!(url, None);
            }
            other => panic!("unexpected {other:?}"),
        }
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLaudio", "timestamp": "1744344496", "type": "audio",
            "audio": { "mime_type": "audio/mpeg", "id": "1908647269898588" }
        }));
        assert!(matches!(
            m.kind,
            InboundKind::Media {
                msg_type: "audio",
                voice: false,
                ..
            }
        ));
    }

    #[test]
    fn webhook_video_document_sticker() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLvid", "timestamp": "1744344496", "type": "video",
            "video": { "caption": "Timelapse of growth", "mime_type": "video/mp4", "sha256": "vdGU", "id": "731675419373506" }
        }));
        assert!(matches!(
            m.kind,
            InboundKind::Media {
                msg_type: "video",
                ..
            }
        ));
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLdoc", "timestamp": "1744344496", "type": "document",
            "document": { "caption": "my receipt", "filename": "receipt.pdf", "mime_type": "application/pdf", "sha256": "V5OP", "id": "622684793477189" }
        }));
        match m.kind {
            InboundKind::Media {
                msg_type,
                filename,
                caption,
                ..
            } => {
                assert_eq!(msg_type, "document");
                assert_eq!(filename.as_deref(), Some("receipt.pdf"));
                assert_eq!(caption.as_deref(), Some("my receipt"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLstk", "timestamp": "1744344496", "type": "sticker",
            "sticker": { "mime_type": "image/webp", "sha256": "wvqX", "id": "1908647269898587", "animated": true }
        }));
        match m.kind {
            InboundKind::Media { msg_type, mime, .. } => {
                assert_eq!(msg_type, "sticker");
                assert_eq!(mime.as_deref(), Some("image/webp"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn webhook_location() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLloc", "timestamp": "1744344496", "type": "location",
            "location": { "address": "101 Forest Ave, Palo Alto, CA 94301", "latitude": 37.44221496582,
                          "longitude": -122.16165924072, "name": "Philz Coffee", "url": "https://philzcoffee.com/" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Location {
                latitude: 37.44221496582,
                longitude: -122.16165924072,
                name: Some("Philz Coffee".into()),
                address: Some("101 Forest Ave, Palo Alto, CA 94301".into()),
            }
        );
        // Stringly-typed coordinates are accepted too.
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLloc2", "timestamp": "1744344496", "type": "location",
            "location": { "latitude": "-23.5", "longitude": "-46.6" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Location {
                latitude: -23.5,
                longitude: -46.6,
                name: None,
                address: None
            }
        );
    }

    #[test]
    fn webhook_contacts() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLct", "timestamp": "1744344496", "type": "contacts",
            "contacts": [
                { "name": { "first_name": "Barbara", "last_name": "Johnson", "formatted_name": "Barbara J. Johnson" },
                  "org": { "company": "Social Tsunami" },
                  "phones": [ { "phone": "+1 (415) 555-0829", "wa_id": "14125550829", "type": "MOBILE" } ] },
                { "name": { "first_name": "Ana", "last_name": "Silva" }, "phones": [ { "wa_id": "5511999999999" } ] }
            ]
        }));
        assert_eq!(
            m.kind,
            InboundKind::Contacts(vec![
                ContactCard {
                    name: "Barbara J. Johnson".into(),
                    phones: vec!["+1 (415) 555-0829".into()]
                },
                ContactCard {
                    name: "Ana Silva".into(),
                    phones: vec!["5511999999999".into()]
                },
            ])
        );
    }

    #[test]
    fn webhook_reaction_and_removal() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLre", "timestamp": "1749419544", "type": "reaction",
            "reaction": { "message_id": "wamid.HBgLMTQxMjU1NTA4MjkVAgASGBQzQUNCNjk5RDUwNUZGMUZEM0VBRAA=", "emoji": "👍" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Reaction {
                message_id: "wamid.HBgLMTQxMjU1NTA4MjkVAgASGBQzQUNCNjk5RDUwNUZGMUZEM0VBRAA=".into(),
                emoji: Some("👍".into())
            }
        );
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLre2", "timestamp": "1749419544", "type": "reaction",
            "reaction": { "message_id": "wamid.HBgLtarget" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Reaction {
                message_id: "wamid.HBgLtarget".into(),
                emoji: None
            }
        );
    }

    #[test]
    fn webhook_button_and_interactive_replies_with_context() {
        let m = inbound(json!({
            "context": { "from": "15550783881", "id": "wamid.HBgLtemplate" },
            "from": "16505551234", "id": "wamid.HBgLbtn", "timestamp": "1750091045", "type": "button",
            "button": { "payload": "Unsubscribe", "text": "Unsubscribe" }
        }));
        assert_eq!(m.context_id.as_deref(), Some("wamid.HBgLtemplate"));
        assert_eq!(
            m.kind,
            InboundKind::Button {
                payload: Some("Unsubscribe".into()),
                text: Some("Unsubscribe".into())
            }
        );

        let m = inbound(json!({
            "context": { "from": "15550783881", "id": "wamid.HBgLinter" },
            "from": "16505551234", "id": "wamid.HBgLbr", "timestamp": "1750025136", "type": "interactive",
            "interactive": { "type": "button_reply", "button_reply": { "id": "cancel-button", "title": "Cancel" } }
        }));
        assert_eq!(m.context_id.as_deref(), Some("wamid.HBgLinter"));
        assert_eq!(
            m.kind,
            InboundKind::Interactive {
                kind: "button_reply".into(),
                id: "cancel-button".into(),
                title: Some("Cancel".into()),
                description: None
            }
        );

        let m = inbound(json!({
            "context": { "from": "15550783881", "id": "wamid.HBgLlist" },
            "from": "16505551234", "id": "wamid.HBgLlr", "timestamp": "1749854575", "type": "interactive",
            "interactive": { "type": "list_reply", "list_reply": { "id": "priority_express", "title": "Priority Mail Express", "description": "Next Day to 2 Days" } }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Interactive {
                kind: "list_reply".into(),
                id: "priority_express".into(),
                title: Some("Priority Mail Express".into()),
                description: Some("Next Day to 2 Days".into())
            }
        );

        // Flow replies and friends → Unknown, but still parsed.
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLnfm", "timestamp": "1749854575", "type": "interactive",
            "interactive": { "type": "nfm_reply", "nfm_reply": { "name": "flow", "body": "Sent", "response_json": "{}" } }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Unknown {
                type_name: "interactive/nfm_reply".into()
            }
        );
    }

    #[test]
    fn webhook_unsupported_order_system_unknown() {
        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLuns", "timestamp": "1750090702",
            "errors": [ { "code": 131051, "title": "Message type unknown", "message": "Message type unknown",
                          "error_data": { "details": "Message type is currently not supported." } } ],
            "type": "unsupported", "unsupported": { "type": "edit" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Unknown {
                type_name: "unsupported".into()
            }
        );
        assert_eq!(m.raw["errors"][0]["code"], 131051);

        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLord", "timestamp": "1750096325", "type": "order",
            "order": { "catalog_id": "194836987003835", "text": "Love these!", "product_items": [] }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Unknown {
                type_name: "order".into()
            }
        );

        let m = inbound(json!({
            "from": "16505551234", "id": "wamid.HBgLsys", "timestamp": "1750269342", "type": "system",
            "system": { "body": "User changed number", "wa_id": "12195555358", "type": "user_changed_number" }
        }));
        assert_eq!(
            m.kind,
            InboundKind::Unknown {
                type_name: "system".into()
            }
        );
        assert_eq!(m.push_name, None);
        assert_eq!(m.from, "16505551234");

        // No type at all.
        let m =
            inbound(json!({ "from": "16505551234", "id": "wamid.HBgLnotype", "timestamp": "1" }));
        assert_eq!(
            m.kind,
            InboundKind::Unknown {
                type_name: "unknown".into()
            }
        );
    }

    #[test]
    fn webhook_bsuid_era_without_from_uses_contact_wa_id_or_user_id() {
        let raw = envelope(json!({
            "messaging_product": "whatsapp",
            "metadata": { "display_phone_number": "15550783881", "phone_number_id": "106540352242922" },
            "contacts": [ { "profile": { "name": "Sheena Nelson" }, "wa_id": "16505551234", "user_id": "US.13491208655302741918" } ],
            "messages": [ { "from_user_id": "US.13491208655302741918", "id": "wamid.HBgLbsuid", "timestamp": "1749416383",
                            "type": "text", "text": { "body": "hi" } } ]
        }));
        let m = parse_webhook(&raw).unwrap().remove(0).messages.remove(0);
        assert_eq!(m.from, "16505551234");
        assert_eq!(m.from_user_id.as_deref(), Some("US.13491208655302741918"));
        assert_eq!(m.wa_id.as_deref(), Some("16505551234"));

        let raw = envelope(json!({
            "messaging_product": "whatsapp",
            "metadata": { "phone_number_id": "106540352242922" },
            "contacts": [ { "profile": { "name": "Nobody" }, "user_id": "US.13491208655302741918" } ],
            "messages": [ { "id": "wamid.HBgLbsuid2", "timestamp": "1749416383", "type": "text", "text": { "body": "hi" } } ]
        }));
        let m = parse_webhook(&raw).unwrap().remove(0).messages.remove(0);
        assert_eq!(m.from, "US.13491208655302741918");
        assert_eq!(m.from_user_id.as_deref(), Some("US.13491208655302741918"));
    }

    #[test]
    fn webhook_multi_contact_batch_matches_sender_by_user_id_and_never_guesses() {
        // Two BSUID senders without phone numbers in one batch: each message
        // must attach to ITS contact (matched via from_user_id == user_id).
        let raw = envelope(json!({
            "messaging_product": "whatsapp",
            "metadata": { "phone_number_id": "106540352242922" },
            "contacts": [
                { "profile": { "name": "Alice" }, "user_id": "US.1000000000000000001" },
                { "profile": { "name": "Bob" }, "user_id": "US.2000000000000000002" }
            ],
            "messages": [
                { "from_user_id": "US.1000000000000000001", "id": "wamid.HBgLmc1", "timestamp": "1", "type": "text", "text": { "body": "a" } },
                { "from_user_id": "US.2000000000000000002", "id": "wamid.HBgLmc2", "timestamp": "2", "type": "text", "text": { "body": "b" } },
                { "from_user_id": "US.3000000000000000003", "id": "wamid.HBgLmc3", "timestamp": "3", "type": "text", "text": { "body": "c" } }
            ]
        }));
        let msgs = parse_webhook(&raw).unwrap().remove(0).messages;
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].from, "US.1000000000000000001");
        assert_eq!(msgs[0].push_name.as_deref(), Some("Alice"));
        assert_eq!(msgs[1].from, "US.2000000000000000002");
        assert_eq!(msgs[1].push_name.as_deref(), Some("Bob"));
        // Unmatched sender in a multi-contact batch: keep its own id, no
        // borrowed push_name / wa_id from an unrelated contact.
        assert_eq!(msgs[2].from, "US.3000000000000000003");
        assert_eq!(msgs[2].push_name, None);
        assert_eq!(msgs[2].wa_id, None);

        // Mixed: one contact with a phone (wa_id) + one BSUID-only.
        let raw = envelope(json!({
            "messaging_product": "whatsapp",
            "metadata": { "phone_number_id": "106540352242922" },
            "contacts": [
                { "profile": { "name": "Phone" }, "wa_id": "16505551234" },
                { "profile": { "name": "Hidden" }, "user_id": "US.2000000000000000002" }
            ],
            "messages": [
                { "from_user_id": "US.2000000000000000002", "id": "wamid.HBgLmc4", "timestamp": "1", "type": "text", "text": { "body": "x" } },
                { "from": "16505551234", "id": "wamid.HBgLmc5", "timestamp": "2", "type": "text", "text": { "body": "y" } }
            ]
        }));
        let msgs = parse_webhook(&raw).unwrap().remove(0).messages;
        assert_eq!(msgs[0].from, "US.2000000000000000002");
        assert_eq!(msgs[0].push_name.as_deref(), Some("Hidden"));
        assert_eq!(msgs[1].from, "16505551234");
        assert_eq!(msgs[1].push_name.as_deref(), Some("Phone"));
    }

    #[test]
    fn webhook_statuses_all_kinds() {
        let raw = envelope(json!({
            "messaging_product": "whatsapp",
            "metadata": { "display_phone_number": "15550783881", "phone_number_id": "106540352242922" },
            "statuses": [
                { "id": "wamid.HBgLs1", "status": "sent", "timestamp": "1750030073", "recipient_id": "16505551234",
                  "conversation": { "id": "72b14d6bd5407799e66f64d1b338e567", "expiration_timestamp": "1750116480", "origin": { "type": "marketing" } },
                  "pricing": { "billable": true, "pricing_model": "PMP", "type": "regular", "category": "marketing" } },
                { "id": "wamid.HBgLs2", "status": "delivered", "timestamp": "1750263773", "recipient_id": "16505551234" },
                { "id": "wamid.HBgLs3", "status": "read", "timestamp": "1750030073", "recipient_id": "16505551234" },
                { "id": "wamid.HBgLs4", "status": "played", "timestamp": "1750030074", "recipient_id": "16505551234" },
                { "id": "wamid.HBgLs5", "status": "failed", "timestamp": "1751142888", "recipient_id": "16505551234",
                  "errors": [ { "code": 131049, "title": "This message was not delivered to maintain healthy ecosystem engagement.",
                                "message": "This message was not delivered to maintain healthy ecosystem engagement.",
                                "error_data": { "details": "In order to maintain a healthy ecosystem engagement, the message failed to be delivered." },
                                "href": "/documentation/business-messaging/whatsapp/support/error-codes" } ] },
                { "id": "wamid.HBgLs6", "status": "failed", "timestamp": "1751142889", "recipient_id": "16505551234",
                  "errors": [ { "code": 131047, "title": "Re-engagement message" } ] },
                { "status": "sent", "timestamp": "1", "recipient_id": "16505551234" }
            ]
        }));
        let b = parse_webhook(&raw).unwrap().remove(0);
        assert!(b.messages.is_empty());
        assert_eq!(b.statuses.len(), 6, "entry without id is skipped");
        assert_eq!(
            b.statuses[0],
            StatusUpdate {
                wamid: "wamid.HBgLs1".into(),
                recipient: "16505551234".into(),
                status: "sent".into(),
                timestamp: 1750030073,
                error: None
            }
        );
        assert_eq!(b.statuses[1].status, "delivered");
        assert_eq!(b.statuses[2].status, "read");
        assert_eq!(b.statuses[3].status, "read", "played folds into read");
        assert_eq!(b.statuses[3].timestamp, 1750030074);
        assert_eq!(b.statuses[4].status, "failed");
        assert_eq!(
            b.statuses[4].error.as_deref(),
            Some("131049: This message was not delivered to maintain healthy ecosystem engagement. — In order to maintain a healthy ecosystem engagement, the message failed to be delivered.")
        );
        assert_eq!(
            b.statuses[5].error.as_deref(),
            Some("131047: Re-engagement message")
        );
    }

    #[test]
    fn webhook_multiple_entries_ignores_other_fields_keeps_errors() {
        let raw = serde_json::to_vec(&json!({
            "object": "whatsapp_business_account",
            "entry": [
                { "id": "102290129340398", "changes": [
                    { "field": "message_template_status_update", "value": { "event": "APPROVED", "message_template_id": 1 } },
                    { "field": "messages", "value": {
                        "messaging_product": "whatsapp",
                        "metadata": { "display_phone_number": "15550783881", "phone_number_id": "106540352242922" },
                        "errors": [ { "code": 130429, "title": "Rate limit hit", "message": "Rate limit hit",
                                      "error_data": { "details": "too many" } } ] } },
                    { "field": "messages", "value": { "messaging_product": "whatsapp", "messages": [ { "id": "x", "type": "text" } ] } }
                ] },
                { "id": "other", "changes": [
                    { "field": "messages", "value": {
                        "metadata": { "phone_number_id": "222222222222222" },
                        "contacts": [ { "profile": { "name": "A" }, "wa_id": "5511999999999" } ],
                        "messages": [ { "from": "5511999999999", "id": "wamid.HBgLa", "timestamp": "2", "type": "text", "text": { "body": "a" } },
                                      { "from": "5511999999999", "timestamp": "2", "type": "text", "text": { "body": "no id → skipped" } } ],
                        "statuses": [ { "id": "wamid.HBgLb", "status": "delivered", "timestamp": "3", "recipient_id": "5511999999999" } ] } }
                ] }
            ]
        }))
        .unwrap();
        let batches = parse_webhook(&raw).unwrap();
        assert_eq!(
            batches.len(),
            2,
            "template update + metadata-less change skipped"
        );
        assert_eq!(batches[0].phone_number_id, "106540352242922");
        assert_eq!(batches[0].errors.len(), 1);
        assert_eq!(batches[0].errors[0]["code"], 130429);
        assert!(batches[0].messages.is_empty() && batches[0].statuses.is_empty());
        assert_eq!(batches[1].phone_number_id, "222222222222222");
        assert_eq!(batches[1].messages.len(), 1);
        assert_eq!(batches[1].messages[0].push_name.as_deref(), Some("A"));
        assert_eq!(batches[1].statuses.len(), 1);
        assert_eq!(batches[1].statuses[0].wamid, "wamid.HBgLb");
    }

    #[test]
    fn webhook_tolerates_odd_bodies() {
        assert!(parse_webhook(b"{}").unwrap().is_empty());
        assert!(
            parse_webhook(br#"{"object":"page","entry":[{"changes":"nope"}]}"#)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            parse_webhook(b"not json"),
            Err(Error::BadRequest(_))
        ));
    }

    // ---- error mapping ---------------------------------------------------------

    fn graph_err(code: i64, message: &str, details: Option<&str>) -> Vec<u8> {
        let mut e = json!({ "message": message, "type": "OAuthException", "code": code, "fbtrace_id": "Az8or2yhqkZfEZ" });
        if let Some(d) = details {
            e["error_data"] = json!({ "messaging_product": "whatsapp", "details": d });
        }
        serde_json::to_vec(&json!({ "error": e })).unwrap()
    }

    #[test]
    fn map_graph_error_table() {
        let e = map_graph_error(400, &graph_err(131047, "(#131047) Re-engagement message", Some("More than 24 hours have passed since the recipient last replied to the sender number.")));
        match e {
            Error::BadRequest(m) => assert!(m.contains("131047") && m.contains("template"), "{m}"),
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            map_graph_error(401, &graph_err(190, "Error validating access token", None)),
            Error::Unauthorized
        ));
        assert!(matches!(
            map_graph_error(400, &graph_err(190, "Error validating access token", None)),
            Error::Unauthorized
        ));
        assert!(matches!(
            map_graph_error(401, &graph_err(999, "whatever", None)),
            Error::Unauthorized
        ));
        let e = map_graph_error(
            400,
            &graph_err(
                130429,
                "(#130429) Rate limit hit",
                Some("Cloud API message throughput has been reached."),
            ),
        );
        match e {
            Error::Conflict(m) => {
                assert!(m.contains("rate limited") && m.contains("130429"), "{m}")
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            map_graph_error(400, &graph_err(131056, "pair rate", None)),
            Error::Conflict(_)
        ));
        assert!(matches!(
            map_graph_error(400, &graph_err(80007, "waba rate", None)),
            Error::Conflict(_)
        ));
        let e = map_graph_error(
            400,
            &graph_err(
                100,
                "(#100) Invalid parameter",
                Some("The parameter to is required."),
            ),
        );
        match e {
            Error::BadRequest(m) => assert_eq!(
                m,
                "cloud: 100 (#100) Invalid parameter — The parameter to is required."
            ),
            other => panic!("{other:?}"),
        }
        for code in [
            131008, 131009, 132000, 132001, 132012, 132018, 131026, 131030,
        ] {
            assert!(
                matches!(
                    map_graph_error(400, &graph_err(code, "x", None)),
                    Error::BadRequest(_)
                ),
                "{code}"
            );
        }
        assert!(matches!(
            map_graph_error(403, &graph_err(200, "Permissions error", None)),
            Error::Forbidden(_)
        ));
        let e = map_graph_error(500, &graph_err(131000, "Something went wrong", None));
        match e {
            Error::Internal(m) => assert!(m.to_string().contains("131000"), "{m}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn map_graph_error_non_json_by_status() {
        assert!(matches!(
            map_graph_error(404, b"Not Found"),
            Error::NotFound(_)
        ));
        assert!(matches!(map_graph_error(401, b""), Error::Unauthorized));
        assert!(matches!(
            map_graph_error(403, b"<html>"),
            Error::Forbidden(_)
        ));
        assert!(matches!(map_graph_error(400, b"bad"), Error::BadRequest(_)));
        assert!(matches!(
            map_graph_error(429, b"slow down"),
            Error::Conflict(_)
        ));
        assert!(matches!(
            map_graph_error(502, b"<html>bad gateway</html>"),
            Error::Internal(_)
        ));
        // JSON but not an error envelope.
        assert!(matches!(
            map_graph_error(500, br#"{"foo":1}"#),
            Error::Internal(_)
        ));
    }

    // ---- live (opt-in) -----------------------------------------------------------

    /// Live smoke against Graph. Gated: `RUWA_CLOUD_LIVE_TEST=1` plus
    /// `RUWA_CLOUD_PHONE_NUMBER_ID`, `RUWA_CLOUD_ACCESS_TOKEN`, `RUWA_CLOUD_TEST_TO`.
    #[tokio::test]
    #[ignore]
    async fn live_validate_and_send_text() {
        if std::env::var("RUWA_CLOUD_LIVE_TEST").ok().as_deref() != Some("1") {
            eprintln!("skipping: RUWA_CLOUD_LIVE_TEST!=1");
            return;
        }
        let creds = CloudCreds {
            provider: CloudProvider::Meta,
            phone_number_id: std::env::var("RUWA_CLOUD_PHONE_NUMBER_ID")
                .expect("RUWA_CLOUD_PHONE_NUMBER_ID"),
            waba_id: std::env::var("RUWA_CLOUD_WABA_ID").ok(),
            access_token: std::env::var("RUWA_CLOUD_ACCESS_TOKEN")
                .expect("RUWA_CLOUD_ACCESS_TOKEN"),
            api_key: None,
            base_url: None,
            app_secret: None,
            verify_token: None,
            graph_version: std::env::var("RUWA_CLOUD_GRAPH_VERSION")
                .unwrap_or_else(|_| DEFAULT_GRAPH_VERSION.into()),
        };
        let to = std::env::var("RUWA_CLOUD_TEST_TO").expect("RUWA_CLOUD_TEST_TO");
        let c = CloudClient::new(creds, std::env::var("RUWA_CLOUD_PROXY").ok().as_deref()).unwrap();
        let info = c.validate().await.expect("validate");
        eprintln!("phone: {info:?}");
        let r = c
            .send(text_payload(&to, "ruwa cloud live test", None))
            .await
            .expect("send");
        eprintln!("sent: {r:?}");
        assert!(r.wamid.starts_with("wamid."));
    }

    // ---- Kapso Platform API ----------------------------------------------

    #[test]
    fn kapso_platform_accepts_proxy_and_rejects_garbage() {
        assert!(KapsoPlatform::new("k-key", None, Some("socks5://127.0.0.1:1080")).is_ok());
        assert!(KapsoPlatform::new("k-key", None, Some("http://user:pw@127.0.0.1:3128")).is_ok());
        let p = KapsoPlatform::new("k-key", None, None).unwrap();
        assert_eq!(p.url("customers"), "https://api.kapso.ai/platform/v1/customers");
        assert_eq!(p.url("/customers"), "https://api.kapso.ai/platform/v1/customers");
        // Kapso spells WhatsApp resources `whatsapp/…`; a hyphen 404s. Pin it.
        assert!(!KAPSO_WEBHOOKS_PATH.contains('-'));
        assert!(!KAPSO_PHONE_NUMBERS_PATH.contains('-'));
        assert_eq!(
            p.url(KAPSO_WEBHOOKS_PATH),
            "https://api.kapso.ai/platform/v1/whatsapp/webhooks"
        );
        assert_eq!(
            p.url(KAPSO_PHONE_NUMBERS_PATH),
            "https://api.kapso.ai/platform/v1/whatsapp/phone_numbers"
        );
        assert_eq!(
            p.url(&format!("{KAPSO_PHONE_NUMBERS_PATH}/106540352242922")),
            "https://api.kapso.ai/platform/v1/whatsapp/phone_numbers/106540352242922"
        );
        assert_eq!(
            p.url("customers/550e8400-e29b-41d4-a716-446655440000"),
            "https://api.kapso.ai/platform/v1/customers/550e8400-e29b-41d4-a716-446655440000"
        );
        // base override, trailing slash trimmed
        let p2 = KapsoPlatform::new("k-key", Some("https://kapso.example/platform/v2/"), None)
            .unwrap();
        assert_eq!(p2.url("customers"), "https://kapso.example/platform/v2/customers");
        // Debug never leaks the key
        assert!(!format!("{p:?}").contains("k-key"));
        let err = KapsoPlatform::new("k-key", None, Some("::not a url::")).unwrap_err();
        assert!(matches!(err, Error::BadRequest(_)), "{err}");
    }

    #[test]
    fn kapso_broadcasts_path_spelling_and_url_composition() {
        // Same `whatsapp/…` caveat as the other Kapso resources — a hyphen 404s.
        assert!(!KAPSO_BROADCASTS_PATH.contains('-'));
        let p = KapsoPlatform::new("k-key", None, None).unwrap();
        assert_eq!(
            p.url(KAPSO_BROADCASTS_PATH),
            "https://api.kapso.ai/platform/v1/whatsapp/broadcasts"
        );
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            p.url(&format!("{KAPSO_BROADCASTS_PATH}/{uuid}/send")),
            "https://api.kapso.ai/platform/v1/whatsapp/broadcasts/\
             550e8400-e29b-41d4-a716-446655440000/send"
        );
    }

    #[test]
    fn parse_broadcast_unwraps_data_and_defaults_counts() {
        // Bare object, sparse: every count defaults to 0, template is None.
        let bare = parse_broadcast(&serde_json::json!({ "id": "b1", "status": "draft" }));
        assert_eq!(bare.id.as_deref(), Some("b1"));
        assert_eq!(bare.status.as_deref(), Some("draft"));
        assert_eq!(bare.sent_count, 0);
        assert_eq!(bare.total_recipients, 0);
        assert!(bare.template.is_none());
        assert!(bare.response_rate.is_none());

        // `{data:{…}}` envelope with a template + counts.
        let wrapped = parse_broadcast(&serde_json::json!({
            "data": {
                "id": "b2",
                "name": "Promo",
                "status": "sending",
                "sent_count": 3,
                "delivered_count": "2",
                "response_rate": 0.5,
                "scheduled_at": "2026-09-01T12:00:00Z",
                "whatsapp_template": {
                    "id": "tpl-1",
                    "name": "promo",
                    "language_code": "en_US",
                    "category": "MARKETING",
                    "status": "APPROVED",
                    "meta_template_id": "998877"
                }
            }
        }));
        assert_eq!(wrapped.id.as_deref(), Some("b2"));
        assert_eq!(wrapped.sent_count, 3);
        assert_eq!(wrapped.delivered_count, 2);
        assert_eq!(wrapped.response_rate, Some(0.5));
        assert_eq!(wrapped.scheduled_at.as_deref(), Some("2026-09-01T12:00:00Z"));
        let tpl = wrapped.template.expect("template");
        assert_eq!(tpl.name.as_deref(), Some("promo"));
        assert_eq!(tpl.meta_template_id.as_deref(), Some("998877"));
    }

    #[test]
    fn parse_broadcast_meta_reads_pagination() {
        let v = serde_json::json!({
            "data": [],
            "meta": { "page": 2, "per_page": 50, "total_pages": 4, "total_count": 175 }
        });
        assert_eq!(parse_broadcast_meta(&v), (2, 50, 4, 175));
        // Absent meta → all zeros.
        assert_eq!(parse_broadcast_meta(&serde_json::json!({ "data": [] })), (0, 0, 0, 0));
    }

    #[test]
    fn add_recipients_result_reads_errors_array() {
        // Exercise the `data.{added,duplicates,errors}` extraction directly.
        let d = serde_json::json!({
            "data": { "added": 8, "duplicates": 2, "errors": ["bad number +1", "no components"] }
        });
        let d = d.get("data").unwrap();
        let errors: Vec<String> = d
            .get("errors")
            .and_then(serde_json::Value::as_array)
            .map(|a| a.iter().map(|e| e.as_str().unwrap().to_string()).collect())
            .unwrap();
        assert_eq!(errors, vec!["bad number +1".to_string(), "no components".to_string()]);
        assert_eq!(d.get("added").and_then(u64_of), Some(8));
        assert_eq!(d.get("duplicates").and_then(u64_of), Some(2));
    }

    #[test]
    fn broadcast_methods_reject_bad_ids_before_network() {
        let p = KapsoPlatform::new("k-key", None, None).unwrap();
        let bad = p.broadcast_id("../etc/passwd");
        assert!(matches!(bad, Err(Error::BadRequest(_))));
        assert_eq!(p.broadcast_id("  b-1  ").unwrap(), "b-1");
    }

    #[test]
    fn is_kapso_id_accepts_uuids_and_digits_only() {
        assert!(is_kapso_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_kapso_id("106540352242922"));
        assert!(is_kapso_id("cust_abc-123"));
        assert!(!is_kapso_id(""));
        assert!(!is_kapso_id("../../me"));
        assert!(!is_kapso_id("a b"));
        assert!(!is_kapso_id("id?x=1"));
    }

    #[test]
    fn kapso_phone_number_parses_waba_id() {
        let d = serde_json::json!({
            "id": "row-1",
            "internal_id": "550e8400-e29b-41d4-a716-446655440000",
            "phone_number_id": "1332248166628278",
            "business_account_id": "98765432109",
            "display_phone_number": "+55 11 96447-5055",
            "verified_name": "Acme",
        });
        let n = parse_kapso_phone_number(&d).unwrap();
        assert_eq!(n.business_account_id.as_deref(), Some("98765432109"));
        // Alternate key spelling is also accepted.
        let d2 = serde_json::json!({
            "internal_id": "550e8400-e29b-41d4-a716-446655440000",
            "phone_number_id": "1",
            "whatsapp_business_account_id": "111",
        });
        assert_eq!(
            parse_kapso_phone_number(&d2).unwrap().business_account_id.as_deref(),
            Some("111")
        );
    }

    #[test]
    fn kapso_project_event_created_from_header() {
        let raw = br#"{
          "phone_number_id": "123456789012345",
          "project": { "id": "proj_abc" },
          "customer": { "id": "cust_xyz" },
          "source": { "business_account_id": "998877" },
          "occurred_at": "2026-08-27T12:00:00Z"
        }"#;
        let ev = parse_kapso_project_event(raw, Some("whatsapp.phone_number.created")).unwrap();
        assert_eq!(ev.event, "whatsapp.phone_number.created");
        assert_eq!(ev.phone_number_id.as_deref(), Some("123456789012345"));
        assert_eq!(ev.customer_id.as_deref(), Some("cust_xyz"));
        assert_eq!(ev.project_id.as_deref(), Some("proj_abc"));
        assert_eq!(ev.business_account_id.as_deref(), Some("998877"));
        assert_eq!(ev.occurred_at.as_deref(), Some("2026-08-27T12:00:00Z"));
    }

    #[test]
    fn kapso_project_event_name_falls_back_to_body_and_rejects_non_json() {
        // Minimal payload: name only in the body, no header.
        let raw = br#"{ "event": "whatsapp.phone_number.disconnected", "phone_number_id": "1" }"#;
        let ev = parse_kapso_project_event(raw, None).unwrap();
        assert_eq!(ev.event, "whatsapp.phone_number.disconnected");
        assert_eq!(ev.phone_number_id.as_deref(), Some("1"));
        assert!(ev.customer_id.is_none());
        assert!(ev.project_id.is_none());
        // Non-JSON body → BadRequest.
        assert!(matches!(
            parse_kapso_project_event(b"not json at all", None),
            Err(Error::BadRequest(_))
        ));
    }

    #[test]
    fn setup_link_body_omits_nulls_and_defaults_billing() {
        // Minimal: only the required bool + the default billing mode.
        let b = setup_link_body(&SetupLinkOpts::default());
        let sl = b.get("setup_link").unwrap();
        assert_eq!(sl.get("provision_phone_number").unwrap(), &json!(false));
        assert_eq!(sl.get("meta_billing_mode").unwrap(), &json!("partner_managed"));
        assert!(sl.get("allowed_connection_types").is_none());
        assert!(sl.get("success_redirect_url").is_none());
        assert!(sl.get("failure_redirect_url").is_none());
        assert!(sl.get("phone_number_country_isos").is_none());
        assert!(sl.get("language").is_none());

        // Fully populated; blank optionals are dropped, blank ISOs filtered.
        let opts = SetupLinkOpts {
            provision_phone_number: true,
            connection_type: Some("coexistence".into()),
            meta_billing_mode: Some("customer_managed".into()),
            success_redirect_url: Some("https://ok.example".into()),
            failure_redirect_url: Some("  ".into()),
            country_isos: vec!["US".into(), "  ".into(), "BR".into()],
            language: Some("pt".into()),
        };
        let full = setup_link_body(&opts);
        let sl = full.get("setup_link").unwrap();
        assert_eq!(sl.get("provision_phone_number").unwrap(), &json!(true));
        assert_eq!(
            sl.get("allowed_connection_types").unwrap(),
            &json!(["coexistence"])
        );
        assert_eq!(
            sl.get("meta_billing_mode").unwrap(),
            &json!("customer_managed")
        );
        assert_eq!(
            sl.get("success_redirect_url").unwrap(),
            &json!("https://ok.example")
        );
        assert!(sl.get("failure_redirect_url").is_none());
        assert_eq!(
            sl.get("phone_number_country_isos").unwrap(),
            &json!(["US", "BR"])
        );
        assert_eq!(sl.get("language").unwrap(), &json!("pt"));
    }
}
