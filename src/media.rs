//! Encrypted media upload/download.
//!
//! WA media is AES-256-CBC encrypted with HMAC-SHA256 MAC. The 32-byte
//! mediaKey is HKDF-expanded into (iv, cipher_key, mac_key, ref_key).
//! Encrypted blobs are uploaded to mmg.whatsapp.net and the resulting
//! URL+sha256+filelength go into the protobuf message.
//!
//! Wire layout:
//!   ciphertext = AES-256-CBC(cipher_key, iv, plaintext)  // PKCS7 padded
//!   mac10      = HMAC-SHA256(mac_key, iv || ciphertext)[..10]
//!   uploaded   = ciphertext || mac10
//!
//! References:
//!   - whatsmeow/mediaconn.go
//!   - whatsmeow/upload.go / download.go
//!   - whatsmeow/util/cbcutil
#![allow(dead_code)]

use ::hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Per-media-type info string the HKDF expand uses. WA pins these to four
/// constants keyed on the file's content kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MediaType {
    Image,
    Video,
    Audio,
    /// Voice note (push-to-talk). Same encrypt scheme + upload host as
    /// `Audio` (shares "WhatsApp Audio Keys" and `/mms/audio`); the only
    /// wire difference is the `ptt=true` flag on the AudioMessage proto,
    /// which is what makes the recipient render a voice bubble.
    Ptt,
    Document,
    Sticker,
    /// History sync blob — same encrypt scheme as the user-facing media
    /// types but with a distinct HKDF info so a leaked image key can't
    /// decrypt a history dump and vice versa.
    History,
    /// App-state patch external blob — same scheme, distinct info.
    AppState,
}

impl MediaType {
    pub fn hkdf_info(self) -> &'static [u8] {
        match self {
            MediaType::Image => b"WhatsApp Image Keys",
            MediaType::Video => b"WhatsApp Video Keys",
            MediaType::Audio => b"WhatsApp Audio Keys",
            MediaType::Ptt => b"WhatsApp Audio Keys",
            MediaType::Document => b"WhatsApp Document Keys",
            MediaType::Sticker => b"WhatsApp Image Keys",
            MediaType::History => b"WhatsApp History Keys",
            MediaType::AppState => b"WhatsApp App State Keys",
        }
    }
}

/// HKDF-expand the 32-byte mediaKey into (iv, cipher_key, mac_key, ref_key).
pub struct DerivedMediaKeys {
    pub iv: [u8; 16],
    pub cipher_key: [u8; 32],
    pub mac_key: [u8; 32],
    pub ref_key: [u8; 32],
}

pub fn derive_media_keys(media_key: &[u8; 32], ty: MediaType) -> DerivedMediaKeys {
    let hk = Hkdf::<Sha256>::new(None, media_key);
    let mut out = [0u8; 112];
    hk.expand(ty.hkdf_info(), &mut out)
        .expect("112 < 255*32 hkdf max");
    let mut iv = [0u8; 16];
    let mut cipher_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    let mut ref_key = [0u8; 32];
    iv.copy_from_slice(&out[0..16]);
    cipher_key.copy_from_slice(&out[16..48]);
    mac_key.copy_from_slice(&out[48..80]);
    ref_key.copy_from_slice(&out[80..112]);
    DerivedMediaKeys {
        iv,
        cipher_key,
        mac_key,
        ref_key,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("AES-CBC operation failed")]
    Aes,
    #[error("MAC verification failed")]
    BadMac,
    #[error("encrypted blob too short to contain MAC")]
    Truncated,
}

/// Output of an `encrypt()` call: the bytes ready to upload + the hashes
/// the protobuf message wants (file_sha256 over PLAINTEXT, file_enc_sha256
/// over ciphertext+mac, file_length).
pub struct EncryptedMedia {
    pub ciphertext: Vec<u8>,
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
    pub file_length: u64,
}

/// Encrypt `plaintext` for upload. `media_key` is typically random per file.
pub fn encrypt(plaintext: &[u8], media_key: &[u8; 32], ty: MediaType) -> Result<EncryptedMedia, MediaError> {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    type Enc = cbc::Encryptor<Aes256>;

    let dk = derive_media_keys(media_key, ty);
    let enc = Enc::new(&dk.cipher_key.into(), &dk.iv.into());
    let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    let mac = compute_mac(&dk.mac_key, &dk.iv, &ct);
    let mut out = Vec::with_capacity(ct.len() + 10);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&mac[..10]);

    let mut h = Sha256::new();
    h.update(plaintext);
    let file_sha256: [u8; 32] = h.finalize().into();
    let mut h = Sha256::new();
    h.update(&out);
    let file_enc_sha256: [u8; 32] = h.finalize().into();

    Ok(EncryptedMedia {
        ciphertext: out,
        media_key: *media_key,
        file_sha256,
        file_enc_sha256,
        file_length: plaintext.len() as u64,
    })
}

/// Decrypt a downloaded blob. `blob` is `ciphertext || mac10`.
pub fn decrypt(blob: &[u8], media_key: &[u8; 32], ty: MediaType) -> Result<Vec<u8>, MediaError> {
    use aes::Aes256;
    use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
    type Dec = cbc::Decryptor<Aes256>;

    if blob.len() < 10 {
        return Err(MediaError::Truncated);
    }
    let (ct, mac10) = blob.split_at(blob.len() - 10);
    let dk = derive_media_keys(media_key, ty);

    let want_mac = compute_mac(&dk.mac_key, &dk.iv, ct);
    if &want_mac[..10] != mac10 {
        return Err(MediaError::BadMac);
    }
    let dec = Dec::new(&dk.cipher_key.into(), &dk.iv.into());
    dec.decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| MediaError::Aes)
}

fn compute_mac(mac_key: &[u8; 32], iv: &[u8; 16], ct: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key");
    mac.update(iv);
    mac.update(ct);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

/// Common knobs for any media message: where the encrypted blob landed,
/// what kind of file it is, and (optionally) a caption.
#[derive(Debug, Clone, Default)]
pub struct UploadedMedia {
    /// `https://mmg.whatsapp.net/...` from the upload-host response.
    pub url: String,
    /// e.g. `/mms/image/...` — the path portion the server uses for retries.
    pub direct_path: String,
    /// MIME type (e.g. `image/jpeg`).
    pub mimetype: String,
    pub caption: Option<String>,
}

/// Build a `waE2E.Message` containing an ImageMessage referencing the given
/// upload + encryption metadata. Returned bytes are the inner Signal payload
/// the caller passes through `pad_message` + `SessionCipher::encrypt`.
pub fn build_image_message(
    enc: &EncryptedMedia,
    upload: &UploadedMedia,
    width: Option<u32>,
    height: Option<u32>,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{ImageMessage, Message};
    use ::prost::Message as _;
    let img = ImageMessage {
        url: Some(upload.url.clone()),
        direct_path: Some(upload.direct_path.clone()),
        mimetype: Some(upload.mimetype.clone()),
        caption: upload.caption.clone(),
        file_sha256: Some(enc.file_sha256.to_vec()),
        file_enc_sha256: Some(enc.file_enc_sha256.to_vec()),
        media_key: Some(enc.media_key.to_vec()),
        file_length: Some(enc.file_length),
        width,
        height,
        ..Default::default()
    };
    let msg = Message {
        image_message: Some(Box::new(img)),
        ..Default::default()
    };
    msg.encode_to_vec()
}

pub fn build_video_message(
    enc: &EncryptedMedia,
    upload: &UploadedMedia,
    seconds: Option<u32>,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{Message, VideoMessage};
    use ::prost::Message as _;
    let vid = VideoMessage {
        url: Some(upload.url.clone()),
        direct_path: Some(upload.direct_path.clone()),
        mimetype: Some(upload.mimetype.clone()),
        caption: upload.caption.clone(),
        file_sha256: Some(enc.file_sha256.to_vec()),
        file_enc_sha256: Some(enc.file_enc_sha256.to_vec()),
        media_key: Some(enc.media_key.to_vec()),
        file_length: Some(enc.file_length),
        seconds,
        ..Default::default()
    };
    let msg = Message {
        video_message: Some(Box::new(vid)),
        ..Default::default()
    };
    msg.encode_to_vec()
}

pub fn build_audio_message(
    enc: &EncryptedMedia,
    upload: &UploadedMedia,
    seconds: Option<u32>,
    ptt: bool,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{AudioMessage, Message};
    use ::prost::Message as _;
    let aud = AudioMessage {
        url: Some(upload.url.clone()),
        direct_path: Some(upload.direct_path.clone()),
        mimetype: Some(upload.mimetype.clone()),
        file_sha256: Some(enc.file_sha256.to_vec()),
        file_enc_sha256: Some(enc.file_enc_sha256.to_vec()),
        media_key: Some(enc.media_key.to_vec()),
        file_length: Some(enc.file_length),
        seconds,
        ptt: Some(ptt),
        ..Default::default()
    };
    let msg = Message {
        audio_message: Some(Box::new(aud)),
        ..Default::default()
    };
    msg.encode_to_vec()
}

pub fn build_document_message(
    enc: &EncryptedMedia,
    upload: &UploadedMedia,
    file_name: Option<String>,
) -> Vec<u8> {
    use crate::proto::wa_web_protobufs_e2e::{DocumentMessage, Message};
    use ::prost::Message as _;
    let doc = DocumentMessage {
        url: Some(upload.url.clone()),
        direct_path: Some(upload.direct_path.clone()),
        mimetype: Some(upload.mimetype.clone()),
        file_sha256: Some(enc.file_sha256.to_vec()),
        file_enc_sha256: Some(enc.file_enc_sha256.to_vec()),
        media_key: Some(enc.media_key.to_vec()),
        file_length: Some(enc.file_length),
        file_name,
        caption: upload.caption.clone(),
        ..Default::default()
    };
    let msg = Message {
        document_message: Some(Box::new(doc)),
        ..Default::default()
    };
    msg.encode_to_vec()
}

/// MediaType → URL path segment WhatsApp uses for upload endpoints.
/// `History` and `AppState` are receive-only on this path — clients only
/// ever decrypt these blobs, never upload them, so they fall through to
/// the document path defensively.
pub fn upload_path(ty: MediaType) -> &'static str {
    match ty {
        MediaType::Image => "/mms/image",
        MediaType::Video => "/mms/video",
        MediaType::Audio => "/mms/audio",
        MediaType::Ptt => "/mms/audio",
        MediaType::Document => "/mms/document",
        MediaType::Sticker => "/mms/image",
        MediaType::History | MediaType::AppState => "/mms/document",
    }
}

/// Result of `upload_encrypted`.
#[derive(Debug, Clone)]
pub struct UploadResult {
    pub url: String,
    pub direct_path: String,
}

/// PUT `encrypted` to mmg.whatsapp.net. `host` and `auth_token` come from
/// the mediaconn IQ; `enc_sha256_b64url` is the ciphertext sha256 base64'd
/// (whatsmeow uses URL-safe base64 without padding for the upload token).
/// Build a reqwest client that egresses through `proxy` (socks5/socks5h/http)
/// when set, so media traffic shares the session's IP. A bad proxy URL is a
/// hard error — we never silently fall back to a direct connection.
fn proxy_client(proxy: Option<&str>) -> Result<reqwest::Client, MediaError> {
    let mut b = reqwest::Client::builder();
    if let Some(url) = proxy {
        b = b.proxy(reqwest::Proxy::all(url).map_err(|_| MediaError::Aes)?);
    }
    b.build().map_err(|_| MediaError::Aes)
}

pub async fn upload_encrypted(
    host: &str,
    auth_token: &str,
    encrypted: &[u8],
    enc_sha256: &[u8; 32],
    ty: MediaType,
    proxy: Option<&str>,
) -> Result<UploadResult, MediaError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    let token = B64.encode(enc_sha256);
    let url = format!(
        "https://{host}{path}/{token}?auth={auth}&token={token}",
        path = upload_path(ty),
        auth = auth_token,
    );
    let resp = proxy_client(proxy)?
        .post(&url)
        .body(encrypted.to_vec())
        .send()
        .await
        .map_err(|_| MediaError::Aes)?;
    if !resp.status().is_success() {
        return Err(MediaError::Aes);
    }
    let json: serde_json::Value = resp.json().await.map_err(|_| MediaError::Aes)?;
    let url = json["url"].as_str().unwrap_or("").to_string();
    let direct_path = json["direct_path"].as_str().unwrap_or("").to_string();
    Ok(UploadResult { url, direct_path })
}

/// GET `<base>/<direct_path>` (no auth needed for downloads — the URL is
/// keyed). Returns the encrypted blob, ready for `decrypt`.
pub async fn download_encrypted(url: &str, proxy: Option<&str>) -> Result<Vec<u8>, MediaError> {
    let resp = proxy_client(proxy)?
        .get(url)
        .send()
        .await
        .map_err(|_| MediaError::Aes)?;
    if !resp.status().is_success() {
        return Err(MediaError::Aes);
    }
    let bytes = resp.bytes().await.map_err(|_| MediaError::Aes)?;
    Ok(bytes.to_vec())
}

// ===== AWS Signature V4 — in-house signer ===================================
//
// Hand-rolled SigV4 (no aws-sdk) for the S3/R2/MinIO media client. Pure: given
// the request components it returns the `Authorization` header. Verified against
// the AWS-documented "GET Object" test vector in tests.

/// Credentials + target scope for a SigV4 signature.
pub struct AwsCreds<'a> {
    pub access_key: &'a str,
    pub secret_key: &'a str,
    pub region: &'a str,
    pub service: &'a str,
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac =
        <Hmac<Sha256>>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

/// Compute the SigV4 `Authorization` header value for a request.
///
/// - `canonical_uri`: already path-encoded (e.g. `/bucket/key`); `/` preserved.
/// - `canonical_query`: already sorted + percent-encoded (`""` if none).
/// - `headers`: `(lowercase-name, value)` pairs; MUST include `host`,
///   `x-amz-date`, and `x-amz-content-sha256`.
/// - `payload_sha256_hex`: hex SHA-256 of the body (empty body = the well-known
///   `e3b0c442…` hash).
/// - `amz_date`: ISO8601 basic, `YYYYMMDDTHHMMSSZ`.
pub fn sigv4_authorization(
    creds: &AwsCreds,
    method: &str,
    canonical_uri: &str,
    canonical_query: &str,
    headers: &[(String, String)],
    payload_sha256_hex: &str,
    amz_date: &str,
) -> String {
    let mut hs: Vec<&(String, String)> = headers.iter().collect();
    hs.sort_by(|a, b| a.0.cmp(&b.0));
    let canonical_headers: String =
        hs.iter().map(|(k, v)| format!("{k}:{}\n", v.trim())).collect();
    let signed_headers = hs
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");

    let canonical_request = format!(
        "{method}\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{payload_sha256_hex}"
    );

    let date = &amz_date[..8]; // YYYYMMDD
    let scope = format!("{date}/{}/{}/aws4_request", creds.region, creds.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let k_date = hmac_sha256(format!("AWS4{}", creds.secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, creds.region.as_bytes());
    let k_service = hmac_sha256(&k_region, creds.service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        creds.access_key
    )
}

// ===== S3 / R2 / MinIO — minimal in-house object client =====================

/// S3-compatible storage config (works against MinIO, AWS S3, Cloudflare R2).
/// Loaded from `RUWA_S3_*` env when `RUWA_MEDIA_STORE=s3`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3Config {
    /// Base endpoint, no trailing slash, e.g. `http://minio:9000`.
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub access_key: String,
    pub secret_key: String,
    /// Optional public base URL for serving objects (CDN/R2 public bucket). When
    /// unset, object URLs are `endpoint/bucket/key` (path-style).
    pub public_base_url: Option<String>,
}

impl S3Config {
    /// Parse from a variable lookup. `Ok(None)` when `RUWA_MEDIA_STORE` != `s3`
    /// (the default `db` mode); `Err` when in `s3` mode but a required var is
    /// missing. Injectable for tests.
    pub fn from_vars(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        if get("RUWA_MEDIA_STORE").unwrap_or_default() != "s3" {
            return Ok(None);
        }
        let req = |k: &str| {
            get(k)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("{k} is required for RUWA_MEDIA_STORE=s3"))
        };
        let opt = |k: &str| get(k).filter(|v| !v.is_empty());
        Ok(Some(S3Config {
            endpoint: req("RUWA_S3_ENDPOINT")?.trim_end_matches('/').to_string(),
            bucket: req("RUWA_S3_BUCKET")?,
            region: opt("RUWA_S3_REGION").unwrap_or_else(|| "us-east-1".into()),
            access_key: req("RUWA_S3_ACCESS_KEY")?,
            secret_key: req("RUWA_S3_SECRET_KEY")?,
            public_base_url: opt("RUWA_S3_PUBLIC_BASE_URL")
                .map(|v| v.trim_end_matches('/').to_string()),
        }))
    }

    /// Load from process env (`db` mode → `None`).
    pub fn from_env() -> Result<Option<Self>, String> {
        Self::from_vars(|k| std::env::var(k).ok())
    }

    /// Public URL of `key` (uses `public_base_url` when set, else path-style).
    pub fn object_url(&self, key: &str) -> String {
        match &self.public_base_url {
            Some(base) => format!("{base}/{key}"),
            None => format!("{}/{}/{}", self.endpoint, self.bucket, key),
        }
    }
}

/// RFC-3986 percent-encode per AWS canonical-URI rules: unreserved chars stay,
/// `/` is kept when `keep_slash`, everything else becomes `%XX`.
fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b'/' if keep_slash => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// host[:port] of an endpoint URL (the value SigV4 signs as the `host` header).
fn endpoint_host(endpoint: &str) -> String {
    match url::Url::parse(endpoint) {
        Ok(u) => match (u.host_str(), u.port()) {
            (Some(h), Some(p)) => format!("{h}:{p}"),
            (Some(h), None) => h.to_string(),
            _ => String::new(),
        },
        Err(_) => String::new(),
    }
}

/// Build the signed PUT: returns (url, headers incl. Authorization). Pure — the
/// unit-testable core of `put_object` (the network send is the live part).
fn s3_put_signed(
    cfg: &S3Config,
    key: &str,
    body: &[u8],
    content_type: &str,
    amz_date: &str,
) -> (String, Vec<(String, String)>) {
    let payload_hash = sha256_hex(body);
    let canonical_uri = format!(
        "/{}/{}",
        uri_encode(&cfg.bucket, false),
        uri_encode(key, true)
    );
    let mut headers = vec![
        ("host".to_string(), endpoint_host(&cfg.endpoint)),
        ("content-type".to_string(), content_type.to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), amz_date.to_string()),
    ];
    let auth = sigv4_authorization(
        &AwsCreds {
            access_key: &cfg.access_key,
            secret_key: &cfg.secret_key,
            region: &cfg.region,
            service: "s3",
        },
        "PUT",
        &canonical_uri,
        "",
        &headers,
        &payload_hash,
        amz_date,
    );
    headers.push(("authorization".to_string(), auth));
    (format!("{}{}", cfg.endpoint, canonical_uri), headers)
}

/// Upload `body` to `key` and return its public URL. Live (the `[human-gate]`
/// round-trip exercises the actual network PUT).
pub async fn put_object(
    cfg: &S3Config,
    key: &str,
    body: &[u8],
    content_type: &str,
) -> Result<String, MediaError> {
    let amz_date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let (url, headers) = s3_put_signed(cfg, key, body, content_type, &amz_date);
    let mut req = reqwest::Client::new().put(&url).body(body.to_vec());
    for (k, v) in &headers {
        req = req.header(k.as_str(), v.as_str());
    }
    let resp = req.send().await.map_err(|_| MediaError::Aes)?;
    if resp.status().is_success() {
        Ok(cfg.object_url(key))
    } else {
        Err(MediaError::Aes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigv4_matches_aws_get_object_test_vector() {
        // AWS-documented "GET Object" SigV4 example (S3, us-east-1).
        // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        let empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let creds = AwsCreds {
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            region: "us-east-1",
            service: "s3",
        };
        let headers = vec![
            ("host".to_string(), "examplebucket.s3.amazonaws.com".to_string()),
            ("range".to_string(), "bytes=0-9".to_string()),
            ("x-amz-content-sha256".to_string(), empty.to_string()),
            ("x-amz-date".to_string(), "20130524T000000Z".to_string()),
        ];
        let auth = sigv4_authorization(
            &creds,
            "GET",
            "/test.txt",
            "",
            &headers,
            empty,
            "20130524T000000Z",
        );
        // The exact signature from the AWS docs.
        assert!(
            auth.contains(
                "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
            ),
            "auth = {auth}"
        );
        assert!(auth.contains(
            "Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request"
        ));
        assert!(auth.contains("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date"));
    }

    fn s3_vars() -> std::collections::HashMap<&'static str, &'static str> {
        [
            ("RUWA_MEDIA_STORE", "s3"),
            ("RUWA_S3_ENDPOINT", "http://minio:9000/"),
            ("RUWA_S3_BUCKET", "wa-media"),
            ("RUWA_S3_ACCESS_KEY", "AKIA"),
            ("RUWA_S3_SECRET_KEY", "secret"),
        ]
        .into_iter()
        .collect()
    }

    #[test]
    fn s3_config_parse_modes_and_defaults() {
        // db mode (default) → None.
        assert_eq!(S3Config::from_vars(|_| None).unwrap(), None);
        assert_eq!(
            S3Config::from_vars(|k| (k == "RUWA_MEDIA_STORE").then(|| "db".to_string())).unwrap(),
            None
        );

        // s3 mode, full vars → endpoint trimmed, region defaulted.
        let m = s3_vars();
        let cfg = S3Config::from_vars(|k| m.get(k).map(|s| s.to_string()))
            .unwrap()
            .unwrap();
        assert_eq!(cfg.endpoint, "http://minio:9000"); // trailing slash trimmed
        assert_eq!(cfg.bucket, "wa-media");
        assert_eq!(cfg.region, "us-east-1"); // default
        assert!(cfg.public_base_url.is_none());

        // s3 mode missing a required var → Err.
        let mut m2 = s3_vars();
        m2.remove("RUWA_S3_BUCKET");
        let err = S3Config::from_vars(|k| m2.get(k).map(|s| s.to_string())).unwrap_err();
        assert!(err.contains("RUWA_S3_BUCKET"));
    }

    #[test]
    fn s3_object_url_path_style_and_public() {
        let m = s3_vars();
        let mut cfg = S3Config::from_vars(|k| m.get(k).map(|s| s.to_string()))
            .unwrap()
            .unwrap();
        // Path-style when no public base.
        assert_eq!(
            cfg.object_url("a/b/c"),
            "http://minio:9000/wa-media/a/b/c"
        );
        // Public base URL wins.
        cfg.public_base_url = Some("https://cdn.example.com".into());
        assert_eq!(cfg.object_url("a/b/c"), "https://cdn.example.com/a/b/c");
    }

    /// C6 (human-gate): live MinIO/S3 round-trip. Run with a real bucket:
    ///   RUWA_LIVE_TEST=1 cargo test c6_live_s3 -- --ignored
    /// Defaults to the docker MinIO (localhost:9000, minioadmin, bucket wa-media
    /// set to public-download); override via RUWA_S3_TEST_* if needed.
    #[tokio::test]
    #[ignore]
    async fn c6_live_s3_round_trip() {
        if std::env::var("RUWA_LIVE_TEST").as_deref() != Ok("1") {
            return;
        }
        let env = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_string());
        let cfg = S3Config {
            endpoint: env("RUWA_S3_TEST_ENDPOINT", "http://localhost:9000"),
            bucket: env("RUWA_S3_TEST_BUCKET", "wa-media"),
            region: env("RUWA_S3_TEST_REGION", "us-east-1"),
            access_key: env("RUWA_S3_TEST_ACCESS_KEY", "minioadmin"),
            secret_key: env("RUWA_S3_TEST_SECRET_KEY", "minioadmin"),
            public_base_url: None,
        };
        let key = format!("livetest/{}.bin", crate::session::uuid_v4());
        let body = b"ruwa-c6-roundtrip-payload";

        // PUT via our in-house SigV4 client.
        let url = put_object(&cfg, &key, body, "application/octet-stream")
            .await
            .expect("put_object should succeed against MinIO");
        assert_eq!(url, format!("{}/{}/{}", cfg.endpoint, cfg.bucket, key));

        // GET it back (bucket is public-download) and verify the bytes.
        let got = reqwest::Client::new()
            .get(&url)
            .send()
            .await
            .expect("GET object")
            .bytes()
            .await
            .expect("read body");
        assert_eq!(got.as_ref(), body);
    }

    #[test]
    fn s3_put_signed_builds_url_and_signed_headers() {
        let m = s3_vars();
        let cfg = S3Config::from_vars(|k| m.get(k).map(|s| s.to_string()))
            .unwrap()
            .unwrap();
        let body = b"hello";
        let (url, headers) =
            s3_put_signed(&cfg, "sess/5511@s.whatsapp.net/m1", body, "image/jpeg", "20130524T000000Z");
        // '@' in the key is percent-encoded in the path; '/' preserved.
        assert_eq!(url, "http://minio:9000/wa-media/sess/5511%40s.whatsapp.net/m1");
        let h = |name: &str| headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
        assert_eq!(h("host"), Some("minio:9000"));
        assert_eq!(h("content-type"), Some("image/jpeg"));
        assert_eq!(h("x-amz-content-sha256"), Some(sha256_hex(body).as_str()));
        assert!(h("authorization").unwrap().starts_with("AWS4-HMAC-SHA256 Credential=AKIA/"));
    }

    #[test]
    fn encrypt_then_decrypt_round_trips() {
        let media_key = [0x42u8; 32];
        let pt = b"the quick brown fox jumps over the lazy dog".repeat(4);
        let enc = encrypt(&pt, &media_key, MediaType::Image).unwrap();
        assert_eq!(enc.media_key, media_key);
        assert_eq!(enc.file_length, pt.len() as u64);
        // file_sha256 is over plaintext.
        let mut h = Sha256::new();
        h.update(&pt);
        let want_pt: [u8; 32] = h.finalize().into();
        assert_eq!(enc.file_sha256, want_pt);
        // file_enc_sha256 is over ciphertext+mac.
        let mut h = Sha256::new();
        h.update(&enc.ciphertext);
        let want_ct: [u8; 32] = h.finalize().into();
        assert_eq!(enc.file_enc_sha256, want_ct);

        let recovered = decrypt(&enc.ciphertext, &media_key, MediaType::Image).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn decrypt_rejects_tampered_mac() {
        let media_key = [0x33u8; 32];
        let mut enc = encrypt(b"hi", &media_key, MediaType::Audio).unwrap();
        let n = enc.ciphertext.len();
        enc.ciphertext[n - 1] ^= 0x01;
        assert!(matches!(
            decrypt(&enc.ciphertext, &media_key, MediaType::Audio),
            Err(MediaError::BadMac)
        ));
    }

    #[test]
    fn different_media_types_produce_different_keys() {
        let mk = [0x77u8; 32];
        let img = derive_media_keys(&mk, MediaType::Image);
        let vid = derive_media_keys(&mk, MediaType::Video);
        assert_ne!(img.cipher_key, vid.cipher_key);
        assert_ne!(img.iv, vid.iv);
    }

    #[test]
    fn ptt_shares_audio_keys_and_path() {
        // Voice notes ride the same transport as plain audio.
        let mk = [0x55u8; 32];
        assert_eq!(
            derive_media_keys(&mk, MediaType::Ptt).cipher_key,
            derive_media_keys(&mk, MediaType::Audio).cipher_key
        );
        assert_eq!(upload_path(MediaType::Ptt), upload_path(MediaType::Audio));
    }

    #[test]
    fn build_audio_message_sets_ptt_flag() {
        use crate::proto::wa_web_protobufs_e2e::Message;
        use ::prost::Message as _;
        let enc = EncryptedMedia {
            ciphertext: vec![0u8; 16],
            media_key: [0u8; 32],
            file_sha256: [0u8; 32],
            file_enc_sha256: [0u8; 32],
            file_length: 16,
        };
        let upload = UploadedMedia {
            url: "https://m".into(),
            direct_path: "/v/m".into(),
            mimetype: "audio/ogg; codecs=opus".into(),
            caption: None,
        };
        let voice = Message::decode(&*build_audio_message(&enc, &upload, Some(3), true)).unwrap();
        assert_eq!(voice.audio_message.unwrap().ptt, Some(true));
        let plain = Message::decode(&*build_audio_message(&enc, &upload, Some(3), false)).unwrap();
        assert_eq!(plain.audio_message.unwrap().ptt, Some(false));
    }
}
