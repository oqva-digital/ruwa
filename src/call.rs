//! Voice-call stack (WhatsApp 1:1 audio) — signaling, SRTP media crypto, and
//! (later) the audio bridge. See `docs/calls-port-plan.md` and `SPEC.md`.
//!
//! This first slice is the **E2E-SRTP crypto core**: keys derive from the
//! 32-byte `callKey` (decrypted from the offer's `<enc>` via the existing
//! Signal session) plus the device-qualified participant LID, through
//! HKDF-SHA256 then an AES-CM PRF (the libsrtp KDF). Payloads use AES-128-CTR
//! with a 4-byte WARP MESSAGE-INTEGRITY tag (HMAC-SHA1). Every primitive is
//! pinned byte-for-byte against known-answer vectors (the recv path has no
//! authentication of its own, so round-trip tests alone can't catch a
//! symmetric mistake — only KATs can). Ported from the MIT `whatsapp-rust`
//! `wacore/src/voip` reference; algorithm, not API surface.

#![allow(dead_code)] // consumed by the upcoming media-loop/transport slices (F2).

// MLow — Meta's proprietary split-band CELP codec that WhatsApp 1:1 calls use by
// default. Vendored wholesale (pure-Rust, MIT) from whatsapp-rust
// `wacore/src/voip/mlow`; a `call/` submodule for the same reason
// `protocol/tokens.rs` is one — a large vendored blob that would swamp call.rs.
// Needed because many peers (WhatsApp Business, newer clients) ignore our
// forced-Opus accept and send MLow, which stock Opus mis-decodes into robotic
// noise. See `src/call/mlow/mod.rs`.
mod mlow;

use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr128BE;

type AesCtr = Ctr128BE<Aes128>;

/// HKDF-SHA256 with an explicit salt, reusing ruwa's HKDF primitive. WhatsApp's
/// VoIP derivations all pass a 32-zero-byte salt (RFC 5869 salt = HashLen zeros).
fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    crate::crypto::hkdf::expand_with_salt(Some(salt), ikm, info, len)
}

/// Device-qualified participant id used as the HKDF `info` for E2E-SRTP: strip
/// any resource, keep an existing `:N@lid` device suffix, give a bare `@lid` an
/// implicit `:0`, and pass everything else through unchanged. Send keys use our
/// own LID; recv keys use the peer's — get this wrong and audio is one-way
/// garbage that still "decrypts". Mirrors `format_participant_id`.
pub fn format_participant_id(jid: &str) -> String {
    let bare = jid.split('/').next().unwrap_or(jid).trim();
    let Some(at) = bare.rfind('@') else {
        return bare.to_string();
    };
    if at == 0 {
        return bare.to_string();
    }
    let user = &bare[..at];
    let domain = &bare[at + 1..];
    if domain != "lid" {
        return bare.to_string();
    }
    // A LID on the wire is `<number>[.<agent>][:<device>]@lid`. The SRTP
    // participant id used as the HKDF `info` is just `<number>:<device>@lid` —
    // WhatsApp adds the `.<agent>` (e.g. `.1`) in call signaling but NOT in the
    // key-derivation id. Verified live: our own LID arrives already agent-less
    // (pn_to_lid drops it) and our SEND keys matched the peer; the peer's accept
    // jid still carried `.1`, so keeping it made every inbound packet fail to
    // decrypt. Strip the agent so both directions derive matching keys.
    let (user_no_dev, device) = match user.split_once(':') {
        Some((u, d)) => (u, d),
        None => (user, "0"),
    };
    let number = user_no_dev.split('.').next().unwrap_or(user_no_dev);
    format!("{number}:{device}@lid")
}

/// Session keys for one direction of the E2E 1:1 SRTP cipher.
#[derive(Clone)]
pub struct E2eSrtpKeys {
    pub cipher_key: [u8; 16],
    pub salt: [u8; 14],
    pub auth_key: [u8; 20],
}

// Manual Debug so a stray `{:?}` can't leak session keys into a log.
impl core::fmt::Debug for E2eSrtpKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("E2eSrtpKeys([redacted])")
    }
}

/// AES-CM PRF (libsrtp KDF): IV = master_salt (14B) with `label` XORed into
/// byte 7, zero-padded to 16, then an AES-128-CTR keystream over `len` zeros.
fn aes_cm_kdf(master_key: &[u8], master_salt: &[u8], label: u8, len: usize) -> Vec<u8> {
    let mut iv = [0u8; 16];
    iv[..14].copy_from_slice(&master_salt[..14]);
    iv[7] ^= label;
    let mut out = vec![0u8; len];
    let mut cipher = AesCtr::new_from_slices(master_key, &iv).expect("16-byte key/iv");
    cipher.apply_keystream(&mut out);
    out
}

/// Expand a 46-byte HKDF master into session keys with the given KDF labels.
/// SRTP uses labels 0x00/0x01/0x02; SRTCP uses 0x03/0x04/0x05.
fn session_keys_from_master(master: &[u8], labels: [u8; 3]) -> E2eSrtpKeys {
    let master_key = &master[0..16];
    let master_salt = &master[16..30];
    let mut keys = E2eSrtpKeys {
        cipher_key: [0u8; 16],
        salt: [0u8; 14],
        auth_key: [0u8; 20],
    };
    keys.cipher_key
        .copy_from_slice(&aes_cm_kdf(master_key, master_salt, labels[0], 16));
    keys.auth_key
        .copy_from_slice(&aes_cm_kdf(master_key, master_salt, labels[1], 20));
    keys.salt
        .copy_from_slice(&aes_cm_kdf(master_key, master_salt, labels[2], 14));
    keys
}

/// Stage-1 HKDF: `master(46B) = HKDF-SHA256(salt=[0;32], ikm=callKey[..32],
/// info=participant_lid, 46)`. `None` if `call_key` is under 32 bytes.
fn e2e_master(call_key: &[u8], participant_lid: &str) -> Option<Vec<u8>> {
    if call_key.len() < 32 {
        return None;
    }
    Some(hkdf_sha256(
        &[0u8; 32],
        &call_key[..32],
        participant_lid.as_bytes(),
        46,
    ))
}

/// E2E 1:1 **SRTP** keys from `call_key` (>= 32B) and a participant LID.
pub fn derive_e2e_keys(call_key: &[u8], participant_lid: &str) -> Option<E2eSrtpKeys> {
    Some(session_keys_from_master(
        &e2e_master(call_key, participant_lid)?,
        [0x00, 0x01, 0x02],
    ))
}

/// E2E 1:1 **SRTCP** keys — same HKDF master, distinct KDF labels.
pub fn derive_srtcp_keys(call_key: &[u8], participant_lid: &str) -> Option<E2eSrtpKeys> {
    Some(session_keys_from_master(
        &e2e_master(call_key, participant_lid)?,
        [0x03, 0x04, 0x05],
    ))
}

/// E2E RTP IV: salt right-aligned into 16 bytes, then the SSRC XORed at bytes
/// 4-7 and the 48-bit packet index (`ROC<<16 | seq`) XORed at bytes 8-13.
pub fn build_e2e_rtp_iv(salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 16] {
    let mut iv = [0u8; 16];
    // Clamp so an oversized salt can't underflow `off`; the production caller
    // passes the 14-byte `E2eSrtpKeys.salt` (n = 14, off = 0).
    let n = salt.len().min(14);
    let off = 14 - n;
    iv[off..off + n].copy_from_slice(&salt[..n]);
    iv[4] ^= (ssrc >> 24) as u8;
    iv[5] ^= (ssrc >> 16) as u8;
    iv[6] ^= (ssrc >> 8) as u8;
    iv[7] ^= ssrc as u8;
    let packet_index = (roc as u64) * 0x1_0000 + (seq as u64);
    let hi16 = ((packet_index >> 32) & 0xffff) as u16;
    let lo32 = (packet_index & 0xffff_ffff) as u32;
    iv[8] ^= (hi16 >> 8) as u8;
    iv[9] ^= hi16 as u8;
    iv[10] ^= (lo32 >> 24) as u8;
    iv[11] ^= (lo32 >> 16) as u8;
    iv[12] ^= (lo32 >> 8) as u8;
    iv[13] ^= lo32 as u8;
    iv
}

/// AES-128-CTR encrypt/decrypt of an RTP payload (symmetric).
pub fn crypt_payload(keys: &E2eSrtpKeys, ssrc: u32, seq: u16, roc: u32, payload: &[u8]) -> Vec<u8> {
    let iv = build_e2e_rtp_iv(&keys.salt, ssrc, roc, seq);
    let mut out = payload.to_vec();
    let mut cipher = AesCtr::new_from_slices(&keys.cipher_key, &iv).expect("16-byte key/iv");
    cipher.apply_keystream(&mut out);
    out
}

// ===== WARP MESSAGE-INTEGRITY (per-RTP auth) ================================

/// WARP MI tag length in bytes (the `<relay>` default; range 1..=20).
pub const WARP_MI_TAG_LEN: usize = 4;

/// WARP MI tag = first `tag_len` bytes of `HMAC-SHA1(auth_key, packet || roc_be32)`.
/// Keyed by the per-participant SRTP `auth_key`, NOT a separate warp key.
pub fn compute_warp_mi_tag(
    auth_key: &[u8],
    packet_without_tag: &[u8],
    roc: u32,
    tag_len: usize,
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut mac = Hmac::<Sha1>::new_from_slice(auth_key).expect("HMAC accepts any key length");
    mac.update(packet_without_tag);
    mac.update(&roc.to_be_bytes());
    mac.finalize().into_bytes()[..tag_len].to_vec()
}

/// Constant-time-verify a received WARP MI tag. Callers MUST reject a packet
/// whose tag fails BEFORE folding recv ROC state (RFC 3711 §3.3.1), so an
/// unauthenticated packet can't desync the rollover counter.
pub fn verify_warp_mi_tag(
    auth_key: &[u8],
    packet_without_tag: &[u8],
    roc: u32,
    tag_len: usize,
    received_tag: &[u8],
) -> bool {
    use subtle::ConstantTimeEq;
    let expected = compute_warp_mi_tag(auth_key, packet_without_tag, roc, tag_len);
    expected.ct_eq(received_tag).into()
}

/// Append the WARP MI tag to a protected packet.
pub fn append_warp_mi_tag(
    auth_key: &[u8],
    packet_without_tag: &[u8],
    roc: u32,
    tag_len: usize,
) -> Vec<u8> {
    let tag = compute_warp_mi_tag(auth_key, packet_without_tag, roc, tag_len);
    let mut out = Vec::with_capacity(packet_without_tag.len() + tag.len());
    out.extend_from_slice(packet_without_tag);
    out.extend_from_slice(&tag);
    out
}

// ===== SSRC derivation ======================================================

/// Participant / stream SSRC: `HKDF-SHA256(salt=slot_word_LE32, ikm=call_id,
/// info=lid, 4)`, read back as a little-endian u32. Audio media is slot 0.
pub fn derive_wasm_participant_ssrc(call_id: &str, lid: &str, slot_word: u32) -> u32 {
    let okm = hkdf_sha256(&slot_word.to_le_bytes(), call_id.as_bytes(), lid.as_bytes(), 4);
    u32::from_le_bytes([okm[0], okm[1], okm[2], okm[3]])
}

// ===== ROC trackers (RFC 3711 rollover counter) =============================

/// Send-side ROC tracker for monotonic 16-bit sequence numbers.
#[derive(Default)]
pub struct RocTracker {
    roc: u32,
    last_seq: u16,
    initialized: bool,
}

impl RocTracker {
    /// Fold the next outbound `seq`, returning the ROC to build its IV with.
    pub fn advance(&mut self, seq: u16) -> u32 {
        if !self.initialized {
            self.last_seq = seq;
            self.initialized = true;
            return self.roc;
        }
        // A signed 16-bit gap below -32768 is the wrap (seq jumped backward past
        // the half-range).
        if (seq as i32 - self.last_seq as i32) < -32768 {
            self.roc = self.roc.wrapping_add(1);
        }
        self.last_seq = seq;
        self.roc
    }
}

/// Recv-side ROC estimator (RFC 3711 §3.3.1 guess-index). Tolerates
/// reorder/loss: each packet's ROC is guessed from the highest seq seen, so a
/// late packet straddling a wrap decrypts under the right (lower) ROC. Estimate
/// (non-mutating) to build the IV / verify the tag, then commit ONLY after the
/// tag authenticates — an unauthenticated packet must not fold state.
#[derive(Default)]
pub struct RecvRocTracker {
    roc: u32,
    s_l: u16,
    initialized: bool,
}

impl RecvRocTracker {
    /// Estimate the ROC for `seq` WITHOUT mutating state.
    pub fn estimate_roc(&self, seq: u16) -> u32 {
        if !self.initialized {
            return self.roc;
        }
        if self.s_l < 0x8000 {
            if (seq as i32 - self.s_l as i32) > 0x8000 {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if (self.s_l as i32 - seq as i32) > 0x8000 {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        }
    }

    /// Fold an AUTHENTICATED packet's `(v, seq)` into the state; `v` must come
    /// from a prior [`Self::estimate_roc`] whose MI tag verified.
    pub fn commit_roc(&mut self, v: u32, seq: u16) {
        if !self.initialized {
            self.s_l = seq;
            self.initialized = true;
            return;
        }
        if v == self.roc {
            if seq > self.s_l {
                self.s_l = seq;
            }
        } else if v == self.roc.wrapping_add(1) {
            self.roc = v;
            self.s_l = seq;
        }
        // v == roc-1 (reordered late packet): leave state untouched.
    }

    /// Estimate + commit in one step. Test-only: production authenticates the
    /// WARP tag against `estimate_roc` first and only commits on success.
    #[cfg(test)]
    fn guess_roc(&mut self, seq: u16) -> u32 {
        let v = self.estimate_roc(seq);
        self.commit_roc(v, seq);
        v
    }
}

// ===== Signaling: <call> stanza parse + answer builders =====================
//
// Ported from whatsapp-rust `wacore/src/stanza/call.rs` (algorithm, not API
// surface — ruwa's Node is an attr map + content, not a typed NodeRef). Only
// the 1:1-audio answer path: parse the offer's callKey `<enc>` + audio, and
// build the receipt / preaccept / accept we send back. Child order in
// preaccept/accept is server-enforced (a mis-ordered stanza is rejected 439).

use crate::protocol::binary::{Attrs, Content, Node};

/// `<capability ver=1>` blob selecting WhatsApp's **standard Opus** fallback
/// (not MLOW): the MLOW-gate bit (capability 31 = `use_mlow_codec_v1`) is byte 5
/// bit 7, cleared here. This is the codec ruwa forces on accept (libopus).
pub const CAPABILITY_STANDARD_OPUS_OFFER: [u8; 7] = [0x01, 0x05, 0xf7, 0x09, 0xe0, 0xbb & 0x7f, 0x13];
/// Audio-only `<preaccept>` capability, standard-Opus variant.
pub const CAPABILITY_STANDARD_OPUS_PREACCEPT: [u8; 7] =
    [0x01, 0x05, 0xf7, 0x09, 0xe0, 0xbb & 0x7f, 0x07];

/// `voip_settings` JSON forcing the standard-Opus decoder (PT 120, 16 kHz clock).
pub const STANDARD_OPUS_PT120_SETTINGS: &[u8] =
    br#"{"encode":{"use_mlow_codec_v1":"false"},"options":{"enable_48khz_rtp_clock":"false"}}"#;

/// The Signal-encrypted callKey carried by an `<offer>` for our device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferEnc {
    /// Signal message wire type: `pkmsg` (establishes a session) or `msg`.
    pub enc_type: String,
    /// `<enc v>` padding version; defaults to 2 when absent.
    pub version: u32,
    pub ciphertext: Vec<u8>,
}

/// The fields of an inbound `<call><offer>` the answer path needs. The callKey
/// still has to be decrypted from `enc` (a Signal 1:1 decrypt against
/// `call_creator`) at accept time; the parsed `relay` drives the media transport.
#[derive(Debug, Clone)]
pub struct ParsedOffer {
    pub call_id: String,
    pub call_creator: String,
    /// Caller JID (the `<call>` `from`).
    pub from: String,
    pub is_video: bool,
    /// Offered `<audio enc rate>` rates, in the order advertised.
    pub audio_rates: Vec<u32>,
    /// The callKey `<enc>` addressed to this device.
    pub enc: OfferEnc,
    /// The parsed `<relay>` block (endpoints + STUN key + tokens), if present.
    pub relay: Option<RelayData>,
    /// The peer advertised MLow in its offer `<capability>` (byte 5 bit 7, the
    /// `use_mlow_codec_v1` gate). Such peers send MLow media regardless of our
    /// forced-Opus accept, so the media loop must decode/encode MLow for them.
    pub mlow: bool,
}

/// True if a call `<capability ver=1>` blob has the MLow gate bit set (byte 5
/// bit 7). Our own offer/accept clears it to force Opus; a peer whose offer
/// keeps it set will speak MLow. Mirrors `CAPABILITY_MLOW_OFFER[5] & 0x80`.
pub fn capability_wants_mlow(blob: &[u8]) -> bool {
    blob.get(5).is_some_and(|b| b & 0x80 != 0)
}

fn child<'a>(node: &'a Node, tag: &str) -> Option<&'a Node> {
    match &node.content {
        Content::Nodes(ns) => ns.iter().find(|c| c.tag == tag),
        _ => None,
    }
}

fn children<'a>(node: &'a Node, tag: &'a str) -> impl Iterator<Item = &'a Node> {
    let it = match &node.content {
        Content::Nodes(ns) => Some(ns.iter()),
        _ => None,
    };
    it.into_iter().flatten().filter(move |c| c.tag == tag)
}

fn node_bytes(node: &Node) -> Option<&[u8]> {
    match &node.content {
        Content::Bytes(b) => Some(b),
        _ => None,
    }
}

fn parse_offer_enc(enc: &Node) -> Option<OfferEnc> {
    let ciphertext = node_bytes(enc)?.to_vec();
    if ciphertext.is_empty() {
        return None;
    }
    Some(OfferEnc {
        enc_type: enc.attrs.get("type").cloned().unwrap_or_else(|| "pkmsg".into()),
        version: enc.attrs.get("v").and_then(|v| v.parse().ok()).unwrap_or(2),
        ciphertext,
    })
}

/// Select the callKey `<enc>` for our own device: a bare `<enc>` child of the
/// offer (single-device), else the `<destination><to jid=own_lid><enc>` entry
/// matching our LID (multi-device). `None` if the offer carries no enc for us.
fn enc_for_device(offer: &Node, own_lid: &str) -> Option<OfferEnc> {
    if let Some(enc) = child(offer, "enc") {
        return parse_offer_enc(enc);
    }
    let dest = child(offer, "destination")?;
    for to in children(dest, "to") {
        if to.attrs.get("jid").map(String::as_str) == Some(own_lid) {
            if let Some(enc) = child(to, "enc") {
                return parse_offer_enc(enc);
            }
        }
    }
    None
}

/// Parse an inbound `<call>` whose action is `<offer>` into a [`ParsedOffer`].
/// `own_lid` selects our per-device callKey enc on a multi-device offer.
/// `None` for a non-offer `<call>` or an offer with no usable enc for us.
pub fn parse_offer(call: &Node, own_lid: &str) -> Option<ParsedOffer> {
    if call.tag != "call" {
        return None;
    }
    let offer = child(call, "offer")?;
    let call_id = offer.attrs.get("call-id").cloned()?;
    let call_creator = offer.attrs.get("call-creator").cloned()?;
    let from = call.attrs.get("from").cloned().unwrap_or_default();
    let is_video = child(offer, "video").is_some();
    let audio_rates = children(offer, "audio")
        .filter_map(|a| a.attrs.get("rate").and_then(|r| r.parse::<u32>().ok()))
        .collect();
    let enc = enc_for_device(offer, own_lid)?;
    let relay = find_relay(call).map(parse_relay_data);
    let mlow = child(offer, "capability")
        .and_then(node_bytes)
        .is_some_and(capability_wants_mlow);
    Some(ParsedOffer {
        call_id,
        call_creator,
        from,
        is_video,
        audio_rates,
        enc,
        relay,
        mlow,
    })
}

/// Extract the 32-byte callKey from a decrypted `waE2E.Message` — the offer's
/// `<enc>` plaintext after a Signal 1:1 decrypt + unpad. The key lives at
/// `Message.call(10).callKey(1)`. `None` if absent or not exactly 32 bytes
/// (a malformed peer callKey; SRTP derivation requires 32).
pub fn call_key_from_e2e(plaintext: &[u8]) -> Option<[u8; 32]> {
    use ::prost::Message as _;
    let msg = crate::proto::wa_web_protobufs_e2e::Message::decode(plaintext).ok()?;
    let key = msg.call?.call_key?;
    key.as_slice().try_into().ok()
}

// --- answer builders (non-AD jids, child order load-bearing) ----------------

fn attr(pairs: &[(&str, &str)]) -> Attrs {
    let mut a = Attrs::new();
    for (k, v) in pairs {
        a.insert((*k).into(), (*v).into());
    }
    a
}

fn node(tag: &str, attrs: Attrs, content: Content) -> Node {
    Node { tag: tag.into(), attrs, content }
}

fn audio_opus(rate: &str) -> Node {
    node("audio", attr(&[("enc", "opus"), ("rate", rate)]), Content::None)
}

/// `<encopt keygen=2>` — selects the v2 SRTP key path; mandatory on
/// offer/preaccept/accept.
fn encopt_node() -> Node {
    node("encopt", attr(&[("keygen", "2")]), Content::None)
}

fn capability_node(blob: &[u8]) -> Node {
    node("capability", attr(&[("ver", "1")]), Content::Bytes(blob.to_vec()))
}

/// `<call to id><ACTION call-id call-creator>children</ACTION></call>`.
fn call_wrap(to: &str, id: &str, action: Node) -> Node {
    node("call", attr(&[("to", to), ("id", id)]), Content::Nodes(vec![action]))
}

fn offer_action(tag: &str, call_id: &str, call_creator: &str, children: Vec<Node>) -> Node {
    node(
        tag,
        attr(&[("call-id", call_id), ("call-creator", call_creator)]),
        Content::Nodes(children),
    )
}

/// `<receipt><offer/></receipt>` — the ring acknowledgement sent immediately on
/// receiving an offer. `own_ad` (our LID or PN) is omitted when unavailable.
pub fn build_offer_ack_receipt(
    from: &str,
    stanza_id: &str,
    call_id: &str,
    call_creator: &str,
    own_ad: Option<&str>,
) -> Node {
    let mut attrs = attr(&[("to", from), ("id", stanza_id)]);
    if let Some(ad) = own_ad {
        attrs.insert("from".into(), ad.into());
    }
    let offer = node(
        "offer",
        attr(&[("call-id", call_id), ("call-creator", call_creator)]),
        Content::None,
    );
    node("receipt", attrs, Content::Nodes(vec![offer]))
}

/// `<preaccept>`: audio → encopt → capability. Sent BEFORE the callKey decrypt
/// to stop the caller's sibling devices ringing. Audio-only (1:1).
pub fn build_preaccept(
    call_id: &str,
    to: &str,
    call_creator: &str,
    wrapper_id: &str,
    audio_rates: &[&str],
) -> Node {
    let mut children: Vec<Node> = audio_rates.iter().map(|r| audio_opus(r)).collect();
    children.push(encopt_node());
    children.push(capability_node(&CAPABILITY_STANDARD_OPUS_PREACCEPT));
    call_wrap(to, wrapper_id, offer_action("preaccept", call_id, call_creator, children))
}

/// `<accept>` forcing standard Opus: audio → net → encopt → capability →
/// voip_settings. The wrapper `id` is REQUIRED — an idless accept is silently
/// dropped by the server. 1:1 audio only (no te/rte/metadata/video).
pub fn build_accept(
    call_id: &str,
    to: &str,
    call_creator: &str,
    wrapper_id: &str,
    audio_rates: &[&str],
) -> Node {
    let mut children: Vec<Node> = audio_rates.iter().map(|r| audio_opus(r)).collect();
    children.push(node("net", attr(&[("medium", "2")]), Content::None));
    children.push(encopt_node());
    children.push(capability_node(&CAPABILITY_STANDARD_OPUS_OFFER));
    children.push(node(
        "voip_settings",
        attr(&[("uncompressed", "1")]),
        Content::Bytes(STANDARD_OPUS_PT120_SETTINGS.to_vec()),
    ));
    call_wrap(to, wrapper_id, offer_action("accept", call_id, call_creator, children))
}

/// `<call to id><terminate call-id call-creator [reason]/></call>` — ends an
/// active call we answered (our hangup). Addressed to the answering device
/// (`to` = the caller). Both jids ship non-AD.
pub fn build_terminate(
    msg_id: &str,
    to: &str,
    call_creator: &str,
    call_id: &str,
    reason: Option<&str>,
) -> Node {
    fn non_ad(jid: &str) -> String {
        match jid.split_once('@') {
            Some((user, server)) => format!("{}@{}", user.split(':').next().unwrap_or(user), server),
            None => jid.to_string(),
        }
    }
    let mut ta = attr(&[("call-id", call_id), ("call-creator", &non_ad(call_creator))]);
    if let Some(r) = reason {
        ta.insert("reason".into(), r.into());
    }
    node(
        "call",
        attr(&[("id", msg_id), ("to", &non_ad(to))]),
        Content::Nodes(vec![node("terminate", ta, Content::None)]),
    )
}

// ===== Outbound origination: place a 1:1 audio call =========================
//
// Ported from whatsapp-rust `src/voip/facade.rs::place_call` + upstream
// `wacore/src/stanza/call.rs::build_offer` (1:1-audio subset). We initiate:
// generate a callKey, Signal-encrypt it to each of the peer's devices, ship a
// `<call><offer>`, then the server's `<ack type=offer>` carries the `<relay>`
// (same block shape as an inbound offer) that drives the media transport.

/// `<capability ver=1>` offer blob with the MLOW-gate bit (capability 31 =
/// `use_mlow_codec_v1`, byte 5 bit 7) SET — the phone's default. ruwa forces
/// standard Opus instead ([`CAPABILITY_STANDARD_OPUS_OFFER`]); this constant is
/// kept only to document what we deliberately clear.
pub const CAPABILITY_MLOW_OFFER: [u8; 7] = [0x01, 0x05, 0xf7, 0x09, 0xe0, 0xbb, 0x13];

/// Generate a fresh call-id: `"00"` + 15 random bytes as lowercase hex = 32
/// hex chars. Mirrors WA Web's `_e()` / whatsapp-rust `gen_call_id`.
pub fn generate_call_id() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 15];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let mut s = String::with_capacity(32);
    s.push_str("00");
    for b in raw {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A freshly generated 32-byte callKey (the E2E-SRTP master secret both sides
/// derive from). Generated by the CALLER, encrypted to the callee's devices.
pub fn generate_call_key() -> [u8; 32] {
    use rand::RngCore;
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// Encode the callKey as the plaintext body of a `waE2E.Message` (`call.callKey`,
/// fields 10→1) — the exact shape [`call_key_from_e2e`] decodes on the inbound
/// side. This is what gets Signal-encrypted (after message padding) per device.
pub fn encode_call_key_message(call_key: &[u8; 32]) -> Vec<u8> {
    use ::prost::Message as _;
    let msg = crate::proto::wa_web_protobufs_e2e::Message {
        call: Some(Box::new(crate::proto::wa_web_protobufs_e2e::Call {
            call_key: Some(call_key.to_vec()),
            ..Default::default()
        })),
        ..Default::default()
    };
    msg.encode_to_vec()
}

/// One peer device's Signal-encrypted callKey, ready to place in an `<offer>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferDeviceKey {
    /// The device's wire JID (`<to jid>`), kept as usync returned it.
    pub device_jid: String,
    /// `pkmsg` (establishes a session) or `msg`.
    pub enc_type: String,
    pub ciphertext: Vec<u8>,
}

/// `<enc v=2 type=… count=0>ct</enc>`.
fn offer_enc_node(enc_type: &str, ciphertext: &[u8]) -> Node {
    node(
        "enc",
        attr(&[("v", "2"), ("type", enc_type), ("count", "0")]),
        Content::Bytes(ciphertext.to_vec()),
    )
}

/// Build the outbound `<call to id><offer …>…</offer></call>`. Child order is
/// load-bearing (the server returns `<ack error=439>` on a wrong order):
/// `[audio] net capability [destination] encopt [device-identity]`.
///
/// - `to` / `call_creator`: the peer's LID (bare) and our own LID (bare).
/// - `wrapper_id`: the `<call id>` — the ack-correlation id, NOT the call-id.
/// - `device_keys`: one per surviving peer device (from [`encode_call_key_message`]
///   Signal-encrypted). When there's exactly one and the peer is single-device,
///   a bare `<enc>` is emitted; otherwise each rides in `<destination><to jid>`.
/// - `multi_device`: true when the peer's FULL resolved device set had >1 entry
///   (computed before encrypt filtering) — keeps the addressed shape stable.
/// - `device_identity`: our ADV account proto, attached iff any enc is `pkmsg`.
#[allow(clippy::too_many_arguments)]
pub fn build_offer(
    call_id: &str,
    to: &str,
    call_creator: &str,
    wrapper_id: &str,
    audio_rate: &str,
    privacy_token: Option<&[u8]>,
    device_keys: &[OfferDeviceKey],
    multi_device: bool,
    device_identity: Option<&[u8]>,
) -> Node {
    let mut children: Vec<Node> = Vec::new();
    if let Some(tok) = privacy_token {
        children.push(node("privacy", Attrs::new(), Content::Bytes(tok.to_vec())));
    }
    children.push(audio_opus(audio_rate));
    // The offer advertises medium=3 (accept/transport use medium=2).
    children.push(node("net", attr(&[("medium", "3")]), Content::None));
    children.push(capability_node(&CAPABILITY_STANDARD_OPUS_OFFER));

    let addressed = multi_device || device_keys.len() > 1;
    let any_pkmsg = device_keys.iter().any(|d| d.enc_type == "pkmsg");
    if addressed {
        let tos: Vec<Node> = device_keys
            .iter()
            .map(|d| {
                node(
                    "to",
                    attr(&[("jid", &d.device_jid)]),
                    Content::Nodes(vec![offer_enc_node(&d.enc_type, &d.ciphertext)]),
                )
            })
            .collect();
        children.push(node("destination", Attrs::new(), Content::Nodes(tos)));
    } else if let Some(d) = device_keys.first() {
        children.push(offer_enc_node(&d.enc_type, &d.ciphertext));
    }
    children.push(encopt_node());
    if any_pkmsg {
        if let Some(di) = device_identity {
            children.push(node("device-identity", Attrs::new(), Content::Bytes(di.to_vec())));
        }
    }
    call_wrap(to, wrapper_id, offer_action("offer", call_id, call_creator, children))
}

// ===== Relay parse: the <relay> block of an offer ===========================
//
// Ported from whatsapp-rust `wacore/src/voip/relay_parse.rs` (1:1-audio subset).
// The offer carries a `<relay>` with the endpoints + crypto material the media
// transport dials: `<key>` (STUN MESSAGE-INTEGRITY key — used as raw ASCII, NOT
// decoded), `<token id>` (relay tokens), and `<te2>` endpoints (IPv4:port).

/// Default te2 port (0x0D96). A relay answering here carries uplink but does
/// NOT forward the peer's stream back — see [`WEB_CLIENT_RELAY_PORT`].
pub const WHATSAPP_RELAY_PORT: u16 = 3478;
/// The web-client media port. Prefer an endpoint here or the call goes silently
/// one-way (WhatsApp issue #1098): a 3478 pick connects but never delivers the
/// peer's audio back.
pub const WEB_CLIENT_RELAY_PORT: u16 = 3480;
/// The relay is untrusted; bound `<token id>` so it can't force a huge alloc.
const MAX_RELAY_TOKENS: usize = 64;
/// `<hbh_key>` length: 14-byte salt seed + 16-byte key seed.
const HBH_KEY_LEN: usize = 30;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAddress {
    pub protocol: u8,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct RelayEndpoint {
    pub relay_id: u32,
    pub relay_name: String,
    pub token_id: u32,
    pub auth_token_id: u32,
    pub is_fna: bool,
    pub addresses: Vec<RelayAddress>,
    pub c2r_rtt_ms: Option<u32>,
}

/// The parsed `<relay>` block. Secret material (keys/tokens) is held but never
/// logged — the `Debug` impl redacts it.
#[derive(Clone, Default)]
pub struct RelayData {
    pub hbh_key: Option<Vec<u8>>,
    pub relay_key: Option<Vec<u8>>,
    /// Raw `<key>` content BEFORE base64 decode — this is the STUN MI key, used
    /// verbatim (decoding it first fails the allocate).
    pub relay_key_ascii: Option<Vec<u8>>,
    pub warp_mi_tag_len: Option<u32>,
    pub uuid: Option<String>,
    pub relay_tokens: Vec<Vec<u8>>,
    pub auth_tokens: Vec<Vec<u8>>,
    pub endpoints: Vec<RelayEndpoint>,
}

impl core::fmt::Debug for RelayData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let redact = |o: &Option<Vec<u8>>| o.as_ref().map(|_| "[redacted]");
        f.debug_struct("RelayData")
            .field("hbh_key", &redact(&self.hbh_key))
            .field("relay_key", &redact(&self.relay_key))
            .field("relay_key_ascii", &redact(&self.relay_key_ascii))
            .field("warp_mi_tag_len", &self.warp_mi_tag_len)
            .field("uuid", &self.uuid)
            .field("relay_tokens", &format_args!("[{} redacted]", self.relay_tokens.len()))
            .field("auth_tokens", &format_args!("[{} redacted]", self.auth_tokens.len()))
            .field("endpoints", &self.endpoints)
            .finish()
    }
}

fn looks_like_base64(txt: &str) -> bool {
    txt.len() >= 4
        && txt.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/' || c == b'=')
}

fn try_decode_base64(bytes: &[u8]) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let txt = std::str::from_utf8(bytes).ok()?;
    if !looks_like_base64(txt) {
        return None;
    }
    B64.decode(txt).ok()
}

/// Decode `<hbh_key>` to its 30 bytes; handles a double-base64 wrapper.
fn decode_hbh_key(bytes: &[u8]) -> Option<Vec<u8>> {
    if bytes.is_empty() {
        return None;
    }
    let mut decoded = try_decode_base64(bytes).unwrap_or_else(|| bytes.to_vec());
    if decoded.len() != HBH_KEY_LEN {
        if let Some(inner) = try_decode_base64(&decoded) {
            if inner.len() == HBH_KEY_LEN {
                decoded = inner;
            }
        }
    }
    (decoded.len() == HBH_KEY_LEN).then_some(decoded)
}

/// Decode `<key>` to raw bytes (16B for STUN MI), falling back to the input.
fn decode_relay_key_content(bytes: &[u8]) -> Vec<u8> {
    try_decode_base64(bytes).unwrap_or_else(|| bytes.to_vec())
}

/// Parse `<token id=i>`/`<auth_token id=i>` children into a sparse-by-index Vec
/// (missing lower indices padded with empty Vecs). Ids past the cap are dropped.
fn parse_indexed_tokens(relay: &Node, tag: &str) -> Vec<Vec<u8>> {
    let mut tokens: Vec<Vec<u8>> = Vec::new();
    for node in children(relay, tag) {
        let Some(bytes) = node_bytes(node) else { continue };
        let id = node
            .attrs
            .get("id")
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(tokens.len());
        if id >= MAX_RELAY_TOKENS {
            continue;
        }
        while tokens.len() <= id {
            tokens.push(Vec::new());
        }
        tokens[id] = bytes.to_vec();
    }
    tokens
}

/// Parse a te2 address payload: 6 bytes = IPv4(4)+port(2 BE), 18 = IPv6+port.
fn parse_te2_address(bytes: &[u8], protocol: u8) -> Option<RelayAddress> {
    match bytes.len() {
        6 => Some(RelayAddress {
            protocol,
            ipv4: Some(format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])),
            ipv6: None,
            port: ((bytes[4] as u16) << 8) | bytes[5] as u16,
        }),
        18 => {
            let mut parts = Vec::with_capacity(8);
            for i in (0..16).step_by(2) {
                parts.push(format!("{:x}", ((bytes[i] as u16) << 8) | bytes[i + 1] as u16));
            }
            Some(RelayAddress {
                protocol,
                ipv4: None,
                ipv6: Some(parts.join(":")),
                port: ((bytes[16] as u16) << 8) | bytes[17] as u16,
            })
        }
        _ => None,
    }
}

/// Find the first `<relay>` node anywhere in a `<call>` subtree (the offer's
/// relay may sit under `<call>` or `<offer>`).
pub fn find_relay(node: &Node) -> Option<&Node> {
    if node.tag == "relay" {
        return Some(node);
    }
    match &node.content {
        Content::Nodes(ns) => ns.iter().find_map(find_relay),
        _ => None,
    }
}

/// Parse a `<relay>` node into [`RelayData`]. `None` inputs (no relay) are the
/// caller's concern; a present-but-empty relay parses to an all-default struct.
pub fn parse_relay_data(relay: &Node) -> RelayData {
    let find_bytes = |tag: &str| child(relay, tag).and_then(node_bytes);

    let key_bytes = find_bytes("key").map(<[u8]>::to_vec);
    let hbh_key_bytes = find_bytes("hbh_key").map(<[u8]>::to_vec);
    let warp_mi_tag_len = find_bytes("warp_mi_tag_len")
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0);

    let relay_tokens = parse_indexed_tokens(relay, "token");
    let auth_tokens = parse_indexed_tokens(relay, "auth_token");

    let mut endpoints: Vec<RelayEndpoint> = Vec::new();
    let mut index_by_key: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for te2 in children(relay, "te2") {
        let Some(addr_bytes) = node_bytes(te2) else { continue };
        let attr_u32 = |k: &str| te2.attrs.get(k).and_then(|s| s.parse::<u32>().ok());
        let relay_id = attr_u32("relay_id").unwrap_or(0);
        let relay_name = te2.attrs.get("relay_name").cloned().unwrap_or_default();
        let token_id = attr_u32("token_id").unwrap_or(0);
        let auth_token_id = attr_u32("auth_token_id").unwrap_or(0);
        let is_fna = te2.attrs.get("is_fna").map(String::as_str) == Some("1");
        let protocol = attr_u32("protocol").unwrap_or(0) as u8;
        let c2r_rtt_ms = attr_u32("c2r_rtt");
        let Some(address) = parse_te2_address(addr_bytes, protocol) else { continue };

        let key = format!("{relay_id}:{relay_name}");
        let idx = *index_by_key.entry(key).or_insert_with(|| {
            endpoints.push(RelayEndpoint {
                relay_id,
                relay_name: relay_name.clone(),
                token_id,
                auth_token_id,
                is_fna,
                addresses: Vec::new(),
                c2r_rtt_ms,
            });
            endpoints.len() - 1
        });
        endpoints[idx].addresses.push(address);
        if let Some(rtt) = c2r_rtt_ms {
            endpoints[idx].c2r_rtt_ms = Some(rtt);
        }
    }

    RelayData {
        hbh_key: hbh_key_bytes.as_deref().and_then(decode_hbh_key),
        relay_key: key_bytes.as_deref().map(decode_relay_key_content),
        relay_key_ascii: key_bytes,
        warp_mi_tag_len,
        uuid: relay.attrs.get("uuid").cloned(),
        relay_tokens,
        auth_tokens,
        endpoints,
    }
}

/// The first IPv4 address+port of an endpoint (what the transport dials).
pub fn get_primary_ipv4_address(ep: &RelayEndpoint) -> Option<(String, u16)> {
    ep.addresses.iter().find_map(|a| a.ipv4.clone().map(|ip| (ip, a.port)))
}

/// An outbound (non-FNA, authed) relay candidate.
pub fn is_outbound_relay_candidate(ep: &RelayEndpoint) -> bool {
    !ep.is_fna && ep.auth_token_id != 0
}

/// Select the endpoint the media transport should dial. Prefers one on
/// [`WEB_CLIENT_RELAY_PORT`] (3480) — else the call is silently one-way — then
/// an outbound candidate, then any non-FNA, then the first; at each tier
/// preferring a USABLE endpoint (has an IPv4 AND a non-empty token we hold).
pub fn get_media_relay_endpoint(rd: &RelayData) -> Option<&RelayEndpoint> {
    let usable = |e: &RelayEndpoint| {
        get_primary_ipv4_address(e).is_some()
            && rd.relay_tokens.get(e.token_id as usize).is_some_and(|t| !t.is_empty())
    };
    let on_web_port = |e: &RelayEndpoint| {
        get_primary_ipv4_address(e).is_some_and(|(_, port)| port == WEB_CLIENT_RELAY_PORT)
    };
    let pick = |usable_only: bool| {
        rd.endpoints
            .iter()
            .find(|e| on_web_port(e) && (!usable_only || usable(e)))
            .or_else(|| rd.endpoints.iter().find(|e| is_outbound_relay_candidate(e) && (!usable_only || usable(e))))
            .or_else(|| rd.endpoints.iter().find(|e| !e.is_fna && (!usable_only || usable(e))))
            .or_else(|| rd.endpoints.iter().find(|e| !usable_only || usable(e)))
    };
    pick(true).or_else(|| pick(false))
}

// ===== STUN: relay allocate + consent ping ==================================
//
// Ported from whatsapp-rust `wacore/src/voip/stun.rs` (1:1-audio subset). The
// media transport connects to the relay by sending a STUN Allocate (relay token
// + stream descriptors + XOR endpoint, MESSAGE-INTEGRITY keyed by the relay
// `<key>` ASCII), then keeps it alive with a WhatsApp consent ping (0x0801).

const STUN_MAGIC: u32 = 0x2112_a442;
const STUN_FINGERPRINT_XOR: u32 = 0x5354_554e;
const STUN_XOR_PORT: u16 = 0x2112;
const STUN_XOR_ADDR: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];
const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
const ATTR_FINGERPRINT: u16 = 0x8028;
const ATTR_ERROR_CODE: u16 = 0x0009;
const ATTR_RELAY_TOKEN: u16 = 0x4000;
const STUN_ATTR_STREAM_DESCRIPTORS: u16 = 0x4024;
const STUN_ATTR_WASM_RELAY_ENDPOINT: u16 = 0x0016;

pub const MSG_ALLOCATE_REQUEST: u16 = 0x0003;
pub const MSG_BINDING_SUCCESS: u16 = 0x0101;
pub const MSG_ALLOCATE_SUCCESS: u16 = 0x0103;
pub const MSG_ALLOCATE_ERROR: u16 = 0x0113;
pub const MSG_WHATSAPP_PING: u16 = 0x0801;
pub const MSG_WHATSAPP_PONG: u16 = 0x0802;

fn pad4(n: usize) -> usize {
    (4 - (n % 4)) % 4
}

fn stun_attr(attr_type: u16, value: &[u8]) -> Vec<u8> {
    let pad = pad4(value.len());
    let mut buf = Vec::with_capacity(4 + value.len() + pad);
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buf.extend_from_slice(value);
    buf.resize(buf.len() + pad, 0);
    buf
}

/// CRC-32 (IEEE, reflected, poly 0xedb88320) for the STUN FINGERPRINT.
fn crc32(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in buf {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

fn stun_pseudo_header(msg_type: u16, msg_len: u16, tx: &[u8; 12]) -> [u8; 20] {
    let mut h = [0u8; 20];
    h[0..2].copy_from_slice(&msg_type.to_be_bytes());
    h[2..4].copy_from_slice(&msg_len.to_be_bytes());
    h[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    h[8..20].copy_from_slice(tx);
    h
}

/// Encode a STUN request (RFC 5389): header + attrs, then optional
/// MESSAGE-INTEGRITY (HMAC-SHA1 over a pseudo-header whose length already counts
/// the MI attr) and FINGERPRINT.
pub fn encode_stun_request(
    msg_type: u16,
    tx: &[u8; 12],
    attrs: &[u8],
    integrity_key: Option<&[u8]>,
    include_fingerprint: bool,
) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    let mut body = attrs.to_vec();
    if let Some(key) = integrity_key {
        let msg_len = (body.len() + 24) as u16; // attrs + MI attr (4 + 20)
        let header = stun_pseudo_header(msg_type, msg_len, tx);
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(&header);
        mac.update(&body);
        let mi = mac.finalize().into_bytes();
        body.extend_from_slice(&stun_attr(ATTR_MESSAGE_INTEGRITY, &mi));
    }
    if include_fingerprint {
        let msg_len = (body.len() + 8) as u16; // attrs + FINGERPRINT attr (4 + 4)
        let header = stun_pseudo_header(msg_type, msg_len, tx);
        let mut crc_input = Vec::with_capacity(20 + body.len());
        crc_input.extend_from_slice(&header);
        crc_input.extend_from_slice(&body);
        let fp = crc32(&crc_input) ^ STUN_FINGERPRINT_XOR;
        body.extend_from_slice(&stun_attr(ATTR_FINGERPRINT, &fp.to_be_bytes()));
    }
    let mut out = Vec::with_capacity(20 + body.len());
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC.to_be_bytes());
    out.extend_from_slice(tx);
    out.extend_from_slice(&body);
    out
}

/// XOR-encoded IPv4:port (6 bytes) for the WASM relay endpoint attr.
pub fn encode_xor_relay_endpoint(ipv4: &str, port: u16) -> Option<[u8; 6]> {
    let octets: Vec<u8> = ipv4.split('.').filter_map(|n| n.parse::<u8>().ok()).collect();
    if octets.len() != 4 {
        return None;
    }
    let mut buf = [0u8; 6];
    buf[0..2].copy_from_slice(&(port ^ STUN_XOR_PORT).to_be_bytes());
    for i in 0..4 {
        buf[2 + i] = octets[i] ^ STUN_XOR_ADDR[i];
    }
    Some(buf)
}

fn create_wasm_relay_endpoint_attr(endpoint_xor: &[u8; 6]) -> [u8; 8] {
    let mut buf = [0u8; 8];
    buf[0..2].copy_from_slice(&1u16.to_be_bytes());
    buf[2..8].copy_from_slice(endpoint_xor);
    buf
}

// Minimal protobuf wire encoding for the stream-descriptor attr.
fn pb_varint(out: &mut Vec<u8>, mut v: u64) {
    while v > 0x7f {
        out.push(((v & 0x7f) | 0x80) as u8);
        v >>= 7;
    }
    out.push((v & 0xff) as u8);
}
fn pb_tag(out: &mut Vec<u8>, field: u32, wire: u32) {
    pb_varint(out, ((field << 3) | wire) as u64);
}
fn pb_len_delim(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    pb_tag(out, field, 2);
    pb_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

/// `(stream_index, sub_type, slot_word)` in WASM wire order: audio/video0/video1
/// × media/FEC/NACK.
const WASM_STREAM_SLOTS: [(u32, u32, u32); 9] = [
    (0, 0, 0), (0, 1, 1), (0, 2, 4),
    (1, 0, 2), (1, 1, 3), (1, 2, 5),
    (2, 0, 7), (2, 1, 8), (2, 2, 6),
];

/// Stream descriptors for the allocate: one per stream slot, SSRC derived from
/// (call_id, our participant LID, slot).
pub fn create_wasm_stream_descriptors(call_id: &str, self_participant_id: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for (stream_index, sub_type, slot) in WASM_STREAM_SLOTS.iter().copied() {
        let ssrc = derive_wasm_participant_ssrc(call_id, self_participant_id, slot);
        if ssrc == 0 {
            continue;
        }
        let mut d = Vec::new();
        if stream_index != 0 {
            pb_tag(&mut d, 1, 0);
            pb_varint(&mut d, stream_index as u64);
        }
        if sub_type != 0 {
            pb_tag(&mut d, 2, 0);
            pb_varint(&mut d, sub_type as u64);
        }
        pb_tag(&mut d, 3, 0);
        pb_varint(&mut d, ssrc as u64);
        pb_len_delim(&mut out, 1, &d);
    }
    out
}

/// Build the 1:1 WASM STUN Allocate: RELAY_TOKEN + STREAM_DESCRIPTORS +
/// WASM_RELAY_ENDPOINT, MESSAGE-INTEGRITY keyed by the relay `<key>` ASCII
/// (`integrity_key`), no FINGERPRINT.
pub fn build_wasm_stun_allocate_request(
    tx: &[u8; 12],
    relay_token: &[u8],
    endpoint_xor: &[u8; 6],
    integrity_key: &[u8],
    call_id: &str,
    self_participant_id: &str,
) -> Vec<u8> {
    let mut attrs = stun_attr(ATTR_RELAY_TOKEN, relay_token);
    attrs.extend_from_slice(&stun_attr(
        STUN_ATTR_STREAM_DESCRIPTORS,
        &create_wasm_stream_descriptors(call_id, self_participant_id),
    ));
    attrs.extend_from_slice(&stun_attr(
        STUN_ATTR_WASM_RELAY_ENDPOINT,
        &create_wasm_relay_endpoint_attr(endpoint_xor),
    ));
    encode_stun_request(MSG_ALLOCATE_REQUEST, tx, &attrs, Some(integrity_key), false)
}

/// WhatsApp consent ping (type 0x0801, empty body) — keeps the relay alloc alive.
pub fn build_whatsapp_ping(tx: &[u8; 12]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&MSG_WHATSAPP_PING.to_be_bytes());
    out[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    out[8..20].copy_from_slice(tx);
    out
}

pub fn is_stun_packet(data: &[u8]) -> bool {
    data.len() >= 2 && (data[0] & 0xc0) == 0x00
}
pub fn stun_message_type(data: &[u8]) -> Option<u16> {
    (data.len() >= 2).then(|| (((data[0] & 0x3f) as u16) << 8) | data[1] as u16)
}
pub fn stun_transaction_id(data: &[u8]) -> Option<&[u8]> {
    (data.len() >= 20).then(|| &data[8..20])
}

fn is_complete_stun(data: &[u8]) -> bool {
    if !(is_stun_packet(data) && data.len() >= 20 && data[4..8] == STUN_MAGIC.to_be_bytes()) {
        return false;
    }
    let body_len = ((data[2] as usize) << 8) | data[3] as usize;
    body_len.is_multiple_of(4) && data.len() >= 20 + body_len
}

pub fn is_allocate_or_binding_success(data: &[u8]) -> bool {
    is_complete_stun(data)
        && matches!(stun_message_type(data), Some(MSG_ALLOCATE_SUCCESS | MSG_BINDING_SUCCESS))
}
pub fn is_allocate_error(data: &[u8]) -> bool {
    is_complete_stun(data) && stun_message_type(data) == Some(MSG_ALLOCATE_ERROR)
}
pub fn is_whatsapp_pong(data: &[u8], tx: Option<&[u8]>) -> bool {
    if !is_stun_packet(data) || stun_message_type(data) != Some(MSG_WHATSAPP_PONG) {
        return false;
    }
    match tx {
        None | Some(&[]) => true,
        Some(want) => stun_transaction_id(data) == Some(want),
    }
}

/// `class*100 + number` from an ERROR-CODE attr of an allocate/binding error.
pub fn parse_stun_error_code(data: &[u8]) -> Option<u16> {
    if !is_complete_stun(data) {
        return None;
    }
    let t = stun_message_type(data)?;
    if t != MSG_ALLOCATE_ERROR && t != 0x0111 {
        return None;
    }
    let body_len = ((data[2] as usize) << 8) | data[3] as usize;
    let end = (20 + body_len).min(data.len());
    let mut off = 20;
    while off + 4 <= end {
        let attr_type = ((data[off] as u16) << 8) | data[off + 1] as u16;
        let len = ((data[off + 2] as usize) << 8) | data[off + 3] as usize;
        if attr_type == ATTR_ERROR_CODE && len >= 4 && off + 8 <= end {
            let class = data[off + 6] as u16;
            let number = data[off + 7] as u16;
            return Some(class * 100 + number);
        }
        off += 4 + len + pad4(len);
    }
    None
}

// ===== Media transport: UDP→DTLS→SCTP→DataChannel to the relay ==============
//
// Ported from whatsapp-rust `src/voip/transport.rs`. The WA relay speaks the
// WebRTC data-channel protocol, so the media plane is: connect a UDP socket to
// the relay, DTLS-handshake as client (self-signed cert, server-cert check
// SKIPPED — SRTP keys come from the callKey, not DTLS), run an SCTP association,
// and open the pre-negotiated id=0 DataChannel that carries STUN/RTP/RTCP as
// binary messages. Live-only — validated against a real relay, never in a unit
// test (see the RUWA_LIVE_TEST-gated test).

use std::net::SocketAddr;
use std::sync::Arc;

/// DataChannel label WA Web uses (pre-negotiated, id=0).
const DATA_CHANNEL_LABEL: &str = "pre-negotiated";
/// SCTP-over-DTLS WebRTC port.
const SCTP_PORT: u16 = 5000;
/// Bound on the UDP+DTLS+SCTP+DataChannel handshake.
const RELAY_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
/// SCTP reassembles inbound messages up to 65536 regardless of MTU; a smaller
/// buffer yields a fatal ErrShortBuffer. Size to the reassembly cap.
const RELAY_SCTP_READ_BUF: usize = 65536;

/// Bridge the util-0.11 `Conn` produced by webrtc-dtls to the util-0.17 `Conn`
/// consumed by webrtc-sctp. The traits are identical across the version gap.
struct DtlsToSctpConn(Arc<webrtc_dtls::conn::DTLSConn>);

fn remap_util_err(e: webrtc_util_011::Error) -> webrtc_util::Error {
    webrtc_util::Error::Other(e.to_string())
}

#[async_trait::async_trait]
impl webrtc_util::Conn for DtlsToSctpConn {
    async fn connect(&self, addr: SocketAddr) -> Result<(), webrtc_util::Error> {
        webrtc_util_011::Conn::connect(&*self.0, addr).await.map_err(remap_util_err)
    }
    async fn recv(&self, buf: &mut [u8]) -> Result<usize, webrtc_util::Error> {
        webrtc_util_011::Conn::recv(&*self.0, buf).await.map_err(remap_util_err)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), webrtc_util::Error> {
        webrtc_util_011::Conn::recv_from(&*self.0, buf).await.map_err(remap_util_err)
    }
    async fn send(&self, buf: &[u8]) -> Result<usize, webrtc_util::Error> {
        webrtc_util_011::Conn::send(&*self.0, buf).await.map_err(remap_util_err)
    }
    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> Result<usize, webrtc_util::Error> {
        webrtc_util_011::Conn::send_to(&*self.0, buf, target).await.map_err(remap_util_err)
    }
    fn local_addr(&self) -> Result<SocketAddr, webrtc_util::Error> {
        webrtc_util_011::Conn::local_addr(&*self.0).map_err(remap_util_err)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        webrtc_util_011::Conn::remote_addr(&*self.0)
    }
    async fn close(&self) -> Result<(), webrtc_util::Error> {
        webrtc_util_011::Conn::close(&*self.0).await.map_err(remap_util_err)
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

fn install_default_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// A connected relay media channel: the DataChannel plus the SCTP association it
/// rides (held for teardown). Send/recv carry STUN/RTP/RTCP binary messages.
pub struct RelayTransport {
    dc: Arc<webrtc_data::data_channel::DataChannel>,
    assoc: Arc<webrtc_sctp::association::Association>,
}

impl RelayTransport {
    /// Dial one relay endpoint: UDP→DTLS→SCTP→pre-negotiated id=0 DataChannel.
    async fn dial(relay_addr: SocketAddr) -> anyhow::Result<Self> {
        use anyhow::{anyhow, Context};
        use webrtc_sctp::association::{Association, Config as SctpConfig};

        // 1. UDP socket connected to the relay (bind in the relay's family).
        let bind_addr = if relay_addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
        let udp = tokio::net::UdpSocket::bind(bind_addr).await.context("bind udp")?;
        udp.connect(relay_addr).await.context("connect udp to relay")?;
        let udp: Arc<dyn webrtc_util_011::Conn + Send + Sync> = Arc::new(udp);

        // 2. DTLS client — self-signed cert, server-cert verification skipped
        //    (media auth is the SRTP callKey, not DTLS).
        install_default_crypto_provider();
        let cert = webrtc_dtls::crypto::Certificate::generate_self_signed(vec!["wa-voip".to_owned()])
            .map_err(|e| anyhow!("dtls self-signed cert: {e}"))?;
        let dtls_config = webrtc_dtls::config::Config {
            certificates: vec![cert],
            insecure_skip_verify: true,
            server_name: "localhost".to_owned(),
            ..Default::default()
        };
        let dtls = webrtc_dtls::conn::DTLSConn::new(udp, dtls_config, true, None)
            .await
            .map_err(|e| anyhow!("dtls handshake: {e}"))?;
        let net_conn: Arc<dyn webrtc_util::Conn + Send + Sync> =
            Arc::new(DtlsToSctpConn(Arc::new(dtls)));

        // 3. SCTP association (client) over DTLS.
        let assoc = Association::client(SctpConfig {
            net_conn,
            max_receive_buffer_size: 0,
            max_message_size: 0,
            mtu: 0,
            name: "wa-voip".to_owned(),
            remote_port: SCTP_PORT,
            local_port: SCTP_PORT,
        })
        .await
        .map_err(|e| anyhow!("sctp client: {e}"))?;
        let assoc = Arc::new(assoc);

        // 4. Pre-negotiated id=0 DataChannel, UNRELIABLE + UNORDERED: real-time
        //    RTP must not head-of-line-block on a reliable/ordered stream.
        use webrtc_sctp::chunk::chunk_payload_data::PayloadProtocolIdentifier;
        use webrtc_sctp::stream::ReliabilityType;
        let stream = assoc
            .open_stream(0, PayloadProtocolIdentifier::Binary)
            .await
            .map_err(|e| anyhow!("open sctp media stream: {e}"))?;
        stream.set_reliability_params(true, ReliabilityType::Rexmit, 0);
        let dc = webrtc_data::data_channel::DataChannel::client(
            stream,
            webrtc_data::data_channel::Config {
                channel_type: webrtc_data::message::message_channel_open::ChannelType::PartialReliableRexmitUnordered,
                reliability_parameter: 0,
                negotiated: true,
                label: DATA_CHANNEL_LABEL.to_owned(),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| anyhow!("datachannel client: {e}"))?;

        Ok(RelayTransport { dc: Arc::new(dc), assoc })
    }

    /// Connect to the relay, racing the advertised port and the web-client port
    /// (3480) — a relay may only answer on one, and either alone can black-hole.
    /// Bounded by [`RELAY_CONNECT_TIMEOUT`].
    pub async fn connect(relay_ip: &str, relay_port: u16) -> anyhow::Result<Self> {
        use anyhow::anyhow;
        let ip: std::net::IpAddr = relay_ip.parse().map_err(|_| anyhow!("bad relay ip {relay_ip}"))?;
        let mut candidates = vec![SocketAddr::new(ip, relay_port)];
        if relay_port != WEB_CLIENT_RELAY_PORT {
            candidates.push(SocketAddr::new(ip, WEB_CLIENT_RELAY_PORT));
        }
        let dials = candidates.iter().map(|&addr| Box::pin(Self::dial(addr)));
        let winner = tokio::time::timeout(
            RELAY_CONNECT_TIMEOUT,
            futures_util::future::select_ok(dials),
        )
        .await
        .map_err(|_| anyhow!("relay connect timed out (DTLS/SCTP didn't complete)"))?
        .map_err(|e| anyhow!("relay connect: {e}"))?
        .0;
        Ok(winner)
    }

    /// Send one binary message (STUN/RTP/RTCP) over the DataChannel.
    pub async fn send(&self, data: &[u8]) -> anyhow::Result<()> {
        self.dc
            .write(&bytes::Bytes::copy_from_slice(data))
            .await
            .map(|_| ())
            .map_err(|e| anyhow::anyhow!("relay datachannel write: {e}"))
    }

    /// Receive one binary message into `buf`, returning its length. Cancel-safe
    /// (one DataChannel message per call), so it composes in a `select!` loop.
    pub async fn recv(&self, buf: &mut [u8]) -> anyhow::Result<usize> {
        self.dc.read(buf).await.map_err(|e| anyhow::anyhow!("relay datachannel read: {e}"))
    }

    /// Tear down the DataChannel + SCTP association (releases the DTLS/UDP socket).
    pub async fn close(&self) {
        let _ = self.dc.close().await;
        let _ = self.assoc.close().await;
    }

    /// Connect, send the STUN Allocate, and wait for allocate-success — leaving
    /// the transport ready for media. Returns the transport + the negotiated
    /// audio SSRC (slot 0). Used by the accept path.
    pub async fn connect_and_allocate(
        relay_ip: &str,
        relay_port: u16,
        relay_token: &[u8],
        integrity_key: &[u8],
        call_id: &str,
        self_lid: &str,
    ) -> anyhow::Result<Self> {
        use anyhow::anyhow;
        let transport = Self::connect(relay_ip, relay_port).await?;
        let endpoint_xor = encode_xor_relay_endpoint(relay_ip, relay_port)
            .ok_or_else(|| anyhow!("relay ip not v4: {relay_ip}"))?;
        let tx: [u8; 12] = rand_tx_id();
        let allocate = build_wasm_stun_allocate_request(
            &tx, relay_token, &endpoint_xor, integrity_key, call_id, self_lid,
        );
        transport.send(&allocate).await?;
        // Wait for allocate-success (ignore other inbound until then), bounded.
        let mut buf = vec![0u8; RELAY_SCTP_READ_BUF];
        let deadline = std::time::Duration::from_secs(10);
        let got = tokio::time::timeout(deadline, async {
            loop {
                let n = transport.recv(&mut buf).await?;
                let pkt = &buf[..n];
                if is_allocate_or_binding_success(pkt) {
                    return Ok::<(), anyhow::Error>(());
                }
                if is_allocate_error(pkt) {
                    return Err(anyhow!("relay allocate error {:?}", parse_stun_error_code(pkt)));
                }
            }
        })
        .await;
        match got {
            Ok(Ok(())) => Ok(transport),
            Ok(Err(e)) => {
                transport.close().await;
                Err(e)
            }
            Err(_) => {
                transport.close().await;
                Err(anyhow!("relay allocate timed out"))
            }
        }
    }
}

/// OS-RNG STUN transaction id (unpredictable for consent freshness).
fn rand_tx_id() -> [u8; 12] {
    use rand::RngCore;
    let mut id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

// ===== Media loop: bridge the relay to the agent's PCM channels ==============

/// Classify a relay DataChannel packet by its first byte: STUN (consent), RTCP,
/// or RTP (media). Mirrors the reference demux.
enum RelayPacket {
    Stun,
    Rtcp,
    Rtp,
    Other,
}
fn classify_relay_packet(data: &[u8]) -> RelayPacket {
    match data.first() {
        None => RelayPacket::Other,
        Some(b) if b & 0xc0 == 0x00 => RelayPacket::Stun, // STUN: top 2 bits 0
        Some(b) if (0x80..=0xbf).contains(b) => {
            // RTP/RTCP share version 2; RTCP payload types are 200..=207 (byte[1] 0xc8..=0xcf).
            match data.get(1) {
                Some(pt) if (0xc8..=0xcf).contains(pt) => RelayPacket::Rtcp,
                _ => RelayPacket::Rtp,
            }
        }
        _ => RelayPacket::Other,
    }
}

/// Parameters for one call's media loop.
pub struct MediaLoop {
    pub transport: RelayTransport,
    /// Send keys (derived from our own LID) + our audio SSRC.
    pub send_keys: E2eSrtpKeys,
    pub send_ssrc: u32,
    /// Recv keys (derived from the peer's LID) for unprotecting the peer's audio.
    pub recv_keys: E2eSrtpKeys,
    /// PCM (960-sample, 16 kHz mono, s16le) frames FROM the agent to send to WA.
    pub from_agent: tokio::sync::mpsc::Receiver<Vec<i16>>,
    /// Decoded PCM frames from WA TO the agent.
    pub to_agent: tokio::sync::mpsc::Sender<Vec<i16>>,
    /// Fires to tear the loop down (WS closed, hangup, peer terminate).
    pub shutdown: Arc<tokio::sync::Notify>,
    /// The peer speaks MLow (from its offer capability): decode inbound with
    /// [`mlow::MlowDecoder`] and encode outbound with [`mlow::MlowEncoder`]
    /// instead of Opus, else it hears/produces robotic noise.
    pub mlow: bool,
}

impl MediaLoop {
    /// Drive the call media until shutdown or a fatal transport error. Owns one
    /// tokio task: a 60 ms send ticker (agent PCM → Opus → RTP → SRTP → relay;
    /// silence on underrun), a 1 s STUN consent ping (the real liveness signal —
    /// audio-only needs no RTCP answered), and an inbound pump (relay → unprotect
    /// → Opus decode → agent). Loss-tolerant: a bad packet is dropped, not fatal.
    pub async fn run(mut self) {
        let mut codec = match OpusCodec::new() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error=%e, "call: opus init failed");
                return;
            }
        };
        let mut rtp = RtpStream::new(self.send_ssrc, CODEC_FRAME_SAMPLES as u32);
        // WhatsApp's standard-Opus profile rides PT 120 (RTP_PAYLOAD_TYPE_WHATSAPP_AUDIO)
        // at a 16 kHz RTP clock — the codec is chosen by capability bit 31
        // (use_mlow_codec_v1=false), NOT by the PT. PT 111 is only for the
        // RFC-7587 48 kHz clock variant; stamping it while we run a 16 kHz clock
        // makes the peer drop every packet (call connects but carries no audio).
        rtp.set_payload_type(RTP_PAYLOAD_TYPE_MLOW); // 120 = WhatsApp audio PT
        // MLow peers get MLow speech markers + MLow-encoded payloads; Opus peers
        // get standard-Opus bytes (no markers). Both ride PT 120.
        rtp.set_mlow_profile(self.mlow);
        let mut mlow_dec = mlow::MlowDecoder::new();
        let mut mlow_enc = mlow::MlowEncoder::new();
        let mut send_roc = RocTracker::default();
        let mut recv_roc = RecvRocTracker::default();

        let mut send_tick = tokio::time::interval(std::time::Duration::from_millis(60));
        let mut ping_tick = tokio::time::interval(std::time::Duration::from_secs(1));
        let mut stat_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        let silence = vec![0i16; CODEC_FRAME_SAMPLES];
        let mut rx_buf = vec![0u8; RELAY_SCTP_READ_BUF];

        // Media-plane diagnostics (the loop is otherwise silent). Counts let a
        // live test tell "no audio" apart from "audio flowed": rtp_tx = packets
        // we sent, voiced_tx = non-silence frames from the agent, rtp_rx = RTP
        // packets from the peer, decrypt_ok/fail = SRTP unprotect outcome.
        let (mut rtp_tx, mut voiced_tx, mut rtp_rx, mut decrypt_ok, mut decrypt_fail) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        // Recv codec probe: mlow_like = payloads that look like WhatsApp MLOW
        // speech (peer ignored our forced-Opus → we can't decode it); decode_fail
        // = libopus rejected the payload. `probes` bounds the per-packet log.
        let (mut mlow_like, mut decode_fail, mut probes) = (0u64, 0u64, 0u32);

        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,

                _ = stat_tick.tick() => {
                    tracing::info!(
                        rtp_tx, voiced_tx, rtp_rx, decrypt_ok, decrypt_fail, mlow_like, decode_fail,
                        "call: media stats (5s)"
                    );
                }

                _ = send_tick.tick() => {
                    // Agent PCM, or silence on underrun (Opus DTX makes it cheap).
                    let pcm = match self.from_agent.try_recv() {
                        Ok(frame) => { voiced_tx += 1; frame }
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => silence.clone(),
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                    };
                    let payload = if self.mlow {
                        let f32pcm: Vec<f32> = pcm.iter().map(|&s| s as f32 / 32768.0).collect();
                        match mlow_enc.encode(&f32pcm) {
                            Ok(p) => p,
                            Err(e) => { tracing::warn!(error=?e, "call: mlow encode"); continue; }
                        }
                    } else {
                        match codec.encode(&pcm) {
                            Ok(p) => p,
                            Err(e) => { tracing::warn!(error=%e, "call: opus encode"); continue; }
                        }
                    };
                    let hdr = rtp.next_packet(&payload, false);
                    let mut header_bytes = Vec::new();
                    encode_rtp_header_into(&hdr, &mut header_bytes);
                    let roc = send_roc.advance(hdr.sequence_number);
                    let pkt = protect_audio_rtp(&self.send_keys, &header_bytes, &payload, self.send_ssrc, hdr.sequence_number, roc);
                    if let Err(e) = self.transport.send(&pkt).await {
                        tracing::warn!(error=%e, "call: relay send failed — ending media");
                        break;
                    }
                    rtp_tx += 1;
                }

                _ = ping_tick.tick() => {
                    let _ = self.transport.send(&build_whatsapp_ping(&rand_tx_id())).await;
                }

                r = self.transport.recv(&mut rx_buf) => {
                    let n = match r {
                        Ok(n) => n,
                        Err(e) => { tracing::warn!(error=%e, "call: relay recv failed — ending media"); break; }
                    };
                    let pkt = &rx_buf[..n];
                    if let RelayPacket::Rtp = classify_relay_packet(pkt) {
                        rtp_rx += 1;
                        if let Some((hdr, payload)) = unprotect_audio_rtp(&self.recv_keys, &mut recv_roc, pkt) {
                            decrypt_ok += 1;
                            // Codec probe: WA MLOW speech frames start 0x48..=0x57
                            // (20/60 ms); standard Opus TOC bytes don't. If the peer
                            // ignores our forced-Opus accept and sends MLOW, decoding
                            // it as Opus yields robotic garbage — this counts it.
                            if payload.first().is_some_and(|b| (0x48..=0x57).contains(b)) {
                                mlow_like += 1;
                            }
                            if probes < 5 {
                                probes += 1;
                                tracing::info!(
                                    pt = hdr.payload_type, len = payload.len(),
                                    b0 = payload.first().copied().unwrap_or(0),
                                    b1 = payload.get(1).copied().unwrap_or(0),
                                    "call: recv payload probe"
                                );
                            }
                            if self.mlow {
                                let f = mlow_dec.decode(&payload);
                                let pcm: Vec<i16> = f
                                    .iter()
                                    .map(|&s| (s * 32768.0).clamp(-32768.0, 32767.0) as i16)
                                    .collect();
                                let _ = self.to_agent.try_send(pcm);
                            } else {
                                match codec.decode(&payload) {
                                    Ok(pcm) => { let _ = self.to_agent.try_send(pcm); }
                                    Err(_) => decode_fail += 1,
                                }
                            }
                        } else {
                            decrypt_fail += 1;
                        }
                    }
                    // STUN pong / RTCP: ignored (keepalive drives liveness).
                }
            }
        }
        self.transport.close().await;
        tracing::info!(
            rtp_tx, voiced_tx, rtp_rx, decrypt_ok, decrypt_fail, mlow_like, decode_fail,
            "call: media loop ended"
        );
    }
}

// ===== RTP framing (audio) ==================================================
//
// Ported from whatsapp-rust `wacore/src/voip/rtp.rs` (audio subset — video
// dropped). WhatsApp RTP is standard RTP with a 0xdebe extension: a 16-byte
// speech header (X=1, 0 ext words) or a 20-byte DTX header carrying the
// 0x30010000 word. The send sequencer stamps seq/timestamp and the speech-start
// marker.

const RTP_VERSION: u8 = 2;
const RTP_FIXED_HEADER_LEN: usize = 12;
const WHATSAPP_RTP_HEADER_SIZE: usize = 16;
const WHATSAPP_RTP_HEADER_DTX_SIZE: usize = 20;
const WHATSAPP_RTP_EXTENSION_PROFILE: u16 = 0xdebe;
const WHATSAPP_RTP_EXTENSION_DTX_WORD: u32 = 0x3001_0000;

pub const RTP_PAYLOAD_TYPE_OPUS: u8 = 111;
pub const RTP_PAYLOAD_TYPE_MLOW: u8 = 120;
pub const RTP_PAYLOAD_TYPE_MLOW_RED: u8 = 121;

const OPUS_PRIMING_FRAME_1: [u8; 18] = [
    0x12, 0x36, 0x26, 0x2b, 0x4a, 0xc8, 0x2b, 0x09, 0xc9, 0x1f, 0x34, 0xc2, 0xd6, 0x7a, 0x01, 0x73,
    0x1b, 0x2e,
];
const OPUS_PRIMING_FRAME_2: [u8; 5] = [0x90, 0xb8, 0x14, 0x14, 0xc4];

pub fn is_whatsapp_opus_rtp_payload(pt: u8) -> bool {
    matches!(pt, RTP_PAYLOAD_TYPE_OPUS | RTP_PAYLOAD_TYPE_MLOW | RTP_PAYLOAD_TYPE_MLOW_RED)
}

/// Opus/MLOW DTX (comfort-noise) payload — a short frame that carries no speech.
pub fn is_opus_dtx_payload(payload: &[u8]) -> bool {
    match payload.len() {
        0 => false,
        1..=2 => true,
        n if n <= 15 => {
            let b0 = payload[0];
            if (b0 & 0xf8) == 0x08 || b0 == 0x0a {
                return true;
            }
            (b0 & 0xf0) == 0x30 && n <= 6
        }
        _ => false,
    }
}

fn is_mlow_dtx_payload(payload: &[u8]) -> bool {
    payload.first().is_some_and(|b| b & 0xC0 == 0x80)
}

pub fn is_opus_priming_payload(payload: &[u8]) -> bool {
    payload == OPUS_PRIMING_FRAME_1 || payload == OPUS_PRIMING_FRAME_2
}

/// An audio RTP header. `extension_word` set → a 20-byte DTX/piggyback header;
/// else a 16-byte speech header (X=1, 0 ext words).
#[derive(Clone, Debug)]
pub struct RtpHeader {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub extension_word: Option<u32>,
}

impl RtpHeader {
    pub fn byte_size(&self) -> usize {
        if self.extension_word.is_some() {
            WHATSAPP_RTP_HEADER_DTX_SIZE
        } else {
            WHATSAPP_RTP_HEADER_SIZE
        }
    }
}

/// Append the encoded audio RTP header to `out`.
pub fn encode_rtp_header_into(header: &RtpHeader, out: &mut Vec<u8>) {
    let size = header.byte_size();
    let mut b = [0u8; WHATSAPP_RTP_HEADER_DTX_SIZE];
    b[0] = (RTP_VERSION << 6) | 0x10; // X=1 (WhatsApp always sets the 0xdebe ext)
    b[1] = ((header.marker as u8) << 7) | (header.payload_type & 0x7f);
    b[2..4].copy_from_slice(&header.sequence_number.to_be_bytes());
    b[4..8].copy_from_slice(&header.timestamp.to_be_bytes());
    b[8..12].copy_from_slice(&header.ssrc.to_be_bytes());
    b[12..14].copy_from_slice(&WHATSAPP_RTP_EXTENSION_PROFILE.to_be_bytes());
    b[15] = header.extension_word.is_some() as u8; // ext word count (0 or 1)
    if let Some(w) = header.extension_word {
        b[16..20].copy_from_slice(&w.to_be_bytes());
    }
    out.extend_from_slice(&b[..size]);
}

pub fn is_rtp_version2(data: &[u8]) -> bool {
    data.len() >= RTP_FIXED_HEADER_LEN && (data[0] >> 6) & 0x03 == RTP_VERSION
}

/// Full on-wire RTP header length (fixed 12 + CSRC + optional ext block), or `None`.
pub fn rtp_header_byte_length(data: &[u8]) -> Option<usize> {
    if data.len() < RTP_FIXED_HEADER_LEN || (data[0] >> 6) & 0x03 != RTP_VERSION {
        return None;
    }
    let cc = (data[0] & 0x0f) as usize;
    let mut header_len = RTP_FIXED_HEADER_LEN + cc * 4;
    if data.len() < header_len {
        return None;
    }
    if (data[0] >> 4) & 1 == 1 {
        if data.len() < header_len + 4 {
            return None;
        }
        let ext_words = ((data[header_len + 2] as usize) << 8) | data[header_len + 3] as usize;
        header_len += 4 + ext_words * 4;
        if data.len() < header_len {
            return None;
        }
    }
    Some(header_len)
}

/// Parse the fixed RTP header fields (the extension word is not decoded).
pub fn parse_rtp_header(data: &[u8]) -> Option<RtpHeader> {
    rtp_header_byte_length(data)?;
    Some(RtpHeader {
        marker: (data[1] >> 7) & 1 == 1,
        payload_type: data[1] & 0x7f,
        sequence_number: u16::from_be_bytes([data[2], data[3]]),
        timestamp: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        ssrc: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
        extension_word: None,
    })
}

/// Send-side audio RTP sequencer: stamps seq (from 1) + timestamp (advancing by
/// `samples_per_packet`), sets the speech-start marker, and picks the DTX ext
/// word on comfort-noise frames.
pub struct RtpStream {
    pub ssrc: u32,
    seq: u16,
    timestamp: u32,
    last_sent_timestamp: Option<u32>,
    samples_per_packet: u32,
    speech_started: bool,
    speech_start_markers: bool,
    mlow_profile: bool,
    payload_type: u8,
}

impl RtpStream {
    pub fn new(ssrc: u32, samples_per_packet: u32) -> Self {
        Self {
            ssrc,
            seq: 1,
            timestamp: 0,
            last_sent_timestamp: None,
            samples_per_packet,
            speech_started: false,
            speech_start_markers: true,
            mlow_profile: true,
            payload_type: RTP_PAYLOAD_TYPE_MLOW,
        }
    }

    pub fn set_payload_type(&mut self, pt: u8) -> bool {
        if pt > 127 {
            return false;
        }
        self.payload_type = pt;
        true
    }

    /// MLOW profile toggle: when off (standard-Opus), no MLOW speech-start
    /// markers. The payload type is set separately via [`Self::set_payload_type`]
    /// (WhatsApp audio rides PT 120 regardless; the codec is picked by
    /// capability bit 31, not the PT).
    pub fn set_mlow_profile(&mut self, enabled: bool) {
        self.mlow_profile = enabled;
        self.speech_start_markers = enabled;
    }

    /// The last emitted send timestamp (for an RTCP Sender Report).
    pub fn rtp_timestamp(&self) -> u32 {
        self.last_sent_timestamp.unwrap_or(self.timestamp)
    }

    /// Build the header for the next outbound audio packet.
    pub fn next_packet(&mut self, payload: &[u8], marker: bool) -> RtpHeader {
        let dtx = if self.mlow_profile {
            is_mlow_dtx_payload(payload)
        } else {
            is_opus_dtx_payload(payload)
        };
        let priming = is_opus_priming_payload(payload);
        let speech = !dtx && !priming;
        let use_marker = marker || (self.speech_start_markers && speech && !self.speech_started);
        if dtx {
            self.speech_started = false;
        } else if speech {
            self.speech_started = true;
        }
        let header = RtpHeader {
            marker: use_marker,
            payload_type: self.payload_type,
            sequence_number: self.seq,
            timestamp: self.timestamp,
            ssrc: self.ssrc,
            extension_word: dtx.then_some(WHATSAPP_RTP_EXTENSION_DTX_WORD),
        };
        self.last_sent_timestamp = Some(header.timestamp);
        self.seq = self.seq.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(self.samples_per_packet);
        header
    }
}

// ===== Opus codec (standard-Opus answer) ====================================
//
// We force standard Opus on accept, so the media plane speaks libopus. Fixed
// operating point: 16 kHz mono, 60 ms frames = 960 samples — the WA audio clock.
// PCM at the API boundary is s16le, sliced 3×20 ms for the WS bridge.

/// Sample rate of the WA audio codec path.
pub const CODEC_SAMPLE_RATE: u32 = 16_000;
/// Samples in one 60 ms WA codec frame at 16 kHz.
pub const CODEC_FRAME_SAMPLES: usize = 960;

/// libopus encoder/decoder pair for one call, fixed at 16 kHz mono.
pub struct OpusCodec {
    encoder: opus::Encoder,
    decoder: opus::Decoder,
}

impl OpusCodec {
    pub fn new() -> anyhow::Result<Self> {
        let mut encoder = opus::Encoder::new(CODEC_SAMPLE_RATE, opus::Channels::Mono, opus::Application::Voip)
            .map_err(|e| anyhow::anyhow!("opus encoder: {e}"))?;
        // ~24 kbps VBR with DTX — matches the standard-Opus answer profile.
        let _ = encoder.set_bitrate(opus::Bitrate::Bits(24_000));
        let decoder = opus::Decoder::new(CODEC_SAMPLE_RATE, opus::Channels::Mono)
            .map_err(|e| anyhow::anyhow!("opus decoder: {e}"))?;
        Ok(Self { encoder, decoder })
    }

    /// Encode one 60 ms (960-sample) PCM frame to an Opus payload.
    pub fn encode(&mut self, pcm: &[i16]) -> anyhow::Result<Vec<u8>> {
        self.encoder.encode_vec(pcm, 4000).map_err(|e| anyhow::anyhow!("opus encode: {e}"))
    }

    /// Decode one Opus payload to a 60 ms (960-sample) PCM frame. An empty
    /// payload requests packet-loss concealment (a comfort/interpolated frame).
    pub fn decode(&mut self, payload: &[u8]) -> anyhow::Result<Vec<i16>> {
        let mut out = vec![0i16; CODEC_FRAME_SAMPLES];
        let n = self
            .decoder
            .decode(payload, &mut out, false)
            .map_err(|e| anyhow::anyhow!("opus decode: {e}"))?;
        out.truncate(n);
        Ok(out)
    }
}

// ===== SRTP packet protect/unprotect (RTP + crypto, the media-loop API) ======

/// Protect one outbound audio RTP packet: `header_bytes` (cleartext) ++
/// AES-CTR(payload) ++ 4-byte WARP MI tag over the lot. `roc` from the send
/// tracker; `keys` are our send keys (derived from our own LID).
pub fn protect_audio_rtp(
    keys: &E2eSrtpKeys,
    header_bytes: &[u8],
    payload: &[u8],
    ssrc: u32,
    seq: u16,
    roc: u32,
) -> Vec<u8> {
    let ct = crypt_payload(keys, ssrc, seq, roc, payload);
    let mut pkt = Vec::with_capacity(header_bytes.len() + ct.len() + WARP_MI_TAG_LEN);
    pkt.extend_from_slice(header_bytes);
    pkt.extend_from_slice(&ct);
    append_warp_mi_tag(&keys.auth_key, &pkt, roc, WARP_MI_TAG_LEN)
}

/// Unprotect one inbound audio SRTP packet with the peer's recv keys: verify the
/// WARP tag against the estimated ROC, and only on success commit the ROC and
/// return `(header, decrypted_payload)`. `None` (dropped) on a bad tag / malformed
/// packet — WITHOUT desyncing the ROC. `keys` are the recv keys (peer's LID).
pub fn unprotect_audio_rtp(
    keys: &E2eSrtpKeys,
    roc_tracker: &mut RecvRocTracker,
    packet: &[u8],
) -> Option<(RtpHeader, Vec<u8>)> {
    if packet.len() < WARP_MI_TAG_LEN {
        return None;
    }
    let (body, tag) = packet.split_at(packet.len() - WARP_MI_TAG_LEN);
    let header_len = rtp_header_byte_length(body)?;
    let hdr = parse_rtp_header(body)?;
    let roc = roc_tracker.estimate_roc(hdr.sequence_number);
    if !verify_warp_mi_tag(&keys.auth_key, body, roc, WARP_MI_TAG_LEN, tag) {
        return None;
    }
    roc_tracker.commit_roc(roc, hdr.sequence_number);
    let ct = &body[header_len..];
    let pt = crypt_payload(keys, hdr.ssrc, hdr.sequence_number, roc, ct);
    Some((hdr, pt))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vectors captured from the `whatsapp-rust` reference stack
    // (synthetic inputs — callKey = 00..1f, LIDs 111…/222… — no real data).
    // These pin the byte-exact output of the whole HKDF → AES-CM-PRF chain; a
    // round-trip test alone would pass even if both directions were wrong
    // identically, so the KATs are the real guard.
    const CALL_KEY_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const SELF_LID: &str = "111111111111111:0@lid";
    const PEER_LID: &str = "222222222222222:0@lid";
    const CALL_ID: &str = "00112233445566778899AABBCCDDEEFF";

    fn kk() -> Vec<u8> {
        hex::decode(CALL_KEY_HEX).unwrap()
    }

    #[test]
    fn derive_e2e_keys_matches_kat() {
        let peer = derive_e2e_keys(&kk(), PEER_LID).unwrap();
        assert_eq!(hex::encode(peer.cipher_key), "747055a9d18be0fcdc0e29d871309081");
        assert_eq!(hex::encode(peer.salt), "10fb8133eff7639cc0d06788f49c");
        assert_eq!(hex::encode(peer.auth_key), "8eff4bb04971d92512b034ce0ebc466059bfc6ea");

        let me = derive_e2e_keys(&kk(), SELF_LID).unwrap();
        assert_eq!(hex::encode(me.cipher_key), "261bde5b556020e3e6da0f5e3132db57");
        assert_eq!(hex::encode(me.salt), "44224a8c019b379c4bbf7dda284a");
        assert_eq!(hex::encode(me.auth_key), "56b2655b60a1c17c03dfe94950d5df233481ad41");
    }

    #[test]
    fn short_call_key_is_rejected() {
        assert!(derive_e2e_keys(&[0u8; 31], PEER_LID).is_none());
        assert!(derive_srtcp_keys(&[0u8; 31], PEER_LID).is_none());
    }

    #[test]
    fn srtcp_keys_differ_from_srtp_keys() {
        // Same callKey/LID, different KDF labels → must not collide.
        let srtp = derive_e2e_keys(&kk(), PEER_LID).unwrap();
        let srtcp = derive_srtcp_keys(&kk(), PEER_LID).unwrap();
        assert_ne!(srtp.cipher_key, srtcp.cipher_key);
        assert_ne!(srtp.salt, srtcp.salt);
        assert_ne!(srtp.auth_key, srtcp.auth_key);
    }

    #[test]
    fn rtp_iv_and_payload_match_kat() {
        let peer = derive_e2e_keys(&kk(), PEER_LID).unwrap();
        let (ssrc, seq, roc) = (0x1234_5678u32, 7u16, 0u32);
        let iv = build_e2e_rtp_iv(&peer.salt, ssrc, roc, seq);
        assert_eq!(hex::encode(iv), "10fb8133fdc335e4c0d06788f49b0000");

        let payload = hex::decode("102132435465768798a9bacb").unwrap();
        let ct = crypt_payload(&peer, ssrc, seq, roc, &payload);
        assert_eq!(hex::encode(&ct), "17b30591a2650ed7bbae9c5a");
        // Symmetric: decrypt round-trips.
        assert_eq!(crypt_payload(&peer, ssrc, seq, roc, &ct), payload);
    }

    #[test]
    fn warp_mi_tag_matches_kat_and_verifies() {
        let peer = derive_e2e_keys(&kk(), PEER_LID).unwrap();
        let packet = hex::decode("90780007000003c012345678deadbeef").unwrap();
        let tag = compute_warp_mi_tag(&peer.auth_key, &packet, 0, WARP_MI_TAG_LEN);
        assert_eq!(hex::encode(&tag), "53fada83");
        assert!(verify_warp_mi_tag(&peer.auth_key, &packet, 0, WARP_MI_TAG_LEN, &tag));
        // A flipped roc or tag byte must fail.
        assert!(!verify_warp_mi_tag(&peer.auth_key, &packet, 1, WARP_MI_TAG_LEN, &tag));
        let appended = append_warp_mi_tag(&peer.auth_key, &packet, 0, WARP_MI_TAG_LEN);
        assert_eq!(&appended[appended.len() - 4..], &tag[..]);
    }

    #[test]
    fn ssrc_matches_kat() {
        assert_eq!(derive_wasm_participant_ssrc(CALL_ID, PEER_LID, 0), 1805509457);
        assert_eq!(derive_wasm_participant_ssrc(CALL_ID, PEER_LID, 1), 2479325408);
    }

    #[test]
    fn participant_id_normalization() {
        assert_eq!(format_participant_id("12345@lid"), "12345:0@lid");
        assert_eq!(format_participant_id("12345:6@lid"), "12345:6@lid");
        assert_eq!(format_participant_id("12345@s.whatsapp.net"), "12345@s.whatsapp.net");
        assert_eq!(format_participant_id("12345:6@lid/phone"), "12345:6@lid");
        // The `.<agent>` suffix (WA call-signaling wire form) is dropped for the
        // HKDF participant id — verified live: keeping it made recv decrypt fail.
        assert_eq!(format_participant_id("10000000000001.1@lid"), "10000000000001:0@lid");
        assert_eq!(format_participant_id("10000000000002.1:64@lid"), "10000000000002:64@lid");
    }

    #[test]
    fn build_iv_tolerates_oversized_salt() {
        // Latent-panic guard: a salt longer than 14 bytes must not underflow.
        let _ = build_e2e_rtp_iv(&[0xABu8; 32], 0xdead_beef, 7, 0xFFFF);
        let iv = build_e2e_rtp_iv(&[0x11u8; 14], 0, 0, 0);
        assert_eq!(&iv[0..14], &[0x11u8; 14]);
        assert_eq!(&iv[14..16], &[0u8; 2]);
    }

    #[test]
    fn roc_trackers_wrap() {
        let mut tx = RocTracker::default();
        assert_eq!(tx.advance(0xFFFE), 0);
        assert_eq!(tx.advance(0xFFFF), 0);
        assert_eq!(tx.advance(0x0000), 1, "0xFFFF→0x0000 bumps ROC");
        assert_eq!(tx.advance(0x0000), 1, "a backward dip does not bump");

        let mut rx = RecvRocTracker::default();
        assert_eq!(rx.guess_roc(0xFFFE), 0);
        assert_eq!(rx.guess_roc(0xFFFF), 0);
        assert_eq!(rx.guess_roc(0x0000), 1);
        // Reordered dip stays in the same ROC without corrupting state.
        assert_eq!(rx.guess_roc(0x0000), 1);
        assert_eq!(rx.guess_roc(0x0002), 1);
    }

    #[test]
    fn unauthenticated_estimate_does_not_advance_roc() {
        // estimate_roc must never fold state — only commit_roc (after auth) does.
        let mut rx = RecvRocTracker::default();
        rx.guess_roc(0x7FFE); // seed
        let _ = rx.estimate_roc(0xFFFE);
        let _ = rx.estimate_roc(0x7FFD);
        assert_eq!(rx.estimate_roc(0x7FFF), 0, "estimate alone maps to roc=0");
    }

    #[test]
    fn payload_roundtrips_across_seq_wrap() {
        let keys = E2eSrtpKeys {
            cipher_key: [7u8; 16],
            salt: [9u8; 14],
            auth_key: [0u8; 20],
        };
        let ssrc = 0x5741_0001u32;
        let seqs = [0xFFFEu16, 0xFFFF, 0x0000, 0x0001];
        let pts: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i.wrapping_mul(37); 40]).collect();

        let mut send_roc = RocTracker::default();
        let sent: Vec<(u16, Vec<u8>)> = seqs
            .iter()
            .zip(&pts)
            .map(|(&seq, pt)| {
                let roc = send_roc.advance(seq);
                (seq, crypt_payload(&keys, ssrc, seq, roc, pt))
            })
            .collect();

        // Receiver with a small post-wrap reorder; guess-index recovers each ROC.
        let mut recv_roc = RecvRocTracker::default();
        for &i in &[0usize, 1, 3, 2] {
            let (seq, ct) = &sent[i];
            let roc = recv_roc.guess_roc(*seq);
            assert_eq!(&crypt_payload(&keys, ssrc, *seq, roc, ct), &pts[i]);
        }
    }

    // ---- end-to-end SRTP loopback (the shape the media loop will use) --------

    /// A minimal RTP-ish header (12 bytes) so the WARP tag covers header+payload
    /// exactly as the real packetizer will. Contents are irrelevant to the
    /// crypto; only that both sides tag/verify over the same bytes.
    fn fake_rtp_header(ssrc: u32, seq: u16, ts: u32) -> Vec<u8> {
        let mut h = vec![0x90, 0x78];
        h.extend_from_slice(&seq.to_be_bytes());
        h.extend_from_slice(&ts.to_be_bytes());
        h.extend_from_slice(&ssrc.to_be_bytes());
        h
    }

    /// Full send→wire→recv for one E2E-SRTP audio stream, exactly as the media
    /// plane will drive it: the *sender's* LID keys both encrypt+tag on send and
    /// (as the receiver's "recv keys for this peer") verify+decrypt on recv. The
    /// receiver authenticates the WARP tag against an *estimated* ROC and only
    /// commits ROC state on success — so this is also the integration guard that
    /// the pieces compose the way the KATs promise per-primitive.
    #[test]
    fn srtp_loopback_authenticates_decrypts_and_survives_wrap() {
        // Both endpoints derive the same keys from the sender's LID (E2E model).
        let keys = derive_e2e_keys(&kk(), SELF_LID).unwrap();
        let ssrc = derive_wasm_participant_ssrc(CALL_ID, SELF_LID, 0);

        // 4 frames straddling the 16-bit sequence wrap.
        let seqs = [0xFFFEu16, 0xFFFF, 0x0000, 0x0001];
        let frames: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i.wrapping_add(1).wrapping_mul(53); 60]).collect();

        // Sender: monotonic seqs, encrypt payload, then append the WARP MI tag
        // over header||ciphertext (roc from the send tracker).
        let mut send_roc = RocTracker::default();
        let wire: Vec<Vec<u8>> = seqs
            .iter()
            .enumerate()
            .map(|(i, &seq)| {
                let roc = send_roc.advance(seq);
                let mut pkt = fake_rtp_header(ssrc, seq, i as u32 * 960);
                pkt.extend_from_slice(&crypt_payload(&keys, ssrc, seq, roc, &frames[i]));
                append_warp_mi_tag(&keys.auth_key, &pkt, roc, WARP_MI_TAG_LEN)
            })
            .collect();

        // Receiver, delivered in order: verify tag @estimated-roc, commit, decrypt.
        let mut recv_roc = RecvRocTracker::default();
        for (i, packet) in wire.iter().enumerate() {
            let (body, tag) = packet.split_at(packet.len() - WARP_MI_TAG_LEN);
            let seq = u16::from_be_bytes([body[2], body[3]]);
            let roc = recv_roc.estimate_roc(seq);
            assert!(
                verify_warp_mi_tag(&keys.auth_key, body, roc, WARP_MI_TAG_LEN, tag),
                "frame {i} (seq {seq:#06x}) must authenticate"
            );
            recv_roc.commit_roc(roc, seq);
            let payload = &body[12..]; // strip the 12-byte header
            assert_eq!(
                &crypt_payload(&keys, ssrc, seq, roc, payload),
                &frames[i],
                "frame {i} must decrypt to the original"
            );
        }
    }

    /// A tampered packet must fail authentication AND must not fold recv ROC
    /// state (the desync the estimate-before-commit split exists to prevent).
    #[test]
    fn srtp_loopback_rejects_tampered_packet_without_desync() {
        let keys = derive_e2e_keys(&kk(), SELF_LID).unwrap();
        let ssrc = derive_wasm_participant_ssrc(CALL_ID, SELF_LID, 0);

        let build = |seq: u16, roc: u32, frame: &[u8]| {
            let mut pkt = fake_rtp_header(ssrc, seq, 0);
            pkt.extend_from_slice(&crypt_payload(&keys, ssrc, seq, roc, frame));
            append_warp_mi_tag(&keys.auth_key, &pkt, roc, WARP_MI_TAG_LEN)
        };

        let mut recv_roc = RecvRocTracker::default();
        // First good packet seeds the receiver.
        let good = build(0x0001, 0, &[1u8; 60]);
        let (body, tag) = good.split_at(good.len() - WARP_MI_TAG_LEN);
        let roc = recv_roc.estimate_roc(0x0001);
        assert!(verify_warp_mi_tag(&keys.auth_key, body, roc, WARP_MI_TAG_LEN, tag));
        recv_roc.commit_roc(roc, 0x0001);

        // A forged packet: flip one ciphertext byte, keep the old tag.
        let mut forged = build(0x0002, 0, &[2u8; 60]);
        let ct_idx = 12; // first payload byte
        forged[ct_idx] ^= 0xFF;
        let (fbody, ftag) = forged.split_at(forged.len() - WARP_MI_TAG_LEN);
        let froc = recv_roc.estimate_roc(0x0002);
        assert!(
            !verify_warp_mi_tag(&keys.auth_key, fbody, froc, WARP_MI_TAG_LEN, ftag),
            "a tampered payload must fail the WARP tag"
        );
        // Crucially: we did NOT commit_roc for the forged packet. A subsequent
        // legit packet still authenticates under the un-desynced state.
        let next = build(0x0003, 0, &[3u8; 60]);
        let (nbody, ntag) = next.split_at(next.len() - WARP_MI_TAG_LEN);
        let nroc = recv_roc.estimate_roc(0x0003);
        assert!(
            verify_warp_mi_tag(&keys.auth_key, nbody, nroc, WARP_MI_TAG_LEN, ntag),
            "recv state must be intact after rejecting the forgery"
        );
    }

    /// Randomized inverse property: for many (frame, ssrc, seq, roc) draws, the
    /// cipher is its own inverse and the WARP tag round-trips. No proptest dep —
    /// a deterministic LCG keeps it reproducible.
    #[test]
    fn crypt_and_tag_inverse_over_many_random_frames() {
        let keys = derive_e2e_keys(&kk(), PEER_LID).unwrap();
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            state
        };
        for _ in 0..2000 {
            let r = next();
            let ssrc = r as u32;
            let seq = (r >> 32) as u16;
            let roc = (r >> 48) as u32;
            let len = (r % 200) as usize;
            let frame: Vec<u8> = (0..len).map(|i| (next() >> (i % 8)) as u8).collect();

            let ct = crypt_payload(&keys, ssrc, seq, roc, &frame);
            assert_eq!(crypt_payload(&keys, ssrc, seq, roc, &ct), frame, "cipher must self-invert");

            let tagged = append_warp_mi_tag(&keys.auth_key, &ct, roc, WARP_MI_TAG_LEN);
            let (body, tag) = tagged.split_at(tagged.len() - WARP_MI_TAG_LEN);
            assert!(verify_warp_mi_tag(&keys.auth_key, body, roc, WARP_MI_TAG_LEN, tag));
            // Wrong ROC must not verify (ROC is part of the authenticated input).
            assert!(!verify_warp_mi_tag(&keys.auth_key, body, roc.wrapping_add(1), WARP_MI_TAG_LEN, tag));
        }
    }

    // ---- signaling: offer parse + answer builders ---------------------------

    fn enc_node(ty: &str, v: &str, ct: &[u8]) -> Node {
        Node {
            tag: "enc".into(),
            attrs: attr(&[("type", ty), ("v", v)]),
            content: Content::Bytes(ct.to_vec()),
        }
    }

    fn audio_child(rate: &str) -> Node {
        node("audio", attr(&[("enc", "opus"), ("rate", rate)]), Content::None)
    }

    /// A single-device offer with a bare `<enc>` child.
    fn single_device_offer() -> Node {
        let offer = node(
            "offer",
            attr(&[("call-id", "CALLID1"), ("call-creator", "111@lid")]),
            Content::Nodes(vec![
                audio_child("16000"),
                audio_child("8000"),
                enc_node("pkmsg", "2", &[0xAA, 0xBB, 0xCC]),
            ]),
        );
        node("call", attr(&[("from", "111@lid"), ("id", "STANZA1")]), Content::Nodes(vec![offer]))
    }

    #[test]
    fn parse_offer_single_device() {
        let p = parse_offer(&single_device_offer(), "999:0@lid").unwrap();
        assert_eq!(p.call_id, "CALLID1");
        assert_eq!(p.call_creator, "111@lid");
        assert_eq!(p.from, "111@lid");
        assert!(!p.is_video);
        assert_eq!(p.audio_rates, vec![16000, 8000]);
        assert_eq!(p.enc.enc_type, "pkmsg");
        assert_eq!(p.enc.version, 2);
        assert_eq!(p.enc.ciphertext, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn parse_offer_multi_device_picks_our_enc() {
        let mk_to = |jid: &str, ct: &[u8]| {
            node("to", attr(&[("jid", jid)]), Content::Nodes(vec![enc_node("msg", "2", ct)]))
        };
        let dest = node(
            "destination",
            Attrs::new(),
            Content::Nodes(vec![
                mk_to("888:0@lid", &[0x11]),
                mk_to("999:0@lid", &[0x22, 0x33]), // ours
            ]),
        );
        let offer = node(
            "offer",
            attr(&[("call-id", "C2"), ("call-creator", "111@lid")]),
            Content::Nodes(vec![audio_child("16000"), dest]),
        );
        let call = node("call", attr(&[("from", "111@lid")]), Content::Nodes(vec![offer]));

        let p = parse_offer(&call, "999:0@lid").unwrap();
        assert_eq!(p.enc.enc_type, "msg");
        assert_eq!(p.enc.ciphertext, vec![0x22, 0x33]);
        // A device not listed in the offer gets nothing to decrypt.
        assert!(parse_offer(&call, "777:0@lid").is_none());
    }

    #[test]
    fn parse_offer_rejects_non_offer_and_empty_enc() {
        // A <call> whose action isn't <offer>.
        let term = node("call", attr(&[("from", "x")]),
            Content::Nodes(vec![node("terminate", attr(&[("call-id", "c")]), Content::None)]));
        assert!(parse_offer(&term, "999:0@lid").is_none());
        // Offer with an empty <enc> body → no usable key.
        let offer = node("offer", attr(&[("call-id", "c"), ("call-creator", "1@lid")]),
            Content::Nodes(vec![enc_node("pkmsg", "2", &[])]));
        let call = node("call", attr(&[("from", "1@lid")]), Content::Nodes(vec![offer]));
        assert!(parse_offer(&call, "999:0@lid").is_none());
    }

    #[test]
    fn offer_ack_receipt_shape() {
        let r = build_offer_ack_receipt("111@lid", "STANZA1", "CALLID1", "111@lid", Some("999:0@lid"));
        assert_eq!(r.tag, "receipt");
        assert_eq!(r.attrs.get("to").unwrap(), "111@lid");
        assert_eq!(r.attrs.get("id").unwrap(), "STANZA1");
        assert_eq!(r.attrs.get("from").unwrap(), "999:0@lid");
        let Content::Nodes(ch) = &r.content else { panic!() };
        assert_eq!(ch[0].tag, "offer");
        assert_eq!(ch[0].attrs.get("call-id").unwrap(), "CALLID1");
        // Without own_ad the `from` attr is omitted.
        let r2 = build_offer_ack_receipt("111@lid", "S", "C", "1@lid", None);
        assert!(!r2.attrs.contains_key("from"));
    }

    // ---- outbound origination -----------------------------------------------

    #[test]
    fn call_id_shape_is_00_plus_30_hex() {
        let id = generate_call_id();
        assert_eq!(id.len(), 32);
        assert!(id.starts_with("00"));
        assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(generate_call_id(), generate_call_id(), "each call-id is fresh");
    }

    #[test]
    fn call_key_roundtrips_through_the_e2e_message() {
        // What we encode for the offer must be exactly what the answer path
        // decodes — encode_call_key_message ⇄ call_key_from_e2e.
        let key = generate_call_key();
        let body = encode_call_key_message(&key);
        assert_eq!(call_key_from_e2e(&body), Some(key));
    }

    #[test]
    fn offer_single_device_uses_bare_enc_and_forces_opus() {
        let dk = [OfferDeviceKey {
            device_jid: "111:0@lid".into(),
            enc_type: "msg".into(),
            ciphertext: vec![0xAA, 0xBB],
        }];
        let o = build_offer("CALLID1", "111@lid", "999@lid", "WRAP1", "16000", None, &dk, false, None);
        assert_eq!(o.tag, "call");
        assert_eq!(o.attrs.get("to").unwrap(), "111@lid");
        assert_eq!(o.attrs.get("id").unwrap(), "WRAP1");
        let Content::Nodes(ch) = &o.content else { panic!() };
        let offer = &ch[0];
        assert_eq!(offer.tag, "offer");
        assert_eq!(offer.attrs.get("call-id").unwrap(), "CALLID1");
        assert_eq!(offer.attrs.get("call-creator").unwrap(), "999@lid");
        let Content::Nodes(oc) = &offer.content else { panic!() };
        let tags: Vec<&str> = oc.iter().map(|n| n.tag.as_str()).collect();
        // Load-bearing order: audio → net → capability → enc → encopt.
        assert_eq!(tags, vec!["audio", "net", "capability", "enc", "encopt"]);
        assert_eq!(oc[0].attrs.get("rate").unwrap(), "16000");
        assert_eq!(oc[1].attrs.get("medium").unwrap(), "3", "offer uses net medium=3");
        // Standard-Opus capability blob (MLOW gate bit cleared).
        let Content::Bytes(cap) = &oc[2].content else { panic!() };
        assert_eq!(cap, &CAPABILITY_STANDARD_OPUS_OFFER);
        let enc = &oc[3];
        assert_eq!(enc.attrs.get("v").unwrap(), "2");
        assert_eq!(enc.attrs.get("type").unwrap(), "msg");
        assert_eq!(enc.attrs.get("count").unwrap(), "0");
        // No pkmsg → no <device-identity>.
        assert!(!tags.contains(&"device-identity"));
    }

    #[test]
    fn offer_multi_device_addresses_each_enc_and_attaches_identity_on_pkmsg() {
        let dk = [
            OfferDeviceKey { device_jid: "111:0@lid".into(), enc_type: "pkmsg".into(), ciphertext: vec![0x11] },
            OfferDeviceKey { device_jid: "111:5@lid".into(), enc_type: "msg".into(), ciphertext: vec![0x22] },
        ];
        let o = build_offer("C", "111@lid", "999@lid", "W", "16000", Some(b"tok"), &dk, true, Some(b"adv"));
        let Content::Nodes(ch) = &o.content else { panic!() };
        let Content::Nodes(oc) = &ch[0].content else { panic!() };
        let tags: Vec<&str> = oc.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, vec!["privacy", "audio", "net", "capability", "destination", "encopt", "device-identity"]);
        // privacy carries the TC token bytes.
        let Content::Bytes(tok) = &oc[0].content else { panic!() };
        assert_eq!(tok, b"tok");
        // destination has one <to jid><enc> per device.
        let dest = oc.iter().find(|n| n.tag == "destination").unwrap();
        let Content::Nodes(tos) = &dest.content else { panic!() };
        assert_eq!(tos.len(), 2);
        assert_eq!(tos[0].attrs.get("jid").unwrap(), "111:0@lid");
        let Content::Nodes(inner) = &tos[0].content else { panic!() };
        assert_eq!(inner[0].tag, "enc");
        assert_eq!(inner[0].attrs.get("type").unwrap(), "pkmsg");
        // device-identity present because one enc is pkmsg.
        let di = oc.iter().find(|n| n.tag == "device-identity").unwrap();
        let Content::Bytes(b) = &di.content else { panic!() };
        assert_eq!(b, b"adv");
    }

    #[test]
    fn offer_single_pkmsg_device_still_bare_but_carries_identity() {
        // One device, single-device peer → bare <enc>; pkmsg → device-identity.
        let dk = [OfferDeviceKey { device_jid: "111:0@lid".into(), enc_type: "pkmsg".into(), ciphertext: vec![0x01] }];
        let o = build_offer("C", "111@lid", "999@lid", "W", "16000", None, &dk, false, Some(b"adv"));
        let Content::Nodes(ch) = &o.content else { panic!() };
        let Content::Nodes(oc) = &ch[0].content else { panic!() };
        let tags: Vec<&str> = oc.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, vec!["audio", "net", "capability", "enc", "encopt", "device-identity"]);
    }

    /// The accept child order is server-enforced: audio(s) → net → encopt →
    /// capability → voip_settings. A drift here is rejected 439 on the wire.
    #[test]
    fn terminate_node_shape() {
        let n = build_terminate("MID1", "5511900000000:7@s.whatsapp.net", "5511900000000:7@s.whatsapp.net", "CALL1", Some("hangup"));
        assert_eq!(n.tag, "call");
        assert_eq!(n.attrs.get("id").unwrap(), "MID1");
        // Both jids ship non-AD.
        assert_eq!(n.attrs.get("to").unwrap(), "5511900000000@s.whatsapp.net");
        let Content::Nodes(ch) = &n.content else { panic!() };
        assert_eq!(ch[0].tag, "terminate");
        assert_eq!(ch[0].attrs.get("call-id").unwrap(), "CALL1");
        assert_eq!(ch[0].attrs.get("call-creator").unwrap(), "5511900000000@s.whatsapp.net");
        assert_eq!(ch[0].attrs.get("reason").unwrap(), "hangup");
        // No reason → attr omitted.
        let n2 = build_terminate("M", "1@lid", "1@lid", "C", None);
        let Content::Nodes(ch2) = &n2.content else { panic!() };
        assert!(!ch2[0].attrs.contains_key("reason"));
    }

    #[test]
    fn accept_has_load_bearing_child_order_and_forces_opus() {
        let a = build_accept("CALLID1", "111@lid", "111@lid", "WRAP1", &["16000"]);
        assert_eq!(a.tag, "call");
        assert_eq!(a.attrs.get("to").unwrap(), "111@lid");
        assert_eq!(a.attrs.get("id").unwrap(), "WRAP1", "wrapper id is required");
        let Content::Nodes(top) = &a.content else { panic!() };
        let accept = &top[0];
        assert_eq!(accept.tag, "accept");
        assert_eq!(accept.attrs.get("call-id").unwrap(), "CALLID1");
        let Content::Nodes(kids) = &accept.content else { panic!() };
        let tags: Vec<&str> = kids.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, vec!["audio", "net", "encopt", "capability", "voip_settings"]);
        // encopt keygen=2 (v2 SRTP path) and the standard-Opus capability.
        assert_eq!(kids[2].attrs.get("keygen").unwrap(), "2");
        let Content::Bytes(cap) = &kids[3].content else { panic!() };
        assert_eq!(cap, &CAPABILITY_STANDARD_OPUS_OFFER);
        assert_eq!(cap[5] & 0x80, 0, "MLOW gate bit must be cleared (force Opus)");
        let Content::Bytes(vs) = &kids[4].content else { panic!() };
        assert!(std::str::from_utf8(vs).unwrap().contains("\"use_mlow_codec_v1\":\"false\""));
    }

    #[test]
    fn call_key_extracted_from_e2e_message() {
        use crate::proto::wa_web_protobufs_e2e::{Call, Message};
        use ::prost::Message as _;
        let key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let msg = Message {
            call: Some(Box::new(Call { call_key: Some(key.to_vec()), ..Default::default() })),
            ..Default::default()
        };
        let mut buf = Vec::new();
        msg.encode(&mut buf).unwrap();
        assert_eq!(call_key_from_e2e(&buf), Some(key));

        // A message with no call, or a wrong-length key, yields nothing.
        assert_eq!(call_key_from_e2e(&Vec::new()), None);
        let bad = Message {
            call: Some(Box::new(Call { call_key: Some(vec![0u8; 16]), ..Default::default() })),
            ..Default::default()
        };
        let mut b2 = Vec::new();
        bad.encode(&mut b2).unwrap();
        assert_eq!(call_key_from_e2e(&b2), None, "a non-32-byte callKey is rejected");
    }

    #[test]
    fn preaccept_shape() {
        let p = build_preaccept("CALLID1", "111@lid", "111@lid", "WRAP1", &["16000", "8000"]);
        let Content::Nodes(top) = &p.content else { panic!() };
        let pre = &top[0];
        assert_eq!(pre.tag, "preaccept");
        let Content::Nodes(kids) = &pre.content else { panic!() };
        let tags: Vec<&str> = kids.iter().map(|n| n.tag.as_str()).collect();
        assert_eq!(tags, vec!["audio", "audio", "encopt", "capability"]);
        let Content::Bytes(cap) = &kids[3].content else { panic!() };
        assert_eq!(cap, &CAPABILITY_STANDARD_OPUS_PREACCEPT);
    }

    // ---- relay parse --------------------------------------------------------

    fn te2(relay_id: &str, port_be: [u8; 2], ip: [u8; 4], attrs: &[(&str, &str)]) -> Node {
        let mut a = attr(&[("relay_id", relay_id)]);
        for (k, v) in attrs {
            a.insert((*k).into(), (*v).into());
        }
        let mut addr = ip.to_vec();
        addr.extend_from_slice(&port_be);
        Node { tag: "te2".into(), attrs: a, content: Content::Bytes(addr) }
    }
    fn tok(id: &str, bytes: &[u8]) -> Node {
        Node { tag: "token".into(), attrs: attr(&[("id", id)]), content: Content::Bytes(bytes.to_vec()) }
    }

    #[test]
    fn relay_parse_extracts_key_tokens_and_endpoints() {
        // <key> stays raw (STUN MI key); one te2 on 3478, one on 3480.
        let relay = Node {
            tag: "relay".into(),
            attrs: attr(&[("uuid", "U1")]),
            content: Content::Nodes(vec![
                Node { tag: "key".into(), attrs: Attrs::new(), content: Content::Bytes(b"MIKEY-ASCII".to_vec()) },
                Node { tag: "warp_mi_tag_len".into(), attrs: Attrs::new(), content: Content::Bytes(b"4".to_vec()) },
                tok("0", &[0xA0, 0xA1]),
                tok("1", &[0xB0, 0xB1]),
                // relay 5 on 3478 (0x0D96), authed; relay 6 on 3480 (0x0D98), authed.
                te2("5", [0x0D, 0x96], [1, 2, 3, 4], &[("token_id", "0"), ("auth_token_id", "1")]),
                te2("6", [0x0D, 0x98], [5, 6, 7, 8], &[("token_id", "1"), ("auth_token_id", "1")]),
            ]),
        };
        let rd = parse_relay_data(&relay);
        assert_eq!(rd.uuid.as_deref(), Some("U1"));
        assert_eq!(rd.warp_mi_tag_len, Some(4));
        // <key> kept verbatim as the MI key (not base64-decoded away).
        assert_eq!(rd.relay_key_ascii.as_deref(), Some(&b"MIKEY-ASCII"[..]));
        assert_eq!(rd.relay_tokens.len(), 2);
        assert_eq!(rd.relay_tokens[1], vec![0xB0, 0xB1]);
        assert_eq!(rd.endpoints.len(), 2);

        // Media endpoint selection MUST prefer the 3480 one (else one-way audio).
        let ep = get_media_relay_endpoint(&rd).unwrap();
        assert_eq!(get_primary_ipv4_address(ep), Some(("5.6.7.8".into(), WEB_CLIENT_RELAY_PORT)));
        assert_eq!(ep.relay_id, 6);
    }

    #[test]
    fn relay_parse_token_id_bound_and_find_relay() {
        // A token id past the cap is dropped, not allocated.
        let relay = Node {
            tag: "relay".into(),
            attrs: Attrs::new(),
            content: Content::Nodes(vec![tok("9999", &[1]), tok("0", &[2])]),
        };
        let rd = parse_relay_data(&relay);
        assert_eq!(rd.relay_tokens, vec![vec![2u8]]);
        // find_relay locates a nested <relay> under <call><offer>.
        let call = node("call", Attrs::new(), Content::Nodes(vec![
            node("offer", Attrs::new(), Content::Nodes(vec![relay])),
        ]));
        assert!(find_relay(&call).is_some());
        assert!(find_relay(&node("call", Attrs::new(), Content::None)).is_none());
    }

    #[test]
    fn te2_address_parses_ipv4_and_rejects_bad_length() {
        let a = parse_te2_address(&[10, 0, 0, 1, 0x0D, 0x96], 0).unwrap();
        assert_eq!(a.ipv4.as_deref(), Some("10.0.0.1"));
        assert_eq!(a.port, 3478);
        assert!(parse_te2_address(&[1, 2, 3], 0).is_none(), "a 3-byte addr is invalid");
    }

    // ---- STUN (KATs from the whatsapp-rust reference vectors) ---------------

    const STUN_TX: [u8; 12] = [0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab];

    #[test]
    fn crc32_matches_kat() {
        assert_eq!(crc32(b"abc"), 891568578);
    }

    #[test]
    fn whatsapp_ping_matches_kat() {
        assert_eq!(hex::encode(build_whatsapp_ping(&STUN_TX)), "080100002112a442a0a1a2a3a4a5a6a7a8a9aaab");
        // Round-trips through the pong classifier's tx match.
        let ping = build_whatsapp_ping(&STUN_TX);
        assert!(is_stun_packet(&ping));
        assert_eq!(stun_message_type(&ping), Some(MSG_WHATSAPP_PING));
        assert_eq!(stun_transaction_id(&ping), Some(&STUN_TX[..]));
    }

    #[test]
    fn stun_attr_and_xor_endpoint_match_kat() {
        let token = hex::decode("1020304050607080").unwrap();
        assert_eq!(hex::encode(stun_attr(0x4000, &token)), "400000081020304050607080");
        // The KAT xor endpoint 2c84bce246c7 = encode(157.240.226.133, 3478).
        assert_eq!(
            hex::encode(encode_xor_relay_endpoint("157.240.226.133", 3478).unwrap()),
            "2c84bce246c7"
        );
    }

    #[test]
    fn wasm_allocate_structure() {
        // The reference itself does NOT byte-pin the allocate (the captured hex
        // uses an unknown call_id/participant); it asserts structure. Same here:
        // header + relay token + stream descriptors + endpoint + 20-byte MI.
        let tx = STUN_TX;
        let token = hex::decode("1020304050607080").unwrap();
        let endpoint = encode_xor_relay_endpoint("157.240.226.133", 3478).unwrap();
        let mi_key = hex::decode("30313233343536373839616263646566").unwrap();
        let call_id = "CALL-ID-0001";
        let participant = "12345:0@lid";
        let out = build_wasm_stun_allocate_request(&tx, &token, &endpoint, &mi_key, call_id, participant);

        // Header: allocate request, magic, tx.
        assert!(is_stun_packet(&out));
        assert_eq!(stun_message_type(&out), Some(MSG_ALLOCATE_REQUEST));
        assert_eq!(&out[4..8], &STUN_MAGIC.to_be_bytes());
        assert_eq!(stun_transaction_id(&out), Some(&tx[..]));
        // Declared body length matches the real tail.
        let body_len = ((out[2] as usize) << 8) | out[3] as usize;
        assert_eq!(20 + body_len, out.len());

        // Body starts with the relay-token attr.
        assert!(out[20..].starts_with(&stun_attr(ATTR_RELAY_TOKEN, &token)));
        // Carries the stream descriptors (built from the KAT-verified SSRC KDF).
        let sd = stun_attr(STUN_ATTR_STREAM_DESCRIPTORS, &create_wasm_stream_descriptors(call_id, participant));
        assert!(out.windows(sd.len()).any(|w| w == sd), "stream descriptors present");
        // Carries the XOR relay endpoint attr.
        let ep = stun_attr(STUN_ATTR_WASM_RELAY_ENDPOINT, &create_wasm_relay_endpoint_attr(&endpoint));
        assert!(out.windows(ep.len()).any(|w| w == ep), "relay endpoint present");
        // Ends with a 20-byte MESSAGE-INTEGRITY attr (0x0008, len 0x0014).
        assert_eq!(&out[out.len() - 24..out.len() - 20], &[0x00, 0x08, 0x00, 0x14]);
    }

    #[test]
    fn stun_success_error_classifiers() {
        // A minimal allocate-success (type 0x0103, empty body).
        let mut ok = vec![0x01, 0x03, 0x00, 0x00];
        ok.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        ok.extend_from_slice(&STUN_TX);
        assert!(is_allocate_or_binding_success(&ok));
        assert!(!is_allocate_error(&ok));

        // An allocate-error (0x0113) carrying ERROR-CODE 401 (class 4, number 1).
        let ec = stun_attr(ATTR_ERROR_CODE, &[0, 0, 4, 1]);
        let mut err = vec![0x01, 0x13, (ec.len() >> 8) as u8, ec.len() as u8];
        err.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        err.extend_from_slice(&STUN_TX);
        err.extend_from_slice(&ec);
        assert!(is_allocate_error(&err));
        assert_eq!(parse_stun_error_code(&err), Some(401));
        // A truncated packet (lies about body length) is rejected, not panicked.
        assert!(!is_allocate_or_binding_success(&ok[..10]));
        assert_eq!(parse_stun_error_code(&err[..12]), None);
    }

    // ---- RTP framing (KATs from the reference vectors) ----------------------

    #[test]
    fn rtp_speech_and_dtx_headers_match_kat() {
        // Speech: 16-byte header, X=1 / 0 ext words, marker=1, PT 120, seq 1.
        let speech = RtpHeader {
            marker: true, payload_type: RTP_PAYLOAD_TYPE_MLOW, sequence_number: 1,
            timestamp: 0, ssrc: 0x1234_5678, extension_word: None,
        };
        let mut out = Vec::new();
        encode_rtp_header_into(&speech, &mut out);
        assert_eq!(hex::encode(&out), "90f800010000000012345678debe0000");
        assert_eq!(out.len(), 16);

        // DTX: 20-byte header, marker=0, seq 2, ts 320, the 0x30010000 ext word.
        let dtx = RtpHeader {
            marker: false, payload_type: RTP_PAYLOAD_TYPE_MLOW, sequence_number: 2,
            timestamp: 320, ssrc: 0x1234_5678, extension_word: Some(0x3001_0000),
        };
        let mut out = Vec::new();
        encode_rtp_header_into(&dtx, &mut out);
        assert_eq!(hex::encode(&out), "907800020000014012345678debe000130010000");
        assert_eq!(out.len(), 20);
    }

    #[test]
    fn rtp_header_roundtrips_through_parse() {
        let h = RtpHeader {
            marker: true, payload_type: RTP_PAYLOAD_TYPE_OPUS, sequence_number: 42,
            timestamp: 9600, ssrc: 0xdead_beef, extension_word: None,
        };
        let mut buf = Vec::new();
        encode_rtp_header_into(&h, &mut buf);
        buf.extend_from_slice(&[1, 2, 3, 4]); // a fake payload
        assert!(is_rtp_version2(&buf));
        assert_eq!(rtp_header_byte_length(&buf), Some(16));
        let p = parse_rtp_header(&buf).unwrap();
        assert!(p.marker);
        assert_eq!(p.payload_type, RTP_PAYLOAD_TYPE_OPUS);
        assert_eq!(p.sequence_number, 42);
        assert_eq!(p.timestamp, 9600);
        assert_eq!(p.ssrc, 0xdead_beef);
        // Garbage (wrong version) is rejected, not panicked.
        assert!(parse_rtp_header(&[0xff; 8]).is_none());
    }

    #[test]
    fn rtp_stream_sequences_and_marks_speech_start() {
        // Default MLOW profile → speech-start markers on. MLOW speech = b0 in
        // 0x48..0x57; MLOW DTX = b0 & 0xC0 == 0x80.
        let mut s = RtpStream::new(0x0102_0304, 960); // 60ms @16k
        let speech = vec![0x48u8; 60];

        let h1 = s.next_packet(&speech, false);
        assert_eq!(h1.sequence_number, 1, "seq starts at 1");
        assert_eq!(h1.timestamp, 0);
        assert!(h1.marker, "first MLOW speech packet carries the start marker");
        assert_eq!(h1.extension_word, None);

        let h2 = s.next_packet(&speech, false);
        assert_eq!(h2.sequence_number, 2);
        assert_eq!(h2.timestamp, 960, "timestamp advances by samples_per_packet");
        assert!(!h2.marker, "subsequent speech is unmarked");

        // A DTX (comfort-noise) frame carries the DTX ext word and clears the latch.
        let h3 = s.next_packet(&[0x80], false);
        assert_eq!(h3.extension_word, Some(0x3001_0000));
        assert_eq!(s.rtp_timestamp(), h3.timestamp);

        // Standard-Opus profile turns speech-start markers OFF (what our answer uses).
        let mut o = RtpStream::new(1, 960);
        o.set_payload_type(RTP_PAYLOAD_TYPE_OPUS);
        o.set_mlow_profile(false);
        assert!(!o.next_packet(&[0x60u8; 60], false).marker, "opus profile: no start marker");
    }

    #[test]
    fn srtp_packet_protect_unprotect_roundtrips_and_rejects_forgery() {
        // Both sides use the sender's LID keys for this stream (E2E model).
        let keys = derive_e2e_keys(&kk(), SELF_LID).unwrap();
        let ssrc = derive_wasm_participant_ssrc(CALL_ID, SELF_LID, 0);
        let mut send = RtpStream::new(ssrc, 960);
        let mut send_roc = RocTracker::default();
        let mut recv_roc = RecvRocTracker::default();

        for i in 0..3u32 {
            let payload = vec![0x48 + i as u8; 60];
            let hdr = send.next_packet(&payload, false);
            let mut header_bytes = Vec::new();
            encode_rtp_header_into(&hdr, &mut header_bytes);
            let roc = send_roc.advance(hdr.sequence_number);
            let pkt = protect_audio_rtp(&keys, &header_bytes, &payload, ssrc, hdr.sequence_number, roc);

            let (rhdr, rpay) = unprotect_audio_rtp(&keys, &mut recv_roc, &pkt).expect("valid packet");
            assert_eq!(rhdr.sequence_number, hdr.sequence_number);
            assert_eq!(rhdr.ssrc, ssrc);
            assert_eq!(rpay, payload, "payload round-trips");
        }

        // A forged packet (flip a ciphertext byte) is dropped, no ROC desync.
        let payload = vec![0x49u8; 60];
        let hdr = send.next_packet(&payload, false);
        let mut hb = Vec::new();
        encode_rtp_header_into(&hdr, &mut hb);
        let roc = send_roc.advance(hdr.sequence_number);
        let mut pkt = protect_audio_rtp(&keys, &hb, &payload, ssrc, hdr.sequence_number, roc);
        pkt[16] ^= 0xFF; // first payload byte
        assert!(unprotect_audio_rtp(&keys, &mut recv_roc, &pkt).is_none(), "forgery dropped");
    }

    #[test]
    fn opus_codec_encodes_and_decodes_a_60ms_frame() {
        let mut codec = OpusCodec::new().unwrap();
        // A 16 kHz sine-ish 960-sample frame.
        let pcm: Vec<i16> = (0..CODEC_FRAME_SAMPLES)
            .map(|i| ((i as f32 * 0.2).sin() * 8000.0) as i16)
            .collect();
        let payload = codec.encode(&pcm).unwrap();
        assert!(!payload.is_empty() && payload.len() < 4000, "opus payload is bounded");
        let decoded = codec.decode(&payload).unwrap();
        assert_eq!(decoded.len(), CODEC_FRAME_SAMPLES, "decodes back to one 60ms frame");
        // Packet-loss concealment: an empty payload still yields a frame.
        assert_eq!(codec.decode(&[]).unwrap().len(), CODEC_FRAME_SAMPLES);
    }
}
