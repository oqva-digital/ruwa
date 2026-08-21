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
    if domain == "lid" && !user.contains(':') {
        return format!("{user}:0@{domain}");
    }
    bare.to_string()
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
}
