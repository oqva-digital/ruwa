//! Crypto: identity keys, Signal Protocol, group sender keys, key derivation.
//!
//! Layers:
//!   - `identity`: long-term Curve25519 + Ed25519 keypairs per session,
//!     persisted in `identity_keys` table.
//!   - `prekeys`: one-time + signed pre-keys (uploaded to WA server during
//!     registration; consumed on incoming X3DH).
//!   - `signal`: Double Ratchet sessions (per remote JID).
//!   - `senderkey`: group sender-key chain (per group + sender).
//!   - `hkdf` helpers: key derivation used by WA-specific schemes
//!     (media keys, app state, ADV identity).
//!
//! References:
//!   - whatsmeow/util/keys/keypair.go
//!   - libsignal-protocol-go (whatsmeow vendors a fork) — sessions, ratchets
//!   - whatsmeow/util/hkdfutil  — WA's HKDF wrapper
//!   - whatsmeow/util/cbcutil   — AES-256-CBC with HMAC-SHA256 (media)
//!
//! Implemented module-by-module per SPEC.md.

pub mod vault {
    //! Keys-at-rest: AES-256-GCM sealing for the secret DB blobs (private keys
    //! and Signal session records). The key comes from `RUWA_DB_ENCRYPTION_KEY`
    //! (base64, 32 bytes), read and cached once. When no key is set, `seal` and
    //! `open` are transparent pass-throughs, so an unconfigured deployment
    //! stores plaintext exactly as before — and a store written without a key
    //! keeps opening after one is set (legacy rows aren't MAGIC-tagged).
    //!
    //! Sealed layout: `b"OQV1" || nonce(12) || ciphertext+tag`.

    use std::sync::OnceLock;

    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use rand::rngs::OsRng;
    use rand::RngCore;

    const MAGIC: &[u8; 4] = b"OQV1";

    /// The configured 32-byte key, or `None` if `RUWA_DB_ENCRYPTION_KEY` is
    /// unset/invalid. Parsed + cached once for the process lifetime.
    fn key() -> Option<&'static [u8; 32]> {
        static K: OnceLock<Option<[u8; 32]>> = OnceLock::new();
        K.get_or_init(|| {
            let raw = std::env::var("RUWA_DB_ENCRYPTION_KEY").ok()?;
            let bytes = match B64.decode(raw.trim()) {
                Ok(b) => b,
                Err(_) => {
                    tracing::error!("RUWA_DB_ENCRYPTION_KEY is not valid base64; at-rest encryption OFF");
                    return None;
                }
            };
            if bytes.len() != 32 {
                tracing::error!(
                    len = bytes.len(),
                    "RUWA_DB_ENCRYPTION_KEY must decode to 32 bytes; at-rest encryption OFF"
                );
                return None;
            }
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            tracing::info!("at-rest encryption ON (AES-256-GCM)");
            Some(k)
        })
        .as_ref()
    }

    /// True when a valid encryption key is configured.
    pub fn enabled() -> bool {
        key().is_some()
    }

    /// Seal `plaintext` if a key is configured; otherwise return it unchanged.
    pub fn seal(plaintext: &[u8]) -> Vec<u8> {
        match key() {
            Some(k) => seal_with(k, plaintext),
            None => plaintext.to_vec(),
        }
    }

    /// Open `data`. MAGIC-tagged (sealed) blobs are decrypted; anything else is
    /// returned as-is (legacy plaintext written before a key was configured).
    pub fn open(data: &[u8]) -> Result<Vec<u8>, &'static str> {
        if data.len() < MAGIC.len() + 12 || &data[..MAGIC.len()] != MAGIC {
            return Ok(data.to_vec());
        }
        let k = key().ok_or("data is sealed but RUWA_DB_ENCRYPTION_KEY is not set")?;
        open_with(k, data)
    }

    /// Seal with an explicit key (the env-key path delegates here).
    fn seal_with(k: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(k).expect("32-byte key");
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("aes-gcm encrypt never fails for valid key/nonce");
        let mut out = Vec::with_capacity(MAGIC.len() + nonce.len() + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt a MAGIC-tagged blob with an explicit key.
    fn open_with(k: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let cipher = Aes256Gcm::new_from_slice(k).expect("32-byte key");
        let nonce = &data[MAGIC.len()..MAGIC.len() + 12];
        cipher
            .decrypt(Nonce::from_slice(nonce), &data[MAGIC.len() + 12..])
            .map_err(|_| "at-rest decrypt failed (wrong key or corrupt blob)")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // The key is process-global + cached, and tests run in parallel, so we
        // can't toggle the env mid-process. Exercise the pure framing: with no
        // key set (the test default), seal/open are identity, and open tolerates
        // arbitrary non-tagged bytes without panicking.
        #[test]
        fn passthrough_when_no_key() {
            assert!(!enabled());
            let p = b"super secret private key bytes";
            assert_eq!(seal(p), p.to_vec());
            assert_eq!(open(p).unwrap(), p.to_vec());
            assert_eq!(open(b"").unwrap(), Vec::<u8>::new());
            assert_eq!(open(b"OQV").unwrap(), b"OQV".to_vec());
        }

        #[test]
        fn seal_open_round_trips_and_rejects_tampering() {
            let k = [7u8; 32];
            let plaintext = b"32-byte-ish private key material here";

            let sealed = seal_with(&k, plaintext);
            assert_eq!(&sealed[..4], MAGIC, "sealed blob is MAGIC-tagged");
            assert_ne!(sealed, plaintext.to_vec(), "ciphertext differs from plaintext");
            assert_eq!(open_with(&k, &sealed).unwrap(), plaintext.to_vec());

            // Two seals of the same plaintext differ (random nonce).
            assert_ne!(seal_with(&k, plaintext), sealed);

            // Wrong key fails the AEAD tag.
            assert!(open_with(&[9u8; 32], &sealed).is_err());

            // Tampering with the ciphertext fails the tag.
            let mut bad = sealed.clone();
            *bad.last_mut().unwrap() ^= 0xff;
            assert!(open_with(&k, &bad).is_err());
        }
    }
}

pub mod identity {
    //! Long-term per-session keys.
    //!
    //! WhatsApp uses Curve25519 for both Diffie–Hellman (Noise/X3DH) and
    //! signing (XEdDSA over the same key). We keep raw 32-byte representations
    //! so SQL persistence is trivial; convert at the call site when needed.
    //!
    //! whatsmeow reference: util/keys/keypair.go.

    use rand::rngs::OsRng;
    use rand::RngCore;

    /// Curve25519 keypair (clamped scalar, X25519-derived public).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct KeyPair {
        pub private: [u8; 32],
        pub public: [u8; 32],
    }

    impl KeyPair {
        pub fn generate() -> Self {
            let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public = x25519_dalek::PublicKey::from(&secret);
            Self {
                private: secret.to_bytes(),
                public: public.to_bytes(),
            }
        }

        /// Reconstruct from persisted 32-byte slices.
        pub fn from_bytes(priv_b: &[u8], pub_b: &[u8]) -> Result<Self, &'static str> {
            if priv_b.len() != 32 || pub_b.len() != 32 {
                return Err("expected 32-byte private and public");
            }
            let mut private = [0u8; 32];
            let mut public = [0u8; 32];
            private.copy_from_slice(priv_b);
            public.copy_from_slice(pub_b);
            Ok(Self { private, public })
        }
    }

    /// Signed prekey: a fresh keypair whose public part is XEdDSA-signed by
    /// the device's identity private key. Peers fetching our bundle for
    /// X3DH verify this signature with `xeddsa_verify(identity_pub, ...)`
    /// before deriving the master secret.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SignedPreKey {
        pub key_id: u32,
        pub keypair: KeyPair,
        pub signature: [u8; 64],
    }

    /// All long-term keys for a single device (one WA session).
    #[derive(Clone, Debug)]
    pub struct DeviceKeys {
        /// Used in the Noise XX handshake.
        pub noise: KeyPair,
        /// Long-term identity key. Signs signed prekeys (XEdDSA).
        pub identity: KeyPair,
        pub signed_prekey: SignedPreKey,
        /// Random ADV (advertisement) secret used during pairing.
        pub adv_secret: [u8; 32],
        /// 31-bit registration ID per Signal convention.
        pub registration_id: u32,
    }

    impl DeviceKeys {
        pub fn generate() -> Self {
            let noise = KeyPair::generate();
            let identity = KeyPair::generate();
            let spk_keypair = KeyPair::generate();

            // XEdDSA over [DjbType (0x05)] || SPK_pub using the identity
            // private. Mirrors libsignal's `KeyPair.Sign` (see whatsmeow's
            // util/keys/keypair.go::Sign): peers verify against the same
            // 33-byte form when they fetch our prekey bundle for X3DH.
            let mut spk_signed = [0u8; 33];
            spk_signed[0] = 0x05;
            spk_signed[1..].copy_from_slice(&spk_keypair.public);
            let signature = xeddsa_sign(&identity.private, &spk_signed);

            let mut adv_secret = [0u8; 32];
            OsRng.fill_bytes(&mut adv_secret);

            let mut buf = [0u8; 4];
            OsRng.fill_bytes(&mut buf);
            let registration_id = u32::from_be_bytes(buf) & 0x7fff_ffff;

            Self {
                noise,
                identity,
                signed_prekey: SignedPreKey {
                    key_id: 1,
                    keypair: spk_keypair,
                    signature,
                },
                adv_secret,
                registration_id,
            }
        }
    }

    /// XEdDSA signature with a Curve25519 private key over an arbitrary
    /// message. Mirrors libsignal's `curve25519_sign` (used by whatsmeow's
    /// `CreateSignedPreKey`). The output is a 64-byte signature verifiable
    /// against the corresponding Curve25519 *public* key by deriving the
    /// associated Edwards point with sign bit 0.
    ///
    /// Algorithm (per Trevor Perrin's XEddsa / draft-perrin-vasspr-00):
    /// 1. Derive Ed25519 keypair (a, A) from the X25519 scalar k:
    ///    A_raw = k·B; if A_raw's sign bit is set, a = -k else a = k.
    ///    A = (a·B).compress() always has sign bit 0 by construction.
    /// 2. nonce ← H(0xFE || 0xFF^31 || a || M || Z), Z = 64 random bytes.
    /// 3. r = nonce mod L, R = r·B.
    /// 4. h = H(R || A || M) mod L.
    /// 5. s = r + h·a mod L. Signature = R || s.
    ///
    /// Test vector self-consistency is covered by `xeddsa_sign_verifies`;
    /// negative test by `xeddsa_rejects_tampered_message`.
    pub fn xeddsa_sign(curve_priv: &[u8; 32], message: &[u8]) -> [u8; 64] {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest, Sha512};

        // Defensive clamp — Curve25519 priv keys arriving via StaticSecret
        // are already clamped, but `KeyPair::from_bytes` doesn't enforce.
        let mut k_bytes = *curve_priv;
        k_bytes[0] &= 0xF8;
        k_bytes[31] &= 0x7F;
        k_bytes[31] |= 0x40;
        let k = Scalar::from_bytes_mod_order(k_bytes);

        // Step 1: pick (a, A) such that A's sign bit is 0.
        let a_point = ED25519_BASEPOINT_TABLE * &k;
        let a_compressed = a_point.compress();
        let sign_bit_set = (a_compressed.as_bytes()[31] & 0x80) != 0;
        let a_scalar = if sign_bit_set { -k } else { k };
        let big_a_bytes = if sign_bit_set {
            (ED25519_BASEPOINT_TABLE * &a_scalar).compress().to_bytes()
        } else {
            a_compressed.to_bytes()
        };

        // Step 2: random nonce material Z.
        let mut z = [0u8; 64];
        OsRng.fill_bytes(&mut z);

        // Step 3: r = H(prefix || a || M || Z) mod L.
        // Prefix = 0xFE || 0xFF·31 (the libsignal "dom2" tag for XEdDSA).
        let mut h = Sha512::new();
        h.update([0xFEu8]);
        h.update([0xFFu8; 31]);
        h.update(a_scalar.to_bytes());
        h.update(message);
        h.update(z);
        let mut r_bytes = [0u8; 64];
        r_bytes.copy_from_slice(&h.finalize());
        let r = Scalar::from_bytes_mod_order_wide(&r_bytes);

        let big_r = ED25519_BASEPOINT_TABLE * &r;
        let big_r_bytes = big_r.compress().to_bytes();

        // Step 4: h = H(R || A || M) mod L.
        let mut hh = Sha512::new();
        hh.update(big_r_bytes);
        hh.update(big_a_bytes);
        hh.update(message);
        let mut hram_bytes = [0u8; 64];
        hram_bytes.copy_from_slice(&hh.finalize());
        let hram = Scalar::from_bytes_mod_order_wide(&hram_bytes);

        // Step 5: s = r + h·a mod L; concat R || s.
        let s = r + hram * a_scalar;
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r_bytes);
        sig[32..].copy_from_slice(&s.to_bytes());
        sig
    }

    /// Verify an XEdDSA signature against a Curve25519 *public* key by
    /// recovering the associated Edwards point (with sign bit 0) and
    /// running the standard Ed25519 verification equation s·B = R + h·A.
    /// Returns false on any malformedness rather than panicking.
    pub fn xeddsa_verify(curve_pub: &[u8; 32], message: &[u8], sig: &[u8; 64]) -> bool {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        use curve25519_dalek::edwards::CompressedEdwardsY;
        use curve25519_dalek::montgomery::MontgomeryPoint;
        use curve25519_dalek::scalar::Scalar;
        use sha2::{Digest, Sha512};

        let r_bytes: [u8; 32] = match sig[..32].try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };
        let mut s_bytes: [u8; 32] = match sig[32..].try_into() {
            Ok(a) => a,
            Err(_) => return false,
        };

        // XEdDSA stores the SIGN BIT of the public key A in the top bit of the
        // 64-byte signature's last byte (high bit of `s`). The verifier must
        // extract it, clear it from `s` (otherwise `s` parses as non-canonical),
        // and recover A's Edwards point with THAT sign. Real WhatsApp sender keys
        // are ~50/50 sign-0/sign-1, so hardcoding sign 0 silently rejected every
        // sign-1 signer's messages (and our retry NACKs then triggered the
        // phone's "sync paused/loop"). Mirrors libsignal's xed25519 verify.
        let sign_bit = s_bytes[31] >> 7;
        s_bytes[31] &= 0x7F;

        let mont = MontgomeryPoint(*curve_pub);
        let big_a = match mont.to_edwards(sign_bit) {
            Some(p) => p,
            None => return false,
        };
        // A in the hash is the FULL compressed Edwards point INCLUDING its sign
        // bit (which we just recovered from `s`'s high bit) — NOT sign-cleared.
        // Verified empirically against a real sign-1 WhatsApp signature.
        let big_a_bytes = big_a.compress().to_bytes();

        let big_r = match CompressedEdwardsY(r_bytes).decompress() {
            Some(p) => p,
            None => return false,
        };
        let s = match Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)) {
            Some(s) => s,
            None => return false,
        };

        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(big_a_bytes);
        h.update(message);
        let mut hram_bytes = [0u8; 64];
        hram_bytes.copy_from_slice(&h.finalize());
        let hram = Scalar::from_bytes_mod_order_wide(&hram_bytes);

        let lhs = ED25519_BASEPOINT_TABLE * &s;
        let rhs = big_r + hram * big_a;
        lhs == rhs
    }

    #[cfg(test)]
    mod xeddsa_tests {
        use super::*;

        /// Self-consistency: a freshly generated key + message round-trips
        /// through sign+verify. Repeats so we exercise both sign-bit
        /// branches in the signer (k vs -k).
        #[test]
        fn xeddsa_sign_verifies() {
            for _ in 0..32 {
                let kp = KeyPair::generate();
                let msg: Vec<u8> = (0..96).map(|i| i as u8 ^ 0xA5).collect();
                let sig = xeddsa_sign(&kp.private, &msg);
                assert!(
                    xeddsa_verify(&kp.public, &msg, &sig),
                    "valid signature must verify"
                );
            }
        }

        /// Tampering any byte of the message must invalidate the signature.
        #[test]
        fn xeddsa_rejects_tampered_message() {
            let kp = KeyPair::generate();
            let msg = b"signed prekey pubkey 32 bytes....".to_vec();
            let sig = xeddsa_sign(&kp.private, &msg);
            let mut tampered = msg.clone();
            tampered[3] ^= 0x01;
            assert!(!xeddsa_verify(&kp.public, &tampered, &sig));
        }

        /// A signature from one key must not verify under a different
        /// public key.
        #[test]
        fn xeddsa_rejects_wrong_public_key() {
            let kp = KeyPair::generate();
            let other = KeyPair::generate();
            let msg = b"x".to_vec();
            let sig = xeddsa_sign(&kp.private, &msg);
            assert!(!xeddsa_verify(&other.public, &msg, &sig));
        }

        /// One-shot dump for cross-checking our XEdDSA against libsignal-go's
        /// `ecc.VerifySignature`. Prints identity_pub, message, and signature
        /// in hex; pipe `cargo test --release dump_xeddsa_for_libsignal_check
        /// -- --nocapture` into a Go verifier to confirm we match libsignal.
        #[test]
        #[ignore]
        fn dump_xeddsa_for_libsignal_check() {
            for i in 0..3 {
                let kp = KeyPair::generate();
                let spk = KeyPair::generate();
                let sig = xeddsa_sign(&kp.private, &spk.public);
                println!("--- run {i} ---");
                println!("ident_priv: {}", hex_str(&kp.private));
                println!("ident_pub:  {}", hex_str(&kp.public));
                println!("spk_pub:    {}", hex_str(&spk.public));
                println!("signature:  {}", hex_str(&sig));
            }
        }

        fn hex_str(b: &[u8]) -> String {
            let mut s = String::with_capacity(b.len() * 2);
            for x in b {
                s.push_str(&format!("{x:02x}"));
            }
            s
        }

        /// DeviceKeys::generate produces a non-zero, valid SPK signature.
        #[test]
        fn device_keys_generate_signs_spk() {
            let dk = DeviceKeys::generate();
            assert_ne!(dk.signed_prekey.signature, [0u8; 64]);
            // Signed message is `[0x05] || spk_pub`, mirroring libsignal.
            let mut spk_signed = [0u8; 33];
            spk_signed[0] = 0x05;
            spk_signed[1..].copy_from_slice(&dk.signed_prekey.keypair.public);
            assert!(xeddsa_verify(
                &dk.identity.public,
                &spk_signed,
                &dk.signed_prekey.signature,
            ));
        }
    }
}

pub mod prekeys {
    use super::identity::KeyPair;

    /// One-time prekey uploaded during registration; consumed on first
    /// inbound session establishment from a peer.
    #[derive(Clone, Debug)]
    pub struct PreKey {
        pub key_id: u32,
        pub keypair: KeyPair,
    }

    impl PreKey {
        pub fn generate(key_id: u32) -> Self {
            Self {
                key_id,
                keypair: KeyPair::generate(),
            }
        }

        pub fn generate_batch(start_id: u32, count: u32) -> Vec<PreKey> {
            (0..count).map(|i| PreKey::generate(start_id + i)).collect()
        }
    }
}

pub mod signal {
    #![allow(dead_code)] // M3: most items are used by milestones still in progress.
    //! Double Ratchet (Signal Protocol) port — minimum subset for WhatsApp.
    //!
    //! Wire compatibility: this is the standard Signal-protocol algorithm
    //! whatsmeow vendors via libsignal-protocol-go. Persistence format is
    //! ours (we do NOT match libsignal's protobuf SessionStructure).
    //!
    //! Layers (ordered by milestone delivery):
    //!   - chain key advance (HMAC-SHA256 seeds 0x01 + 0x02) — this commit
    //!   - DH ratchet step + RatchetingSession initiate/process — next iter
    //!   - SessionCipher::encrypt/decrypt for WhisperMessage type 1 — after
    //!   - PreKeyWhisperMessage type 3 (X3DH initial) — after that
    //!   - Wire serialization (libsignal-style varint + magic byte) — after
    //!
    //! Hard rule reminder: no third-party WhatsApp library deps. Generic
    //! crypto crates only (RustCrypto / dalek).

    use ::hkdf::Hkdf;
    use hmac::{Hmac, Mac};
    use serde::{Deserialize, Serialize};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    pub const CIPHER_KEY_LEN: usize = 32;
    pub const MAC_KEY_LEN: usize = 32;
    pub const IV_LEN: usize = 16;
    pub const DERIVED_KEY_LEN: usize = CIPHER_KEY_LEN + MAC_KEY_LEN + IV_LEN; // 80

    /// Single chain key. Each step advances `key` via `HMAC(key, 0x02)` and
    /// bumps `index`. `derive_message_keys()` produces (cipher, mac, iv) by
    /// HKDF-expanding `HMAC(key, 0x01)` to 80 bytes.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ChainKey {
        pub key: [u8; 32],
        pub index: u32,
    }

    impl ChainKey {
        pub fn new(key: [u8; 32], index: u32) -> Self {
            Self { key, index }
        }

        /// Advance to the next chain key.
        pub fn next(&self) -> ChainKey {
            ChainKey {
                key: hmac_seed(&self.key, &[0x02]),
                index: self.index + 1,
            }
        }

        /// Derive (cipher_key, mac_key, iv) for the message at `self.index`
        /// using the standard Signal "WhisperMessageKeys" info string.
        pub fn derive_message_keys(&self) -> MessageKeys {
            let mac_seed = hmac_seed(&self.key, &[0x01]);
            let hk = Hkdf::<Sha256>::new(None, &mac_seed);
            let mut out = [0u8; DERIVED_KEY_LEN];
            hk.expand(b"WhisperMessageKeys", &mut out)
                .expect("80 < 255*32");

            let mut cipher_key = [0u8; CIPHER_KEY_LEN];
            let mut mac_key = [0u8; MAC_KEY_LEN];
            let mut iv = [0u8; IV_LEN];
            cipher_key.copy_from_slice(&out[0..CIPHER_KEY_LEN]);
            mac_key.copy_from_slice(&out[CIPHER_KEY_LEN..CIPHER_KEY_LEN + MAC_KEY_LEN]);
            iv.copy_from_slice(&out[CIPHER_KEY_LEN + MAC_KEY_LEN..]);

            MessageKeys {
                cipher_key,
                mac_key,
                iv,
                counter: self.index,
            }
        }
    }

    /// Per-message keys derived from a single point on a chain.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct MessageKeys {
        pub cipher_key: [u8; 32],
        pub mac_key: [u8; 32],
        pub iv: [u8; 16],
        pub counter: u32,
    }

    /// Half of the Double Ratchet's receiver state — per remote ratchet key,
    /// the chain that advances when we receive successive messages from the
    /// same DH ratchet step. We hold a small `skipped` cache to tolerate
    /// out-of-order delivery within a single chain.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ReceiverChain {
        pub remote_ratchet_pub: [u8; 32],
        pub chain_key: ChainKey,
        pub skipped_keys: Vec<MessageKeys>,
    }

    /// Pending X3DH state for sessions started by us — kept until the peer
    /// responds and acknowledges, at which point we drop it.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct PendingPreKey {
        pub pre_key_id: Option<u32>,
        pub signed_pre_key_id: u32,
        pub base_key_pub: [u8; 32],
    }

    /// Current state of one Signal Protocol session with a remote address.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SessionState {
        pub session_version: u32,
        pub local_identity_pub: [u8; 32],
        pub remote_identity_pub: [u8; 32],
        pub root_key: [u8; 32],
        pub sender_chain: Option<ChainKey>,
        pub sender_ratchet_priv: Option<[u8; 32]>,
        pub sender_ratchet_pub: Option<[u8; 32]>,
        pub previous_counter: u32,
        pub receiver_chains: Vec<ReceiverChain>,
        pub pending_pre_key: Option<PendingPreKey>,
        pub local_registration_id: u32,
        pub remote_registration_id: u32,
    }

    /// Versioned wrapper around the live + recently-archived [`SessionState`]s.
    /// Archived states keep us able to decrypt late-arriving messages from a
    /// previous DH ratchet step.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
    pub struct SessionRecord {
        pub current: Option<SessionState>,
        pub previous: Vec<SessionState>,
    }

    impl SessionRecord {
        pub fn new() -> Self {
            Self::default()
        }
    }

    fn hmac_seed(key: &[u8], seed: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(seed);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    // -- X3DH + ratchet step ------------------------------------------------

    /// Maximum number of receiver chains kept alive after DH ratchet steps.
    /// Older chains (with their cached skipped_keys) drop off the end so
    /// the state file doesn't grow unbounded across long sessions.
    pub const MAX_RECEIVER_CHAINS: usize = 5;

    fn dh(priv_key: &[u8; 32], pub_key: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::x25519(*priv_key, *pub_key)
    }

    /// Apply a Double Ratchet DH step to `state` upon receipt of a wire
    /// message bearing a previously-unseen remote ratchet pub. Mirrors
    /// libsignal's `handleRatchetKey`:
    ///
    /// 1. recv chain' = HKDF(root, dh(my_send_priv, their_new_pub))
    /// 2. fresh sender keypair (priv', pub')
    /// 3. send chain' = HKDF(root', dh(priv', their_new_pub))
    /// 4. previous_counter = sender_chain.index
    /// 5. prepend new ReceiverChain; cap at MAX_RECEIVER_CHAINS.
    ///
    /// After this returns, state.receiver_chains[0] is the brand-new
    /// chain ready for normal walking + decrypt.
    fn dh_ratchet_step(
        state: &mut SessionState,
        their_new_pub: &[u8; 32],
    ) -> Result<(), SignalError> {
        use super::identity::KeyPair;

        let send_priv = state
            .sender_ratchet_priv
            .ok_or(SignalError::Malformed("no sender ratchet to step from"))?;

        // Step 1: receiver side.
        let recv_dh = dh(&send_priv, their_new_pub);
        let (root_after_recv, recv_chain) = ratchet_root_step(&state.root_key, &recv_dh);

        // Step 2-3: sender side with fresh keypair.
        let new_send_kp = KeyPair::generate();
        let send_dh = dh(&new_send_kp.private, their_new_pub);
        let (root_after_send, send_chain) = ratchet_root_step(&root_after_recv, &send_dh);

        // Step 4-5: commit.
        state.previous_counter = state
            .sender_chain
            .as_ref()
            .map(|c| c.index)
            .unwrap_or(0);
        state.root_key = root_after_send;
        state.sender_ratchet_priv = Some(new_send_kp.private);
        state.sender_ratchet_pub = Some(new_send_kp.public);
        state.sender_chain = Some(ChainKey::new(send_chain, 0));
        state.receiver_chains.insert(
            0,
            ReceiverChain {
                remote_ratchet_pub: *their_new_pub,
                chain_key: ChainKey::new(recv_chain, 0),
                skipped_keys: vec![],
            },
        );
        if state.receiver_chains.len() > MAX_RECEIVER_CHAINS {
            state.receiver_chains.truncate(MAX_RECEIVER_CHAINS);
        }
        Ok(())
    }

    /// Bootstrap a sender chain on a state that only has a receiver chain
    /// (e.g. Bob right after `process_bob`). Picks the most recent peer
    /// ratchet pub from `receiver_chains[0]`, generates a fresh sender
    /// keypair, and derives the new sender chain from
    /// `dh(new_priv, peer_pub)` via the standard root-step KDF.
    fn bob_first_send_step(state: &mut SessionState) -> Result<(), SignalError> {
        use super::identity::KeyPair;

        let peer_pub = state
            .receiver_chains
            .first()
            .ok_or(SignalError::Malformed("no receiver chain to step from"))?
            .remote_ratchet_pub;
        let new_kp = KeyPair::generate();
        let send_dh = dh(&new_kp.private, &peer_pub);
        let (new_root, send_chain) = ratchet_root_step(&state.root_key, &send_dh);
        state.root_key = new_root;
        state.sender_ratchet_priv = Some(new_kp.private);
        state.sender_ratchet_pub = Some(new_kp.public);
        state.sender_chain = Some(ChainKey::new(send_chain, 0));
        // previous_counter stays 0 — there's no prior sender chain to mark.
        Ok(())
    }

    /// Initial root + (unused) chain from the X3DH master secret.
    /// libsignal v3 prepends 32 0xFF bytes to disambiguate from earlier
    /// versions; we follow the same convention.
    fn initial_kdf(dhs: &[[u8; 32]]) -> ([u8; 32], [u8; 32]) {
        let mut master = vec![0xFFu8; 32];
        for d in dhs {
            master.extend_from_slice(d);
        }
        let salt = [0u8; 32];
        let hk = Hkdf::<Sha256>::new(Some(&salt), &master);
        let mut out = [0u8; 64];
        hk.expand(b"WhisperText", &mut out).unwrap();
        let mut root = [0u8; 32];
        let mut chain = [0u8; 32];
        root.copy_from_slice(&out[..32]);
        chain.copy_from_slice(&out[32..]);
        (root, chain)
    }

    /// Single DH ratchet step: derives `(new_root, new_chain)` from
    /// `HKDF(salt=root_key, ikm=dh, info="WhisperRatchet", L=64)`.
    fn ratchet_root_step(root_key: &[u8; 32], dh_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(Some(root_key), dh_secret);
        let mut out = [0u8; 64];
        hk.expand(b"WhisperRatchet", &mut out).unwrap();
        let mut new_root = [0u8; 32];
        let mut new_chain = [0u8; 32];
        new_root.copy_from_slice(&out[..32]);
        new_chain.copy_from_slice(&out[32..]);
        (new_root, new_chain)
    }

    /// X3DH parameters from the initiator's (Alice's) view.
    pub struct AliceParameters<'a> {
        pub local_identity_priv: &'a [u8; 32],
        pub local_identity_pub: &'a [u8; 32],
        pub local_base_priv: &'a [u8; 32],
        pub local_base_pub: &'a [u8; 32],
        pub local_ratchet_priv: &'a [u8; 32],
        pub local_ratchet_pub: &'a [u8; 32],
        pub remote_identity_pub: &'a [u8; 32],
        pub remote_signed_prekey_pub: &'a [u8; 32],
        pub remote_one_time_prekey_pub: Option<&'a [u8; 32]>,
    }

    /// X3DH parameters from the responder's (Bob's) view, plus the remote
    /// ratchet pub Alice ships in the inner WhisperMessage.
    pub struct BobParameters<'a> {
        pub local_identity_priv: &'a [u8; 32],
        pub local_identity_pub: &'a [u8; 32],
        pub local_signed_prekey_priv: &'a [u8; 32],
        pub local_one_time_prekey_priv: Option<&'a [u8; 32]>,
        pub remote_identity_pub: &'a [u8; 32],
        pub remote_base_pub: &'a [u8; 32],
        pub remote_ratchet_pub: &'a [u8; 32],
    }

    pub struct RatchetingSession;

    impl RatchetingSession {
        /// Build the SessionState an initiator (Alice) holds immediately
        /// after constructing a PreKeyMessage. Subsequent encrypts derive
        /// keys from `sender_chain`.
        pub fn initiate_alice(p: &AliceParameters<'_>) -> SessionState {
            let dh1 = dh(p.local_identity_priv, p.remote_signed_prekey_pub);
            let dh2 = dh(p.local_base_priv, p.remote_identity_pub);
            let dh3 = dh(p.local_base_priv, p.remote_signed_prekey_pub);
            let mut dhs = vec![dh1, dh2, dh3];
            if let Some(opk) = p.remote_one_time_prekey_pub {
                dhs.push(dh(p.local_base_priv, opk));
            }
            let (root, _initial_chain) = initial_kdf(&dhs);

            // Alice's first ratchet step: DH(her ratchet priv, Bob's SPK pub).
            let sending_dh = dh(p.local_ratchet_priv, p.remote_signed_prekey_pub);
            let (new_root, send_chain) = ratchet_root_step(&root, &sending_dh);

            SessionState {
                session_version: 3,
                local_identity_pub: *p.local_identity_pub,
                remote_identity_pub: *p.remote_identity_pub,
                root_key: new_root,
                sender_chain: Some(ChainKey::new(send_chain, 0)),
                sender_ratchet_priv: Some(*p.local_ratchet_priv),
                sender_ratchet_pub: Some(*p.local_ratchet_pub),
                previous_counter: 0,
                receiver_chains: vec![],
                pending_pre_key: None,
                local_registration_id: 0,
                remote_registration_id: 0,
            }
        }

        /// Build the SessionState a responder (Bob) holds after consuming a
        /// PreKeyMessage from Alice. The receiver chain at index 0 lets him
        /// decrypt Alice's first WhisperMessage; he generates his own
        /// sender ratchet on the first reply.
        pub fn process_bob(p: &BobParameters<'_>) -> SessionState {
            let dh1 = dh(p.local_signed_prekey_priv, p.remote_identity_pub);
            let dh2 = dh(p.local_identity_priv, p.remote_base_pub);
            let dh3 = dh(p.local_signed_prekey_priv, p.remote_base_pub);
            let mut dhs = vec![dh1, dh2, dh3];
            if let Some(opk) = p.local_one_time_prekey_priv {
                dhs.push(dh(opk, p.remote_base_pub));
            }
            let (root, _initial_chain) = initial_kdf(&dhs);

            // Bob does the same DH step Alice did, from the other side.
            let recv_dh = dh(p.local_signed_prekey_priv, p.remote_ratchet_pub);
            let (new_root, recv_chain) = ratchet_root_step(&root, &recv_dh);

            SessionState {
                session_version: 3,
                local_identity_pub: *p.local_identity_pub,
                remote_identity_pub: *p.remote_identity_pub,
                root_key: new_root,
                sender_chain: None,
                sender_ratchet_priv: None,
                sender_ratchet_pub: None,
                previous_counter: 0,
                receiver_chains: vec![ReceiverChain {
                    remote_ratchet_pub: *p.remote_ratchet_pub,
                    chain_key: ChainKey::new(recv_chain, 0),
                    skipped_keys: vec![],
                }],
                pending_pre_key: None,
                local_registration_id: 0,
                remote_registration_id: 0,
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Sanity: advancing a chain key produces a different 32-byte key
        /// each step and the index walks forward by 1.
        #[test]
        fn chain_key_next_advances_index_and_changes_key() {
            let ck = ChainKey::new([0x42; 32], 0);
            let n1 = ck.next();
            let n2 = n1.next();
            assert_eq!(ck.index, 0);
            assert_eq!(n1.index, 1);
            assert_eq!(n2.index, 2);
            assert_ne!(ck.key, n1.key);
            assert_ne!(n1.key, n2.key);
        }

        /// Different chain keys at the same index produce different message keys.
        #[test]
        fn derive_message_keys_is_deterministic_per_chain_state() {
            let ck1 = ChainKey::new([0x42; 32], 5);
            let ck1_again = ChainKey::new([0x42; 32], 5);
            let ck2 = ChainKey::new([0x43; 32], 5);

            let m1 = ck1.derive_message_keys();
            let m1_again = ck1_again.derive_message_keys();
            let m2 = ck2.derive_message_keys();

            assert_eq!(m1, m1_again, "same input → same output");
            assert_ne!(m1.cipher_key, m2.cipher_key);
            assert_ne!(m1.mac_key, m2.mac_key);
            assert_ne!(m1.iv, m2.iv);
            assert_eq!(m1.counter, 5);
        }

        /// Counter mirrors chain index; the three sub-keys partition the
        /// 80-byte HKDF output non-overlappingly.
        #[test]
        fn message_keys_layout() {
            let ck = ChainKey::new([0x11; 32], 0);
            let m = ck.derive_message_keys();
            assert_eq!(m.cipher_key.len(), CIPHER_KEY_LEN);
            assert_eq!(m.mac_key.len(), MAC_KEY_LEN);
            assert_eq!(m.iv.len(), IV_LEN);
            // Cipher + mac shouldn't accidentally land on the same bytes.
            assert_ne!(m.cipher_key, m.mac_key);
        }

        /// A SessionRecord with a populated current state round-trips through
        /// bincode unchanged. (Persistence format will be revisited; this
        /// guards against accidental field renames.)
        #[test]
        fn session_record_round_trips_through_serde() {
            let state = SessionState {
                session_version: 3,
                local_identity_pub: [0x01; 32],
                remote_identity_pub: [0x02; 32],
                root_key: [0x03; 32],
                sender_chain: Some(ChainKey::new([0x04; 32], 7)),
                sender_ratchet_priv: Some([0x05; 32]),
                sender_ratchet_pub: Some([0x06; 32]),
                previous_counter: 12,
                receiver_chains: vec![ReceiverChain {
                    remote_ratchet_pub: [0x07; 32],
                    chain_key: ChainKey::new([0x08; 32], 3),
                    skipped_keys: vec![],
                }],
                pending_pre_key: Some(PendingPreKey {
                    pre_key_id: Some(99),
                    signed_pre_key_id: 1,
                    base_key_pub: [0x09; 32],
                }),
                local_registration_id: 0xDEAD,
                remote_registration_id: 0xBEEF,
            };
            let mut record = SessionRecord::new();
            record.current = Some(state);

            let bytes = serde_json::to_vec(&record).unwrap();
            let back: SessionRecord = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(record, back);
        }

        // -- X3DH round-trip test ----------------------------------------

        fn x25519_kp() -> ([u8; 32], [u8; 32]) {
            use rand::rngs::OsRng;
            let s = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let p = x25519_dalek::PublicKey::from(&s);
            (s.to_bytes(), p.to_bytes())
        }

        /// Alice (initiator) and Bob (responder) run X3DH against each other
        /// using a fresh prekey bundle. They MUST agree on the resulting
        /// root_key and on `alice.sender_chain.key == bob.receiver_chain.chain_key.key`.
        #[test]
        fn x3dh_initiate_and_process_agree() {
            let (alice_id_priv, alice_id_pub) = x25519_kp();
            let (alice_base_priv, alice_base_pub) = x25519_kp();
            let (alice_ratchet_priv, alice_ratchet_pub) = x25519_kp();

            let (bob_id_priv, bob_id_pub) = x25519_kp();
            let (bob_spk_priv, bob_spk_pub) = x25519_kp();
            let (bob_opk_priv, bob_opk_pub) = x25519_kp();

            let alice = RatchetingSession::initiate_alice(&AliceParameters {
                local_identity_priv: &alice_id_priv,
                local_identity_pub: &alice_id_pub,
                local_base_priv: &alice_base_priv,
                local_base_pub: &alice_base_pub,
                local_ratchet_priv: &alice_ratchet_priv,
                local_ratchet_pub: &alice_ratchet_pub,
                remote_identity_pub: &bob_id_pub,
                remote_signed_prekey_pub: &bob_spk_pub,
                remote_one_time_prekey_pub: Some(&bob_opk_pub),
            });

            let bob = RatchetingSession::process_bob(&BobParameters {
                local_identity_priv: &bob_id_priv,
                local_identity_pub: &bob_id_pub,
                local_signed_prekey_priv: &bob_spk_priv,
                local_one_time_prekey_priv: Some(&bob_opk_priv),
                remote_identity_pub: &alice_id_pub,
                remote_base_pub: &alice_base_pub,
                remote_ratchet_pub: &alice_ratchet_pub,
            });

            assert_eq!(alice.root_key, bob.root_key, "root_keys must agree");
            let alice_chain = alice.sender_chain.clone().unwrap();
            assert_eq!(bob.receiver_chains.len(), 1);
            assert_eq!(
                alice_chain.key, bob.receiver_chains[0].chain_key.key,
                "alice's sender chain key must equal bob's receiver chain key"
            );
            assert_eq!(alice_chain.index, 0);
            assert_eq!(bob.receiver_chains[0].chain_key.index, 0);
            // Both should derive the same first message keys from that chain.
            assert_eq!(
                alice_chain.derive_message_keys(),
                bob.receiver_chains[0].chain_key.derive_message_keys()
            );
        }

        /// Without the optional one-time prekey, X3DH still completes — the
        /// master secret is just one DH shorter. Both sides must still agree.
        #[test]
        fn x3dh_without_one_time_prekey_still_agrees() {
            let (alice_id_priv, alice_id_pub) = x25519_kp();
            let (alice_base_priv, alice_base_pub) = x25519_kp();
            let (alice_ratchet_priv, alice_ratchet_pub) = x25519_kp();

            let (bob_id_priv, bob_id_pub) = x25519_kp();
            let (bob_spk_priv, bob_spk_pub) = x25519_kp();

            let alice = RatchetingSession::initiate_alice(&AliceParameters {
                local_identity_priv: &alice_id_priv,
                local_identity_pub: &alice_id_pub,
                local_base_priv: &alice_base_priv,
                local_base_pub: &alice_base_pub,
                local_ratchet_priv: &alice_ratchet_priv,
                local_ratchet_pub: &alice_ratchet_pub,
                remote_identity_pub: &bob_id_pub,
                remote_signed_prekey_pub: &bob_spk_pub,
                remote_one_time_prekey_pub: None,
            });
            let bob = RatchetingSession::process_bob(&BobParameters {
                local_identity_priv: &bob_id_priv,
                local_identity_pub: &bob_id_pub,
                local_signed_prekey_priv: &bob_spk_priv,
                local_one_time_prekey_priv: None,
                remote_identity_pub: &alice_id_pub,
                remote_base_pub: &alice_base_pub,
                remote_ratchet_pub: &alice_ratchet_pub,
            });
            assert_eq!(alice.root_key, bob.root_key);
            assert_eq!(
                alice.sender_chain.unwrap().key,
                bob.receiver_chains[0].chain_key.key
            );
        }
    }

    // -- WhisperMessage wire format + SessionCipher --------------------------

    /// Standard libsignal SignalMessage protobuf — see whatsmeow's
    /// libsignal-protocol-go fork (`SignalMessage.proto`). Hand-derived here
    /// rather than vendored because (a) it's tiny and (b) we don't want to
    /// pull a libsignal proto into our `proto/` tree dedicated to whatsmeow's
    /// WhatsApp-specific schemas.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SignalMessageProto {
        #[prost(bytes = "vec", optional, tag = "1")]
        pub ratchet_key: ::core::option::Option<Vec<u8>>,
        #[prost(uint32, optional, tag = "2")]
        pub counter: ::core::option::Option<u32>,
        #[prost(uint32, optional, tag = "3")]
        pub previous_counter: ::core::option::Option<u32>,
        #[prost(bytes = "vec", optional, tag = "4")]
        pub ciphertext: ::core::option::Option<Vec<u8>>,
    }

    /// libsignal v3 version byte: high nibble = current version (3), low
    /// nibble = oldest supported (3) → 0x33.
    pub const WHISPER_VERSION: u8 = 0x33;
    pub const MAC_TRUNCATION_BYTES: usize = 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MessageType {
        /// Standard WhisperMessage (post-X3DH steady state).
        Whisper = 1,
        /// PreKeyWhisperMessage (carries X3DH initial bundle).
        PreKey = 3,
    }

    /// Output of a SessionCipher encrypt: the wire-ready bytes plus the
    /// type tag whatsmeow puts on the `<enc>` element.
    #[derive(Debug, Clone)]
    pub struct CiphertextMessage {
        pub serialized: Vec<u8>,
        pub message_type: MessageType,
    }

    #[derive(Debug, thiserror::Error)]
    pub enum SignalError {
        #[error("session has no sender chain (was process_bob called for an outbound encrypt?)")]
        NoSenderChain,
        #[error("AES-CBC encrypt failed")]
        AesEncrypt,
        #[error("AES-CBC decrypt failed (bad ciphertext or wrong key)")]
        AesDecrypt,
        #[error("MAC verification failed")]
        BadMac,
        #[error("malformed message: {0}")]
        Malformed(&'static str),
    }

    pub struct SessionCipher;

    impl SessionCipher {
        /// Encrypt `plaintext` with the current sender chain. Advances the
        /// chain so successive encrypts use fresh keys. Returns the wire
        /// bytes (version || proto || mac_8) ready to ship inside an
        /// `<enc type="msg">` element.
        ///
        /// If the session has no sender chain yet — e.g. Bob's first reply
        /// after `process_bob` set up only a receiver chain — this also
        /// runs the missing half of the DH ratchet: generates a fresh
        /// sender keypair and derives a sender chain from it.
        pub fn encrypt(
            state: &mut SessionState,
            plaintext: &[u8],
        ) -> Result<CiphertextMessage, SignalError> {
            if state.sender_chain.is_none() {
                bob_first_send_step(state)?;
            }
            let chain = state
                .sender_chain
                .as_ref()
                .ok_or(SignalError::NoSenderChain)?;
            let ratchet_pub = state
                .sender_ratchet_pub
                .ok_or(SignalError::NoSenderChain)?;

            let mks = chain.derive_message_keys();
            let ciphertext = aes256_cbc_encrypt(&mks.cipher_key, &mks.iv, plaintext)?;
            // libsignal serializes ratchet_key as `[0x05] || pub` (33 bytes).
            let mut ratchet_serialized = Vec::with_capacity(33);
            ratchet_serialized.push(0x05);
            ratchet_serialized.extend_from_slice(&ratchet_pub);
            let proto = SignalMessageProto {
                ratchet_key: Some(ratchet_serialized),
                counter: Some(mks.counter),
                previous_counter: Some(state.previous_counter),
                ciphertext: Some(ciphertext),
            };
            let mut serialized = Vec::with_capacity(1 + 64);
            serialized.push(WHISPER_VERSION);
            ::prost::Message::encode(&proto, &mut serialized).expect("Vec<u8> never errors");

            let mac = compute_message_mac(
                &mks.mac_key,
                &state.local_identity_pub,
                &state.remote_identity_pub,
                &serialized,
            );
            serialized.extend_from_slice(&mac[..MAC_TRUNCATION_BYTES]);

            // Advance the sender chain so the next call uses a fresh key.
            state.sender_chain = Some(chain.next());

            Ok(CiphertextMessage {
                serialized,
                message_type: MessageType::Whisper,
            })
        }

        /// Maximum number of skipped message keys cached per chain. Mirrors
        /// libsignal's `MaxMessageKeys = 2000` — a hard upper bound that
        /// caps memory growth from a malicious sender flooding gaps. A
        /// `counter` jump that would push the cache past this limit is
        /// rejected as a denial-of-service signal.
        pub const MAX_SKIPPED_MESSAGE_KEYS: usize = 2000;

        /// Decrypt a WhisperMessage (type 1). The wire bytes must be the
        /// full serialized form `version || proto || mac[..8]` produced by
        /// [`Self::encrypt`].
        ///
        /// Out-of-order delivery within a single ratchet step is supported:
        /// when `counter > chain.index`, the intermediate message keys are
        /// stashed into `state.receiver_chains[i].skipped_keys` so a later
        /// arrival at any of those indices still decrypts. A counter
        /// matching one of the cached entries is decrypted using that
        /// entry, which is then evicted (single-use). DH ratchet stepping
        /// on a NEW remote ratchet_key is still deferred to a follow-up.
        pub fn decrypt(
            state: &mut SessionState,
            wire: &[u8],
        ) -> Result<Vec<u8>, SignalError> {
            use ::prost::Message as _;

            if wire.len() < 1 + MAC_TRUNCATION_BYTES + 1 {
                return Err(SignalError::Malformed("wire too short"));
            }
            if wire[0] != WHISPER_VERSION {
                return Err(SignalError::Malformed("unexpected version byte"));
            }
            let mac_offset = wire.len() - MAC_TRUNCATION_BYTES;
            let body = &wire[..mac_offset];
            let received_mac = &wire[mac_offset..];

            let proto =
                SignalMessageProto::decode(&body[1..]).map_err(|_| SignalError::Malformed("proto"))?;
            let ratchet_key = proto
                .ratchet_key
                .ok_or(SignalError::Malformed("missing ratchet_key"))?;
            // ratchet_key is libsignal-serialized: `[0x05] || pub` (33 bytes).
            // Strip the type prefix; tolerate the bare 32-byte form too for
            // pre-fix self-tests that round-trip without prefix wrapping.
            let ratchet_arr: [u8; 32] = match ratchet_key.len() {
                33 if ratchet_key[0] == 0x05 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&ratchet_key[1..]);
                    a
                }
                32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&ratchet_key);
                    a
                }
                _ => return Err(SignalError::Malformed("ratchet_key wrong length")),
            };
            let counter = proto.counter.unwrap_or(0);
            let ciphertext = proto
                .ciphertext
                .ok_or(SignalError::Malformed("missing ciphertext"))?;

            // Find the matching receiver chain. A miss means the peer
            // rotated their DH ratchet — step both sides accordingly so
            // long-running sessions keep flowing instead of desyncing.
            let chain_idx = match state
                .receiver_chains
                .iter()
                .position(|rc| rc.remote_ratchet_pub == ratchet_arr)
            {
                Some(i) => i,
                None => {
                    dh_ratchet_step(state, &ratchet_arr)?;
                    0
                }
            };

            // Two paths:
            //   (A) counter < chain.index: try the skipped_keys cache.
            //       Hit → use it + remove. Miss → reject.
            //   (B) counter >= chain.index: walk chain forward, stashing
            //       MessageKeys for every intermediate index into
            //       skipped_keys, derive at counter, advance chain.
            let chain = state.receiver_chains[chain_idx].chain_key.clone();
            let (mks, advanced_chain, evict_skipped_idx) = if counter < chain.index {
                let pos = state.receiver_chains[chain_idx]
                    .skipped_keys
                    .iter()
                    .position(|k| k.counter == counter)
                    .ok_or(SignalError::Malformed("counter out of range"))?;
                let mks = state.receiver_chains[chain_idx].skipped_keys[pos].clone();
                (mks, None, Some(pos))
            } else {
                let gap = (counter - chain.index) as usize;
                if state.receiver_chains[chain_idx]
                    .skipped_keys
                    .len()
                    .saturating_add(gap)
                    > Self::MAX_SKIPPED_MESSAGE_KEYS
                {
                    return Err(SignalError::Malformed(
                        "skipped key cache would exceed limit",
                    ));
                }
                let mut walking = chain;
                while walking.index < counter {
                    let mks = walking.derive_message_keys();
                    state.receiver_chains[chain_idx].skipped_keys.push(mks);
                    walking = walking.next();
                }
                let mks = walking.derive_message_keys();
                (mks, Some(walking.next()), None)
            };

            // Verify MAC under the receiver's view: sender_id is the *remote*
            // identity from the local state's perspective, receiver_id is the
            // local identity. (Mirrored vs the encrypt side.)
            let expected_mac = compute_message_mac(
                &mks.mac_key,
                &state.remote_identity_pub,
                &state.local_identity_pub,
                body,
            );
            if expected_mac[..MAC_TRUNCATION_BYTES] != *received_mac {
                return Err(SignalError::BadMac);
            }

            let plaintext = aes256_cbc_decrypt(&mks.cipher_key, &mks.iv, &ciphertext)?;

            // Now that decrypt + MAC verification both succeeded, commit
            // the state mutation. (Failing earlier would leave skipped_keys
            // unchanged in path B because we hadn't pushed yet — but we DID
            // push during the walk; that's intentional and matches libsignal:
            // a successful walk that ends in a bad MAC still advances the
            // cache, since the cached keys are valid for those *positions*
            // and the MAC failure is over THIS message only. Subsequent
            // deliveries at those skipped positions will succeed.)
            if let Some(new_chain) = advanced_chain {
                state.receiver_chains[chain_idx].chain_key = new_chain;
            }
            if let Some(idx) = evict_skipped_idx {
                state.receiver_chains[chain_idx].skipped_keys.remove(idx);
            }
            Ok(plaintext)
        }

        /// Wrap a freshly-encrypted WhisperMessage in a PreKeySignalMessage
        /// envelope. Sent as the very first message to a new peer; tells
        /// the recipient which prekey we consumed so they can rebuild the
        /// session via [`RatchetingSession::process_bob`].
        ///
        /// `state` must already be the post-`initiate_alice` SessionState
        /// (i.e. the caller has run X3DH on Bob's bundle).
        #[allow(clippy::too_many_arguments)]
        pub fn encrypt_pre_key(
            state: &mut SessionState,
            plaintext: &[u8],
            registration_id: u32,
            base_key_pub: &[u8; 32],
            identity_key_pub: &[u8; 32],
            signed_pre_key_id: u32,
            one_time_pre_key_id: Option<u32>,
        ) -> Result<CiphertextMessage, SignalError> {
            let inner = Self::encrypt(state, plaintext)?;
            // libsignal serializes both base_key and identity_key with the
            // [0x05] DjbType prefix → 33 bytes each.
            let mut base_serialized = Vec::with_capacity(33);
            base_serialized.push(0x05);
            base_serialized.extend_from_slice(base_key_pub);
            let mut identity_serialized = Vec::with_capacity(33);
            identity_serialized.push(0x05);
            identity_serialized.extend_from_slice(identity_key_pub);
            let pkm = PreKeySignalMessageProto {
                registration_id: Some(registration_id),
                pre_key_id: one_time_pre_key_id,
                signed_pre_key_id: Some(signed_pre_key_id),
                base_key: Some(base_serialized),
                identity_key: Some(identity_serialized),
                message: Some(inner.serialized),
            };
            let mut serialized = Vec::with_capacity(64);
            serialized.push(WHISPER_VERSION);
            ::prost::Message::encode(&pkm, &mut serialized).expect("Vec<u8> never errors");
            Ok(CiphertextMessage {
                serialized,
                message_type: MessageType::PreKey,
            })
        }
    }

    /// Standard libsignal `PreKeySignalMessage` (type 3).
    ///
    /// No MAC at this layer — the inner [`SignalMessageProto`] still carries
    /// its own truncated HMAC.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct PreKeySignalMessageProto {
        #[prost(uint32, optional, tag = "5")]
        pub registration_id: ::core::option::Option<u32>,
        #[prost(uint32, optional, tag = "1")]
        pub pre_key_id: ::core::option::Option<u32>,
        #[prost(uint32, optional, tag = "6")]
        pub signed_pre_key_id: ::core::option::Option<u32>,
        #[prost(bytes = "vec", optional, tag = "2")]
        pub base_key: ::core::option::Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "3")]
        pub identity_key: ::core::option::Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "4")]
        pub message: ::core::option::Option<Vec<u8>>,
    }

    /// Parsed view of a wire PreKeyWhisperMessage. Caller looks up the
    /// signed prekey + (optional) one-time prekey by id, runs
    /// [`RatchetingSession::process_bob`] with the included keys (note:
    /// `remote_ratchet_pub` must be `inner_ratchet_pub`, NOT `base_key_pub`),
    /// then passes `inner_whisper_wire` to [`SessionCipher::decrypt`].
    #[derive(Debug, Clone)]
    pub struct PreKeyMessageInfo {
        pub registration_id: u32,
        pub pre_key_id: Option<u32>,
        pub signed_pre_key_id: u32,
        pub base_key_pub: [u8; 32],
        pub identity_key_pub: [u8; 32],
        /// The peer's first ratchet public key, extracted from the inner
        /// SignalMessage. process_bob uses this for the first DH ratchet
        /// step that aligns Bob's receiver chain with Alice's sender chain.
        pub inner_ratchet_pub: [u8; 32],
        pub inner_whisper_wire: Vec<u8>,
    }

    /// Parse a PreKeyWhisperMessage wire blob. Pure — does no crypto and
    /// touches no state. The caller drives the rest of the receive path.
    pub fn parse_pre_key_message(wire: &[u8]) -> Result<PreKeyMessageInfo, SignalError> {
        if wire.is_empty() {
            return Err(SignalError::Malformed("empty wire"));
        }
        if wire[0] != WHISPER_VERSION {
            return Err(SignalError::Malformed("unexpected version byte"));
        }
        let proto = <PreKeySignalMessageProto as ::prost::Message>::decode(&wire[1..])
            .map_err(|_| SignalError::Malformed("PreKey proto"))?;

        let signed_pre_key_id = proto
            .signed_pre_key_id
            .ok_or(SignalError::Malformed("PreKey missing signed_pre_key_id"))?;
        let registration_id = proto.registration_id.unwrap_or(0);
        let base_bytes = proto
            .base_key
            .ok_or(SignalError::Malformed("PreKey missing base_key"))?;
        let id_bytes = proto
            .identity_key
            .ok_or(SignalError::Malformed("PreKey missing identity_key"))?;
        let inner = proto
            .message
            .ok_or(SignalError::Malformed("PreKey missing inner message"))?;
        // libsignal serializes both as `[0x05] || pub` (33 bytes); accept
        // the bare 32-byte form as a fallback for self-tests that haven't
        // been updated to the prefixed form.
        fn unwrap_djb_pub(b: &[u8], field: &'static str) -> Result<[u8; 32], SignalError> {
            match b.len() {
                33 if b[0] == 0x05 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b[1..]);
                    Ok(a)
                }
                32 => {
                    let mut a = [0u8; 32];
                    a.copy_from_slice(b);
                    Ok(a)
                }
                _ => Err(SignalError::Malformed(field)),
            }
        }
        let base_key_pub = unwrap_djb_pub(&base_bytes, "PreKey base_key wrong length")?;
        let identity_key_pub = unwrap_djb_pub(&id_bytes, "PreKey identity_key wrong length")?;

        // Peek the inner WhisperMessage to recover the sender's first ratchet
        // pub. The inner wire is `version || proto || mac[..8]`; the proto
        // sits between byte 1 and the MAC.
        if inner.len() < 1 + MAC_TRUNCATION_BYTES + 1 {
            return Err(SignalError::Malformed("inner whisper too short"));
        }
        if inner[0] != WHISPER_VERSION {
            return Err(SignalError::Malformed("inner whisper bad version"));
        }
        let inner_body_end = inner.len() - MAC_TRUNCATION_BYTES;
        let inner_proto = <SignalMessageProto as ::prost::Message>::decode(
            &inner[1..inner_body_end],
        )
        .map_err(|_| SignalError::Malformed("inner whisper proto"))?;
        let inner_ratchet_bytes = inner_proto
            .ratchet_key
            .ok_or(SignalError::Malformed("inner whisper missing ratchet_key"))?;
        let inner_ratchet_pub = unwrap_djb_pub(
            &inner_ratchet_bytes,
            "inner ratchet_key wrong length",
        )?;

        Ok(PreKeyMessageInfo {
            registration_id,
            pre_key_id: proto.pre_key_id,
            signed_pre_key_id,
            base_key_pub,
            identity_key_pub,
            inner_ratchet_pub,
            inner_whisper_wire: inner,
        })
    }

    fn compute_message_mac(
        mac_key: &[u8; 32],
        sender_id: &[u8; 32],
        receiver_id: &[u8; 32],
        version_and_body: &[u8],
    ) -> [u8; 32] {
        // libsignal MAC formula for v3+: HMAC(macKey, senderId.Serialize() ||
        // receiverId.Serialize() || version_and_body), where Serialize() is
        // [0x05] || pub (33 bytes). Without the prefix the recipient's MAC
        // verify fails and the message lands as "Waiting for this message".
        let mut mac = HmacSha256::new_from_slice(mac_key).expect("HMAC accepts any key");
        mac.update(&[0x05]);
        mac.update(sender_id);
        mac.update(&[0x05]);
        mac.update(receiver_id);
        mac.update(version_and_body);
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    fn aes256_cbc_encrypt(
        key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SignalError> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Enc = cbc::Encryptor<Aes256>;
        let enc = Enc::new(key.into(), iv.into());
        Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
    }

    fn aes256_cbc_decrypt(
        key: &[u8; 32],
        iv: &[u8; 16],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SignalError> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Dec = cbc::Decryptor<Aes256>;
        let dec = Dec::new(key.into(), iv.into());
        dec.decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
            .map_err(|_| SignalError::AesDecrypt)
    }

    #[cfg(test)]
    mod cipher_tests {
        use super::*;
        use ::prost::Message as _;

        /// Build matching alice/bob session states via X3DH so we can
        /// reuse them in encrypt round-trip checks (decrypt lands next iter).
        fn paired_x3dh() -> (SessionState, SessionState) {
            use rand::rngs::OsRng;
            fn kp() -> ([u8; 32], [u8; 32]) {
                let s = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                let p = x25519_dalek::PublicKey::from(&s);
                (s.to_bytes(), p.to_bytes())
            }
            let (a_id_priv, a_id_pub) = kp();
            let (a_base_priv, a_base_pub) = kp();
            let (a_ratchet_priv, a_ratchet_pub) = kp();
            let (b_id_priv, b_id_pub) = kp();
            let (b_spk_priv, b_spk_pub) = kp();

            let a = RatchetingSession::initiate_alice(&AliceParameters {
                local_identity_priv: &a_id_priv,
                local_identity_pub: &a_id_pub,
                local_base_priv: &a_base_priv,
                local_base_pub: &a_base_pub,
                local_ratchet_priv: &a_ratchet_priv,
                local_ratchet_pub: &a_ratchet_pub,
                remote_identity_pub: &b_id_pub,
                remote_signed_prekey_pub: &b_spk_pub,
                remote_one_time_prekey_pub: None,
            });
            let b = RatchetingSession::process_bob(&BobParameters {
                local_identity_priv: &b_id_priv,
                local_identity_pub: &b_id_pub,
                local_signed_prekey_priv: &b_spk_priv,
                local_one_time_prekey_priv: None,
                remote_identity_pub: &a_id_pub,
                remote_base_pub: &a_base_pub,
                remote_ratchet_pub: &a_ratchet_pub,
            });
            (a, b)
        }

        #[test]
        fn encrypt_advances_sender_chain_and_emits_valid_wire_layout() {
            let (mut alice, _bob) = paired_x3dh();
            let chain_before = alice.sender_chain.clone().unwrap();

            let plaintext = b"hello world";
            let msg = SessionCipher::encrypt(&mut alice, plaintext).unwrap();
            assert_eq!(msg.message_type, MessageType::Whisper);

            // Wire layout: 1 version byte + proto + 8-byte MAC.
            assert_eq!(msg.serialized[0], WHISPER_VERSION);
            assert!(
                msg.serialized.len() > 1 + MAC_TRUNCATION_BYTES,
                "must include proto bytes between version and mac"
            );

            // Sender chain advanced: index +1, key changed.
            let chain_after = alice.sender_chain.unwrap();
            assert_eq!(chain_after.index, chain_before.index + 1);
            assert_ne!(chain_after.key, chain_before.key);
        }

        #[test]
        fn encrypt_then_manually_decrypt_recovers_plaintext() {
            // Self-consistency: encrypt with paired state, recompute the
            // message keys ourselves on the receiver side, verify the MAC,
            // AES-CBC decrypt — should recover the original plaintext.
            let (mut alice, bob) = paired_x3dh();
            let plaintext = b"the quick brown fox jumps over the lazy dog";

            let msg = SessionCipher::encrypt(&mut alice, plaintext).unwrap();
            // Strip MAC, parse proto.
            let mac_offset = msg.serialized.len() - MAC_TRUNCATION_BYTES;
            let body = &msg.serialized[..mac_offset];
            let mac_received = &msg.serialized[mac_offset..];

            // Bob has the matching receiver chain at index 0 (Alice was at
            // index 0 too when she encrypted). Derive the same message keys.
            let bob_chain = &bob.receiver_chains[0].chain_key;
            let mks = bob_chain.derive_message_keys();

            // Verify MAC on Bob's side.
            let mac = compute_message_mac(
                &mks.mac_key,
                &alice.local_identity_pub,
                &bob.local_identity_pub,
                body,
            );
            assert_eq!(&mac[..MAC_TRUNCATION_BYTES], mac_received);

            // Pull ciphertext out of the proto.
            assert_eq!(body[0], WHISPER_VERSION);
            let proto = SignalMessageProto::decode(&body[1..]).unwrap();
            let ct = proto.ciphertext.unwrap();

            // AES-CBC decrypt with the same derived keys.
            let recovered = aes256_cbc_decrypt(&mks.cipher_key, &mks.iv, &ct).unwrap();
            assert_eq!(recovered, plaintext);
        }

        /// Multi-turn ratchet: ten alternating messages between Alice and
        /// Bob. Every reply forces a DH ratchet step on the receiver and
        /// a sender ratchet step on the next outbound. All ten must
        /// decrypt to the original plaintext.
        ///
        /// Note: the two parties' `root_key` values are intentionally
        /// offset by one DH step at all times — each receive-side full
        /// DH step advances the root by 2 (recv chain then send chain),
        /// while the corresponding sender-side step on the peer advances
        /// it by 1. We therefore do NOT assert root_key equality; the
        /// authoritative invariant is end-to-end plaintext recovery.
        #[test]
        fn multi_turn_dh_ratchet_keeps_session_in_sync() {
            let (mut alice, mut bob) = paired_x3dh();
            for round in 0..5 {
                let pt = format!("a-{round}");
                let msg = SessionCipher::encrypt(&mut alice, pt.as_bytes()).unwrap();
                let recovered = SessionCipher::decrypt(&mut bob, &msg.serialized).unwrap();
                assert_eq!(recovered, pt.as_bytes(), "round {round} A→B");

                let pt = format!("b-{round}");
                let msg = SessionCipher::encrypt(&mut bob, pt.as_bytes()).unwrap();
                let recovered = SessionCipher::decrypt(&mut alice, &msg.serialized).unwrap();
                assert_eq!(recovered, pt.as_bytes(), "round {round} B→A");
            }
            // Both sides should have grown a small history of receiver chains
            // (one per inbound DH step, capped at MAX_RECEIVER_CHAINS).
            assert!(alice.receiver_chains.len() >= 2);
            assert!(bob.receiver_chains.len() >= 2);
            assert!(alice.receiver_chains.len() <= super::MAX_RECEIVER_CHAINS);
            assert!(bob.receiver_chains.len() <= super::MAX_RECEIVER_CHAINS);
        }

        /// After `process_bob`, Bob has only a receiver chain. His first
        /// `encrypt` call must auto-bootstrap a sender chain (the missing
        /// half of the DH ratchet) instead of erroring. The resulting
        /// message decrypts on Alice's side via her own DH ratchet step.
        #[test]
        fn bob_first_reply_bootstraps_sender_chain() {
            let (mut alice, mut bob) = paired_x3dh();
            // Alice → Bob first so Bob's session is real.
            let m_a1 = SessionCipher::encrypt(&mut alice, b"hi bob").unwrap();
            let _ = SessionCipher::decrypt(&mut bob, &m_a1.serialized).unwrap();

            // Bob's first reply: no sender chain yet → must auto-step.
            assert!(bob.sender_chain.is_none());
            let m_b1 = SessionCipher::encrypt(&mut bob, b"hi alice").unwrap();
            assert!(bob.sender_chain.is_some(), "encrypt must bootstrap a sender chain");

            // Alice receives under a NEW remote ratchet pub → triggers her
            // own DH step.
            let recovered = SessionCipher::decrypt(&mut alice, &m_b1.serialized).unwrap();
            assert_eq!(recovered, b"hi alice");
        }

        /// The decisive test: alice.encrypt → bob.decrypt yields the
        /// original plaintext, with both sides advancing their respective
        /// chains in lockstep.
        #[test]
        fn alice_encrypts_and_bob_decrypts() {
            let (mut alice, mut bob) = paired_x3dh();
            let pt = b"hello from alice";

            let msg = SessionCipher::encrypt(&mut alice, pt).unwrap();
            let recovered = SessionCipher::decrypt(&mut bob, &msg.serialized).unwrap();
            assert_eq!(recovered, pt);

            // Both chains have advanced by 1.
            assert_eq!(alice.sender_chain.unwrap().index, 1);
            assert_eq!(bob.receiver_chains[0].chain_key.index, 1);
        }

        #[test]
        fn alice_two_messages_in_order_decrypt_in_order() {
            let (mut alice, mut bob) = paired_x3dh();
            let m1 = SessionCipher::encrypt(&mut alice, b"first").unwrap();
            let m2 = SessionCipher::encrypt(&mut alice, b"second").unwrap();

            assert_eq!(SessionCipher::decrypt(&mut bob, &m1.serialized).unwrap(), b"first");
            assert_eq!(SessionCipher::decrypt(&mut bob, &m2.serialized).unwrap(), b"second");
            assert_eq!(alice.sender_chain.clone().unwrap().index, 2);
            assert_eq!(bob.receiver_chains[0].chain_key.index, 2);
        }

        /// Out-of-order delivery within a single chain: Alice ships
        /// messages 0..5 in order, Bob receives them in shuffled order
        /// 3, 0, 4, 1, 2. All five must decrypt correctly with no chain
        /// desync. Each cache hit must evict (no replay).
        #[test]
        fn out_of_order_delivery_within_chain_decrypts_via_skipped_keys() {
            let (mut alice, mut bob) = paired_x3dh();
            let mut msgs = Vec::new();
            for i in 0..5 {
                let pt = format!("msg-{i}");
                msgs.push(SessionCipher::encrypt(&mut alice, pt.as_bytes()).unwrap());
            }

            // Receive in jumbled order. Index 3 first → keys for 0..3 are
            // cached as skipped, key for 3 is consumed.
            assert_eq!(
                SessionCipher::decrypt(&mut bob, &msgs[3].serialized).unwrap(),
                b"msg-3"
            );
            assert_eq!(bob.receiver_chains[0].skipped_keys.len(), 3);
            assert_eq!(bob.receiver_chains[0].chain_key.index, 4);

            // Now 0 from cache.
            assert_eq!(
                SessionCipher::decrypt(&mut bob, &msgs[0].serialized).unwrap(),
                b"msg-0"
            );
            assert_eq!(bob.receiver_chains[0].skipped_keys.len(), 2);

            // 4 advances past it.
            assert_eq!(
                SessionCipher::decrypt(&mut bob, &msgs[4].serialized).unwrap(),
                b"msg-4"
            );
            assert_eq!(bob.receiver_chains[0].chain_key.index, 5);

            // 1 from cache.
            assert_eq!(
                SessionCipher::decrypt(&mut bob, &msgs[1].serialized).unwrap(),
                b"msg-1"
            );
            assert_eq!(bob.receiver_chains[0].skipped_keys.len(), 1);

            // 2 from cache (last skipped).
            assert_eq!(
                SessionCipher::decrypt(&mut bob, &msgs[2].serialized).unwrap(),
                b"msg-2"
            );
            assert_eq!(bob.receiver_chains[0].skipped_keys.len(), 0);

            // Replay of 0 must now fail — the skipped key was evicted on use.
            let err = SessionCipher::decrypt(&mut bob, &msgs[0].serialized).unwrap_err();
            assert!(matches!(err, SignalError::Malformed(_)));
        }

        /// A counter-jump that would push the skipped-keys cache past the
        /// hard limit gets rejected as a DoS guard. We forge a wire by
        /// hand-crafting a SignalMessageProto with a wildly future counter
        /// (the encrypt path doesn't let us advance that far cheaply).
        #[test]
        fn decrypt_rejects_oversize_counter_jump() {
            use ::prost::Message as _;
            let (alice, mut bob) = paired_x3dh();
            // Real chain ratchet pub from Alice's first encrypt.
            let alice_ratchet_pub = alice.sender_ratchet_pub.unwrap();
            // Forge a wire whose counter is way past the cache limit.
            let counter_far = (super::SessionCipher::MAX_SKIPPED_MESSAGE_KEYS + 10) as u32;
            let proto = SignalMessageProto {
                ratchet_key: Some(alice_ratchet_pub.to_vec()),
                counter: Some(counter_far),
                previous_counter: Some(0),
                ciphertext: Some(vec![0u8; 16]),
            };
            let mut wire = Vec::with_capacity(64);
            wire.push(WHISPER_VERSION);
            proto.encode(&mut wire).unwrap();
            wire.extend_from_slice(&[0u8; MAC_TRUNCATION_BYTES]);
            let err = SessionCipher::decrypt(&mut bob, &wire).unwrap_err();
            // We hit the size guard before MAC is checked — Malformed path.
            assert!(matches!(err, SignalError::Malformed(_)));
        }

        #[test]
        fn decrypt_rejects_bad_mac() {
            let (mut alice, mut bob) = paired_x3dh();
            let mut msg = SessionCipher::encrypt(&mut alice, b"x").unwrap();
            // Flip a bit in the mac (last 8 bytes).
            let n = msg.serialized.len();
            msg.serialized[n - 1] ^= 0x01;
            let err = SessionCipher::decrypt(&mut bob, &msg.serialized).unwrap_err();
            assert!(matches!(err, SignalError::BadMac));
        }

        #[test]
        fn decrypt_rejects_unknown_ratchet_key() {
            let (mut alice, mut bob) = paired_x3dh();
            let msg = SessionCipher::encrypt(&mut alice, b"x").unwrap();

            // Wipe Bob's receiver chains so the ratchet_key isn't found.
            bob.receiver_chains.clear();
            let err = SessionCipher::decrypt(&mut bob, &msg.serialized).unwrap_err();
            assert!(matches!(err, SignalError::Malformed(_)));
        }

        #[test]
        fn decrypt_rejects_truncated_wire_bytes() {
            let (mut alice, mut bob) = paired_x3dh();
            let msg = SessionCipher::encrypt(&mut alice, b"x").unwrap();
            // Take only the first byte (just the version) — clearly too short.
            let err = SessionCipher::decrypt(&mut bob, &msg.serialized[..1]).unwrap_err();
            assert!(matches!(err, SignalError::Malformed(_)));
        }

        /// Full PreKeyMessage flow: Alice has Bob's bundle, runs initiate +
        /// encrypt_pre_key. Bob (with no prior session) parses the envelope,
        /// runs process_bob from the carried base_key + identity_key, then
        /// decrypts the inner WhisperMessage. Recovers the original plaintext.
        #[test]
        fn pre_key_message_round_trip() {
            use rand::rngs::OsRng;
            fn kp() -> ([u8; 32], [u8; 32]) {
                let s = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                let p = x25519_dalek::PublicKey::from(&s);
                (s.to_bytes(), p.to_bytes())
            }
            let (a_id_priv, a_id_pub) = kp();
            let (a_base_priv, a_base_pub) = kp();
            let (a_ratchet_priv, a_ratchet_pub) = kp();
            let (b_id_priv, b_id_pub) = kp();
            let (b_spk_priv, b_spk_pub) = kp();
            let (b_opk_priv, b_opk_pub) = kp();
            let alice_reg_id = 0xCAFE;
            let signed_prekey_id = 7;
            let one_time_prekey_id = 42;

            // Alice: X3DH + first encrypt as PreKey.
            let mut alice = RatchetingSession::initiate_alice(&AliceParameters {
                local_identity_priv: &a_id_priv,
                local_identity_pub: &a_id_pub,
                local_base_priv: &a_base_priv,
                local_base_pub: &a_base_pub,
                local_ratchet_priv: &a_ratchet_priv,
                local_ratchet_pub: &a_ratchet_pub,
                remote_identity_pub: &b_id_pub,
                remote_signed_prekey_pub: &b_spk_pub,
                remote_one_time_prekey_pub: Some(&b_opk_pub),
            });
            let pkm = SessionCipher::encrypt_pre_key(
                &mut alice,
                b"first message via x3dh",
                alice_reg_id,
                &a_base_pub,
                &a_id_pub,
                signed_prekey_id,
                Some(one_time_prekey_id),
            )
            .unwrap();
            assert_eq!(pkm.message_type, MessageType::PreKey);

            // Bob: parse envelope → look up SPK + OPK by id (here we just
            // have the keys directly) → process_bob → decrypt inner.
            let info = parse_pre_key_message(&pkm.serialized).unwrap();
            assert_eq!(info.registration_id, alice_reg_id);
            assert_eq!(info.pre_key_id, Some(one_time_prekey_id));
            assert_eq!(info.signed_pre_key_id, signed_prekey_id);
            assert_eq!(info.base_key_pub, a_base_pub);
            assert_eq!(info.identity_key_pub, a_id_pub);

            let mut bob = RatchetingSession::process_bob(&BobParameters {
                local_identity_priv: &b_id_priv,
                local_identity_pub: &b_id_pub,
                local_signed_prekey_priv: &b_spk_priv,
                local_one_time_prekey_priv: Some(&b_opk_priv),
                remote_identity_pub: &info.identity_key_pub,
                remote_base_pub: &info.base_key_pub,
                remote_ratchet_pub: &a_ratchet_pub,
            });
            let pt = SessionCipher::decrypt(&mut bob, &info.inner_whisper_wire).unwrap();
            assert_eq!(pt, b"first message via x3dh");

            // After receiving the PreKey, Bob can now reply with a regular
            // WhisperMessage IF he sets up his sender chain. (M3 follow-up
            // wires the post-PreKey reply path; this commit only verifies
            // the receive side.)
        }

        #[test]
        fn pre_key_message_without_one_time_prekey() {
            // Same as above but Alice's bundle doesn't include an OPK.
            use rand::rngs::OsRng;
            fn kp() -> ([u8; 32], [u8; 32]) {
                let s = x25519_dalek::StaticSecret::random_from_rng(OsRng);
                let p = x25519_dalek::PublicKey::from(&s);
                (s.to_bytes(), p.to_bytes())
            }
            let (a_id_priv, a_id_pub) = kp();
            let (a_base_priv, a_base_pub) = kp();
            let (a_ratchet_priv, a_ratchet_pub) = kp();
            let (b_id_priv, b_id_pub) = kp();
            let (b_spk_priv, b_spk_pub) = kp();

            let mut alice = RatchetingSession::initiate_alice(&AliceParameters {
                local_identity_priv: &a_id_priv,
                local_identity_pub: &a_id_pub,
                local_base_priv: &a_base_priv,
                local_base_pub: &a_base_pub,
                local_ratchet_priv: &a_ratchet_priv,
                local_ratchet_pub: &a_ratchet_pub,
                remote_identity_pub: &b_id_pub,
                remote_signed_prekey_pub: &b_spk_pub,
                remote_one_time_prekey_pub: None,
            });
            let pkm = SessionCipher::encrypt_pre_key(
                &mut alice,
                b"hello",
                123,
                &a_base_pub,
                &a_id_pub,
                7,
                None,
            )
            .unwrap();
            let info = parse_pre_key_message(&pkm.serialized).unwrap();
            assert!(info.pre_key_id.is_none());

            let mut bob = RatchetingSession::process_bob(&BobParameters {
                local_identity_priv: &b_id_priv,
                local_identity_pub: &b_id_pub,
                local_signed_prekey_priv: &b_spk_priv,
                local_one_time_prekey_priv: None,
                remote_identity_pub: &info.identity_key_pub,
                remote_base_pub: &info.base_key_pub,
                remote_ratchet_pub: &a_ratchet_pub,
            });
            assert_eq!(
                SessionCipher::decrypt(&mut bob, &info.inner_whisper_wire).unwrap(),
                b"hello"
            );
        }

        #[test]
        fn parse_pre_key_message_rejects_bad_input() {
            assert!(parse_pre_key_message(&[]).is_err());
            assert!(parse_pre_key_message(&[0x12]).is_err()); // wrong version
            // Right version, junk proto.
            assert!(parse_pre_key_message(&[WHISPER_VERSION, 0xff, 0xff, 0xff]).is_err());
        }
    }
}

pub mod senderkey {
    //! Sender-key encryption for group messages.
    //!
    //! Mirrors libsignal's groups module: each (group, sender) pair has a
    //! `SenderKeyState` carrying a chain key + signing keypair. The first
    //! group send for a (group, sender) ships a SenderKeyDistributionMessage
    //! (SKDM) inside a 1:1 Signal envelope to every group member; subsequent
    //! sends use the chain alone.
    #![allow(dead_code)]

    use serde::{Deserialize, Serialize};

    use super::signal::ChainKey;

    /// The sender's per-(group, sender) state. `signing_keypair_pub` is
    /// shared with peers via the SKDM so they can verify each message.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SenderKeyState {
        pub key_id: u32,
        pub chain_key: ChainKey,
        pub signing_keypair_priv: [u8; 32],
        pub signing_keypair_pub: [u8; 32],
    }

    /// SenderKeyDistributionMessage payload — what the initiator ships
    /// to every group member to bootstrap their receiver state. Mirrors
    /// libsignal's protobuf SenderKeyDistributionMessage shape.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SenderKeyDistribution {
        pub key_id: u32,
        pub iteration: u32,
        pub chain_key: [u8; 32],
        pub signing_key: [u8; 32],
    }

    /// Receiver-side per-(group, sender) state. The chain advances as
    /// messages arrive; signing_pub is used to verify each message.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SenderKeyReceiverState {
        pub key_id: u32,
        pub chain_key: ChainKey,
        pub signing_pub: [u8; 32],
        /// Cache of message keys for chain iterations we ratcheted PAST without
        /// seeing the message (out-of-order group delivery). Mirrors the 1:1
        /// `skipped_keys` cache; without it an older skmsg whose `iteration` is
        /// below the current chain index is undecryptable ("iteration went
        /// backwards"). `#[serde(default)]` keeps old stored records loadable.
        #[serde(default)]
        pub skipped: Vec<SkippedSenderKey>,
    }

    /// One cached (iv, cipher_key) for a skipped sender-key chain iteration.
    #[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
    pub struct SkippedSenderKey {
        pub iteration: u32,
        pub iv: [u8; 16],
        pub cipher_key: [u8; 32],
    }

    /// Cap on cached skipped sender-key message keys (per group+sender).
    const MAX_SKIPPED_SENDER_KEYS: usize = 2000;

    impl SenderKeyState {
        /// Create a fresh sending state for a (group, self) the first time we
        /// post to a group: random key id, random chain seed, fresh signing
        /// keypair. The signing keypair is what peers verify each skmsg against
        /// (shipped in the SKDM).
        pub fn generate() -> Self {
            use rand::rngs::OsRng;
            use rand::RngCore;
            let kp = super::identity::KeyPair::generate();
            let mut chain = [0u8; 32];
            OsRng.fill_bytes(&mut chain);
            SenderKeyState {
                // Top bit cleared so the id is a comfortably-small uint32 (matches
                // the range real clients pick; avoids any signed/varint surprises).
                key_id: OsRng.next_u32() & 0x7fff_ffff,
                chain_key: ChainKey::new(chain, 0),
                signing_keypair_priv: kp.private,
                signing_keypair_pub: kp.public,
            }
        }

        /// Build the SKDM for a fresh-out-of-the-gate sender.
        pub fn distribution(&self) -> SenderKeyDistribution {
            SenderKeyDistribution {
                key_id: self.key_id,
                iteration: self.chain_key.index,
                chain_key: self.chain_key.key,
                signing_key: self.signing_keypair_pub,
            }
        }
    }

    /// Serialize a [`SenderKeyDistribution`] to the libsignal wire blob peers
    /// expect inside `axolotlSenderKeyDistributionMessage`: version byte (0x33)
    /// || proto{ id, iteration, chainKey(32B), signingKey(0x05||32B DJB) }.
    /// Inverse of [`parse_distribution_wire`].
    pub fn serialize_distribution_wire(dist: &SenderKeyDistribution) -> Vec<u8> {
        let mut signing = Vec::with_capacity(33);
        signing.push(0x05);
        signing.extend_from_slice(&dist.signing_key);
        let proto = SenderKeyDistributionProto {
            id: Some(dist.key_id),
            iteration: Some(dist.iteration),
            chain_key: Some(dist.chain_key.to_vec()),
            signing_key: Some(signing),
        };
        let mut wire = Vec::with_capacity(1 + 64);
        wire.push(super::signal::WHISPER_VERSION);
        ::prost::Message::encode(&proto, &mut wire).expect("Vec<u8> never errors");
        wire
    }

    /// Apply an incoming SKDM to bootstrap receiver state.
    pub fn install_distribution(
        skdm: &SenderKeyDistribution,
    ) -> SenderKeyReceiverState {
        SenderKeyReceiverState {
            key_id: skdm.key_id,
            chain_key: ChainKey::new(skdm.chain_key, skdm.iteration),
            signing_pub: skdm.signing_key,
            skipped: vec![],
        }
    }

    /// libsignal `SenderKeyDistributionMessage` protobuf (the `axolotl…` bytes
    /// inside waE2E's `SenderKeyDistributionMessage`). Wire = version byte
    /// (`0x33`) || this proto. `signing_key` is a DJB pubkey (`0x05` || 32).
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SenderKeyDistributionProto {
        #[prost(uint32, optional, tag = "1")]
        pub id: ::core::option::Option<u32>,
        #[prost(uint32, optional, tag = "2")]
        pub iteration: ::core::option::Option<u32>,
        #[prost(bytes = "vec", optional, tag = "3")]
        pub chain_key: ::core::option::Option<Vec<u8>>,
        #[prost(bytes = "vec", optional, tag = "4")]
        pub signing_key: ::core::option::Option<Vec<u8>>,
    }

    /// Parse the libsignal SKDM wire blob (the `axolotlSenderKeyDistributionMessage`
    /// bytes) into a [`SenderKeyDistribution`]. Strips the version byte and the
    /// `0x05` DJB prefix on the signing key; tolerates a bare 32-byte signing key.
    pub fn parse_distribution_wire(wire: &[u8]) -> Result<SenderKeyDistribution, SkMsgError> {
        if wire.is_empty() {
            return Err(SkMsgError::Malformed("empty SKDM wire"));
        }
        // First byte is the (version<<4 | version) byte; the proto follows.
        let proto = <SenderKeyDistributionProto as ::prost::Message>::decode(&wire[1..])
            .map_err(|_| SkMsgError::Malformed("SKDM proto"))?;
        let chain = proto.chain_key.ok_or(SkMsgError::Malformed("SKDM chainKey"))?;
        let chain_key: [u8; 32] = chain
            .as_slice()
            .try_into()
            .map_err(|_| SkMsgError::Malformed("SKDM chainKey length"))?;
        let sk = proto.signing_key.ok_or(SkMsgError::Malformed("SKDM signingKey"))?;
        let signing_key: [u8; 32] = match sk.len() {
            33 if sk[0] == 0x05 => sk[1..].try_into().unwrap(),
            32 => sk.as_slice().try_into().unwrap(),
            _ => return Err(SkMsgError::Malformed("SKDM signingKey length")),
        };
        Ok(SenderKeyDistribution {
            key_id: proto.id.unwrap_or(0),
            iteration: proto.iteration.unwrap_or(0),
            chain_key,
            signing_key,
        })
    }

    // -- Per-message wire (skmsg) encrypt + decrypt ------------------------

    /// libsignal SenderKeyMessage protobuf. Wire = version byte
    /// (`0x33` = WHISPER_VERSION) || proto || 64-byte XEdDSA signature
    /// over (version || proto). The signature is created with the
    /// sender's `signing_keypair_priv` and verified with `signing_pub`
    /// from the SKDM.
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct SenderKeyMessageProto {
        #[prost(uint32, optional, tag = "1")]
        pub key_id: ::core::option::Option<u32>,
        #[prost(uint32, optional, tag = "2")]
        pub iteration: ::core::option::Option<u32>,
        #[prost(bytes = "vec", optional, tag = "3")]
        pub ciphertext: ::core::option::Option<Vec<u8>>,
    }

    pub const SKMSG_SIGNATURE_LEN: usize = 64;

    #[derive(Debug, thiserror::Error)]
    pub enum SkMsgError {
        #[error("AES error")]
        Aes,
        #[error("malformed: {0}")]
        Malformed(&'static str),
        #[error("signature verify failed")]
        BadSignature,
    }

    /// Derive (iv16, cipher_key32) for a single sender-key message at the
    /// chain's current index. Mirrors libsignal: `seed = HMAC(chain, 0x01)`,
    /// then HKDF-expand with info "WhisperGroup" to 48 bytes.
    fn derive_sender_message_keys(chain: &super::signal::ChainKey) -> ([u8; 16], [u8; 32]) {
        use ::hkdf::Hkdf;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&chain.key).expect("HMAC any key");
        mac.update(&[0x01]);
        let seed: [u8; 32] = mac.finalize().into_bytes().into();
        let hk = Hkdf::<Sha256>::new(None, &seed);
        let mut out = [0u8; 48];
        hk.expand(b"WhisperGroup", &mut out).expect("48 < 255*32");
        let mut iv = [0u8; 16];
        let mut ck = [0u8; 32];
        iv.copy_from_slice(&out[..16]);
        ck.copy_from_slice(&out[16..]);
        (iv, ck)
    }

    /// Encrypt a padded plaintext for the group as a SenderKeyMessage.
    /// Advances the sender chain. Returns wire bytes: version || proto ||
    /// XEdDSA signature. Caller wraps in `<enc type="skmsg">`.
    pub fn encrypt_sender_key_message(
        state: &mut SenderKeyState,
        padded: &[u8],
    ) -> Result<Vec<u8>, SkMsgError> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
        type Enc = cbc::Encryptor<Aes256>;

        let (iv, cipher_key) = derive_sender_message_keys(&state.chain_key);
        let enc = Enc::new(&cipher_key.into(), &iv.into());
        let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(padded);

        let proto = SenderKeyMessageProto {
            key_id: Some(state.key_id),
            iteration: Some(state.chain_key.index),
            ciphertext: Some(ciphertext),
        };
        let mut wire = Vec::with_capacity(1 + 64 + SKMSG_SIGNATURE_LEN);
        wire.push(super::signal::WHISPER_VERSION);
        ::prost::Message::encode(&proto, &mut wire).expect("Vec<u8> never errors");
        let sig = super::identity::xeddsa_sign(&state.signing_keypair_priv, &wire);
        wire.extend_from_slice(&sig);

        // Advance the chain so the next encrypt uses fresh keys.
        state.chain_key = state.chain_key.next();
        Ok(wire)
    }

    /// Verify + decrypt one SenderKeyMessage wire blob. Walks the receiver
    /// chain forward to `iteration` (caching skipped keys would be a
    /// follow-up; today out-of-order sender-key delivery is rejected).
    pub fn decrypt_sender_key_message(
        state: &mut SenderKeyReceiverState,
        wire: &[u8],
    ) -> Result<Vec<u8>, SkMsgError> {
        use aes::Aes256;
        use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Dec = cbc::Decryptor<Aes256>;

        if wire.len() < 1 + SKMSG_SIGNATURE_LEN + 1 {
            return Err(SkMsgError::Malformed("wire too short"));
        }
        if wire[0] != super::signal::WHISPER_VERSION {
            return Err(SkMsgError::Malformed("unexpected version byte"));
        }
        let sig_offset = wire.len() - SKMSG_SIGNATURE_LEN;
        let signed_body = &wire[..sig_offset];
        let sig_bytes: [u8; 64] = wire[sig_offset..]
            .try_into()
            .map_err(|_| SkMsgError::Malformed("signature length"))?;

        // Verify signature first — cheaper than the proto decode + decrypt
        // round trip if a peer is forging messages.
        if !super::identity::xeddsa_verify(&state.signing_pub, signed_body, &sig_bytes) {
            return Err(SkMsgError::BadSignature);
        }

        let proto = <SenderKeyMessageProto as ::prost::Message>::decode(&signed_body[1..])
            .map_err(|_| SkMsgError::Malformed("proto"))?;
        let iteration = proto.iteration.unwrap_or(0);
        let ciphertext = proto
            .ciphertext
            .ok_or(SkMsgError::Malformed("missing ciphertext"))?;

        // Out-of-order (older) message: try the skipped-key cache.
        if iteration < state.chain_key.index {
            let pos = state
                .skipped
                .iter()
                .position(|s| s.iteration == iteration)
                .ok_or(SkMsgError::Malformed("iteration went backwards (no cached key)"))?;
            let sk = state.skipped[pos].clone();
            let dec = Dec::new(&sk.cipher_key.into(), &sk.iv.into());
            let plaintext = dec
                .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
                .map_err(|_| SkMsgError::Aes)?;
            // One-time use: a chain key never repeats an iteration.
            state.skipped.remove(pos);
            return Ok(plaintext);
        }
        // Walk the chain forward, caching the message keys for every iteration
        // we skip over (gaps from out-of-order delivery) so they can decrypt
        // later. Bounded so a forged huge `iteration` can't blow up memory.
        if iteration.saturating_sub(state.chain_key.index) as usize > MAX_SKIPPED_SENDER_KEYS {
            return Err(SkMsgError::Malformed("iteration jump too large"));
        }
        let mut walking = state.chain_key.clone();
        while walking.index < iteration {
            let (iv, cipher_key) = derive_sender_message_keys(&walking);
            state.skipped.push(SkippedSenderKey { iteration: walking.index, iv, cipher_key });
            walking = walking.next();
        }
        let (iv, cipher_key) = derive_sender_message_keys(&walking);

        let dec = Dec::new(&cipher_key.into(), &iv.into());
        let plaintext = dec
            .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
            .map_err(|_| SkMsgError::Aes)?;

        state.chain_key = walking.next();
        // Evict oldest cached keys beyond the cap.
        if state.skipped.len() > MAX_SKIPPED_SENDER_KEYS {
            let excess = state.skipped.len() - MAX_SKIPPED_SENDER_KEYS;
            state.skipped.drain(0..excess);
        }
        Ok(plaintext)
    }

    #[cfg(test)]
    mod skmsg_tests {
        use super::super::identity::KeyPair;
        use super::*;

        fn fresh_state() -> SenderKeyState {
            let kp = KeyPair::generate();
            SenderKeyState {
                key_id: 7,
                chain_key: ChainKey::new([0x42; 32], 0),
                signing_keypair_priv: kp.private,
                signing_keypair_pub: kp.public,
            }
        }

        /// Sender encrypts → SKDM bootstraps the receiver → receiver
        /// decrypts. The chain advances on both sides so the next encrypt
        /// at iteration=1 also decrypts.
        #[test]
        fn encrypt_decrypt_round_trip_advances_chain() {
            let mut sender = fresh_state();
            let dist = sender.distribution();
            let mut recv = install_distribution(&dist);

            let m0 = encrypt_sender_key_message(&mut sender, b"hello group").unwrap();
            let pt0 = decrypt_sender_key_message(&mut recv, &m0).unwrap();
            assert_eq!(pt0, b"hello group");
            assert_eq!(sender.chain_key.index, 1);
            assert_eq!(recv.chain_key.index, 1);

            let m1 = encrypt_sender_key_message(&mut sender, b"second").unwrap();
            let pt1 = decrypt_sender_key_message(&mut recv, &m1).unwrap();
            assert_eq!(pt1, b"second");
        }

        /// Regression for the XEdDSA sign-bit bug: a REAL captured WhatsApp
        /// sender-key signature whose public key A has sign bit 1 (the high bit
        /// of `s` is set). Before the fix, `xeddsa_verify` hardcoded sign 0 and
        /// rejected it (→ undecryptable group messages + the phone's sync loop).
        /// The signed body + signature are the exact bytes off the wire.
        #[test]
        fn xeddsa_verify_accepts_sign_bit_1_signature() {
            fn unhex(s: &str) -> Vec<u8> {
                (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
            }
            // skmsg wire (version||proto||sig) captured from a real group sender.
            let wire = unhex("3308dfcbcbd30710001a50aaa721c3a43d10fa999d6af4e6b1e8f32728262b332bd2caeb524e7612e2ce11db9e4629252708321632bbb3cd2102d85b3cd079ab4f38bcd055b62387525bf96f546f3b9f5fa58c9eb38f90f263c1a49c868c3bc78081a8e119be4b1217ae0e6c401d09a52478ffe561ca060a0247641e6861c1da199568a3e93b76986efc9e2bb46e9837cffb7c5815c5c8124cef8f");
            let u = unhex("810042efe959863d9c15bf772cd9e71b33d3ac87ef11dddfafed697d2ccd106e");
            let mut key = [0u8; 32];
            key.copy_from_slice(&u);
            let sig_off = wire.len() - 64;
            let signed_body = &wire[..sig_off];
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&wire[sig_off..]);
            assert_eq!(sig[63] >> 7, 1, "fixture must have sign bit 1 to guard the bug");
            assert!(
                super::super::identity::xeddsa_verify(&key, signed_body, &sig),
                "real sign-bit-1 WhatsApp signature must verify"
            );
        }

        /// A freshly generated sending state round-trips through SKDM wire
        /// serialization: serialize → parse → install must decrypt the sender's
        /// skmsg. This is the on-the-wire SKDM format real group peers parse, so
        /// it must match `parse_distribution_wire` exactly.
        #[test]
        fn serialize_distribution_wire_round_trips() {
            let mut sender = SenderKeyState::generate();
            let dist = sender.distribution();
            let wire = serialize_distribution_wire(&dist);
            assert_eq!(wire[0], super::super::signal::WHISPER_VERSION);
            let parsed = parse_distribution_wire(&wire).expect("parse our own SKDM wire");
            assert_eq!(parsed, dist);

            // And the receiver bootstrapped from the parsed wire decrypts.
            let mut recv = install_distribution(&parsed);
            let m = encrypt_sender_key_message(&mut sender, b"hi group").unwrap();
            assert_eq!(decrypt_sender_key_message(&mut recv, &m).unwrap(), b"hi group");
        }

        /// Out-of-order group delivery: receiving iteration 2 first caches the
        /// keys for 0 and 1, so the later-arriving 0 and 1 still decrypt
        /// ("iteration went backwards" no longer fails).
        #[test]
        fn out_of_order_skmsg_decrypts_via_skipped_cache() {
            let mut sender = fresh_state();
            let dist = sender.distribution();
            let mut recv = install_distribution(&dist);

            let m0 = encrypt_sender_key_message(&mut sender, b"zero").unwrap();
            let m1 = encrypt_sender_key_message(&mut sender, b"one").unwrap();
            let m2 = encrypt_sender_key_message(&mut sender, b"two").unwrap();

            // Receive 2 first → chain jumps to 3, keys for 0+1 cached.
            assert_eq!(decrypt_sender_key_message(&mut recv, &m2).unwrap(), b"two");
            assert_eq!(recv.chain_key.index, 3);
            assert_eq!(recv.skipped.len(), 2);
            // Now the older messages still decrypt from the cache…
            assert_eq!(decrypt_sender_key_message(&mut recv, &m0).unwrap(), b"zero");
            assert_eq!(decrypt_sender_key_message(&mut recv, &m1).unwrap(), b"one");
            assert!(recv.skipped.is_empty());
            // …and replaying a consumed iteration now fails (one-time use).
            assert!(decrypt_sender_key_message(&mut recv, &m0).is_err());
        }

        /// A signature flipped after encrypt MUST fail verify before any
        /// proto / ciphertext path runs.
        #[test]
        fn tampered_signature_rejects_before_decrypt() {
            let mut sender = fresh_state();
            let dist = sender.distribution();
            let mut recv = install_distribution(&dist);
            let mut wire = encrypt_sender_key_message(&mut sender, b"x").unwrap();
            let n = wire.len();
            wire[n - 5] ^= 0x01;
            assert!(matches!(
                decrypt_sender_key_message(&mut recv, &wire),
                Err(SkMsgError::BadSignature)
            ));
        }

        /// The libsignal SKDM wire (version byte || proto, signingKey DJB-
        /// prefixed) parses back to the sender's distribution and the parsed
        /// distribution decrypts the sender's messages end-to-end.
        #[test]
        fn skdm_wire_parses_and_decrypts() {
            let mut sender = fresh_state();
            let dist = sender.distribution();
            let proto = SenderKeyDistributionProto {
                id: Some(dist.key_id),
                iteration: Some(dist.iteration),
                chain_key: Some(dist.chain_key.to_vec()),
                signing_key: Some({
                    let mut v = vec![0x05u8];
                    v.extend_from_slice(&dist.signing_key);
                    v
                }),
            };
            let mut wire = vec![super::super::signal::WHISPER_VERSION];
            ::prost::Message::encode(&proto, &mut wire).unwrap();

            let parsed = parse_distribution_wire(&wire).unwrap();
            assert_eq!(parsed, dist);

            let mut recv = install_distribution(&parsed);
            let m = encrypt_sender_key_message(&mut sender, b"group hi").unwrap();
            assert_eq!(decrypt_sender_key_message(&mut recv, &m).unwrap(), b"group hi");
        }

        /// A bare 32-byte signing key (no 0x05 prefix) is also accepted.
        #[test]
        fn skdm_wire_tolerates_bare_signing_key() {
            let sender = fresh_state();
            let dist = sender.distribution();
            let proto = SenderKeyDistributionProto {
                id: Some(dist.key_id),
                iteration: Some(dist.iteration),
                chain_key: Some(dist.chain_key.to_vec()),
                signing_key: Some(dist.signing_key.to_vec()),
            };
            let mut wire = vec![super::super::signal::WHISPER_VERSION];
            ::prost::Message::encode(&proto, &mut wire).unwrap();
            assert_eq!(parse_distribution_wire(&wire).unwrap(), dist);
        }

        /// A signing pub from a different state must reject — the SKDM is
        /// the only authentic binding between a sender and a chain.
        #[test]
        fn wrong_signing_pub_rejects() {
            let mut sender = fresh_state();
            let dist = sender.distribution();
            let mut recv = install_distribution(&dist);
            // Replace recv's signing_pub with someone else's pub.
            let attacker = KeyPair::generate();
            recv.signing_pub = attacker.public;
            let wire = encrypt_sender_key_message(&mut sender, b"x").unwrap();
            assert!(matches!(
                decrypt_sender_key_message(&mut recv, &wire),
                Err(SkMsgError::BadSignature)
            ));
        }
    }
}

pub mod hkdf {
    #![allow(dead_code)] // expand() is used by upcoming milestones (M2/M5).

    use ::hkdf::Hkdf;
    use sha2::Sha256;

    /// WA's standard HKDF-expand pattern: `expand(secret, info, len)` with no salt.
    /// Equivalent to HKDF-SHA256 with salt = HashLen zeros (RFC 5869).
    pub fn expand(secret: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        expand_with_salt(None, secret, info, len)
    }

    /// HKDF-SHA256 with explicit salt. `salt = None` is treated as HashLen zeros.
    pub fn expand_with_salt(
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        len: usize,
    ) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(salt, ikm);
        let mut out = vec![0u8; len];
        hk.expand(info, &mut out).expect("hkdf output length out of range");
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// RFC 5869 Test Case 1 (HKDF-SHA256 basic).
        ///   IKM  = 0x0b * 22
        ///   salt = 0x000102030405060708090a0b0c
        ///   info = 0xf0f1f2f3f4f5f6f7f8f9
        ///   L    = 42
        ///   OKM  = 3cb25f25faacd57a90434f64d0362f2a
        ///          2d2d0a90cf1a5a4c5db02d56ecc4c5bf
        ///          34007208d5b887185865
        #[test]
        fn rfc5869_test_case_1() {
            let ikm = [0x0bu8; 22];
            let salt = hex::decode("000102030405060708090a0b0c").unwrap();
            let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
            let expected = hex::decode(
                "3cb25f25faacd57a90434f64d0362f2a\
                 2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            )
            .unwrap();
            let okm = expand_with_salt(Some(&salt), &ikm, &info, 42);
            assert_eq!(okm, expected);
        }
    }
}

pub mod msg_secret {
    //! Message-secret modifications (edits / poll-edits / event-edits).
    //!
    //! Modern WhatsApp delivers a message EDIT as a `SecretEncryptedMessage`
    //! whose `encPayload` is AES-256-GCM-sealed under a key HKDF-derived from the
    //! ORIGINAL message's 32-byte `messageContextInfo.messageSecret`. This mirrors
    //! whatsmeow `generateMsgSecretKey` + `decryptMsgSecret` (msgsecret.go).

    use super::hkdf;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    /// Use-case strings, byte-identical to whatsmeow's `MsgSecretType`. They are
    /// appended to the HKDF `info`, so any drift silently breaks decryption.
    pub const USE_CASE_MESSAGE_EDIT: &str = "Message Edit";
    pub const USE_CASE_POLL_EDIT: &str = "Poll Edit";
    pub const USE_CASE_EVENT_EDIT: &str = "Event Edit";

    /// Derive the 32-byte AES key: `HKDF-SHA256(ikm = orig_secret, salt = nil,
    /// info = orig_msg_id ++ orig_sender ++ mod_sender ++ use_case)`. The two
    /// JIDs must be the `ToNonAD().String()` forms (device/agent stripped) the
    /// sender used, or GCM authentication fails.
    pub fn derive_key(
        orig_secret: &[u8],
        orig_msg_id: &str,
        orig_sender: &str,
        mod_sender: &str,
        use_case: &str,
    ) -> [u8; 32] {
        let mut info = Vec::with_capacity(
            orig_msg_id.len() + orig_sender.len() + mod_sender.len() + use_case.len(),
        );
        info.extend_from_slice(orig_msg_id.as_bytes());
        info.extend_from_slice(orig_sender.as_bytes());
        info.extend_from_slice(mod_sender.as_bytes());
        info.extend_from_slice(use_case.as_bytes());
        let okm = hkdf::expand(orig_secret, &info, 32);
        let mut k = [0u8; 32];
        k.copy_from_slice(&okm);
        k
    }

    /// AES-256-GCM decrypt with empty AAD (the case for every *edit* use-case;
    /// poll-votes/reactions add AAD but aren't handled here). `iv` must be 12
    /// bytes and `ct_with_tag` is ciphertext with the 16-byte tag appended.
    /// Returns `None` on a wrong key / tampered input (GCM auth failure) so the
    /// caller can try the next sender candidate.
    pub fn decrypt(key: &[u8; 32], iv: &[u8], ct_with_tag: &[u8]) -> Option<Vec<u8>> {
        if iv.len() != 12 {
            return None;
        }
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        cipher.decrypt(Nonce::from_slice(iv), ct_with_tag).ok()
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        /// The derived key round-trips through AES-256-GCM, and a different
        /// use-case (or sender) yields a key that fails authentication — the
        /// exact property the edit-decrypt path relies on.
        #[test]
        fn derive_key_round_trips_and_is_use_case_bound() {
            let secret = [0x42u8; 32];
            let (mid, orig, mods) = ("ORIG123", "555@s.whatsapp.net", "555@s.whatsapp.net");
            let key = derive_key(&secret, mid, orig, mods, USE_CASE_MESSAGE_EDIT);

            let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
            let iv = [7u8; 12];
            let pt = b"edited text payload";
            let ct = cipher.encrypt(Nonce::from_slice(&iv), &pt[..]).unwrap();

            assert_eq!(decrypt(&key, &iv, &ct).as_deref(), Some(&pt[..]));

            // Wrong use-case → wrong key → auth failure (None), not garbage.
            let wrong = derive_key(&secret, mid, orig, mods, USE_CASE_POLL_EDIT);
            assert!(decrypt(&wrong, &iv, &ct).is_none());
            // Non-12-byte IV is rejected outright.
            assert!(decrypt(&key, &[7u8; 16], &ct).is_none());
        }
    }
}

pub mod linking {
    //! Phone-number ("Link with phone number") pairing crypto.
    //!
    //! WhatsApp's alternative to QR pairing: instead of the primary phone
    //! scanning a QR, the companion generates an 8-char code the user types
    //! into their phone. The code keys a PBKDF2/AES-CTR wrap of each side's
    //! ephemeral Curve25519 public key; an ECDH over those plus the identity
    //! keys derives the same `adv_secret` that the regular `<pair-success>`
    //! flow consumes — so once the dance finishes, pairing completes exactly
    //! as it does for QR.
    //!
    //! whatsmeow reference: pair-code.go (`generateCompanionEphemeralKey`,
    //! `PairPhone`, `handleCodePairNotification`).

    use super::hkdf;
    use super::identity::KeyPair;
    use aes::Aes256;
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use ctr::cipher::{KeyIvInit, StreamCipher};
    use hmac::{Hmac, Mac};
    use rand::rngs::OsRng;
    use rand::RngCore;
    use sha2::Sha256;

    /// WhatsApp's custom base32 alphabet for linking codes (Crockford-ish:
    /// digits `1-9` then `A-Z` minus the ambiguous `I`/`O`/`0`/`U`).
    const LINKING_ALPHABET: &[u8; 32] = b"123456789ABCDEFGHJKLMNPQRSTVWXYZ";

    /// PBKDF2 iteration count whatsmeow uses for the linking-code KDF (`2 << 16`).
    const LINK_PBKDF2_ITERS: u32 = 2 << 16;

    /// AES-256 in CTR mode with a 128-bit big-endian counter — matches Go's
    /// `cipher.NewCTR`, which seeds the counter with the full IV and increments
    /// the whole 128-bit block big-endian.
    type Aes256Ctr = ctr::Ctr128BE<Aes256>;

    /// Result of [`generate_companion_ephemeral_key`]: our ephemeral keypair,
    /// the 80-byte wrapped ephemeral public to send to the server, and the
    /// human-facing linking code (still un-hyphenated, 8 chars).
    pub struct CompanionEphemeral {
        pub keypair: KeyPair,
        /// `salt(32) || iv(16) || aes-ctr(ephemeral_pub)(32)`.
        pub ephemeral_key: [u8; 80],
        /// 8-char base32 code; the user types it as `XXXX-XXXX`.
        pub linking_code: String,
    }

    /// Output of the companion side of the code-pair notification: the wrapped
    /// key bundle to send back, and the derived adv secret to persist (it
    /// authenticates the subsequent `<pair-success>`).
    pub struct CodePairResult {
        /// `keyBundleSalt(32) || keyBundleNonce(12) || aes-gcm(key bundle)`.
        pub wrapped_key_bundle: Vec<u8>,
        pub adv_secret: [u8; 32],
    }

    /// Encode bytes with WhatsApp's linking base32 alphabet, MSB-first, no
    /// padding. A 5-byte input yields exactly 8 chars (the linking-code case).
    pub fn base32_encode(data: &[u8]) -> String {
        let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
        let mut acc: u64 = 0;
        let mut bits: u32 = 0;
        for &b in data {
            acc = (acc << 8) | b as u64;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                let idx = ((acc >> bits) & 0x1f) as usize;
                out.push(LINKING_ALPHABET[idx] as char);
                acc &= (1u64 << bits) - 1;
            }
        }
        if bits > 0 {
            let idx = ((acc << (5 - bits)) & 0x1f) as usize;
            out.push(LINKING_ALPHABET[idx] as char);
        }
        out
    }

    /// PBKDF2-HMAC-SHA256 (RFC 2898). Hand-rolled on the `hmac` crate ruwa
    /// already depends on, to avoid pulling in the `pbkdf2` crate.
    pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iters: u32, dk_len: usize) -> Vec<u8> {
        type HmacSha256 = Hmac<Sha256>;
        let mut out = Vec::with_capacity(dk_len);
        let n_blocks = dk_len.div_ceil(32) as u32;
        for block in 1..=n_blocks {
            // U_1 = PRF(password, salt || INT_BE32(block))
            let mut mac =
                <HmacSha256 as Mac>::new_from_slice(password).expect("hmac key any length");
            mac.update(salt);
            mac.update(&block.to_be_bytes());
            let mut u = mac.finalize().into_bytes();
            let mut t = u;
            for _ in 1..iters {
                let mut mac =
                <HmacSha256 as Mac>::new_from_slice(password).expect("hmac key any length");
                mac.update(&u);
                u = mac.finalize().into_bytes();
                for (ti, ui) in t.iter_mut().zip(u.iter()) {
                    *ti ^= *ui;
                }
            }
            out.extend_from_slice(&t);
        }
        out.truncate(dk_len);
        out
    }

    /// Derive the AES-CTR key for a wrapped ephemeral pubkey from the linking
    /// code and the wrap's salt.
    fn link_code_key(linking_code: &str, salt: &[u8]) -> [u8; 32] {
        let dk = pbkdf2_sha256(linking_code.as_bytes(), salt, LINK_PBKDF2_ITERS, 32);
        let mut k = [0u8; 32];
        k.copy_from_slice(&dk);
        k
    }

    /// Wrap a 32-byte ephemeral public key under `linking_code` with a fresh
    /// random salt+iv: returns `salt(32) || iv(16) || ciphertext(32)`.
    fn wrap_ephemeral_pub(linking_code: &str, pubkey: &[u8; 32]) -> [u8; 80] {
        let mut salt = [0u8; 32];
        let mut iv = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut iv);
        let key = link_code_key(linking_code, &salt);
        let mut buf = *pubkey;
        Aes256Ctr::new((&key).into(), (&iv).into()).apply_keystream(&mut buf);
        let mut out = [0u8; 80];
        out[0..32].copy_from_slice(&salt);
        out[32..48].copy_from_slice(&iv);
        out[48..80].copy_from_slice(&buf);
        out
    }

    /// Unwrap an 80-byte wrapped ephemeral public key using `linking_code`.
    fn unwrap_ephemeral_pub(linking_code: &str, wrapped: &[u8]) -> Result<[u8; 32], &'static str> {
        if wrapped.len() < 80 {
            return Err("wrapped ephemeral pub too short");
        }
        let salt = &wrapped[0..32];
        let iv = &wrapped[32..48];
        let key = link_code_key(linking_code, salt);
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&wrapped[48..80]);
        let iv_arr: [u8; 16] = iv.try_into().expect("iv slice is 16 bytes");
        Aes256Ctr::new((&key).into(), (&iv_arr).into()).apply_keystream(&mut buf);
        Ok(buf)
    }

    /// Companion side, step 1: generate the ephemeral keypair + linking code and
    /// the 80-byte wrapped ephemeral pub to put in the `companion_hello` IQ.
    pub fn generate_companion_ephemeral_key() -> CompanionEphemeral {
        let keypair = KeyPair::generate();
        let mut code_bytes = [0u8; 5];
        OsRng.fill_bytes(&mut code_bytes);
        let linking_code = base32_encode(&code_bytes);
        let ephemeral_key = wrap_ephemeral_pub(&linking_code, &keypair.public);
        CompanionEphemeral {
            keypair,
            ephemeral_key,
            linking_code,
        }
    }

    /// Companion side, step 2: handle the code-pair notification. Decrypts the
    /// primary's wrapped ephemeral pub, derives the shared secrets, builds the
    /// encrypted key bundle for the `companion_finish` IQ, and returns the
    /// `adv_secret` to persist. Mirrors `handleCodePairNotification`.
    pub fn complete_code_pair(
        linking_code: &str,
        our_eph_priv: &[u8; 32],
        our_identity: &KeyPair,
        wrapped_primary_eph_pub: &[u8],
        primary_identity_pub: &[u8],
    ) -> Result<CodePairResult, &'static str> {
        if primary_identity_pub.len() != 32 {
            return Err("primary identity pub must be 32 bytes");
        }
        let primary_eph_pub = unwrap_ephemeral_pub(linking_code, wrapped_primary_eph_pub)?;

        let mut adv_secret_random = [0u8; 32];
        let mut key_bundle_salt = [0u8; 32];
        let mut key_bundle_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut adv_secret_random);
        OsRng.fill_bytes(&mut key_bundle_salt);
        OsRng.fill_bytes(&mut key_bundle_nonce);

        let ephemeral_shared = x25519_dalek::x25519(*our_eph_priv, primary_eph_pub);

        // Encrypt the key bundle: our identity pub || primary identity pub || adv randomness.
        let bundle_key = hkdf::expand_with_salt(
            Some(&key_bundle_salt),
            &ephemeral_shared,
            b"link_code_pairing_key_bundle_encryption_key",
            32,
        );
        let mut plaintext = Vec::with_capacity(96);
        plaintext.extend_from_slice(&our_identity.public);
        plaintext.extend_from_slice(primary_identity_pub);
        plaintext.extend_from_slice(&adv_secret_random);
        let cipher = Aes256Gcm::new_from_slice(&bundle_key).expect("32-byte key");
        let ct = cipher
            .encrypt(Nonce::from_slice(&key_bundle_nonce), plaintext.as_ref())
            .map_err(|_| "key bundle encrypt failed")?;
        let mut wrapped_key_bundle = Vec::with_capacity(32 + 12 + ct.len());
        wrapped_key_bundle.extend_from_slice(&key_bundle_salt);
        wrapped_key_bundle.extend_from_slice(&key_bundle_nonce);
        wrapped_key_bundle.extend_from_slice(&ct);

        // adv_secret = HKDF(ephemeral_shared || identity_shared || adv_random, "adv_secret").
        let mut primary_id = [0u8; 32];
        primary_id.copy_from_slice(primary_identity_pub);
        let identity_shared = x25519_dalek::x25519(our_identity.private, primary_id);
        let mut adv_input = Vec::with_capacity(96);
        adv_input.extend_from_slice(&ephemeral_shared);
        adv_input.extend_from_slice(&identity_shared);
        adv_input.extend_from_slice(&adv_secret_random);
        let adv = hkdf::expand_with_salt(None, &adv_input, b"adv_secret", 32);
        let mut adv_secret = [0u8; 32];
        adv_secret.copy_from_slice(&adv);

        Ok(CodePairResult {
            wrapped_key_bundle,
            adv_secret,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn base32_known_vector() {
            // All-zero 5 bytes -> 8x the first alphabet char ('1').
            assert_eq!(base32_encode(&[0u8; 5]), "11111111");
            // 0xFF * 5 = 40 one-bits -> 8x the last char ('Z').
            assert_eq!(base32_encode(&[0xFFu8; 5]), "ZZZZZZZZ");
            // A 5-byte input always yields exactly 8 chars.
            assert_eq!(base32_encode(&[0x12, 0x34, 0x56, 0x78, 0x9a]).len(), 8);
        }

        #[test]
        fn pbkdf2_rfc_vector() {
            // Well-known PBKDF2-HMAC-SHA256 vector: P="password", S="salt",
            // c=1, dkLen=32.
            let dk = pbkdf2_sha256(b"password", b"salt", 1, 32);
            assert_eq!(
                hex::encode(dk),
                "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
            );
            // c=2.
            let dk2 = pbkdf2_sha256(b"password", b"salt", 2, 32);
            assert_eq!(
                hex::encode(dk2),
                "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
            );
        }

        #[test]
        fn ephemeral_wrap_roundtrips() {
            let kp = KeyPair::generate();
            let wrapped = wrap_ephemeral_pub("ABCD1234", &kp.public);
            let got = unwrap_ephemeral_pub("ABCD1234", &wrapped).unwrap();
            assert_eq!(got, kp.public);
            // Wrong code yields different (garbage) plaintext.
            let bad = unwrap_ephemeral_pub("ZZZZ9999", &wrapped).unwrap();
            assert_ne!(bad, kp.public);
        }

        #[test]
        fn companion_key_shapes() {
            let c = generate_companion_ephemeral_key();
            assert_eq!(c.linking_code.len(), 8);
            assert!(c.linking_code.bytes().all(|b| LINKING_ALPHABET.contains(&b)));
            // The wrapped pub round-trips back to the keypair's public.
            let unwrapped = unwrap_ephemeral_pub(&c.linking_code, &c.ephemeral_key).unwrap();
            assert_eq!(unwrapped, c.keypair.public);
        }

        // Full two-sided round trip: simulate the primary device and confirm
        // both sides derive the SAME ephemeral shared secret, which is what the
        // adv_secret (and thus pair-success) ultimately depends on.
        #[test]
        fn code_pair_derives_matching_ephemeral_secret() {
            // Companion generates its ephemeral + code.
            let companion = generate_companion_ephemeral_key();
            let code = companion.linking_code.clone();

            // Primary makes its own ephemeral keypair and identity key, and
            // wraps its ephemeral pub under the same code (as the phone would).
            let primary_eph = KeyPair::generate();
            let primary_identity = KeyPair::generate();
            let wrapped_primary = wrap_ephemeral_pub(&code, &primary_eph.public);

            let our_identity = KeyPair::generate();
            let result = complete_code_pair(
                &code,
                &companion.keypair.private,
                &our_identity,
                &wrapped_primary,
                &primary_identity.public,
            )
            .unwrap();

            // Companion's view of the ephemeral shared secret:
            let companion_shared =
                x25519_dalek::x25519(companion.keypair.private, primary_eph.public);
            // Primary's view (it would unwrap the companion's pub from the
            // companion_hello IQ; here we use it directly):
            let primary_shared =
                x25519_dalek::x25519(primary_eph.private, companion.keypair.public);
            assert_eq!(companion_shared, primary_shared);

            // Sanity: the wrapped key bundle is salt(32)+nonce(12)+GCM(96+16).
            assert_eq!(result.wrapped_key_bundle.len(), 32 + 12 + 96 + 16);
            assert_eq!(result.adv_secret.len(), 32);
        }
    }
}
