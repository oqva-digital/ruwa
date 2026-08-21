# Calls — port plan & findings (F2)

Distilled from a three-way study of the MIT references `oxidezap/whatsapp-rust`
(`wacore/src/voip` + `src/voip`, primary) and `purpshell/meowcaller`. This is
the implementation source of truth for `src/call.rs`. Wire/crypto constants
carry `file:line` back to whatsapp-rust in the full reports (kept out-of-repo).

## The shape of an answered 1:1 audio call

No ICE, no `<transport>`/`<relaylatency>` negotiation. The media plane connects
directly to ONE relay endpoint parsed from the offer:

```
offer(<enc> callKey, <relay> endpoints+key+token)
  → <receipt><offer/>            (ring ack)
  → <preaccept>                  (stop sibling ringing; sent BEFORE decrypt)
  → decrypt callKey from <enc>   (normal Signal 1:1 decrypt vs call-creator)
  → <accept>                     (id attr REQUIRED or silently dropped)
  → open media channel to relay  (UDP→DTLS→SCTP→pre-negotiated DataChannel id=0)
  → STUN Allocate over channel   (relay token + <key> ASCII as MI)
  → allocate-success ⇒ media flows (RTP/RTCP as binary DataChannel messages)
```

## What's pure (no new deps) vs what pulls foreign crates

**Pure RustCrypto — reuses what ruwa already has** (`aes`, `ctr`, `aes-gcm`,
`hmac`, `sha1`, `sha2`/`hkdf`, `subtle`, `base64`). ~1400–1700 LOC:
- Call stanza parse (offer/accept/terminate/reject) + relay `<relay>` parse.
- callKey decrypt: offer `<enc v=2 type=pkmsg|msg>` → Signal decrypt vs
  `call-creator` → unpad → protobuf `Message.call(10).callKey(1)` = 32 bytes.
  **The proto is already vendored** (`waE2E` lines 1603/2118); reuses ruwa Signal.
- E2E-SRTP keys: `HKDF-SHA256(salt=[0;32], ikm=callKey, info=participant_LID, 46B)`
  → master_key[0..16] + master_salt[16..30] → AES-CM PRF (libsrtp KDF, labels
  0/1/2 for SRTP, 3/4/5 for SRTCP). `info` = self LID for send keys, peer LID
  for recv keys. SSRC = `LE32(HKDF(salt=slot_LE32, ikm=call_id, info=LID, 4))`.
- RTP header encode/parse (PT 120, 16B speech / 20B DTX), WARP MI tag
  (HMAC-SHA1, first 4 bytes over `pkt||roc_be32` — keyed by the SRTP auth_key,
  not a separate key), RTCP SR/SDES, demux, SFrame recv (AES-128-GCM, 16B nonce).

**Foreign-dependency pulls (the two real decisions):**

1. **Transport** (~400 LOC + crates). The WA relay speaks the WebRTC
   data-channel protocol; raw UDP+SRTP will NOT connect. Needs
   `webrtc-dtls` + `webrtc-sctp` + `webrtc-data` + `webrtc-util` + `rustls`/`ring`.
   All **pure-Rust** (ring has asm, no cmake) — but a heavy foreign pull that
   conflicts with ruwa's minimal-deps ethos. DTLS is used only as an opaque
   tunnel (cert verification skipped); SRTP keys come from the callKey.

2. **Codec.** Default 1:1 codec is **MLow** (Meta's Opus-fork CELP, 16 kHz /
   60 ms). Options: (a) port wacore's ~19k-LOC pure-Rust MLow (no FFI, matches
   the no-C rule, huge, needs the shipped KAT vectors to validate — lift
   wholesale, never rewrite); (b) `opus` FFI crate (tiny adapter but pulls
   libopus/C + cmake, and native Opus only works if the peer negotiates it —
   MLow is the default, so libopus alone does NOT give a working default call);
   (c) **encoded-I/O passthrough** — ruwa ships/receives raw MLow/Opus payloads
   and never decodes; the engine's `AudioIo::Encoded` path supports exactly this.
   (c) defers the codec decision but means the audio bridge carries encoded
   frames, not PCM — so the external agent must decode, which most voice-agent
   stacks can't do for MLow. The PCM-bridge contract in SPEC.md assumes (a).

## Port order (each fatia compiles + tests green)

1. **Signaling + crypto core** (pure, no new deps): stanza parse/build, relay
   parse, callKey decrypt, E2E-SRTP + SRTCP key derivation, SSRC, WARP tag,
   RTP/RTCP framing, state machine + registry. Unit-tested against reference
   shapes. This is invariant under every transport/codec choice below.
2. **Transport**: UDP→DTLS→SCTP→DataChannel + STUN Allocate + keepalive
   (1 s allocate re-send + WA-ping 0x0801; relay drops after ~4 s silence).
3. **Media loop**: sans-IO engine (allocate/keepalive/RTCP timers, jitter
   buffer, 20 ms playout) + driver task. One tokio task per call; separate
   read-pump task; codec inline (MLow 60 ms decode ≪ 20 ms budget).
4. **Audio bridge**: the WS endpoint (SPEC.md contract) + codec.

Timing constants (reproduce exactly): keepalive 1000 ms, RTCP 1500 ms, playout
20 ms, allocate timeout 10 s, frame 960 samples @16 kHz/60 ms, playout target
1920 / cap 2400 / drain 320, seq starts at 1, SRTCP index starts at 1,
WARP tag 4 bytes. Prefer the relay endpoint on **port 3480** (3478 completes
the handshake but carries one-way audio only — silent-call trap).

## Decisions (locked 2026-08-20)

- **Architecture: in-process.** ruwa owns signaling + transport + codec in its
  own binary; the consumer just talks to ruwa's API (Twilio-style). This pulls
  the webrtc-rs stack (`webrtc-dtls`/`-sctp`/`-data`/`-util` + `rustls`/`ring`)
  into the build — accepted cost, since it IS WhatsApp protocol logic and must
  live in ruwa.
- **Codec: libopus FFI + force standard Opus.** Answer with the standard-Opus
  fallback (clear capability bit 31, `voip_settings use_mlow_codec_v1=false`,
  PT 120, 16 kHz, 60 ms, ~24 kbps DTX) and run libopus (`opus` crate, ~150-LOC
  adapter). This adds a C/cmake dependency — a deliberate exception, scoped to
  the call feature. Risk: a peer that ignores the callee's Opus choice ⇒ end
  the call `codec_mismatch` (never emit garbage). If field data shows too many
  mismatches, v2 lifts wacore's pure-Rust MLow wholesale. The PCM audio-bridge
  contract in SPEC.md holds under this choice (libopus decodes → PCM).

Fatia 1 (signaling + crypto core) is invariant under both decisions and is
built first.
