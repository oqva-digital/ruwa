# ruwa — SPEC

API-first multi-tenant WhatsApp Web client in Rust. A from-scratch port of
[whatsmeow](https://github.com/tulir/whatsmeow) — no Baileys, no whatsmeow
runtime, no FFI bridges. Standalone Rust, exposes everything over HTTP.

This document is the **design contract** — the milestones, acceptance
criteria, and non-negotiables the implementation is held to.

## Non-negotiables

- **No external WA libraries.** No Baileys, no whatsmeow, no FFI shims. Crypto
  primitives from RustCrypto / dalek / snow are fine; protocol logic must be
  ours.
- **Multi-tenant by design.** One process hosts many WA sessions. Every
  per-tenant write carries `session_id`.
- **Pragmatic file count, ≤10 source files in `src/`.** Today: `main.rs`,
  `api.rs`, `protocol.rs`, `crypto.rs`, `store.rs`, `media.rs`, `session.rs`,
  `error.rs`. Add files only when a module crosses ~1500 lines and the split
  is along a real seam (e.g. `protocol/binary.rs`, `protocol/noise.rs`).
- **API-first.** No CLI. Every behavior is reachable via HTTP. Bearer-token
  auth via `RUWA_API_TOKEN`.
- **SQLite single-file persistence.** Schema in `migrations/`, applied on boot.
- **Every commit must compile.** `cargo check` clean. Tests added for non-
  trivial logic; `cargo test` must stay green.

## File map

```
ruwa/
├── Cargo.toml               # locked dep versions
├── build.rs                 # prost compilation of proto/
├── SPEC.md                  # this file (design contract)
├── CLAUDE.md                # per-iteration briefing rules
├── README.md
├── migrations/
│   └── 0001_initial.sql     # full schema
├── proto/                   # vendored .proto files
└── src/
    ├── main.rs              # entry, env, axum bootstrap
    ├── api.rs               # HTTP routes, bearer auth
    ├── session.rs           # SessionManager + multi-tenant state
    ├── store.rs             # SQLite connection + migrations
    ├── error.rs             # error types + IntoResponse
    ├── protocol.rs          # binary nodes, Noise XX, frame socket, connection
    ├── crypto.rs            # identity, prekeys, Signal, sender keys, HKDF
    └── media.rs             # encrypted upload/download
```

## API surface (target)

```
GET  /health
GET  /v1/sessions
POST /v1/sessions                     {"label": "..."}
GET  /v1/sessions/:id
DELETE /v1/sessions/:id

POST /v1/sessions/:id/connect         (initiates pairing if unpaired, else reconnects)
POST /v1/sessions/:id/reconnect       (force a real socket bounce + re-login without re-pairing)
POST /v1/sessions/:id/resync-appstate (force a full app-state snapshot; repopulates NCT salt / tokens)
GET  /v1/sessions/:id/qr              -> {"code":"...", "image_png_base64":"..."}
POST /v1/sessions/:id/pair-phone      {"phone":"15551234567"} -> {"code":"ABCD-1234"}  (Link with phone number; alternative to QR)
POST /v1/sessions/:id/logout

POST /v1/sessions/:id/messages        {"to":"5511...","text":"hi", "reply_to": "..."}
POST /v1/sessions/:id/messages/media  multipart: file + JSON metadata
GET  /v1/sessions/:id/events          SSE stream (qr, paired, message, ...)
GET  /v1/sessions/:id/messages?chat=...&q=...&limit=...
GET  /v1/sessions/:id/contacts
GET  /v1/sessions/:id/chats
GET  /v1/sessions/:id/groups
POST /v1/sessions/:id/groups/:jid/participants  add|remove|promote|demote
POST /v1/sessions/:id/presence        {"to":"...","state":"typing|paused"}
POST /v1/sessions/:id/history/backfill {"chat":"...","count":50,"requests":10}
```

All `/v1/*` require `Authorization: Bearer $RUWA_API_TOKEN`.

## Required protobuf packages

To be vendored under `proto/` (from `github.com/tulir/whatsmeow/proto`):

| Milestone | Packages |
|---|---|
| M1 | waCommon, waAdv, waCompanionReg |
| M3 | waE2E |
| M5 | waMediaTransport (subset) |
| M6 | (groups reuse waE2E) |
| M7 | waSyncAction, waServerSync, waHistorySync |
| M8 | waMsgRetry, waMmsRetry |

Vendor `.proto` files on demand by raw URL:
`https://raw.githubusercontent.com/tulir/whatsmeow/main/proto/<pkg>/<file>.proto`

Strip `option go_package = ...;` lines so prost is happy.

## Milestones

Each milestone has a goal, acceptance items, and source pointers (whatsmeow
file paths to read while implementing).

### M1 — Foundations

**Goal:** project compiles with proto codegen working, axum boots, sqlite
opens with full schema, identity keys generate.

- [ ] Vendor minimum protos: `waCommon`, `waAdv`, `waCompanionReg`, `waE2E`.
- [ ] `build.rs` compiles them into `OUT_DIR`; `mod proto` re-enabled in `main.rs`.
- [ ] Health endpoint `/health` returns `{"status":"ok"}`.
- [ ] `POST /v1/sessions` creates a session row, `GET /v1/sessions` lists it.
- [ ] On session creation: generate Curve25519 noise key, identity key, signed
      prekey, ADV secret, registration_id; persist to `sessions` row.
- [ ] Generate 30 one-time prekeys on creation, persist to `prekeys`.
- [ ] HKDF helper has unit test against an RFC 5869 vector.
- [ ] Bearer auth rejects missing/wrong token with 401.
- [ ] `cargo test` green; `cargo clippy -- -D warnings` clean (or
      explicitly allowed at module scope).

### M2 — Pairing + connection

**Goal:** Real QR pairing against `wss://web.whatsapp.com/ws/chat`.

References:
- whatsmeow/socket/noisehandshake.go
- whatsmeow/socket/framesocket.go
- whatsmeow/binary/{encoder,decoder,token}.go
- whatsmeow/pair.go, pair-code.go
- whatsmeow/notification.go (`<iq>` handling)

- [ ] Binary node encoder/decoder (`protocol::binary`) with round-trip tests
      for: simple node, nested children, attrs with JID, byte content,
      list-of-nodes content, large packed strings.
- [ ] Token tables vendored (verify against whatsmeow's `token.go`).
- [ ] Frame socket: 3-byte length prefix; integration test via mock WS.
- [ ] Noise XX handshake driver against real WS; on success emits the
      `NoiseCipher` and writes the `<stream:start>` opener per whatsmeow.
- [ ] `POST /v1/sessions/:id/connect`: starts the connection task in the
      background, transitions session through Pending → AwaitingQr.
- [ ] `GET /v1/sessions/:id/qr`: returns the current ref+pubkey+identity+adv
      QR string and an SVG base64 (PNG dropped — qrcode's PNG path needs the
      `image` feature whose deps require rustc 1.88+).
- [ ] On QR scan: receive `<pair-success>` `<iq>`, persist server-issued
      account proto, business name, push name, platform. Status → Syncing
      (see below), then → Connected once initial app-state syncs.

  Session status lifecycle (the `status` field + matching SSE/webhook events):
  `pending → connecting → awaiting_qr → syncing → connected`, with
  `disconnected` / `logged_out` / `blocked` / `proxy_error` as exits.
  **`syncing`** is entered on login (`<success>`): the socket is up but the
  initial app-state (contacts/chats/settings + LID↔PN maps) hasn't landed, so
  consumers must NOT send/receive yet. **`connected` means READY** — it (and the
  `connected` event) fire only once every app-state collection is applied
  (or a fallback timeout elapses, so a session never hangs in `syncing`).
  History-sync backfill continues after `connected`.
- [ ] Reconnect after pairing without re-QR; persists across process restart.
- [ ] `POST /v1/sessions/:id/logout`: sends `<remove-companion-device>` IQ,
      clears credentials, status → LoggedOut.

### M3 — Send text

**Goal:** send 1:1 plaintext messages via Signal.

References:
- whatsmeow/send.go
- whatsmeow/encryption.go
- whatsmeow/message.go
- whatsmeow/util/signal* (libsignal-protocol-go fork)

- [ ] Port enough libsignal: `SessionRecord`, `SessionState`, `RatchetingSession`,
      `SessionCipher`, `PreKeyWhisperMessage` (type 3) and `WhisperMessage` (type 1).
      Vector tests against libsignal-go fixtures.
- [ ] X3DH initial-message construction for first send to a new peer
      (uses recipient's prekey bundle fetched via `<iq>` `usync`).
- [ ] `<iq type="get" xmlns="usync">` to fetch device list + prekey bundle.
- [ ] Build `<message>` node with per-device `<enc>` children of types
      `pkmsg` / `msg`. Padded plaintext per whatsmeow's pad rules.
- [ ] `POST /v1/sessions/:id/messages` body
      `{"to": "5511...", "text": "hi", "reply_to": "..." (optional)}` →
      returns `{"id":"<msg_id>","timestamp":<ts>}`.
- [ ] Persist outgoing message to `messages` table (from_me=1).

### M4 — Receive + store + events

**Goal:** decrypt incoming messages, persist, deliver to API consumers.

- [ ] Inbound `<message>` decoding: dispatch by `<enc type=>` to Signal
      session decryption.
- [ ] Padding strip; protobuf decode of waE2E.Message.
- [ ] Store row inserted with normalized `body_text` for text messages.
- [ ] `<receipt>` reply (`type="server-error"` on failure, normal ack on
      success). Whatsmeow's recv logic in `whatsmeow/receive.go` is the
      canonical reference.
- [ ] SSE endpoint `GET /v1/sessions/:id/events` streams `SessionEvent`s,
      one per WA event (qr, paired, message, disconnect, ...).
- [ ] Ack-retry loop: messages we fail to decrypt enqueue a `<retry>` per
      whatsmeow/retry.go. Cap retries per-message.
- [ ] `GET /v1/sessions/:id/messages` query: pagination, chat filter, search
      via SQLite FTS (or LIKE fallback if FTS5 not built).

### M5 — Media (send + receive)

**Goal:** encrypted media round-trip.

References:
- whatsmeow/upload.go, download.go
- whatsmeow/mediaconn.go
- whatsmeow/util/cbcutil

- [ ] AES-256-CBC + HMAC-SHA256 encryption helper with HKDF-derived
      (iv, cipher_key, mac_key, ref_key). Unit tests.
- [ ] `mediaconn` IQ to fetch upload host + auth token.
- [ ] Upload: PUT to mmg.whatsapp.net `/<media_type>?auth=...&token=...`.
      Returns `direct_path` + `url`.
- [ ] Build `ImageMessage` / `VideoMessage` / `AudioMessage` /
      `DocumentMessage` protobufs and route through M3 send pipeline.
- [ ] Inbound media: lazy download via `media download` endpoint or
      auto-download flag on session.
- [ ] `POST /v1/sessions/:id/messages/media` (multipart): `file`, JSON
      metadata `{"to":"...","caption":"...","filename":"...","mime":"..."}`.
- [ ] `GET /v1/sessions/:id/messages/:chat/:msgid/media` streams decrypted
      bytes; first call downloads + caches under `media_path`.

### M6 — Groups

**Goal:** send/receive group messages, manage groups.

References:
- whatsmeow/group.go
- whatsmeow/util/randutil.go (group_jid generation)
- libsignal SenderKey / SenderKeyDistributionMessage

- [ ] Sender keys + SKDM port (libsignal `groups` package).
- [ ] Group `<message>` send: derive sender key, distribute SKDM to each
      participant via 1:1 Signal (the M3 pipeline), encrypt body once with
      sender key, broadcast.
- [ ] Group receive: pull SKDM, install sender chain, decrypt subsequent
      bodies via sender chain.
- [ ] Group IQs: `create`, `subject`, `description`, `participants add|remove|
      promote|demote`, `leave`, `invite link get|revoke`, `join code`.
- [ ] `groups` + `group_participants` tables populated on group events.

### M7 — App state + history sync

**Goal:** contacts, chat metadata, history backfill.

References:
- whatsmeow/appstate*.go
- whatsmeow/historysync*.go

- [ ] App state LTHash + key chain crypto.
- [ ] Patch decoding for `regular`, `regular_high`, `regular_low`,
      `critical_block`, `critical_unblock_low` collections.
- [ ] Mutations applied to `contacts` / `chats` / `messages`.
- [ ] History sync (HSv2): receive `<notification>` containing protobuf
      payloads, decrypt, deserialize, persist.
- [ ] `POST /v1/sessions/:id/history/backfill` requests older messages.
- [ ] `GET /v1/sessions/:id/contacts`, `GET .../chats`, `GET .../groups`.

### M8 — Polish

- [ ] Reactions (`<message>` with `ReactionMessage` protobuf).
- [ ] Quoted replies, edits (`EditedMessage`), deletions (`RevokeMessage`).
- [ ] Presence: `<presence type="composing|paused">`.
- [ ] Read receipts: `<receipt type="read">`.
- [ ] Disconnect/reconnect with exponential backoff; surface as events.
- [ ] Read-only mode (`RUWA_READONLY=1`) blocks all mutating routes.

## "Main features at least" stopping point

Implementation may pause after **M5 ✅ + M6 ✅ + M7 ✅** with all
acceptance items checked. M8 is polish; M2-M7 represent the core feature
parity with `wacli`.

## Conventions

- Functions returning `Result<T>` use the local `error::Result`. Convert
  external errors at the boundary (`?` with `From`).
- `tracing::info!` for state transitions, `tracing::debug!` for wire-level.
- Tests next to source: `#[cfg(test)] mod tests { ... }` at file end.
- For wire formats with whatsmeow as the reference, prefer porting the
  algorithm (not the API surface). Idiomatic Rust > 1:1 transliteration.
- All protobuf types live behind `mod proto`; never expose them in API JSON
  directly — translate to neutral structs in `api.rs`.

## Test data

- HKDF: RFC 5869 vectors.
- AES-GCM: NIST CAVP vectors (a small handful).
- Signal: capture libsignal-go test vectors and embed under
  `tests/vectors/signal/` (generated on M3).
- Binary node: round-trip property test plus a few golden vectors captured
  from a real WA session (deferred — for now, manual encode/decode pairs).
