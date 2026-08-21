# ruwa — SPEC

API-first multi-tenant WhatsApp Web client in Rust. A from-scratch port of
[whatsmeow](https://github.com/tulir/whatsmeow) — no Baileys, no whatsmeow
runtime, no FFI bridges. Standalone Rust, exposes everything over HTTP.
Sessions of `kind: "cloud"` swap the Web socket for Meta's official Cloud API
(Graph) behind the same HTTP surface — see *Cloud backend design*.

This document is the **design contract** — the milestones, acceptance
criteria, and non-negotiables the implementation is held to.

## Non-negotiables

- **No external WA libraries.** No Baileys, no whatsmeow, no FFI shims. Crypto
  primitives from RustCrypto / dalek / snow are fine; protocol logic must be
  ours.
- **Multi-tenant by design.** One process hosts many WA sessions. Every
  per-tenant write carries `session_id`.
- **Pragmatic file count, ≤11 source files in `src/`.** Today: `main.rs`,
  `api.rs`, `protocol.rs`, `crypto.rs`, `store.rs`, `media.rs`, `session.rs`,
  `error.rs`, `egress.rs`, `cloud.rs`, `protocol/tokens.rs`. Add files only when a module crosses ~1500 lines and the split
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
    ├── media.rs             # encrypted upload/download
    ├── egress.rs            # SSE / webhook / redis event fan-out
    └── cloud.rs             # Meta Cloud API (Graph) backend for kind=cloud sessions
```

## API surface (target)

```
GET  /health
GET  /v1/sessions
POST /v1/sessions                     {"label": "...", "kind": "web"|"cloud",
                                       "cloud": {"phone_number_id","waba_id","access_token","app_secret","verify_token","graph_version"}}
GET  /v1/sessions/:id                 (SessionMeta carries "kind" and, for cloud, "cloud": {phone_number_id, waba_id, graph_version, display_phone_number?, verified_name?} — never secrets)
PUT  /v1/sessions/:id/cloud           {same "cloud" object; only provided fields replace}  (cloud only; 501 on web)
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
POST /v1/sessions/:id/calls/:call_id/reject {"peer":"5511..."}  (decline an incoming call; call_id + peer come from the call_offer event. Inbound calls emit call_offer / call_terminate events; no media plane — web only)

# cloud sessions only (501 on web):
POST /v1/sessions/:id/messages/template     {"to","name","language","body_params":[..],"header"?,"buttons"?,"components"?,"reply_to"?}
POST /v1/sessions/:id/messages/interactive  {"to","type":"button"|"list"|"cta_url","body","header"?,"footer"?,"buttons"|"button"+"sections"|"cta","reply_to"?}
GET  /v1/sessions/:id/templates?status=&limit=&after=   -> {"templates":[{id,name,language,status,category,components}], "next": cursor|null}
POST /v1/sessions/:id/templates             {"name","language","category","components":[..],"allow_category_change"?} -> 201 {id,status,category}
DELETE /v1/sessions/:id/templates/:name     (?hsm_id=)  -> {"success":true}

# Meta webhook (no bearer; verify-token / HMAC-signature guarded):
GET  /v1/cloud/webhook                ?hub.mode=subscribe&hub.verify_token=&hub.challenge=  -> 200 raw challenge | 403
POST /v1/cloud/webhook                raw JSON + X-Hub-Signature-256; routed by metadata.phone_number_id -> 200 | 401 bad signature

# AI text assistant (instance-wide; ADMIN token only — a per-session key gets 401):
GET    /v1/settings/ai                -> {"configured","provider":"anthropic"|"openai"|null,"model","base_url","system_prompt","api_key_hint":"••••abcd"|null}  (never the key)
PUT    /v1/settings/ai                {"provider","api_key"?,"model"?,"base_url"?,"system_prompt"?} -> 200 GET shape  (readonly-gated; api_key required on first set / provider change; openai needs "model")
DELETE /v1/settings/ai                -> 204  (readonly-gated)
POST   /v1/settings/ai/test           -> {"ok":true,"provider","model","latency_ms","reply"} | 502 {"error":"ai upstream: <status> <excerpt>"}
POST   /v1/ai/improve-text            {"text"(1..8000),"mode"?:"improve"|"formal"|"casual"|"shorter"|"grammar"|"translate"|"custom","language"?,"instruction"?}
                                      -> {"text","provider","model"} | 400 unconfigured/bad input | 422 model refused | 502 upstream
```

All `/v1/*` require `Authorization: Bearer $RUWA_API_TOKEN` — except
`/v1/cloud/webhook`, which Meta calls directly and is guarded by the verify token
(GET) and the per-session `app_secret` HMAC (POST).

### Cloud backend design (`src/cloud.rs`)

- **Kind discriminator.** `sessions.kind` = `web` (default) | `cloud`. `SessionMeta`
  serializes `kind` and, for cloud, a non-secret `cloud` block. Cloud sessions reuse
  the same `messages` / `contacts` / `chats` tables, the same `SessionEvent` bus and
  the same egress (SSE / webhook / Redis); consumers only see capability differences.
- **`cloud.rs` is pure.** Graph client (`validate`, `send`, `upload_media`,
  `media_info`, `download`, templates, `mark_read`), payload builders, webhook
  parser, signature check and error mapping — no dependency on `session.rs` /
  `store.rs`. Persistence + event emission live in `SessionManager`
  (`cloud_send`, `cloud_ingest`); HTTP wiring in `api.rs`.
- **Connect = validate.** `POST …/connect` on a cloud session runs
  `GET /{phone_number_id}?fields=id,display_phone_number,verified_name,quality_rating`;
  success sets `jid = "<display_phone_number digits>@s.whatsapp.net"`, `push_name =
  verified_name`, status `connected`, emits `paired` + `connected`; failure sets
  `disconnected` + `disconnected{reason}`. `reconnect` == connect; `logout` marks
  `logged_out` and keeps the creds. No long-lived socket task, **no leasing** —
  every replica restores, validates and runs its egress worker, because Meta may
  deliver a webhook to any instance.
- **Synchronous send.** Handlers POST to `/{phone_number_id}/messages` inline; the
  returned `wamid` becomes `message_id`, the row is persisted with status `sent`,
  `message_sent` is emitted, and the HTTP reply is `202 {"id": wamid, "timestamp",
  "status": "sent"}`. A Graph error maps to an HTTP error (`190`/`401` → 401;
  parameter / template / window (`131047` → "send a template") / undeliverable
  errors → 400; rate limits `130429`/`131056`/`80007` → 409; else 500) and **no row**
  is written. Outbound media is uploaded to Meta first (`POST /{pnid}/media`,
  multipart) and sent by id.
- **Lazy inbound media.** The webhook only stores `media_id` (+ mimetype / sha256 /
  caption / filename) in `payload_json`; the first `GET …/messages/:chat/:id/media`
  resolves `GET /{media_id}` → url → bearer download and caches it via
  `message_set_media_path`, exactly like web media.
- **Webhook ingest.** `POST /v1/cloud/webhook` (body limit 4 MB — Meta batches up
  to 3 MB): resolve each batch's session by `metadata.phone_number_id` (unknown →
  200 + ignore) and verify `X-Hub-Signature-256` **per batch** under that session's
  own `app_secret` (HMAC-SHA256 of the raw bytes, constant-time; unsigned only if
  `RUWA_CLOUD_ALLOW_UNSIGNED=1`) — any mapped batch failing → 401, nothing stored
  (a forged body can't ride another tenant's signature). Sessions are hydrated
  from the shared store on demand, so a webhook may land on any instance. Ack 200
  fast, then insert `messages[]` (dedupe on wamid — retries emit nothing), upsert
  contact / chat, and emit `message` with the same body shapes as web (`text`,
  media with a `…/media` URL, `location`, `contact`, `reaction`, plus cloud-only
  `button` and `interactive`; unknown types → `{type:"unknown", raw}`).
  `statuses[]` advance the row status **monotonically** (`sent < delivered < read
  < failed`; Meta neither orders nor dedupes them) and emit `message_sent` /
  `message_delivered` / **`message_read`** / **`message_failed{reason:"<code>:
  <title>"}`** (`played` → read) only when the row actually moved. The two new
  events are additive; web sessions never emit them today.
- **One session per number.** `cloud_phone_number_id` is unique (partial unique
  index); `create` / `PUT …/cloud` answer 409 for a number another session owns,
  and changing `phone_number_id` needs the master token (a per-session key may
  only rotate token / secret / verify token / graph version). Cloud sends refuse
  non-phone recipients (`@lid`, `@g.us`, `@broadcast`, …) with 400 instead of
  digit-stripping them into an unrelated number.
- **Sealed secrets.** `access_token` and `app_secret` are stored as sealed BLOBs
  (`crypto::vault::seal` / `store::unseal`, honoring `RUWA_DB_ENCRYPTION_KEY`) and
  are never serialized to the API, logs or events.
- **Unsupported routes → 501.** Web-only routes on a cloud session (`qr`,
  `pair-phone`, `resync-appstate`, `mark-online`, `messages/poll|event|edit|revoke`,
  `history/backfill`, `onwhatsapp`, `contacts/:jid/picture|block|unblock`,
  `profile`, `presence`, `sessions/import`) and cloud-only routes on a web session
  (`messages/template|interactive`, `templates`, `PUT …/cloud`) return
  `Error::NotImplemented` = **501** with a clear message. `groups` returns `[]`.
- Graph version defaults to `v25.0` (per-session `graph_version`). Webhook verify
  token: `RUWA_CLOUD_VERIFY_TOKEN` if set, else any cloud session's `verify_token`.

### AI text assistant design (`egress::ai` + `api.rs`)

An optional, instance-wide writing assistant for the Console composer: it rewrites a
draft WhatsApp message per a `mode` (improve / formal / casual / shorter / grammar /
translate / custom) by calling an LLM over **raw HTTP** (no SDK) — Anthropic's
Messages API (`POST {base_url}/v1/messages`, `x-api-key`, `anthropic-version:
2023-06-01`, `max_tokens` 16000 (a ceiling — Opus 5's adaptive-thinking tokens
count against it), no sampling/thinking params; on the Opus 5 / Fable 5 family also
`anthropic-beta: server-side-fallback-2026-07-01` + `"fallbacks": "default"`; reply =
concatenated `content[].text`, `stop_reason: "refusal"` → 422, `"max_tokens"` → 502
"reply was cut off" rather than a silent half-rewrite) or any OpenAI-compatible
`POST {base_url}/chat/completions` (`Authorization: Bearer`, system + user messages,
reply = `choices[0].message.content`, `finish_reason: "length"` → 502 likewise).
60 s timeout, two retries on 429/5xx/connection failures (a timeout is not retried —
the model already spent a minute on it). Prompt = a fixed WhatsApp-tuned system prompt (overridable via
`system_prompt`) + a fixed, non-editable **response protocol** suffix ("output only the
final message; never include reasoning/`<think>` tags; if you will not rewrite, reply
exactly `[[REFUSED]]`") + `"Instruction: <mode text>\n\nDraft:\n<text>"`; the answer is
cleaned — inlined chain-of-thought blocks (`<think>`/`<thinking>`/`<reasoning>`/
`<thought>`, closed or not, as emitted by DeepSeek-R1/Qwen-style models behind an
OpenAI-compatible endpoint) are stripped, wrapping quotes removed — and a reply that is
empty or carries the `[[REFUSED]]` sentinel is a **422 refusal**, so a prose refusal
("I can't help with that") never reaches the composer looking like a rewrite. The provider module lives in `src/egress.rs` as `pub mod ai`
(another outbound third-party HTTP integration; `src/` stays ≤ 10 files) with the
request builders / response parsers unit-tested against fixtures — no network in
tests. Config (`AiConfig { provider, api_key, model, base_url?, system_prompt? }`)
is one JSON blob under `app_settings['ai']` (migration 0023, SQLite + Postgres),
**sealed at rest** through the same `vault::seal` / `store::unseal` choke point as
private keys and Cloud API credentials, and the key is **never** serialized back —
`GET` returns only a `••••abcd` hint. All routes are admin-token only; `PUT`/`DELETE`
honor `RUWA_READONLY`. Defaults: anthropic → `claude-opus-5` @
`https://api.anthropic.com`; openai → `https://api.openai.com/v1`, model required.

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

## Calls (voice — design contract for `src/call.rs`)

ruwa is the call **infrastructure**: signaling + SRTP media plane + an audio
bridge. Call *logic* (the voice agent) lives in an external service. Porting
references (MIT): `oxidezap/whatsapp-rust` `wacore/src/voip` + `src/voip`
(primary), `purpshell/meowcaller` (media-loop model); spec at wacrg.org.
1:1 audio only in v1 — no video, no group calls.

### Lifecycle & control (HTTP + existing egress plane)

- Events on SSE/webhooks: `call_offer` (shipped), `call_terminate` (shipped),
  plus `call_active` (media flowing) when the media plane lands.
- `POST /v1/sessions/:id/calls/:call_id/reject` (shipped).
- `POST /v1/sessions/:id/calls/:call_id/accept` — answers; media starts when
  the audio WS is connected (or dialed out). Optional `{"codec":"auto"|"opus"}`.
- `POST /v1/sessions/:id/calls/:call_id/hangup` — terminate an active call.

### Audio bridge (WebSocket, Twilio-Media-Streams-shaped)

- `GET /v1/sessions/:id/calls/:call_id/audio` → WS upgrade (bearer). Later:
  optional outbound mode (ruwa dials the agent's WS on answer).
- **Binary frame = 20 ms of s16le PCM, 16 kHz mono = 640 bytes, headerless.**
  Multiples of 640 allowed (bulk TTS); ruwa paces. Non-multiple → close 4008.
  ruwa aggregates 3×20 ms → one 60 ms WA codec frame; slices inbound the
  same way. 16 kHz native = WA's codec rate; PCM16@16k is what voice-agent
  stacks (OpenAI Realtime, Deepgram, Pipecat) consume directly.
- Text control frames (JSON): ruwa→agent `start` (format + codec + from),
  `active`, `peer_muted`, `mark` (echo), `stop{reason}`, `underrun`/`overrun`;
  agent→ruwa `mark`, `clear` (barge-in: flush outbound buffer), `stop` (=hangup).
- **ruwa owns the clock**: a 60 ms ticker always feeds WA. Agent underrun →
  encode silence (DTX). Overflow (>~5 s buffered) → drop-oldest + `overrun`.
  Inbound to a slow agent: drop after ~2 s, never stall the SRTP loop.
  WS disconnect ≠ hangup: ~10 s silence grace + one reconnect (`resumed`).

### Codec

- v1: answer forcing the **standard-Opus fallback** (clear capability bit 31,
  `voip_settings use_mlow_codec_v1=false`, PT 120, 16 kHz clock, 60 ms frames,
  ~24 kbps, DTX) — verified live by whatsapp-rust against Android/Web peers.
  If the peer sends MLOW anyway: end the call `codec_mismatch` (honest,
  observable) — never emit garbage audio.
- v2 (only if field data demands): adapt wacore's pure-Rust MIT MLOW
  (`wacore/src/voip/mlow`, ~19k LOC). Never write MLOW from scratch.

### Non-negotiables for the port

- Media crypto/params (SRTP suites, key derivation, RTP layering) are ported
  from whatsapp-rust `wacore/src/voip` — algorithm, not API surface.
- The media loop must never block the session's recv/send pumps: the call
  stack runs in its own tasks, bridged by bounded channels.
- Every stanza builder/parser in `call.rs` unit-tested against shapes lifted
  from the reference implementations.

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
