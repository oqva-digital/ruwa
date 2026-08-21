# ruwa — Rust WhatsApp Client

**API-first and MCP-ready: a multi-tenant WhatsApp client in Rust — one small binary that turns WhatsApp into a clean HTTP API _and_ a set of MCP tools for AI agents.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)

ruwa is a from-scratch port of [whatsmeow](https://github.com/tulir/whatsmeow): it
speaks WhatsApp's multi-device (WhatsApp Web) protocol directly and exposes it as a
bearer-authed REST API with Server-Sent Events, webhooks, and Redis event streams.
**No Baileys, no whatsmeow runtime, no FFI, no heavy SDKs** — Signal, Noise, the WA
binary protocol, the Redis and S3 clients, and SigV4 are all implemented in-house.
It can also drive numbers on Meta's **official Cloud API** (`kind=cloud` sessions)
behind the very same API — see below.
The result is a single **~9 MB binary** that idles at **~11 MB RAM** and runs many
WhatsApp accounts at once.

> ⚠️ **Unofficial.** ruwa is an independent implementation of the WhatsApp Web
> multi-device protocol. It is **not** affiliated with, authorized, or endorsed by
> WhatsApp or Meta, and automating real accounts may violate WhatsApp's Terms of
> Service and carries a risk of account bans. Use numbers you own, prefer
> throwaway accounts for testing, and use your own judgment.

## Why ruwa

|  | ruwa | Evolution API | whatsmeow / Baileys |
|---|---|---|---|
| Form factor | single HTTP server — **9 MB binary / 173 MB image** | Node app — **1.75 GB image** | a library you build a server around |
| Idle RAM | **~11 MB** | ~278 MB (api + Postgres + Redis) | ~18 MB (Go) |
| Multi-tenant | **built-in** — N accounts, per-tenant API keys | yes | do-it-yourself |
| Dependencies | **in-house** crypto + protocol + Redis/S3 clients | Baileys + full Node stack | Go / TS library |
| Interface | REST + SSE + webhooks + Redis | REST + webhooks | library calls |
| **Agent tools (MCP)** | **built-in — 39 tools** | none | none |
| Store | **SQLite or Postgres** | Postgres + Redis | your choice |

**What's different:** ruwa is the lightest WhatsApp server we know of and the fastest
in our head-to-head (below) — there's no Node event loop, no Baileys, and no SDK
sprawl, just Rust + tokio and a hand-written protocol stack you can audit end to end.

## Benchmarks

Measured head-to-head on one machine (Apple Silicon, release builds) against Evolution
API 2.3.7 and a whatsmeow Go harness. Full method and honest caveats in [`bench/`](bench/).

**Footprint & efficiency**

|  | ruwa | Evolution 2.3.7 | whatsmeow (harness) |
|---|---|---|---|
| Docker image | **173 MB** | 1.75 GB | — |
| Binary | **9.3 MB** | (Node app) | 20 MB |
| Idle RAM | **11 MB** | ~278 MB (api + pg + redis) | 18.2 MB |
| RAM, 1 live session | **33.8 MB** | ~272 MB (full stack) | — |
| HTTP throughput¹ | **~180,800 req/s** | ~205 req/s | — |
| Codebase | **11 files, ~22k LoC** | 188 `.ts` | 155 `.go` |

¹ Trivial `/health` endpoint — this measures the Rust + tokio HTTP ceiling, **not**
WhatsApp send (WhatsApp's own servers gate that). whatsmeow/Baileys are libraries with
no server, so only their footprint is comparable.

**Send latency** — send API call → message arrives at the recipient, via one shared
reader (real WhatsApp, n=10):

| Stack | p50 | range |
|---|---|---|
| **ruwa** | **263 ms** | 249–279 |
| whatsmeow | 382 ms | 353–439 |
| Evolution 2.3.7 | 712 ms | 659–762 |

**Receive processing** — `recv→ack`, the intra-client wire interval (Signal decrypt +
protobuf decode + emit receipt), the only apples-to-apples cross-stack metric (real
WhatsApp, n=12):

| Protocol | p50 | mean | max |
|---|---|---|---|
| **ruwa** | **1.1 ms** | 1.3 | 3.1 |
| whatsmeow | 3.0 ms | 3.2 | 7.0 |
| Evolution | 5.0 ms | 4.8 | 9.0 |

ruwa is the lightest on every footprint axis and fastest on both send and receive.

**Reliability (cloud soak)** — a continuous send↔receive probe between two live
sessions on Railway (Postgres-backed, egress through a residential proxy), run
for **83.5 h** straight:

| Metric | Result |
|---|---|
| Round-trip delivery | **100%** (406/406, 0 failed) |
| Connection uptime | **99.6%** per session |
| Send→received latency | p50 **0.77 s** · p95 2.33 s |
| Webhook deliveries | 3,624 · **0** bad HMAC signatures |

End-to-end over the public internet + a residential proxy + WhatsApp's own
servers — the honest production figure. It's an order higher than the controlled
single-machine **send latency** above (which isolates ruwa's own overhead, not
the network round-trip).
Numbers are single-machine and point-in-time — see [`bench/`](bench/) for the rigs and
caveats.

## Features

- **Messaging** — text with **@mentions** and **reply/quote**, media
  (image/video/audio/ptt/document/sticker), **location**, **contact (vCard)**,
  **poll**, **calendar event**, reactions, edit, revoke.
- **Meta Cloud API backend (`kind=cloud`)** — the *official* WhatsApp Business
  Platform behind the **same `/v1/*` API and events**: create a session with a
  `phone_number_id` + System User token instead of scanning a QR, and ruwa handles
  the Graph calls, webhook signature checks, and media for you. See
  [Meta WhatsApp Cloud API backend](#meta-whatsapp-cloud-api-official-backend).
- **Template + interactive messages** — send approved **templates** (body params,
  media headers, buttons), **interactive** button / list / CTA-URL messages, and
  list / create / delete templates — on cloud sessions.
- **Multi-tenant sessions** — pair via QR or phone code (web) or Meta Cloud API
  credentials (cloud), many accounts per instance, **per-tenant
  API keys**, **per-session proxy**, graceful shutdown.
- **Event egress** — live **SSE** stream, **webhooks** (HMAC-signed, retried,
  event-filtered), and **Redis** queues (RPUSH / PUBLISH) — pick one or all.
- **Media storage** — keep blobs in the DB (default) or offload to **S3 / R2 / MinIO**
  via the in-house SigV4 client.
- **Number & profile** — onWhatsApp check, profile-picture fetch, block/unblock,
  set your own name / status / picture, typing & presence, read receipts.
- **Resilience** — automatic reconnect with backoff, a 25 s keepalive, and a
  **zombie-socket watchdog** that force-reconnects a silently half-open connection —
  the failure mode that quietly kills naive clients behind residential proxies.
- **Storage & HA** — **SQLite or Postgres**, optional **AES-256-GCM encryption at
  rest**, cross-instance **leasing** for multi-replica deployments.
- **Ops** — `/health`, Prometheus `/metrics`, and a built-in dashboard (ruwa Console)
  served at `GET /`.
- **Console** — record and send **voice notes (Ogg/Opus)**, **attach files**
  (image / video / audio / document), and an optional **AI text assistant** that
  rewrites a draft (improve, formal, casual, shorter, grammar, translate, custom) —
  bring your own Anthropic or OpenAI-compatible key. See
  [AI text assistant](#ai-text-assistant).
- **Agent-ready (MCP)** — a first-party **Model Context Protocol** server (`mcp/`)
  exposing 39 tools so any MCP client (Claude, etc.) can create instances, pair them,
  send every message type, manage chats, and **search history by meaning** — no other
  WhatsApp stack ships this.

## Agent-ready (MCP)

ruwa ships a first-party **Model Context Protocol** server (`mcp/ruwa-mcp`) so an AI
agent can drive WhatsApp directly — no REST glue. As far as we know, no other WhatsApp
stack (Evolution, whatsmeow, Baileys) offers this out of the box.

**39 tools** cover the full lifecycle — _create an instance → pair it (QR or phone
code) → hold a conversation → wire up webhooks_: `create_session`, `get_qr`,
`pair_phone`, `connect_session`,
`send_text` (with @mentions / quote), `send_media` / `location` / `poll` / `reaction`,
`edit_message` / `revoke_message`, `mark_read`, `set_typing`, `set_presence`,
`list_chats` / `list_messages` / `list_contacts`, `search_conversations` (semantic),
`sync_history` (deep backfill), `on_whatsapp`, `set_webhook`, and more.

```sh
cd mcp && npm install && npm run build
# register with Claude Code (or drop the equivalent JSON into any MCP client):
claude mcp add ruwa \
  --env RUWA_BASE_URL=http://localhost:8080 \
  --env RUWA_API_TOKEN=your-admin-token \
  -- node "$(pwd)/mcp/dist/index.js"
```

Then just ask: *"create a WhatsApp instance, show me the QR, and once it's connected
send 'oi' to 5511999999999."* Full install guide (Claude Code / Desktop / Cursor +
troubleshooting): [`mcp/INSTALL.md`](mcp/INSTALL.md); tool list: [`mcp/README.md`](mcp/README.md).

## What problems it solves

- **One API for many numbers** — run a single account or hundreds behind one uniform,
  bearer-authed HTTP interface.
- **Cheap to host** — fits in a small container and idles in megabytes, not gigabytes,
  so it runs on the smallest instances.
- **Stays connected** — built-in reconnect, keepalive, and zombie detection survive
  proxy resets and network blips instead of going silently dead.
- **Own your stack** — self-hosted, auditable, no third-party WhatsApp library, no
  vendor lock-in; the entire crypto + protocol surface is in this repo.
- **Integrate fast** — SSE / webhooks / Redis for inbound, REST for outbound,
  Prometheus + a dashboard for operations.

## When to use ruwa — and when not to

**Good fit**

- You need programmatic WhatsApp (send **and** receive) over HTTP, for one account or many.
- You want a small, fast, self-hosted server you can run on cheap infrastructure.
- You're replacing Evolution API and want a fraction of the footprint and latency.
- You want first-class events (SSE / webhooks / Redis) and built-in media handling.
- You're building an **AI agent** that needs WhatsApp — the MCP server gives it tools directly.

**Not a fit**

- You need Meta's compliance, SLAs, and support **without** running anything yourself
  — ruwa's `kind=cloud` sessions do speak the official Cloud API, but you still
  self-host ruwa (and bring your own Meta app / WABA).
- You can't tolerate account-ban risk or operating in a ToS gray area (web sessions
  only — cloud sessions use the official API).
- You don't want to self-host or operate a service.
- You need capabilities outside the WhatsApp Web multi-device protocol surface.

## Quick start

The easiest way — a prebuilt, self-contained binary (the dashboard is baked in),
run as a background service. No Docker, no Rust:

```sh
curl -fsSL https://raw.githubusercontent.com/oqva-digital/ruwa/main/install.sh | bash
# prints your dashboard URL + API token; manage with `ruwactl status|logs|stop`
```

Or grab a binary for your OS from the [Releases](https://github.com/oqva-digital/ruwa/releases)
page and run it directly:

```sh
chmod +x ruwa-macos-arm64
RUWA_API_TOKEN=$(openssl rand -hex 32) ./ruwa-macos-arm64
# dashboard at http://127.0.0.1:8080/ — paste the token
```

Then open the dashboard, create a session, and scan the QR (WhatsApp → Linked
devices). Send a message via the API:

```sh
curl -H "Authorization: Bearer $RUWA_API_TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"to":"5511999999999","text":"hello from ruwa"}' \
     http://127.0.0.1:8080/v1/sessions/<id>/messages
```

> **Not a developer?** **[GETTING_STARTED.md](GETTING_STARTED.md)** is a friendly,
> step-by-step walkthrough (installer, a "let Claude set it up" path, and Docker).

**Other ways to run it:**
- **From source** (devs): `RUWA_API_TOKEN=$(openssl rand -hex 32) cargo run --release`
- **Docker**: `Dockerfile` + `docker-compose.yml` (copy `.env.example` → `.env`)
- **Cloud / Railway** (24-7): [`DEPLOY.md`](DEPLOY.md) · Full API + protocol: [`SPEC.md`](SPEC.md)

## Configuration

| Var | Default | Purpose |
|---|---|---|
| `RUWA_API_TOKEN` | (random per run) | Bearer token for `/v1/*` + `/metrics` |
| `RUWA_BIND` | `127.0.0.1:8080` | HTTP listen address (also honors `$PORT`) |
| `RUWA_STORE` | `./data/ruwa.db` | SQLite path, or a `postgres://…` URL |
| `RUWA_READONLY` | unset | When `1`, blocks mutating routes |
| `RUWA_DB_ENCRYPTION_KEY` | unset | base64 32-byte key → encrypt secret columns |
| `RUWA_MEDIA_STORE` | `db` | `s3` to offload media (needs `RUWA_S3_*`) |
| `RUWA_LEASING` | unset | `1` enables cross-instance session leasing |
| `RUWA_MODERN_LID_SEND` | unset | `1` enables the modern LID 1:1 stanza (`addressing_mode`/`phash`/`peer_recipient_pn`). Off by default — some servers reject it (error 479) for migrated peers; the default legacy stanza delivers |
| `RUWA_PROXY_DOWNLOADS` | on | `0` routes media + history-sync **downloads** direct (off the session's egress proxy) to save metered proxy bandwidth; the WebSocket and uploads always stay on the proxy |
| `RUWA_SKIP_REDUNDANT_HISTORY` | on | `0` disables the reconnect gate that skips re-downloading heavy history-sync chunks (BOOTSTRAP/FULL/RECENT) the phone re-pushes on reconnect |
| `RUWA_CLOUD_VERIFY_TOKEN` | unset | Verify token Meta sends on the webhook subscription handshake (`GET /v1/cloud/webhook`). Unset → any cloud session's own `verify_token` is accepted |
| `RUWA_CLOUD_ALLOW_UNSIGNED` | unset | `1` accepts Meta webhooks for cloud sessions created **without** an `app_secret` (no `X-Hub-Signature-256` check). Off by default — unsigned deliveries are rejected 401 |
| `RUST_LOG` | `info` | Tracing filter |

Full list (S3, leasing, retention, WA version override) in [`.env.example`](.env.example).

### 1:1 delivery & privacy tokens

Modern WhatsApp gates 1:1 messages to some peers (notably **business accounts** and
**freshly re-paired** sessions) behind a per-contact *privacy token* (`tctoken`).
Without it the server accepts the stanza but returns error **463 (MissingTcToken)**
and never delivers it. ruwa captures that token automatically — from the contact's
messages in real time, and from the HistorySync at (re)link — and echoes it back on
every send. Practical consequence: for a **new or long-dormant** conversation with a
gated peer, the contact has to message first (the normal customer-initiated flow),
**or** the session must (re)link once to backfill every contact's token. Established,
active chats are unaffected.
Cloud sessions are unaffected (Meta's servers handle delivery; the equivalent
constraint there is the 24-hour window + templates, below).

## Meta WhatsApp Cloud API (official) backend

Besides the WhatsApp Web protocol, ruwa can drive a number registered on Meta's
**WhatsApp Business Platform (Cloud API)**. A session created with `"kind": "cloud"`
talks to the Graph API instead of a WhatsApp socket, but exposes the **same
`/v1/sessions/:id/*` routes, the same message/contact/chat tables and the same events**
(SSE / webhooks / Redis) — consumers only notice capability differences.

**When to use which**

| | `kind=web` (default) | `kind=cloud` |
|---|---|---|
| What it is | unofficial WhatsApp Web multi-device client (QR / phone-code pairing) | official Meta Cloud API (Graph) client |
| Account | any personal / business number you can link | a number registered in a WhatsApp Business Account (WABA) |
| Ban / ToS risk | yes | none (official) |
| Cost | free | Meta per-template pricing; free-form replies inside the 24 h window are free |
| Groups, presence, history, polls, edit/revoke | yes | no (see matrix) |
| Templates, interactive messages, delivery SLAs | no | yes |

**Prerequisites** (Meta side, one-time)

1. A Meta developer app with the **WhatsApp** product added, and a **WABA** with a
   registered phone number → note the `phone_number_id` and `waba_id`.
2. A **System User** access token (permanent) with `whatsapp_business_messaging` +
   `whatsapp_business_management` — the `access_token`.
3. The app's **App Secret** (App settings → Basic) — the `app_secret`, used to verify
   `X-Hub-Signature-256` on inbound webhooks. Optional but strongly recommended;
   without it webhooks are rejected unless `RUWA_CLOUD_ALLOW_UNSIGNED=1`.
4. Webhook configuration (App → WhatsApp → Configuration): **Callback URL** =
   `https://<your-ruwa-host>/v1/cloud/webhook`, **Verify token** = the value of
   `RUWA_CLOUD_VERIFY_TOKEN` (or the session's `verify_token`), then **subscribe the
   `messages` field**. ruwa must be reachable from the internet over HTTPS for this.

**Create + connect**

```sh
# 1. create the session (secrets are stored sealed and never returned by the API)
curl -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"label":"acme-support","kind":"cloud",
       "cloud":{"phone_number_id":"106540352242922","waba_id":"102290129340398",
                "access_token":"EAAG...","app_secret":"abcd1234...",
                "verify_token":"my-verify-token","graph_version":"v25.0"}}' \
  http://127.0.0.1:8080/v1/sessions
# → 201 {"id":"<id>","kind":"cloud","cloud":{"phone_number_id":"106540352242922",...},"api_key":"..."}

# 2. connect = validate the credentials against Graph (no QR); status → connected
curl -X POST -H "Authorization: Bearer $RUWA_API_TOKEN" http://127.0.0.1:8080/v1/sessions/<id>/connect
```

Credentials can be rotated later with `PUT /v1/sessions/:id/cloud` (same `cloud`
object; only the fields you send are replaced) — then `POST …/reconnect` to
re-validate against Graph (`connect` is a no-op on an already-connected session).
A Meta `phone_number_id` belongs to exactly one session (409 otherwise), and
changing it requires the master token.

**Send** — the regular endpoints work unchanged; sends are synchronous and the
returned `id` is Meta's `wamid`:

```sh
# free-form text (only inside the 24 h customer-service window)
curl -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"to":"5511999999999","text":"hello from ruwa"}' \
  http://127.0.0.1:8080/v1/sessions/<id>/messages
# → 202 {"id":"wamid.HBgLNTUxMTk5OTk5OTk5ORUCABEYEj...","timestamp":1755500000,"status":"sent"}

# approved template (works outside the window)
curl -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"to":"5511999999999","name":"order_update","language":"pt_BR",
       "body_params":["Ana","1234"],
       "buttons":[{"index":0,"sub_type":"quick_reply","payload":"TRACK"}]}' \
  http://127.0.0.1:8080/v1/sessions/<id>/messages/template

# interactive reply buttons (also "list" and "cta_url")
curl -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'Content-Type: application/json' \
  -d '{"to":"5511999999999","type":"button","body":"Confirm your booking?",
       "buttons":[{"id":"yes","title":"Yes"},{"id":"no","title":"No"}]}' \
  http://127.0.0.1:8080/v1/sessions/<id>/messages/interactive

# templates: list (proxy of the WABA's message_templates), create, delete
curl -H "Authorization: Bearer $RUWA_API_TOKEN" \
  'http://127.0.0.1:8080/v1/sessions/<id>/templates?status=APPROVED&limit=50'
# → {"templates":[{"id":"...","name":"order_update","language":"pt_BR","status":"APPROVED","category":"UTILITY","components":[...]}],"next":null}
```

`header` (text / image / video / document), `components` (raw Cloud-native
components array, used verbatim when present) and `reply_to` are accepted on
`/messages/template`; see [`SPEC.md`](SPEC.md) for the full request shapes.
Inbound messages, template button taps (`type: "button"`) and interactive replies
(`type: "interactive"`) arrive as normal `message` events; delivery receipts arrive
as `message_sent` / `message_delivered` / `message_read` / `message_failed`.

**Capability matrix**

| Feature | `web` | `cloud` |
|---|---|---|
| Text (reply/quote) | ✅ | ✅ (`mentions` ignored) |
| Media (image/video/audio/ptt/document/sticker) | ✅ | ✅ (uploaded to Meta, sent by media id; inbound fetched lazily via `…/media`) |
| Location | ✅ | ✅ |
| Contact (vCard) | ✅ | ✅ |
| Reaction | ✅ | ✅ |
| Read receipts (`chats/:chat/read`) | ✅ | ✅ |
| Typing (`chats/:chat/typing`) | ✅ | ✅ (25 s indicator, attached to the last inbound message; 400 if none) |
| Template messages | — | ✅ |
| Interactive (button / list / cta_url) | — | ✅ |
| Edit / revoke | ✅ | 501 (no Cloud API endpoint) |
| Polls / calendar events | ✅ | 501 |
| Groups | ✅ | `[]` (Groups API not wired) |
| Presence (online / last seen) | ✅ | 501 |
| History backfill | ✅ | 501 (Meta keeps no history) |
| onWhatsApp check | ✅ | 501 (Meta reports `131026` asynchronously instead) |
| Profile picture / block / own profile | ✅ | 501 |
| QR / phone-code pairing, resync-appstate, mark-online | ✅ | 501 |

**24-hour window & templates.** Meta only lets you send free-form (service)
messages within **24 h of the customer's last message**. Outside that window only
**approved templates** go through — Graph answers with error `131047`, which ruwa
maps to **`400 cloud: 131047 outside 24h customer-service window — send a template`**.
Other mappings: `190`/`401` → `401`; `100`, `131008/131009`, `132000/132001/132012/132018`
(bad params / template mismatch), `131026` (undeliverable), `131030` (recipient not
in the sandbox allow-list) → `400`; `130429`, `131056`, `80007` (rate limits) → `409`;
anything else → `500` with the Graph code + message. Failed sends return the error
and persist **no** row; asynchronous failures come back as `message_failed`
events (`reason: "<code>: <title>"`).

## AI text assistant

An optional, instance-wide writing assistant behind the Console's composer (the ✨
"Improve" menu) and a plain HTTP endpoint. It rewrites a draft WhatsApp message —
*improve*, *more formal*, *more casual*, *shorter*, *fix grammar*, *translate to…*,
or a *custom* instruction — by calling an LLM provider you configure: **Anthropic**
(Messages API) or any **OpenAI-compatible** `/chat/completions` endpoint (OpenAI,
OpenRouter, Groq, Ollama, …). Raw HTTP, no SDK; nothing leaves your box except the
draft sent to the provider you chose.

- **Admin-only**: every `/v1/settings/ai*` and `/v1/ai/*` route accepts only
  `RUWA_API_TOKEN` (a per-session `api_key` gets 401).
- **The key is stored sealed server-side** (`app_settings`, encrypted at rest when
  `RUWA_DB_ENCRYPTION_KEY` is set) and **never returned** — `GET` exposes only a
  `••••abcd` hint. `PUT`/`DELETE` respect `RUWA_READONLY`.
- Off until you configure it: the composer button is disabled and
  `POST /v1/ai/improve-text` answers `400 {"error":"ai assistant not configured — set it via PUT /v1/settings/ai"}`.

Configure — Anthropic (model defaults to `claude-opus-5`, base URL to
`https://api.anthropic.com`):

```sh
curl -X PUT localhost:8080/v1/settings/ai \
  -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'content-type: application/json' \
  -d '{"provider":"anthropic","api_key":"sk-ant-api03-EXAMPLE-not-a-real-key"}'
# → {"configured":true,"provider":"anthropic","model":"claude-opus-5",
#    "base_url":"https://api.anthropic.com","system_prompt":null,"api_key_hint":"••••-key"}
```

Configure — OpenAI-compatible (`model` is required; `base_url` defaults to
`https://api.openai.com/v1`, point it at OpenRouter / Groq / Ollama instead):

```sh
curl -X PUT localhost:8080/v1/settings/ai \
  -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'content-type: application/json' \
  -d '{"provider":"openai","api_key":"sk-EXAMPLE-not-a-real-key","model":"gpt-4o-mini",
       "base_url":"https://openrouter.ai/api/v1",
       "system_prompt":"You rewrite WhatsApp messages for a barber shop; keep it warm and short."}'
```

`api_key` may be omitted on a later `PUT` to keep the stored key (same provider);
`system_prompt` overrides the built-in WhatsApp-tuned prompt. Check the wiring with
`POST /v1/settings/ai/test` (`{"ok":true,"provider","model","latency_ms","reply"}`)
and remove everything with `DELETE /v1/settings/ai` (204).

Rewrite a draft:

```sh
curl -X POST localhost:8080/v1/ai/improve-text \
  -H "Authorization: Bearer $RUWA_API_TOKEN" -H 'content-type: application/json' \
  -d '{"text":"hey, ur appointment is tmrw 3pm, pls confirm","mode":"formal"}'
# → {"text":"Hi! Your appointment is tomorrow at 3 pm — could you please confirm?",
#    "provider":"anthropic","model":"claude-opus-5"}
```

`mode` is one of `improve` (default) · `formal` · `casual` · `shorter` · `grammar` ·
`translate` (needs `"language":"pt-BR"`) · `custom` (needs `"instruction"`, ≤ 500
chars); `text` is 1–8000 chars. Upstream failures come back as
`502 {"error":"ai upstream: <status> <message>"}`; a model refusal as
`422 {"error":"ai declined to rewrite this text"}`.

## Contributing

The one hard rule: **no Baileys, no whatsmeow, no third-party WhatsApp library** — the
protocol logic stays ours (RustCrypto / dalek / snow / aes-gcm and friends are fine).
Every commit must pass `cargo check && cargo test && cargo clippy --all-targets -- -D warnings`.
See [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) for conventions and the codebase map.

## License

ruwa is free software licensed under the **GNU Affero General Public License v3.0**
(AGPL-3.0) — see [LICENSE](LICENSE). If you run a modified version of ruwa as a network
service, the AGPL requires you to make the corresponding source available to its users.

© 2026 OQVA Digital.
