# ruwa — Rust WhatsApp Client

**API-first and MCP-ready: a multi-tenant WhatsApp client in Rust — one small binary that turns WhatsApp into a clean HTTP API _and_ a set of MCP tools for AI agents.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)

ruwa is a from-scratch port of [whatsmeow](https://github.com/tulir/whatsmeow): it
speaks WhatsApp's multi-device (WhatsApp Web) protocol directly and exposes it as a
bearer-authed REST API with Server-Sent Events, webhooks, and Redis event streams.
**No Baileys, no whatsmeow runtime, no FFI, no heavy SDKs** — Signal, Noise, the WA
binary protocol, the Redis and S3 clients, and SigV4 are all implemented in-house.
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
| **Agent tools (MCP)** | **built-in — 38 tools** | none | none |
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
Numbers are single-machine and point-in-time — see [`bench/`](bench/) for the rigs and
caveats.

## Features

- **Messaging** — text with **@mentions** and **reply/quote**, media
  (image/video/audio/ptt/document/sticker), **location**, **contact (vCard)**,
  **poll**, **calendar event**, reactions, edit, revoke.
- **Multi-tenant sessions** — pair via QR, many accounts per instance, **per-tenant
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
- **Agent-ready (MCP)** — a first-party **Model Context Protocol** server (`mcp/`)
  exposing 38 tools so any MCP client (Claude, etc.) can create instances, pair them,
  send every message type, manage chats, and **search history by meaning** — no other
  WhatsApp stack ships this.

## Agent-ready (MCP)

ruwa ships a first-party **Model Context Protocol** server (`mcp/ruwa-mcp`) so an AI
agent can drive WhatsApp directly — no REST glue. As far as we know, no other WhatsApp
stack (Evolution, whatsmeow, Baileys) offers this out of the box.

**38 tools** cover the full lifecycle — _create an instance → pair it (QR) → hold a
conversation → wire up webhooks_: `create_session`, `get_qr`, `connect_session`,
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

- You need the **official** WhatsApp Business Cloud API — Meta's compliance, SLAs,
  template messaging at scale, and support. ruwa speaks the *unofficial* Web protocol.
- You can't tolerate account-ban risk or operating in a ToS gray area.
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
| `RUST_LOG` | `info` | Tracing filter |

Full list (S3, leasing, retention, WA version override) in [`.env.example`](.env.example).

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
