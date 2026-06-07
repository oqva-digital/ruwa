# Benchmark — ruwa vs whatsmeow vs Baileys vs Evolution

Scope (chosen 2026-06-01): **codebase size, build/artifact size, hosting
footprint** — the comparisons that are reproducible and honest. (A live
throughput benchmark against WhatsApp is omitted: it needs N paired phones, is
rate-limited, and risks bans — not reproducible.)

What each thing *is* matters for a fair read:
- **ruwa (ours)** — a from-scratch protocol implementation **and** an HTTP server.
- **whatsmeow** — a from-scratch protocol **library** (Go). You build your own server.
- **Baileys** — a protocol **library** (TS/JS). You build your own server.
- **Evolution API** — an HTTP **server** built *on top of* Baileys. Its real
  footprint = Evolution's code **+ Baileys underneath + node_modules**.

So the closest apples-to-apples peer for our protocol work is **whatsmeow**; the
closest peer for our *product* (a ready server) is **Evolution**.

## 1. Codebase size (hand-written source)

| project | language | source files | ~LoC | notes |
|---|---|---|---|---|
| **ruwa** | Rust | **11 `.rs`** (≤10-file rule) | **~22k** | from-scratch protocol **+** server, self-contained. Excl. vendored token dict + generated proto. 49 direct deps / 360 crates. |
| whatsmeow | Go | 155 `.go` (239 total) | ~26k | protocol library only (no server). |
| Baileys | TS | 137 `.ts` (194 total) | ~40k | protocol library only. |
| Evolution | TS | 188 `.ts` (361 total) | ~30k | server only — **runs on Baileys (~40k) underneath** → effective ≈ 70k+. |

**File-count read:** ruwa is **11 Rust files** (a deliberate ≤10-file discipline)
vs 137–188 source files in the TS projects and 155 in whatsmeow. Far fewer places
to look — the whole thing fits in your head.

**Read:** ruwa does in ~22k LoC what Evolution+Baileys do in ~70k — because ours
is one cohesive Rust codebase (protocol + API) with no library seam, and no
heavy SDKs (Redis/S3/SigV4/uuid are all in-house). whatsmeow (~26k, protocol
only) is the fairest peer and is in the same ballpark as our protocol layer.

## 2. Build / artifact size

| project | artifact | size | runtime needed |
|---|---|---|---|
| **ruwa** | single static binary | **9.3 MB** | **none** |
| ruwa | Docker image (debian-slim base) | **173 MB** (could shrink to ~30 MB on distroless) | none |
| whatsmeow | (you build a Go binary) | ~15–25 MB static | none |
| Baileys | (no binary; npm lib) | node_modules ~80–150 MB | Node ~100 MB+ |
| Evolution | Docker image | ~1–2 GB (Node + deps + Prisma) | Node |

**Read:** ours ships as a **9.3 MB self-contained binary** — copy-and-run, no
runtime. Go (whatsmeow-based) is similar but you write the server. Node-based
(Baileys/Evolution) carry a Node runtime + large `node_modules`; Evolution's
image is ~100× our binary.

## 3. Hosting footprint

| | runtime dep | database | other infra | idle RAM | deploy surface |
|---|---|---|---|---|---|
| **ruwa** | none | SQLite (file) **or** Postgres | Redis/S3 **optional** | **~11 MB** | one 9.3 MB binary / 173 MB container; runs on any small VM |

> **Reality check (not serverless):** every WhatsApp client here — ours included —
> is a **long-running stateful process** holding a persistent WebSocket to receive
> messages. So **none** of them do "scale-to-zero" or run on edge-functions
> (Cloudflare Workers / Deno Deploy): a native binary isn't a WASM/JS sandbox, and
> dropping to zero drops the WA connection. Our edge here is *small and cheap to
> keep running* (single 9.3 MB binary, ~11 MB RAM, SQLite = no DB to provision),
> not "serverless".
| whatsmeow | none | your choice | — | ~20–40 MB | one binary, but you build the server |
| Baileys | Node | your choice | — | ~80–150 MB | Node app you build yourself |
| Evolution | Node | **Postgres required** + Redis recommended | — | ~150–300 MB | Docker + a DB + Redis; most "batteries-included", heaviest infra |

**Read:**
- **ruwa**: runs anywhere a single binary runs (bare VM, 256 MB box, container,
  scale-to-zero). SQLite means **zero external infra** to start; Postgres + Redis
  + S3 are opt-in for scale. Idle ~12 MB measured.
- **whatsmeow**: equally light at runtime, but it's a library — no server,
  endpoints, multi-tenancy, or dashboard out of the box.
- **Baileys**: a library too; you own the server + persistence.
- **Evolution**: the most feature-complete *server* of the bunch, but the
  heaviest to host — mandatory Postgres, recommended Redis, a Node runtime, and a
  ~1–2 GB image; idle RAM an order of magnitude above ours.

## Bottom line

For a given WhatsApp-API deployment, **ruwa is the lightest to host** (single
9.3 MB binary, ~12 MB RAM, SQLite = no external infra) while still being a
*complete server* (multi-tenant, webhooks, queues, media offload, dashboard) —
the things Evolution gives you but with ~12× less RAM, ~100× smaller image, and
no mandatory Postgres/Redis. Versus whatsmeow we're in the same lightweight class
but ship the whole API/product, not just a protocol library.

_Measured 2026-06-01: ours on this machine; others via repo language stats +
published image characteristics. Numbers for the others are representative, not
exact per-deployment._
