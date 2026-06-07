# Benchmark — load / speed (ruwa)

Measured 2026-06-01 on this machine (Apple Silicon, release build), fresh server
on `:8099` with a temp SQLite store. These are the **honest, reproducible** speed
numbers — no live WhatsApp (that needs paired phones, is rate-limited, ban-risky).

| metric | ruwa | how |
|---|---|---|
| **Cold start** (exec → `/health` 200) | **439 ms** | includes migrations + bind |
| **Idle RAM** (0 sessions) | **11.0 MB** RSS | fresh process |
| **RAM / session** (idle/pending) | **~108 KB** | 100 sessions → 21.5 MB |
| **HTTP throughput** (`/health`, 50 conns, 5 s) | **~180,800 req/s** | `oha` |
| **Latency** | p50 **0.27 ms**, p99 **0.36 ms**, 100% success | `oha` |
| **Projection** | ~1,000 idle sessions ≈ ~120 MB | 11 MB + 108 KB×N |

## Honest caveats

- **Throughput is on `/health`** — it measures the axum/tokio HTTP stack ceiling,
  not WhatsApp message send/receive (which is gated by WA's own servers, not us).
- **RAM/session is for *idle* sessions** (registered, not connected). A *live*
  session holds a WebSocket + Signal state — more, but still small; can't measure
  without pairing.
- **No cross-runtime load run yet.** A fair Evolution/Baileys comparison needs
  those servers up under the same harness (Evolution also needs Postgres+Redis).
  Their published characteristics (Node event loop, ~150–300 MB idle) put them an
  order of magnitude above ours on RAM; req/s on a trivial endpoint would be
  Node-express-class (tens of thousands/s), below a Rust+tokio stack. Left as a
  follow-up if a head-to-head number is wanted.

## Reproduce

```sh
RUWA_BIND=127.0.0.1:8099 RUWA_STORE=/tmp/b.db RUWA_API_TOKEN=t \
  ./target/release/ruwa &
oha -z 5s -c 50 http://127.0.0.1:8099/health        # throughput
# RAM/session: POST /v1/sessions ×N, then `ps -o rss= -p <pid>`
```

## Head-to-head (measured 2026-06-01, this machine)

| | artifact | idle RAM | req/s (trivial GET) | p50 latency |
|---|---|---|---|---|
| **ruwa** | 9.3 MB binary / 173 MB image | **11 MB** (1 process) | **~180,800** | **0.27 ms** |
| Evolution 2.3.7 | **1.75 GB** image | **~278 MB** (api 229 + pg 40 + redis 9) | **~205** | 235 ms |
| whatsmeow (our Go harness) | 20 MB binary | 18.2 MB | — (harness ≠ real server) | — |
| Baileys | (npm lib) | — (harness not built — npm install heavy) | — | — |

Caveats: req/s endpoints differ slightly (ours `/health`, Evolution `/`), both
trivial; the ~880× gap reflects Rust+tokio vs a Node single-thread + middleware
stack under 50 concurrent conns. whatsmeow/Baileys are libraries, so a req/s
number there measures the wrapper, not the lib — only their *footprint* is
comparable, and ours (9.3 MB / 11 MB) is lighter than even the Go harness.

**Not yet measured: RAM per *live* WhatsApp session** (paired WS + Signal state).
Needs real phones to scan QRs on each system — the most informative per-session
number, best done as a coordinated run. Our *idle/pending* per-session cost is
~108 KB; a live session adds a WebSocket + ratchet state.

## Live end-to-end message latency (measured 2026-06-01, real WhatsApp, 3 stacks)

**Single, identical metric for all three:** send API call → message ARRIVES at
the recipient device, read by **one shared reader** (an Evolution/Baileys
instance on the recipient phone, via its `MESSAGES_UPSERT` webhook). All three
senders sit on the same number → same recipient → same WA path → same reader, so
the reader's constant overhead cancels and only the **send path** differs. (Earlier
attempts mixed one-way vs delivery-receipt metrics and were NOT comparable — do
not trust mixed-metric numbers; this single-reader method is the honest one.)

| Stack | p50 | min–max | mean | n |
|---|---|---|---|---|
| **ruwa** (with device-list cache) | **263 ms** | 249–279 | 263 | 10 |
| whatsmeow | 382 ms | 353–439 | 386 | 10 |
| Evolution 2.3.7 | 712 ms | 659–762 | 713 | 10 |

**ruwa is fastest** — but only after the device-list cache fix. **Before** the fix,
ruwa was **slowest at p50 1319 ms** because `send_text_op` did **two blocking
`usync` device-list round-trips per message** (~1050 ms ≈ 83% of send latency; a
live trace showed dequeue→usync#1 +530ms → usync#2 +523ms → ack +220ms). Caching
the device list (invalidated on `<notification type="devices">`) cut ruwa
**1319 → 263 ms (~5×)**; whatsmeow/Evolution were unchanged run-to-run, confirming
the rig is stable and only ruwa moved.

Method: `/tmp/reader_lat.py` (3 senders → shared Evolution reader on the
recipient). NOTE: rapid pair/unpair churn on real numbers gets devices evicted
(`device_removed` / 401) and the number throttled (503) — pace it and prefer
throwaway numbers; we burned through a lot of session churn getting here.

## Live RECEIVE processing cost — 3-way head-to-head (measured 2026-06-03, real WhatsApp)

Unlocked once ruwa decrypted reliably (3 receive bugs fixed first — see below).
**THE fair metric: `recv→ack`** — the interval from the encrypted `<message>` frame
arriving on a client's socket to that client putting its `<receipt>` back on the
socket. Every WhatsApp protocol client does exactly this, and **both timestamps come
from the same client's own wire log** → it's an *intra-client interval*, so there is
**zero cross-clock, webhook-vs-callback, or transport asymmetry**. This is the only
truly apples-to-apples metric across a server (ruwa), a server-on-a-library
(Evolution/Baileys) and a raw library (whatsmeow).

Rig: one sender (`freshEvoA`, Phone A) → same message to **3 readers on the same
Phone B** (ruwa, evoReaderB, whatsmeow). `recv→ack` extracted per client from its own
wire trace (ruwa debug wire log; whatsmeow `WM_DEBUG` node log; Evolution
`LOG_BAILEYS=trace` `recv xml`/`xml send`). N=12.

| protocol | recv→ack p50 | mean | max |
|---|---|---|---|
| **ruwa** | **1.1 ms** | 1.3 | 3.1 |
| whatsmeow | 3.0 ms | 3.2 | 7.0 |
| Evolution | 5.0 ms | 4.8 | 9.0 |

**ruwa is fastest on all 12 messages — ~3× faster than whatsmeow, ~4.5× faster than
Evolution** at the pure protocol-processing cost (Signal decrypt + protobuf decode +
emit receipt). Caveat: whatsmeow/Evolution log at whole-ms granularity (±0.5 ms
quantization); ruwa at µs — immaterial at this gap. Scripts: `/tmp/h2h3*` (send) +
inline parser over the three wire logs.

**A note on an earlier, weaker cut:** a first pass timed "message surfaced to the
*consumer*" (ruwa+Evolution webhook emit vs whatsmeow in-process callback). That
conflated each stack's *egress* path — apples-to-bananas — so it's superseded by the
wire-level `recv→ack` above. (For the record, server-vs-server at the webhook,
ruwa also beat Evolution 12/12 by ~13–31 ms; and WhatsApp gives the sender only ONE
account-level `DELIVERY_ACK`, not per-device, so sender-side per-reader timing is not
observable — which is why the intra-client wire interval is the right metric.)

Honest caveats: (1) the absolute ~977 ms is ~90% WhatsApp+network, reported only
for context. (2) Capture asymmetry — ruwa posts the webhook via loopback,
Evolution via container→host NAT (~0.5–2 ms favoring ruwa) — small vs the 31 ms,
doesn't change the conclusion. (3) Both readers are linked devices of the same
account; 15/15 consistency + tight spread argue it's client overhead, not phone
fan-out jitter. Method: `/tmp/h2h_run.py` + `/tmp/h2h_recv.py` (unified receiver).

**Receive correctness:** the H2H was only possible after fixing three real
receive bugs this session (all live-verified): 16-byte message pad rejected
(`unpad`), missing `peer_msg`/`sender` receipts, and `extendedTextMessage` (the
text variant for replies/link-previews/business sends) decoding as null. Before
these, ruwa stored its own traffic as undecryptable/unknown.

## Live RAM (1 paired session, rough) — measured 2026-06-03

ruwa process with **1 live paired session: 33.8 MB RSS** (vs 11 MB idle).
evo-api container: **131 MB** (+ evo-pg 129 MB + evo-redis 12 MB = ~272 MB
full-stack). Rough (single sample, ruwa's includes dashboard + the synced 1000-msg
bootstrap), but the order-of-magnitude full-stack gap (~34 MB vs ~272 MB) holds.

## No-phone probes (`bench/probe.sh`, measured 2026-06-01)

- **RAM × idle sessions:** base 11.0 MB → 10:12.1 → 50:13.9 → 100:16.2 → 200:20.8 MB
  ⇒ **~50 KB per idle session** (cleaner than the earlier 108 KB one-shot).
- **Restore time (200 persisted sessions → ready):** **29 ms**.
