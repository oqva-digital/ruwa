# ruwa soak monitor

A zero-dependency (Python 3.9+ stdlib) watchdog that measures **product
readiness** of a live ruwa deployment — not "is the port up", but "can it
actually send and receive, for how long, without going zombie".

## What it checks

| Concern | How |
| --- | --- |
| **Zombie connection** (the Evolution failure: WS open but dead) | Polls `/v1/sessions/:id/health`; flags `connected:true` while `seconds_since_rx` climbs past `ZOMBIE_THRESHOLD_SEC`. |
| **Disconnect / reconnect** | Tracks `status` transitions + `reconnect_count` churn from health polling, and `disconnected`/`connected` events from the SSE stream. |
| **End-to-end delivery** | Drives a human-paced A↔B conversation; every sent message is a probe confirmed *received* by the other account (via SSE and/or webhook) within `ROUNDTRIP_TIMEOUT_SEC`. Correlated by WhatsApp message-id (invisible — the chat reads natural). |
| **Delivery acks** | Tracks `message_sent` → `message_delivered` per probe, with latency. |
| **Webhook send/receive** | Registers a webhook on both sessions → this service's public URL; verifies each callback's HMAC-SHA256 signature, matches it to a probe, measures webhook latency vs SSE. |

Live dashboard at `GET /` (auto-refresh), JSON at `GET /report`, Railway
health at `GET /healthz`.

## Run locally (quick validation, SSE-only)

Webhooks need a public URL, so a local run is SSE-only unless you set
`WEBHOOK_PUBLIC_URL`. Use `FAST=1` to compress the 15–50 min cadence to seconds.

```sh
export RUWA_BASE_URL="https://your-ruwa.up.railway.app"
export RUWA_API_TOKEN="<admin token>"
export FAST=1
python3 monitor.py
# open http://localhost:8090
```

Sessions are auto-discovered (first two `connected`). Pin them with
`SESSION_A` / `SESSION_B` if you have more than two.

## Deploy as a separate Railway service (full soak + webhooks)

Running it on Railway gives it a public domain, which becomes the webhook
target — no tunnel needed.

1. New service in the same Railway project, root directory `monitor/`
   (it has its own `Dockerfile` + `railway.json`).
2. Generate a domain for the service (Settings → Networking).
3. Set variables:
   - `RUWA_BASE_URL` = your ruwa service URL
   - `RUWA_API_TOKEN` = ruwa admin token
   - `WEBHOOK_PUBLIC_URL` = this monitor's Railway URL *(or rely on the
     auto-injected `RAILWAY_PUBLIC_DOMAIN`)*
   - leave `FAST` unset for the real 15–50 min human cadence
4. Deploy. Watch the dashboard at the monitor's domain, or `railway logs`.

## Tuning (env)

| var | default | meaning |
| --- | --- | --- |
| `HEALTH_POLL_SEC` | 30 | health-poll cadence |
| `ZOMBIE_THRESHOLD_SEC` | 90 | rx-gap that counts as a zombie |
| `ROUNDTRIP_TIMEOUT_SEC` | 180 | unconfirmed probe = failure after this |
| `IDLE_MIN_SEC` / `IDLE_MAX_SEC` | 900 / 3000 | gap between conversation topics |
| `WEBHOOK_SECRET` | random/run | HMAC secret for webhook signatures |
| `FAST` | 0 | `1` compresses all human gaps ~30× |
| `AUTO_RECOVER` | 0 | `1` = self-heal: `POST /connect` a session parked `disconnected`/`proxy_error`/`blocked`. Off by default so the soak *measures* ruwa's own recovery instead of masking it. |
| `AUTO_RECOVER_AFTER_SEC` | 60 | how long parked before a recovery kick |

The conversation content lives in `THREADS` in `monitor.py` — pt-BR casual chat;
edit to taste.
