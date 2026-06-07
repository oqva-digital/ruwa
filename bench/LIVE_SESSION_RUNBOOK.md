# Runbook — RAM per *live* WhatsApp session (ruwa vs Evolution)

Goal: measure how much RAM **one paired/connected** WhatsApp session costs, on
ours vs Evolution. Needs **real phones to scan QR** (2 per system). Both servers
can pair out of the box. (whatsmeow/Baileys would need harness work to pair — see
bottom.)

Method everywhere: **baseline RSS (0 sessions) → pair N sessions → RSS again →
per-session = (RSS_N − baseline) / N.** Idle/pending session ≈ 108 KB (ours);
a *live* one adds a WebSocket + Signal ratchet state.

---

## A) ruwa

```sh
cd ~/development/ruwa
# 1. fresh server
rm -f /tmp/ruwa-live.db*
RUWA_BIND=127.0.0.1:8099 RUWA_STORE=/tmp/ruwa-live.db RUWA_API_TOKEN=t \
  ./target/release/ruwa & echo $! > /tmp/ruwa-live.pid
sleep 1
# 2. baseline RSS
ps -o rss= -p $(cat /tmp/ruwa-live.pid) | awk '{printf "baseline: %.1f MB\n",$1/1024}'

# 3. create + connect a session, then open the QR in the dashboard
curl -s -XPOST -H "authorization: Bearer t" -H 'content-type: application/json' \
  -d '{"label":"live1"}' http://127.0.0.1:8099/v1/sessions   # note the "id"
curl -s -XPOST -H "authorization: Bearer t" http://127.0.0.1:8099/v1/sessions/<ID>/connect
#   open http://127.0.0.1:8099/  (paste token t) → Pairing tab → scan the QR
#   wait until health shows "connected":
curl -s -H "authorization: Bearer t" http://127.0.0.1:8099/v1/sessions/<ID>/health

# 4. RSS after session 1, then repeat 3 for session 2, measure again
ps -o rss= -p $(cat /tmp/ruwa-live.pid) | awk '{printf "after N: %.1f MB\n",$1/1024}'
# per-session = (after - baseline) / N

kill $(cat /tmp/ruwa-live.pid)   # when done
```

## B) Evolution (already up: evo-api :8088, apikey `benchkey`)

```sh
# 1. baseline
docker stats --no-stream --format '{{.MemUsage}}' evo-api   # baseline RAM

# 2. create instance + scan QR — easiest via the manager UI:
#    open http://127.0.0.1:8088/manager  → login with apikey "benchkey"
#    → "Instance +" → name it → scan the QR with your phone
#    (CLI alt: POST /instance/create {"instanceName":"live1","integration":"WHATSAPP-BAILEYS","qrcode":true}
#     header apikey: benchkey  → QR in the response; GET /instance/connect/live1 to re-fetch)

# 3. RAM after each connected instance (repeat for instance 2)
docker stats --no-stream --format '{{.MemUsage}}' evo-api
# per-session = (after - baseline) / N   (Evolution shares one Node process, like ours)
```

Note: compare **evo-api RAM only** to ours (its Postgres+Redis are separate
processes; ours needs neither). Or compare full-stack if you want the honest
"total to host" number.

---

## C) whatsmeow / Baileys (optional — needs harness work first)

These are libraries; pairing isn't wired in `bench/whatsmeow-harness`. To measure
live RAM you'd add to each harness: QR pairing + a SQLite/file auth store, print
the QR, scan, then measure RSS. ~30–60 lines each. Decide if the extra data point
is worth it — the ours-vs-Evolution live number is the headline one.

## Cleanup (when finished benchmarking)

```sh
docker rm -f evo-api evo-pg evo-redis ruwa-minio
docker network rm evo-net ruwa-net
```
