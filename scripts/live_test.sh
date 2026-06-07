#!/usr/bin/env bash
# Live end-to-end harness: pairs one WhatsApp number to a fresh session, waits
# for the socket to come up, then tails inbound messages so you can send between
# your two numbers and watch them land. Outbound send helper printed at the end.
#
#   RUWA_API_TOKEN=$(openssl rand -hex 32) ./scripts/live_test.sh
#
# Requires: curl, jq. Optional: qrencode (renders a scannable QR in the terminal;
# without it the harness writes qr.svg for you to open in a browser).
set -euo pipefail

BASE="${RUWA_BASE:-http://127.0.0.1:8080}"
TOKEN="${RUWA_API_TOKEN:?set RUWA_API_TOKEN (e.g. export RUWA_API_TOKEN=$(openssl rand -hex 32))}"
DATA_DIR="${RUWA_DATA_DIR:-./data-livetest}"
auth=(-H "authorization: Bearer ${TOKEN}")

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need curl; need jq

# 1. Start the server in the background (release build) unless one is already up.
SERVER_PID=""
if ! curl -fsS "${BASE}/health" >/dev/null 2>&1; then
  echo "==> building + starting ruwa on ${BASE}"
  mkdir -p "${DATA_DIR}"
  RUWA_BIND="${BASE#http://}" RUWA_STORE="${DATA_DIR}/ruwa.db" RUWA_API_TOKEN="${TOKEN}" \
    RUST_LOG="${RUST_LOG:-info,ruwa=info}" \
    cargo run --release >"${DATA_DIR}/server.log" 2>&1 &
  SERVER_PID=$!
  trap '[ -n "${SERVER_PID}" ] && kill "${SERVER_PID}" 2>/dev/null || true' EXIT
  echo -n "==> waiting for server"
  until curl -fsS "${BASE}/health" >/dev/null 2>&1; do echo -n .; sleep 0.5; done
  echo " up (logs: ${DATA_DIR}/server.log)"
else
  echo "==> reusing server already running on ${BASE}"
fi

# Preflight: make sure OUR token actually authenticates. Catches the common case
# of a stale server already on this port with a different (auto-generated) token.
if ! curl -fsS -o /dev/null "${auth[@]}" "${BASE}/v1/sessions"; then
  port="${BASE##*:}"
  echo "ERROR: a server on ${BASE} rejected this RUWA_API_TOKEN (401)." >&2
  echo "       It was started with a different token. Kill it and re-run:" >&2
  echo "         lsof -ti:${port} | xargs kill 2>/dev/null" >&2
  exit 1
fi

# 2. Create a session + kick off the connect (pairing) flow.
echo "==> creating session"
created=$(curl -fsS "${auth[@]}" -H 'content-type: application/json' \
  -d '{"label":"live-test"}' "${BASE}/v1/sessions")
SID=$(jq -r .id <<<"${created}")
SKEY=$(jq -r .api_key <<<"${created}")
echo "    session id : ${SID}"
echo "    session key: ${SKEY}"
curl -fsS "${auth[@]}" -X POST "${BASE}/v1/sessions/${SID}/connect" >/dev/null

# 3. Render the live QR, re-fetching as it rotates (~every 20s the server
#    advertises the next ref), until the socket reaches connected. Open WhatsApp
#    > Linked Devices > Link a device, and scan whatever is currently on screen.
have_qrencode=0
command -v qrencode >/dev/null 2>&1 && have_qrencode=1 || \
  echo "    (no qrencode — install with: brew install qrencode. Falling back to ${DATA_DIR}/qr.svg)"

echo "==> pairing: open WhatsApp > Linked Devices > Link a device, then scan below"
LAST_QR=""
CONNECTED=0
for _ in $(seq 1 200); do          # ~10 min at 3s/iter
  st=$(curl -fsS "${auth[@]}" "${BASE}/v1/sessions/${SID}/health" 2>/dev/null | jq -r '.status // "?"')
  if [ "${st}" = "connected" ]; then CONNECTED=1; break; fi

  resp=$(curl -fsS "${auth[@]}" "${BASE}/v1/sessions/${SID}/qr" 2>/dev/null || true)
  QR=$(jq -r '.qr // empty' <<<"${resp}" 2>/dev/null || true)
  if [ -n "${QR}" ] && [ "${QR}" != "${LAST_QR}" ]; then
    LAST_QR="${QR}"
    clear 2>/dev/null || printf '\033[2J\033[H'
    echo "==> SCAN THIS (status: ${st}, refreshes automatically) — Ctrl-C to abort"
    if [ "${have_qrencode}" = "1" ]; then
      qrencode -t ANSIUTF8 <<<"${QR}"
    else
      jq -r '.svg_base64' <<<"${resp}" | base64 -d > "${DATA_DIR}/qr.svg"
      echo "    open ${DATA_DIR}/qr.svg in a browser and scan it (re-open on refresh)"
    fi
  else
    printf '\r    waiting… status=%s   ' "${st}"
  fi
  sleep 3
done

echo
[ "${CONNECTED}" = "1" ] || { echo "did not reach connected — check ${DATA_DIR}/server.log"; exit 1; }
echo "==> CONNECTED. Now send a message from your OTHER number to this one."
echo "    Outbound (this number -> a contact):"
echo "      curl -s -H 'authorization: Bearer ${SKEY}' -H 'content-type: application/json' \\"
echo "        -d '{\"to\":\"<E164-no-plus>\",\"text\":\"hi from ruwa\"}' \\"
echo "        ${BASE}/v1/sessions/${SID}/messages"
echo
echo "==> tailing inbound events (Ctrl-C to stop)…"
curl -fsS --no-buffer "${auth[@]}" "${BASE}/v1/sessions/${SID}/events"
