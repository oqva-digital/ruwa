#!/usr/bin/env bash
# No-phone, zero-WA probes for ruwa: restore time + RAM × N idle sessions.
# Usage: bash bench/probe.sh   (run from the repo root; needs the release binary)
set -euo pipefail

BIN=./target/release/ruwa
PORT=8099
DB=/tmp/ruwa-probe.db
TOKEN=t
BASE="http://127.0.0.1:$PORT"

[ -x "$BIN" ] || { echo "build first: cargo build --release"; exit 1; }
command -v python3 >/dev/null || { echo "need python3"; exit 1; }

now() { python3 -c 'import time;print(time.time())'; }
rss_mb() { ps -o rss= -p "$1" | awk '{printf "%.1f",$1/1024}'; }

start() { # -> echoes pid, waits for ready
  rm -f "$DB" "$DB"-* 2>/dev/null || true
  RUWA_BIND="127.0.0.1:$PORT" RUWA_STORE="$DB" RUWA_API_TOKEN="$TOKEN" "$BIN" >/tmp/ruwa-probe.log 2>&1 &
  local pid=$!
  for _ in $(seq 1 300); do curl -fsS "$BASE/health" >/dev/null 2>&1 && break; sleep 0.02; done
  echo "$pid"
}
mksessions() { # $1 = count
  for i in $(seq 1 "$1"); do
    curl -s -o /dev/null -XPOST -H "authorization: Bearer $TOKEN" \
      -H 'content-type: application/json' -d "{\"label\":\"p$i\"}" "$BASE/v1/sessions"
  done
}

echo "=== Probe 1: RAM x N idle sessions ==="
PID=$(start)
echo "base (0 sessions): $(rss_mb "$PID") MB"
made=0
for target in 10 50 100 200; do
  mksessions $((target-made)); made=$target; sleep 1
  echo "N=$target -> $(rss_mb "$PID") MB"
done
kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true

echo
echo "=== Probe 2: restore time with N persisted sessions ==="
# Reuse the DB from probe 1 (200 sessions persisted). Restart, time to ready.
t0=$(now)
RUWA_BIND="127.0.0.1:$PORT" RUWA_STORE="$DB" RUWA_API_TOKEN="$TOKEN" "$BIN" >/tmp/ruwa-probe.log 2>&1 &
PID=$!
for _ in $(seq 1 600); do curl -fsS "$BASE/health" >/dev/null 2>&1 && break; sleep 0.01; done
t1=$(now)
N=$(curl -s -H "authorization: Bearer $TOKEN" "$BASE/v1/sessions" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)))')
python3 -c "print(f'restore {$N} sessions -> ready in {($t1-$t0)*1000:.0f} ms')"
kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true
rm -f "$DB" "$DB"-* 2>/dev/null || true
echo "done."
