#!/usr/bin/env python3
"""
ruwa soak monitor — product-readiness watchdog for a live ruwa deployment.

What it proves (not just "is the port up", but "can it actually deliver"):

  1. LIVENESS + ZOMBIE DETECTION
     Polls /v1/sessions/:id/health for every WhatsApp. Watches status,
     connected, seconds_since_rx, reconnect_count. Flags the exact Evolution
     failure mode: connected:true but seconds_since_rx climbing == zombie WS
     (socket open, but no frames arriving — dead-but-not-closed).

  2. END-TO-END ROUND-TRIP  (the real readiness test)
     Drives a human-paced conversation between the two connected accounts
     (A opens, B replies with 1-2 messages, irregular gaps, typing indicators,
     read receipts). Every sent message becomes a probe: we confirm the
     recipient ACTUALLY RECEIVED it (via SSE and/or webhook) within a timeout.
     Correlation is by WhatsApp message-id — invisible, so the chat reads like
     two real people. A pipe that's open-but-can't-deliver is caught here.

  3. WEBHOOK SEND/RECEIVE
     Registers a webhook on both sessions pointing at this service's own public
     URL. Verifies every callback's HMAC-SHA256 signature, matches it to a
     probe, and measures webhook-delivery latency vs the SSE stream. Webhooks
     are both exercised and monitored.

  4. DISCONNECT / RECONNECT
     Logs every connection-state transition (from health polling AND the SSE
     stream). On exit: uptime %, round-trip success rate, p50/p95 latencies,
     disconnect/reconnect counts, zombie incidents, webhook deliveries
     received vs expected.

Zero dependencies — Python 3.9+ stdlib only. Designed to run forever as a
separate Railway service (so its public domain is the webhook target), but
also runs locally for a quick FAST=1 validation pass.

Config (env):
  RUWA_BASE_URL          required. e.g. https://your-app.up.railway.app
  RUWA_API_TOKEN         required. admin token (RUWA_API_TOKEN of the target)
  SESSION_A, SESSION_B   optional. session ids to use. If unset, the first two
                         CONNECTED sessions are auto-discovered.
  PORT                   webhook receiver + dashboard port (Railway sets this). default 8090
  WEBHOOK_PUBLIC_URL     public base URL of THIS monitor, e.g. https://monitor.up.railway.app
                         If unset, derived from RAILWAY_PUBLIC_DOMAIN. If neither
                         is set, webhook testing is disabled (SSE-only) — fine
                         for a local validation run.
  WEBHOOK_SECRET         HMAC secret for webhook signatures. default: generated per run.
  FAST                   "1" compresses all human gaps (~30x) for a quick local soak.
  HEALTH_POLL_SEC        default 30
  ZOMBIE_THRESHOLD_SEC   default 90  (connected but no rx for this long == zombie)
  ROUNDTRIP_TIMEOUT_SEC  default 180 (probe unconfirmed after this == failure)
  IDLE_MIN_SEC/IDLE_MAX_SEC  gap between conversation topics. default 900/3000 (15-50 min)
"""

import os
import sys
import json
import time
import hmac
import random
import signal
import hashlib
import threading
import urllib.request
import urllib.error
from collections import deque, defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #

def env(name, default=None):
    v = os.environ.get(name)
    return v if v not in (None, "") else default

BASE_URL = (env("RUWA_BASE_URL") or "").rstrip("/")
TOKEN = env("RUWA_API_TOKEN")
SESSION_A = env("SESSION_A")
SESSION_B = env("SESSION_B")
PORT = int(env("PORT", "8090"))
FAST = env("FAST", "0") == "1"
HEALTH_POLL_SEC = float(env("HEALTH_POLL_SEC", "30"))
ZOMBIE_THRESHOLD_SEC = float(env("ZOMBIE_THRESHOLD_SEC", "90"))
ROUNDTRIP_TIMEOUT_SEC = float(env("ROUNDTRIP_TIMEOUT_SEC", "180"))
IDLE_MIN_SEC = float(env("IDLE_MIN_SEC", "900"))
IDLE_MAX_SEC = float(env("IDLE_MAX_SEC", "3000"))
# Opt-in self-heal: when a session sits parked (disconnected/proxy_error/blocked)
# longer than AUTO_RECOVER_AFTER_SEC, POST /connect to kick it. OFF by default so
# the soak MEASURES ruwa's own recovery rather than masking it.
AUTO_RECOVER = env("AUTO_RECOVER", "0") == "1"
AUTO_RECOVER_AFTER_SEC = float(env("AUTO_RECOVER_AFTER_SEC", "60"))
# statuses that a POST /connect can revive (logged_out needs a QR re-pair, so skip)
RECOVERABLE = {"disconnected", "proxy_error", "blocked"}
WEBHOOK_SECRET = env("WEBHOOK_SECRET", hashlib.sha256(os.urandom(16)).hexdigest()[:32])

# public URL this monitor is reachable at (for webhook registration)
_pub = env("WEBHOOK_PUBLIC_URL")
if not _pub:
    rail = env("RAILWAY_PUBLIC_DOMAIN")
    if rail:
        _pub = "https://" + rail.rstrip("/")
WEBHOOK_PUBLIC_URL = _pub.rstrip("/") if _pub else None
WEBHOOK_PATH = "/webhook"

# how much to compress human timing in FAST mode
SCALE = (1.0 / 30.0) if FAST else 1.0

EVENTS_OF_INTEREST = [
    "message", "message_sent", "message_delivered",
    "connected", "disconnected", "logged_out",
]

if not BASE_URL or not TOKEN:
    sys.stderr.write("FATAL: RUWA_BASE_URL and RUWA_API_TOKEN are required.\n")
    sys.exit(2)


def log(msg, level="INFO"):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} [{level}] {msg}"
    print(line, flush=True)


# --------------------------------------------------------------------------- #
# HTTP client (stdlib)
# --------------------------------------------------------------------------- #

def api(method, path, body=None, timeout=30):
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {TOKEN}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            status = r.status
    except urllib.error.HTTPError as e:
        return e.code, _maybe_json(e.read())
    except Exception as e:  # noqa: BLE001 (transient network is expected in a soak)
        return None, {"error": str(e)}
    return status, _maybe_json(raw)


def _maybe_json(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:  # noqa: BLE001
        return raw.decode(errors="replace")


def jid_to_number(jid):
    """'5511999:47@s.whatsapp.net' -> '5511999'."""
    if not jid:
        return None
    return jid.split("@", 1)[0].split(":", 1)[0]


# --------------------------------------------------------------------------- #
# shared metrics
# --------------------------------------------------------------------------- #

class Metrics:
    def __init__(self):
        self.lock = threading.RLock()
        self.start_ts = time.time()

        # server-level health sampling
        self.server_ok = 0
        self.server_fail = 0
        self.server_last_ok = None

        # per-session health: id -> dict
        self.sess = defaultdict(lambda: {
            "status": None, "connected": False,
            "last_change": time.time(),
            "disconnects": 0, "reconnects": 0,
            "zombie_incidents": 0, "max_secs_since_rx": 0.0,
            "reconnect_count": 0, "samples": 0, "connected_samples": 0,
            "sse_up": False, "sse_drops": 0,
            "last_kick": 0.0, "recover_kicks": 0,
        })

        # probes: msg_id -> dict
        self.probes = {}

        # counters
        self.sent_total = 0
        self.rt_sse_ok = 0
        self.rt_webhook_ok = 0
        self.rt_timeout = 0
        self.delivered_acks = 0

        # latency samples (seconds)
        self.lat_sse = []
        self.lat_webhook = []
        self.lat_delivered = []

        # webhook receiver stats
        self.wh_received = 0
        self.wh_sig_ok = 0
        self.wh_sig_bad = 0
        self.wh_by_event = defaultdict(int)

        # inbound (non-probe) counts by source
        self.inbound = defaultdict(int)

        # rolling incident log
        self.incidents = deque(maxlen=200)

    def incident(self, kind, msg):
        with self.lock:
            self.incidents.appendleft({
                "t": time.strftime("%H:%M:%S"), "kind": kind, "msg": msg,
            })
        log(f"{kind}: {msg}", level="WARN" if kind != "RECOVER" else "INFO")


M = Metrics()


def pct(vals, p):
    if not vals:
        return None
    s = sorted(vals)
    k = int(round((p / 100.0) * (len(s) - 1)))
    return s[k]


# --------------------------------------------------------------------------- #
# event handling (shared by SSE + webhook)
# --------------------------------------------------------------------------- #

def handle_event(session_id, ev_type, data, source):
    """source is 'sse' or 'webhook'. session_id is whose stream it came on."""
    now = time.time()
    with M.lock:
        if source == "webhook":
            M.wh_by_event[ev_type] += 1

        if ev_type == "message":
            mid = (data or {}).get("id")
            pr = M.probes.get(mid) if mid else None
            if pr and pr["dst"] == session_id:
                key = "sse_ok_ts" if source == "sse" else "webhook_ok_ts"
                if pr.get(key) is None:
                    pr[key] = now
                    lat = now - pr["sent_ts"]
                    if source == "sse":
                        if pr.get("sse_counted") is None:
                            pr["sse_counted"] = True
                            M.rt_sse_ok += 1
                            M.lat_sse.append(lat)
                    else:
                        if pr.get("wh_counted") is None:
                            pr["wh_counted"] = True
                            M.rt_webhook_ok += 1
                            M.lat_webhook.append(lat)
            else:
                # a real inbound message (not one of our probes), or a probe
                # we already retired. Still proves the receive pipe is alive.
                M.inbound[source] += 1

        elif ev_type == "message_sent":
            mid = (data or {}).get("id")
            pr = M.probes.get(mid) if mid else None
            if pr and pr["src"] == session_id and pr.get("sent_ack_ts") is None:
                pr["sent_ack_ts"] = now

        elif ev_type == "message_delivered":
            mid = (data or {}).get("id")
            pr = M.probes.get(mid) if mid else None
            if pr and pr["src"] == session_id and pr.get("delivered_ack_ts") is None:
                pr["delivered_ack_ts"] = now
                M.delivered_acks += 1
                M.lat_delivered.append(now - pr["sent_ts"])

        elif ev_type in ("disconnected", "logged_out"):
            M.incident("DISCONNECT", f"{session_id[:8]} {ev_type} "
                                     f"({(data or {}).get('reason','')}) via {source}")
        elif ev_type == "connected":
            log(f"session {session_id[:8]} reported 'connected' via {source}")


# --------------------------------------------------------------------------- #
# SSE listener (one thread per session)
# --------------------------------------------------------------------------- #

def sse_listener(session_id, stop):
    backoff = 1.0
    while not stop.is_set():
        url = f"{BASE_URL}/v1/sessions/{session_id}/events"
        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {TOKEN}")
        req.add_header("Accept", "text/event-stream")
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                with M.lock:
                    M.sess[session_id]["sse_up"] = True
                log(f"SSE connected: {session_id[:8]}")
                backoff = 1.0
                data_buf = []
                for raw in r:
                    if stop.is_set():
                        break
                    line = raw.decode(errors="replace").rstrip("\n").rstrip("\r")
                    if line == "":
                        if data_buf:
                            _dispatch_sse(session_id, "\n".join(data_buf))
                            data_buf = []
                        continue
                    if line.startswith(":"):
                        continue  # comment / keepalive
                    if line.startswith("data:"):
                        data_buf.append(line[5:].lstrip())
        except Exception as e:  # noqa: BLE001
            pass
        # stream dropped
        with M.lock:
            if M.sess[session_id]["sse_up"]:
                M.sess[session_id]["sse_drops"] += 1
            M.sess[session_id]["sse_up"] = False
        if not stop.is_set():
            M.incident("SSE_DROP", f"{session_id[:8]} event stream dropped; "
                                   f"reconnecting in {backoff:.0f}s")
            stop.wait(backoff)
            backoff = min(backoff * 2, 30.0)


def _dispatch_sse(session_id, payload):
    try:
        obj = json.loads(payload)
    except Exception:  # noqa: BLE001
        return
    ev_type = obj.get("type", "unknown")
    handle_event(session_id, ev_type, obj, "sse")


# --------------------------------------------------------------------------- #
# health poller
# --------------------------------------------------------------------------- #

def health_poller(session_ids, stop):
    while not stop.is_set():
        # server liveness
        st, _ = api("GET", "/health", timeout=15)
        with M.lock:
            if st == 200:
                M.server_ok += 1
                M.server_last_ok = time.time()
            else:
                M.server_fail += 1
                M.incident("SERVER_DOWN", f"/health returned {st}")

        for sid in session_ids:
            st, h = api("GET", f"/v1/sessions/{sid}/health", timeout=15)
            if st != 200 or not isinstance(h, dict):
                M.incident("HEALTH_ERR", f"{sid[:8]} health HTTP {st}")
                continue
            _apply_health(sid, h)

        _sweep_probes()
        auto_recover(session_ids)
        stop.wait(HEALTH_POLL_SEC)


def auto_recover(session_ids):
    """Opt-in self-heal: kick a parked session with POST /connect. Off by default.
    Network call is done OUTSIDE the lock; rate-limited per session."""
    if not AUTO_RECOVER:
        return
    now = time.time()
    to_kick = []
    with M.lock:
        for sid in session_ids:
            s = M.sess[sid]
            if s["connected"] or s["status"] in (None, "logged_out"):
                continue
            if s["status"] not in RECOVERABLE:
                continue
            if (now - s["last_change"]) < AUTO_RECOVER_AFTER_SEC:
                continue
            if (now - s["last_kick"]) < max(AUTO_RECOVER_AFTER_SEC, 30.0):
                continue  # don't spam /connect every poll
            s["last_kick"] = now
            to_kick.append((sid, s["status"]))
    for sid, status in to_kick:
        st, _ = api("POST", f"/v1/sessions/{sid}/connect", timeout=20)
        with M.lock:
            M.sess[sid]["recover_kicks"] += 1
        M.incident("AUTO_RECOVER",
                   f"{sid[:8]} parked '{status}' -> POST /connect (HTTP {st})")


def _apply_health(sid, h):
    now = time.time()
    status = h.get("status")
    connected = bool(h.get("connected"))
    ssr = h.get("seconds_since_rx")
    rc = h.get("reconnect_count", 0) or 0
    with M.lock:
        s = M.sess[sid]
        s["samples"] += 1
        if connected:
            s["connected_samples"] += 1

        # status transition
        if status != s["status"]:
            prev = s["status"]
            s["status"] = status
            s["last_change"] = now
            if prev is not None:
                if connected:
                    s["reconnects"] += 1
                    M.incident("RECOVER", f"{sid[:8]} {prev} -> {status}")
                else:
                    s["disconnects"] += 1
                    M.incident("DISCONNECT", f"{sid[:8]} {prev} -> {status}")
        s["connected"] = connected

        # reconnect_count churn
        if rc > s["reconnect_count"]:
            delta = rc - s["reconnect_count"]
            s["reconnect_count"] = rc
            if s["samples"] > 1:
                M.incident("RECONNECT_CHURN",
                           f"{sid[:8]} reconnect_count +{delta} (now {rc})")

        # zombie detection: connected but stale rx
        if ssr is not None:
            s["max_secs_since_rx"] = max(s["max_secs_since_rx"], float(ssr))
            if connected and float(ssr) > ZOMBIE_THRESHOLD_SEC:
                s["zombie_incidents"] += 1
                M.incident("ZOMBIE",
                           f"{sid[:8]} connected=true but no rx for {ssr}s "
                           f"(> {ZOMBIE_THRESHOLD_SEC:.0f}s) — likely dead WS")


def _sweep_probes():
    now = time.time()
    with M.lock:
        for mid, pr in list(M.probes.items()):
            if pr.get("timed_out"):
                continue
            confirmed = pr.get("sse_ok_ts") or pr.get("webhook_ok_ts")
            if not confirmed and (now - pr["sent_ts"]) > ROUNDTRIP_TIMEOUT_SEC:
                pr["timed_out"] = True
                M.rt_timeout += 1
                M.incident("ROUNDTRIP_FAIL",
                           f"msg {mid[:12]} {pr['src'][:8]}->{pr['dst'][:8]} "
                           f"not received within {ROUNDTRIP_TIMEOUT_SEC:.0f}s")
        # keep the probe table from growing without bound
        if len(M.probes) > 500:
            for mid in sorted(M.probes, key=lambda k: M.probes[k]["sent_ts"])[:200]:
                M.probes.pop(mid, None)


# --------------------------------------------------------------------------- #
# conversation driver — human-paced A <-> B
# --------------------------------------------------------------------------- #
# Each thread is a topic: a list of (speaker, text). The driver picks topics,
# inserts irregular human gaps, shows typing, marks read, and sends. Correlation
# is by message-id, so the text stays clean and natural.

THREADS = [
    [("A", "oi, tudo certo por aí?"),
     ("B", "opa, tudo sim e vc?"),
     ("B", "acordei agora kkkk")],
    [("A", "viu o jogo ontem?"),
     ("B", "vi, que jogo doido"),
     ("B", "no fim deu tudo certo né")],
    [("A", "bora marcar um café essa semana"),
     ("B", "boraa"),
     ("B", "quinta eu consigo, pode ser?")],
    [("A", "me lembra de pagar aquele boleto depois"),
     ("B", "fechou, te lembro sim"),
     ("A", "valeu demais")],
    [("B", "cara, vi um lugar novo pra almoçar"),
     ("A", "é? onde fica?"),
     ("B", "perto do trabalho, depois te mando o endereço")],
    [("A", "consegue me mandar aquele arquivo?"),
     ("B", "consigo sim, daqui a pouco te mando"),
     ("B", "tô só terminando uma coisa aqui")],
    [("B", "tá frio hoje hein"),
     ("A", "demais, nem quis sair de casa"),
     ("A", "bom dia mesmo assim 😄")],
    [("A", "qual horário fica melhor pra vc amanhã?"),
     ("B", "de manhã eu prefiro"),
     ("B", "umas 10h tá bom?")],
]


def human_gap(lo, hi):
    return max(0.5, random.uniform(lo, hi) * SCALE)


def send_probe(src_sid, dst_sid, dst_number, text):
    st, resp = api("POST", f"/v1/sessions/{src_sid}/messages",
                   {"to": dst_number, "text": text})
    if st != 202 or not isinstance(resp, dict) or "id" not in resp:
        M.incident("SEND_FAIL", f"{src_sid[:8]}->{dst_sid[:8]} HTTP {st} {resp}")
        return None
    mid = resp["id"]
    with M.lock:
        M.sent_total += 1
        M.probes[mid] = {
            "id": mid, "src": src_sid, "dst": dst_sid,
            "sent_ts": time.time(), "text": text,
            "sse_ok_ts": None, "webhook_ok_ts": None,
            "sent_ack_ts": None, "delivered_ack_ts": None, "timed_out": False,
        }
    return mid


def typing(src_sid, dst_number, text):
    """Show 'composing' for a human-plausible duration, then send."""
    try:
        api("POST", f"/v1/sessions/{src_sid}/chats/{dst_number}/typing",
            {"state": "composing"}, timeout=10)
    except Exception:  # noqa: BLE001
        pass
    dur = min(9.0, max(1.5, len(text) / 12.0)) * SCALE
    time.sleep(dur)


def mark_read(reader_sid, other_number, msg_id):
    if not msg_id:
        return
    try:
        api("POST", f"/v1/sessions/{reader_sid}/chats/{other_number}/read",
            {"ids": [msg_id]}, timeout=10)
    except Exception:  # noqa: BLE001
        pass


def conversation_driver(a_sid, a_num, b_sid, b_num, stop):
    sidmap = {"A": (a_sid, a_num), "B": (b_sid, b_num)}
    othermap = {"A": (b_sid, b_num), "B": (a_sid, a_num)}
    last_to = {"A": None, "B": None}  # last probe-id each party received

    # set both present once at start
    for sid in (a_sid, b_sid):
        api("POST", f"/v1/sessions/{sid}/presence", {"state": "available"}, timeout=10)

    threads = list(THREADS)
    random.shuffle(threads)
    ti = 0
    while not stop.is_set():
        thread = threads[ti % len(threads)]
        ti += 1
        log(f"--- conversation topic {ti} ({len(thread)} turns) ---")
        for turn_i, (who, text) in enumerate(thread):
            if stop.is_set():
                return
            src_sid, _ = sidmap[who]
            dst_sid, dst_num = othermap[who]

            # within-topic gap: first turn shorter, replies irregular
            if turn_i == 0:
                stop.wait(human_gap(3, 20))
            else:
                stop.wait(human_gap(8, 120))
            if stop.is_set():
                return

            # "saw your message, replying": read what the other last sent us
            mark_read(src_sid, dst_num, last_to[who])
            # type, then send
            typing(src_sid, dst_num, text)
            mid = send_probe(src_sid, dst_sid, dst_num, text)
            if mid:
                last_to["A" if who == "B" else "B"] = mid
                log(f"sent {who} -> {('B' if who=='A' else 'A')}: "
                    f"{text[:40]!r} ({mid[:12]})")

        # long idle gap between topics (the 15-50 min cadence)
        idle = human_gap(IDLE_MIN_SEC, IDLE_MAX_SEC)
        log(f"idle {idle/60:.1f} min until next topic")
        stop.wait(idle)


# --------------------------------------------------------------------------- #
# webhook receiver + dashboard (one HTTP server)
# --------------------------------------------------------------------------- #

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence default logging
        pass

    def _send(self, code, body, ctype="text/plain"):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/healthz"):
            self._send(200, "ok")
        elif self.path.startswith("/report"):
            self._send(200, json.dumps(snapshot(), indent=2), "application/json")
        else:
            self._send(200, dashboard_html(), "text/html; charset=utf-8")

    def do_POST(self):
        if not self.path.startswith(WEBHOOK_PATH):
            self._send(404, "not found")
            return
        n = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(n) if n else b""
        with M.lock:
            M.wh_received += 1
        # verify HMAC
        sig = self.headers.get("X-Ruwa-Signature", "")
        ok = verify_sig(raw, sig)
        with M.lock:
            if ok:
                M.wh_sig_ok += 1
            else:
                M.wh_sig_bad += 1
        if ok:
            try:
                env_obj = json.loads(raw)
                handle_event(env_obj.get("session"), env_obj.get("event"),
                             env_obj.get("data"), "webhook")
            except Exception:  # noqa: BLE001
                pass
        elif sig:
            M.incident("WEBHOOK_SIG", "received webhook with bad signature")
        self._send(200, "ok")


def verify_sig(raw, sig_header):
    if not sig_header:
        return False
    expected = hmac.new(WEBHOOK_SECRET.encode(), raw, hashlib.sha256).hexdigest()
    got = sig_header.split("=", 1)[1] if "=" in sig_header else sig_header
    return hmac.compare_digest(expected, got)


# --------------------------------------------------------------------------- #
# reporting
# --------------------------------------------------------------------------- #

def snapshot():
    with M.lock:
        uptime = time.time() - M.start_ts
        srv_total = M.server_ok + M.server_fail
        sess = {}
        for sid, s in M.sess.items():
            samples = s["samples"] or 1
            sess[sid] = {
                "status": s["status"], "connected": s["connected"],
                "uptime_pct": round(100.0 * s["connected_samples"] / samples, 2),
                "disconnects": s["disconnects"], "reconnects": s["reconnects"],
                "reconnect_count": s["reconnect_count"],
                "zombie_incidents": s["zombie_incidents"],
                "max_secs_since_rx": round(s["max_secs_since_rx"], 1),
                "sse_up": s["sse_up"], "sse_drops": s["sse_drops"],
                "recover_kicks": s["recover_kicks"],
            }
        rt_total = M.rt_sse_ok + M.rt_timeout
        return {
            "uptime_human": f"{uptime/3600:.2f}h",
            "fast_mode": FAST,
            "webhook_enabled": bool(WEBHOOK_PUBLIC_URL),
            "server_health_pct": round(100.0 * M.server_ok / srv_total, 2) if srv_total else None,
            "sessions": sess,
            "messages_sent": M.sent_total,
            "roundtrip_sse_ok": M.rt_sse_ok,
            "roundtrip_webhook_ok": M.rt_webhook_ok,
            "roundtrip_timeout": M.rt_timeout,
            "roundtrip_success_pct": round(100.0 * M.rt_sse_ok / rt_total, 2) if rt_total else None,
            "delivered_acks": M.delivered_acks,
            "latency_sse_p50": _r(pct(M.lat_sse, 50)),
            "latency_sse_p95": _r(pct(M.lat_sse, 95)),
            "latency_webhook_p50": _r(pct(M.lat_webhook, 50)),
            "latency_webhook_p95": _r(pct(M.lat_webhook, 95)),
            "latency_delivered_p50": _r(pct(M.lat_delivered, 50)),
            "webhook_received": M.wh_received,
            "webhook_sig_ok": M.wh_sig_ok,
            "webhook_sig_bad": M.wh_sig_bad,
            "webhook_by_event": dict(M.wh_by_event),
            "inbound_non_probe": dict(M.inbound),
            "incidents_recent": list(M.incidents)[:30],
        }


def _r(v):
    return round(v, 2) if v is not None else None


def dashboard_html():
    s = snapshot()
    rows = ""
    for sid, d in s["sessions"].items():
        color = "#1a9d4b" if d["connected"] else "#c0392b"
        rows += (f"<tr><td><code>{sid[:12]}</code></td>"
                 f"<td style='color:{color};font-weight:600'>{d['status']}</td>"
                 f"<td>{d['uptime_pct']}%</td><td>{d['disconnects']}</td>"
                 f"<td>{d['reconnects']}</td><td>{d['zombie_incidents']}</td>"
                 f"<td>{d['max_secs_since_rx']}s</td>"
                 f"<td>{'up' if d['sse_up'] else 'DOWN'} ({d['sse_drops']})</td></tr>")
    inc = ""
    for i in s["incidents_recent"]:
        inc += f"<tr><td>{i['t']}</td><td><b>{i['kind']}</b></td><td>{i['msg']}</td></tr>"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>ruwa soak monitor</title>
<style>body{{font:14px/1.5 -apple-system,system-ui,sans-serif;margin:24px;color:#1a1a1a;background:#fafafa}}
h1{{font-size:20px}}table{{border-collapse:collapse;width:100%;margin:10px 0;background:#fff}}
td,th{{border:1px solid #e2e2e2;padding:6px 10px;text-align:left}}th{{background:#f0f0f0}}
.k{{display:inline-block;min-width:230px;color:#555}} .big{{font-size:16px;font-weight:600}}
code{{background:#eee;padding:1px 4px;border-radius:3px}}</style></head><body>
<h1>ruwa soak monitor {'⚡FAST' if FAST else ''}</h1>
<p>uptime <b>{s['uptime_human']}</b> · webhook {'ENABLED' if s['webhook_enabled'] else 'disabled (SSE-only)'}
 · server health <b>{s['server_health_pct']}%</b></p>
<table><tr><th>session</th><th>status</th><th>conn uptime</th><th>disc</th><th>recon</th>
<th>zombie</th><th>max rx-gap</th><th>SSE</th></tr>{rows}</table>
<p class="big">round-trip: {s['roundtrip_sse_ok']} ok · {s['roundtrip_timeout']} FAILED
 · success {s['roundtrip_success_pct']}% &nbsp;|&nbsp; sent {s['messages_sent']} · delivered-acks {s['delivered_acks']}</p>
<p><span class="k">latency send→received (SSE)</span> p50 {s['latency_sse_p50']}s / p95 {s['latency_sse_p95']}s</p>
<p><span class="k">latency send→received (webhook)</span> p50 {s['latency_webhook_p50']}s / p95 {s['latency_webhook_p95']}s</p>
<p><span class="k">webhook deliveries</span> {s['webhook_received']} received · sig ok {s['webhook_sig_ok']} · sig BAD {s['webhook_sig_bad']} · {json.dumps(s['webhook_by_event'])}</p>
<h3>recent incidents</h3><table><tr><th>time</th><th>kind</th><th>detail</th></tr>{inc}</table>
</body></html>"""


def print_summary():
    s = snapshot()
    log("================ SOAK SUMMARY ================")
    log(json.dumps(s, indent=2))


# --------------------------------------------------------------------------- #
# setup / main
# --------------------------------------------------------------------------- #

def discover_sessions():
    if SESSION_A and SESSION_B:
        ids = [SESSION_A, SESSION_B]
    else:
        st, lst = api("GET", "/v1/sessions")
        if st != 200 or not isinstance(lst, list):
            log(f"could not list sessions (HTTP {st}); set SESSION_A/SESSION_B", "ERROR")
            sys.exit(2)
        connected = [x for x in lst if x.get("status") == "connected"]
        if len(connected) < 2:
            log(f"need 2 connected sessions, found {len(connected)}: "
                f"{[ (x.get('id','')[:8], x.get('status')) for x in lst ]}", "ERROR")
            sys.exit(2)
        ids = [connected[0]["id"], connected[1]["id"]]
    nums = []
    for sid in ids:
        st, meta = api("GET", f"/v1/sessions/{sid}")
        num = jid_to_number((meta or {}).get("jid")) if st == 200 else None
        if not num:
            log(f"session {sid[:8]} has no jid/number (status {st}); cannot probe", "ERROR")
            sys.exit(2)
        nums.append(num)
    return ids[0], nums[0], ids[1], nums[1]


def register_webhooks(session_ids):
    if not WEBHOOK_PUBLIC_URL:
        log("WEBHOOK_PUBLIC_URL not set -> webhook test DISABLED (SSE-only). "
            "Set it (or RAILWAY_PUBLIC_DOMAIN) to exercise webhooks.", "WARN")
        return
    url = WEBHOOK_PUBLIC_URL + WEBHOOK_PATH
    for sid in session_ids:
        st, resp = api("PUT", f"/v1/sessions/{sid}/webhook", {
            "url": url, "events": EVENTS_OF_INTEREST,
            "secret": WEBHOOK_SECRET, "enabled": True,
        })
        if st in (200, 201, 202, 204):
            log(f"webhook registered for {sid[:8]} -> {url}")
        else:
            log(f"webhook registration failed for {sid[:8]}: HTTP {st} {resp}", "ERROR")


def main():
    log(f"ruwa soak monitor starting | base={BASE_URL} | FAST={FAST} | "
        f"webhook_pub={WEBHOOK_PUBLIC_URL or '(none)'} | "
        f"auto_recover={'ON@%.0fs' % AUTO_RECOVER_AFTER_SEC if AUTO_RECOVER else 'OFF'}")
    a_sid, a_num, b_sid, b_num = discover_sessions()
    log(f"session A = {a_sid[:8]} ({a_num})   session B = {b_sid[:8]} ({b_num})")
    session_ids = [a_sid, b_sid]

    register_webhooks(session_ids)

    stop = threading.Event()
    threads = []

    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    log(f"dashboard + webhook receiver on :{PORT}  (GET / , /report , {WEBHOOK_PATH})")

    for sid in session_ids:
        th = threading.Thread(target=sse_listener, args=(sid, stop), daemon=True)
        th.start(); threads.append(th)

    hp = threading.Thread(target=health_poller, args=(session_ids, stop), daemon=True)
    hp.start(); threads.append(hp)

    drv = threading.Thread(target=conversation_driver,
                           args=(a_sid, a_num, b_sid, b_num, stop), daemon=True)
    drv.start(); threads.append(drv)

    def shutdown(*_):
        log("shutting down...")
        stop.set()
        print_summary()
        server.shutdown()
        os._exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # periodic heartbeat summary to stdout (Railway logs)
    while not stop.is_set():
        stop.wait(300 if not FAST else 30)
        s = snapshot()
        log(f"heartbeat | rt ok {s['roundtrip_sse_ok']} fail {s['roundtrip_timeout']} "
            f"({s['roundtrip_success_pct']}%) | sent {s['messages_sent']} | "
            f"wh {s['webhook_received']} | server {s['server_health_pct']}%")


if __name__ == "__main__":
    main()
