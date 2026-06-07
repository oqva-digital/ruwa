# Runbook — latency / overhead probes (safe, low/zero WA traffic)

Key insight: **raw send/receive latency is WhatsApp-bound** (~100s of ms, WA
servers + network), so it barely differentiates clients. The *client* difference
shows up in the overhead around the message. Ordered by safe×revealing.

Legend: 🤖 = automated in `bench/probe.sh` (no phone, no WA). 📱 = needs a paired
session (your phone). ⚠️ = uses real WA messages — your own numbers, low volume.

---

## 🤖 No-phone, zero-WA (run `bash bench/probe.sh`)

- **Restore time (#4)** — create N sessions in the DB, restart the server, time
  until `/health` is ready. Shows cold-restore cost at scale.
- **RAM × N idle sessions (curve)** — RSS at N = 10/50/100/200. Gives the
  per-(idle)-session slope + base.

## 📱 Needs a paired session (1 phone)

- **Reconnect-to-ready (#1)** — pair a session, then drop its socket and time the
  recovery. **Where ours shines (515 instant-restart fix).**
  ```sh
  # with a connected session on :8099:
  #   1. note time; force a reconnect by toggling network OR:
  #      sudo pfctl-style block, or just `kill -STOP`/`-CONT` the wifi — simplest:
  #      turn wifi off ~3s then on; watch the events stream:
  curl -sN -H "authorization: Bearer t" http://127.0.0.1:8099/v1/sessions/<ID>/events
  #   2. measure: time from "disconnected" event → next "connected" event.
  ```
- **Idle drift / leak (#2)** — leave 1 session connected ~30 min, sample RSS+CPU:
  ```sh
  while :; do ps -o rss=,%cpu= -p <pid> | awk '{printf "%s  %.1fMB  %s%%\n",strftime("%H:%M"),$1/1024,$2}'; sleep 60; done
  ```
  Healthy = flat RSS, ~0% idle CPU. Rising RSS = leak.

## ⚠️ Real WA messages — **your own numbers, low volume, with pauses**

- **Send latency (#6)** — POST `/messages` → time until the row's status flips to
  `sent`/`delivered` (poll `/messages` or watch `/events`). Mostly WA-bound;
  isolates the client's queue→ship overhead.
- **Receive latency (#7)** — from a 2nd phone of yours, send to the paired number;
  time until it surfaces on `/events` (or the webhook). WA-bound + our dispatch.
- **Media send (#8)** — send a small image; time encrypt+upload+ship. Here the
  client contributes more (crypto + mediaconn + upload).

Compare the same probe on Evolution (its `/manager` + its message endpoints) for
the head-to-head. Expect send/receive ≈ tie (WA-bound); reconnect + idle-drift +
restore are where clients actually differ.

## 🔴 Avoid (ban risk)
High send volume, many distinct recipients, pair/unpair loops. Keep it to a
handful of messages between numbers you own, spaced out.
