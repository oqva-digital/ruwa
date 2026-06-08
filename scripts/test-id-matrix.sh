#!/usr/bin/env bash
# test-id-matrix.sh — map a session's known chats by WhatsApp JID type and run a
# send/receive probe matrix across the reachable types (PN, LID, group), plus the
# same-person PN-vs-LID cross-check.
#
#   RUWA_API_TOKEN=...  RUWA_SESSION=<session-id>  ./scripts/test-id-matrix.sh \
#       [--pn 5511999999999|<jid>]  [--lid <num>@lid]  [--group <jid>@g.us] \
#       [--wait 45]  [--inventory-only]
#
# What it proves, and what it does NOT:
#   • RECEIVE is proven by a real inbound reply landing in the probed chat.
#   • SEND is proven the SAME way — by a returning reply (a round-trip). The server
#     <ack> (the `message_delivered` event) is NOT proof: it fired even while the
#     LID bug was silently dropping messages before they reached the device.
#   • LID-addressed delivery + own-device echo are always on (no flags).
#
# So: after it sends the probes, reply to each from the other phone and watch the
# grid fill in. Requires: curl, jq.
set -euo pipefail

BASE="${RUWA_BASE:-http://127.0.0.1:8080}"
TOKEN="${RUWA_API_TOKEN:?set RUWA_API_TOKEN (Bearer token for the /v1 API)}"
SID="${RUWA_SESSION:?set RUWA_SESSION to the session id to test}"

WAIT=45; PEER_PN=""; PEER_LID=""; PEER_GROUP=""; INV_ONLY=0; PROBE_SPECS=()
while [ $# -gt 0 ]; do case "$1" in
  --pn)             PEER_PN="$2"; shift 2;;
  --lid)            PEER_LID="$2"; shift 2;;
  --group)          PEER_GROUP="$2"; shift 2;;
  --probe)          PROBE_SPECS+=("$2"); shift 2;;   # repeatable: LABEL=<jid>
  --wait)           WAIT="$2"; shift 2;;
  --inventory-only) INV_ONLY=1; shift;;
  *) echo "unknown arg: $1" >&2; exit 1;;
esac; done

auth=(-H "authorization: Bearer ${TOKEN}")
need(){ command -v "$1" >/dev/null 2>&1 || { echo "missing dependency: $1" >&2; exit 1; }; }
need curl; need jq
api(){ curl -fsS "${auth[@]}" "$@"; }
jpost(){ api -H 'content-type: application/json' -X POST "$@"; }

# JID -> human label by @server suffix (the WhatsApp address "type").
jtype(){ case "$1" in
  *@s.whatsapp.net)      echo PN;;
  *@lid)                 echo LID;;
  *@g.us)                echo GROUP;;
  *@newsletter)          echo NEWSLETTER;;
  *@broadcast)           echo BROADCAST;;
  *@bot)                 echo BOT;;
  *@hosted|*@hosted.lid) echo HOSTED;;
  *@msgr|*@interop)      echo INTEROP;;
  *@c.us)                echo LEGACY;;
  *)                     echo OTHER;;
esac; }

# normalize a --pn arg (bare number -> full PN jid; a jid is passed through)
pn_jid(){ case "$1" in *@*) echo "$1";; *) echo "$1@s.whatsapp.net";; esac; }

own_jid="$(api "${BASE}/v1/sessions/${SID}" | jq -r '.jid // empty')"
own_user="${own_jid%%@*}"; own_user="${own_user%%:*}"; own_user="${own_user%%.*}"

chats="$(api "${BASE}/v1/sessions/${SID}/chats")"

echo "════════════════════════════════════════════════════════════════"
echo " ruwa ID matrix — session ${SID}   own=${own_jid:-<unpaired>}"
echo "════════════════════════════════════════════════════════════════"
echo
echo "INVENTORY — known chats by WhatsApp address type:"
echo "$chats" | jq -r '
  ( .[].jid
    | if   endswith("@s.whatsapp.net") then "PN"
      elif endswith("@lid")            then "LID"
      elif endswith("@g.us")           then "GROUP"
      elif endswith("@newsletter")     then "NEWSLETTER"
      elif endswith("@broadcast")      then "BROADCAST"
      elif endswith("@bot")            then "BOT"
      else "OTHER" end )
' | sort | uniq -c | awk '{ printf "   %-12s %s\n", $2, $1 }'
echo
echo "   sample targets:"
for t in PN LID GROUP; do
  s="$(echo "$chats" | jq -r --arg t "$t" '
    map(.jid) | map(select(
      ($t=="PN"    and endswith("@s.whatsapp.net")) or
      ($t=="LID"   and endswith("@lid")) or
      ($t=="GROUP" and endswith("@g.us")) )) | .[0] // empty')"
  printf "     %-6s %s\n" "$t" "${s:-<none known>}"
done
echo

[ "$INV_ONLY" = 1 ] && exit 0

# ---- targets are EXPLICIT-ONLY --------------------------------------------
# Each probe sends a real message to a real person/group, so we NEVER auto-pick:
# you name exactly who to message. With no --pn/--lid/--group this is a no-op.
labels=(); targets=()
add(){ [ -n "$2" ] && { labels+=("$1"); targets+=("$2"); }; }
[ -n "$PEER_PN" ]    && add PN    "$(pn_jid "$PEER_PN")"
[ -n "$PEER_LID" ]   && add LID   "$PEER_LID"
[ -n "$PEER_GROUP" ] && add GROUP "$PEER_GROUP"
# repeatable --probe LABEL=<jid>: arbitrary labeled cells for a full path matrix
for spec in "${PROBE_SPECS[@]:-}"; do
  [ -z "$spec" ] && continue
  add "${spec%%=*}" "${spec#*=}"
done
if [ ${#targets[@]} -eq 0 ]; then
  echo "No targets given — pass --pn / --lid / --group / --probe LABEL=<jid>."
  echo "(intentionally no auto-pick: every probe sends a real message)"
  exit 0
fi

nonce="$(date +%s)"
# Bash 3.2 (macOS) has no associative arrays — use parallel indexed arrays,
# one slot per target, indexed the same as labels[]/targets[].
msgid=(); baserow=(); st_sent=(); st_ack=(); st_deliv=(); st_reply=()
echo "PROBES — sending one tagged message per target:"
for i in "${!targets[@]}"; do
  lbl="${labels[$i]}"; jid="${targets[$i]}"
  baserow[$i]="$(api "${BASE}/v1/sessions/${SID}/events/history?type=message&limit=1" | jq '[.[].id]|max // 0')"
  txt="🧪 ruwa id-matrix ${lbl} ${nonce} — reply to confirm"
  msgid[$i]="$(jpost "${BASE}/v1/sessions/${SID}/messages" \
        -d "$(jq -nc --arg to "$jid" --arg text "$txt" '{to:$to,text:$text}')" | jq -r '.id')"
  st_sent[$i]="·"; st_ack[$i]="·"; st_deliv[$i]="·"; st_reply[$i]="·"
  printf "   %-6s -> %-40s id=%s\n" "$lbl" "$jid" "${msgid[$i]}"
done
echo
echo "Watching for ${WAIT}s ... DELIV (device receipt) lands automatically on delivery."
echo "Reply from the recipient phone too if you also want the REPLY round-trip column."
echo

# ---- poll events/history until replies land or the window closes -----------
deadline=$(( $(date +%s) + WAIT ))
draw(){
  printf "   %-6s %-7s %-9s %-7s %-7s\n" TYPE SENT SRV-ACK DELIV REPLY
  for i in "${!targets[@]}"; do
    printf "   %-6s   %-5s   %-7s   %-5s   %-5s\n" \
      "${labels[$i]}" "${st_sent[$i]}" "${st_ack[$i]}" "${st_deliv[$i]}" "${st_reply[$i]}"
  done
}
printf "   waiting"
while :; do
  sent="$(api "${BASE}/v1/sessions/${SID}/events/history?type=message_sent&limit=80")"
  ackd="$(api "${BASE}/v1/sessions/${SID}/events/history?type=message_delivered&limit=80")"
  inb="$(api "${BASE}/v1/sessions/${SID}/events/history?type=message&limit=80")"
  # /logs is the protocol ring (all sessions) — it carries the recipient device
  # <receipt> for our outbound id, which is the ONLY true delivery proof.
  logs="$(api "${BASE}/v1/logs?limit=2000" | jq -r '.logs[].message' 2>/dev/null || true)"
  for i in "${!targets[@]}"; do
    mid="${msgid[$i]}"; jid="${targets[$i]}"; base="${baserow[$i]:-0}"
    tuser="${jid%%@*}"; tuser="${tuser%%:*}"; tuser="${tuser%%.*}"
    echo "$sent" | jq -e --arg id "$mid" 'any(.ev.id==$id)' >/dev/null 2>&1 && st_sent[$i]="✓"
    echo "$ackd" | jq -e --arg id "$mid" 'any(.ev.id==$id)' >/dev/null 2>&1 && st_ack[$i]="✓"
    # DELIV: a `tag=receipt` for our msg id that is a real delivery receipt —
    # i.e. NOT ty=retry (a retry receipt means the device couldn't decrypt yet).
    # ty= (empty) or ty=read both mean the device got it.
    if printf '%s\n' "$logs" | grep -F "id=$mid" | grep -q 'tag=receipt'; then
      printf '%s\n' "$logs" | grep -F "id=$mid" | grep 'tag=receipt' | grep -qv 'ty=retry' \
        && st_deliv[$i]="✓"
    fi
    # a real inbound reply: a `message` event newer than our pre-send baseline,
    # NOT authored by ourselves (filters the self-echo), matching the probed chat
    # either exactly OR by user-part — so a LID reply still binds after ruwa
    # consolidates it onto the peer's PN chat (chat jid changes, user-part stays).
    echo "$inb" | jq -e --arg jid "$jid" --argjson base "$base" \
                        --arg me "$own_user" --arg tu "$tuser" '
      any(.id > $base
          and ((.ev.from // "") | (startswith($me) | not))
          and ( (.ev.chat == $jid)
                or ($tu != "" and ((.ev.chat // "") | startswith($tu)))
                or ($tu != "" and ((.ev.from // "") | startswith($tu))) ))' >/dev/null 2>&1 \
      && st_reply[$i]="✓"
  done
  # done when every target has a real device receipt (the authoritative signal)
  all_done=1; for i in "${!targets[@]}"; do [ "${st_deliv[$i]}" = "✓" ] || all_done=0; done
  [ "$all_done" = 1 ] && { echo " all delivered!"; break; }
  [ "$(date +%s)" -ge "$deadline" ] && { echo " window closed."; break; }
  printf "."
  sleep 2
done

echo
echo "RESULT"
draw
echo
echo "Legend: SENT=left the wire · SRV-ACK=WhatsApp server acked (NOT device delivery)"
echo "        DELIV=recipient device <receipt> seen in /logs = TRUE delivery (the real proof)"
echo "        REPLY=a reply came back in that chat = full round-trip (send+receive)"
echo "DELIV is authoritative: SRV-ACK ✓ but DELIV · = acked-but-not-delivered to the device."
echo "REPLY can false-negative when two probes hit the same person (consolidated chat)."
