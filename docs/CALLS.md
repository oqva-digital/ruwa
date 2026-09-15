# Voice calls (WhatsApp 1:1 audio)

ruwa is the call **infrastructure**: it does WhatsApp call signaling, the SRTP
media plane, and an audio bridge over a WebSocket. The call *logic* — your voice
agent (TTS/STT/LLM), IVR, or a human at a browser — lives on the other end of
that WebSocket. ruwa speaks **raw PCM**, so any stack that produces/consumes
16 kHz mono audio (OpenAI Realtime, Deepgram, Pipecat, a browser mic) plugs in
directly.

**Scope:** 1:1 audio only. No video, no group calls. **Web sessions only**
(`kind: "web"`, i.e. a linked WhatsApp device) — Cloud API sessions return 501.

## The four endpoints

| Method | Path | What |
|---|---|---|
| `GET` | `/v1/sessions/:id/calls` | List calls ringing right now |
| `GET` | `/v1/sessions/:id/calls/:call_id/audio` | **WS** — answer an inbound call + bridge audio |
| `GET` | `/v1/sessions/:id/calls/dial?peer=<number>` | **WS** — place an outbound call + bridge audio |
| `POST` | `/v1/sessions/:id/calls/:call_id/reject` | Decline a ringing call — body `{"peer":"<caller>"}` |

There is no separate `accept`/`hangup` HTTP call: **opening** the audio WS is how
you answer or dial, and **closing** it is how you hang up. A peer hangup closes
the socket from the server side.

## Events (SSE + webhooks)

An inbound call raises `call_offer`; any end (peer hangup, reject, timeout)
raises `call_terminate`. Subscribe via the session event stream
(`GET /v1/sessions/:id/events`) or a configured webhook.

```json
{"type":"call_offer","call_id":"001b9d…","from":"5511999999999@s.whatsapp.net","media":"audio"}
{"type":"call_terminate","call_id":"001b9d…","from":"5511999999999@s.whatsapp.net","reason":"timeout"}
```

## The audio WebSocket contract

Both `.../audio` (answer) and `.../dial` (originate) upgrade to a WebSocket.

- **Auth:** bearer header, or `?token=<API_TOKEN>` in the URL (browsers can't set
  headers on a WebSocket).
- **Binary frames = audio.** Each is **20 ms of signed 16-bit little-endian PCM,
  16 kHz mono = 640 bytes**, headerless. Multiples of 640 are accepted (e.g. a
  bulk TTS chunk); pace your sending to roughly real time. ruwa aggregates
  three 20 ms frames into one 60 ms WhatsApp Opus frame, and slices inbound
  audio back to 20 ms for you.
- **One text (JSON) control frame today:** the server sends
  `{"event":"start", "call_id":…, "from":…, "audio":{"encoding":"pcm_s16le","rate":16000,"channels":1,"frame_ms":20}, "codec":"opus"}`
  when the media path goes live. On a **dial** that is the moment the peer
  **answers** (before that the call is ringing). **Do not send mic audio before
  `start`** — audio sent during ringing would buffer and then replay with lag.
- **Closing the socket hangs up.** When the peer hangs up (or the call ends for
  any reason), the server closes the socket.
- ruwa owns the send clock (a 60 ms ticker always feeds WhatsApp; silence/DTX on
  underrun) and keeps the agent→WhatsApp buffer shallow, so it will drop your
  audio rather than let latency pile up if you send faster than real time.

### Direction of audio

- **Binary frame you SEND** → spoken to the WhatsApp peer.
- **Binary frame you RECEIVE** → the peer's decoded voice.

## Example: place a call and bridge audio (Node.js)

```js
import WebSocket from "ws";
import { readFileSync } from "node:fs";

const BASE = "https://your-ruwa.example.com"; // ws(s):// derived below
const TOKEN = process.env.RUWA_API_TOKEN;
const SESSION = "your-session-id";
const PEER = "5511999999999"; // digits, DDI included

const url =
  BASE.replace(/^http/, "ws") +
  `/v1/sessions/${SESSION}/calls/dial?peer=${PEER}&token=${encodeURIComponent(TOKEN)}`;

const ws = new WebSocket(url);
ws.binaryType = "arraybuffer";

let live = false;
ws.on("message", (data, isBinary) => {
  if (!isBinary) {
    const msg = JSON.parse(data.toString());
    if (msg.event === "start") {
      live = true;                 // peer answered — start streaming now
      streamPromptAudio();          // your TTS / mic / file → 640-byte frames
    }
    return;
  }
  // `data` is 640 bytes of the peer's voice (s16le 16 kHz mono) — feed your STT.
  handlePeerAudio(new Int16Array(data));
});

ws.on("close", () => console.log("call ended"));

// Send 20 ms (640-byte) frames, paced to real time. Never before `live`.
function sendFrame(int16 /* Int16Array length 320 */) {
  if (live && ws.readyState === WebSocket.OPEN) ws.send(Buffer.from(int16.buffer));
}

// To hang up: ws.close();
```

Answering an inbound call is identical, except the URL is
`/v1/sessions/:id/calls/:call_id/audio` (take `call_id` from the `call_offer`
event), and `start` fires immediately on connect (the call is already ringing on
your side).

## Reject instead of answer

```sh
curl -X POST -H "Authorization: Bearer $RUWA_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"peer":"5511999999999@s.whatsapp.net"}' \
  "$BASE/v1/sessions/$SESSION/calls/$CALL_ID/reject"
```

## Notes & limits

- **Codec:** ruwa forces WhatsApp's standard-Opus profile (PT 120, 16 kHz,
  60 ms). MLOW is not implemented.
- **Media egress:** the call's UDP media does **not** traverse an HTTP proxy
  (only the WhatsApp WebSocket does) — it leaves from the host's own IP.
- **Echo:** ruwa does no acoustic echo cancellation. If you bridge a speaker and
  a mic in the same room you'll get feedback — use headphones or your stack's AEC.
- See `SPEC.md` → "Calls" for the design contract and the roadmap items
  (`accept`/`hangup` HTTP, `call_active`, richer control frames) that are not
  implemented yet.
