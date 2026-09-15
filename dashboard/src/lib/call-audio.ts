/**
 * Live call audio: microphone → 20 ms s16le PCM frames over the call-audio
 * WebSocket, and inbound WS frames → jitter-buffered speaker playback.
 *
 * Bridge contract (SPEC "Calls"): binary WS frame = 20 ms of s16le PCM,
 * 16 kHz mono = 640 bytes (multiples allowed). First server text frame is a
 * JSON `{"event":"start", ...}`; closing the socket hangs the call up.
 *
 * The AudioContext may refuse the 16 kHz sample rate (browser/hardware
 * dependent), so both directions run through a linear resampler that is a
 * passthrough when the context is already at 16 kHz.
 */

const WA_RATE = 16000
const FRAME_SAMPLES = 320 // 20 ms @ 16 kHz

/** Inline AudioWorklet: one node with the mic as input and the speaker as
 * output. Capture side posts Float32 blocks to the main thread; playback side
 * drains a queue of Float32 blocks (underrun → silence). Kept tiny and
 * dependency-free so it can ship as a Blob URL (no separate asset). */
const WORKLET_SRC = `
class CallBridge extends AudioWorkletProcessor {
  constructor() {
    super()
    this.queue = []      // Float32Array playback blocks (context rate)
    this.queued = 0      // total queued samples
    this.offset = 0      // read offset into queue[0]
    this.port.onmessage = (e) => {
      const b = e.data
      if (!(b instanceof Float32Array)) return
      this.queue.push(b)
      this.queued += b.length
      // Keep latency bounded: past ~600 ms of buffered audio, drop oldest.
      while (this.queued - this.offset > sampleRate * 0.6 && this.queue.length > 1) {
        const dropped = this.queue.shift()
        this.queued -= dropped.length - this.offset
        this.offset = 0
      }
    }
  }
  process(inputs, outputs) {
    const mic = inputs[0] && inputs[0][0]
    if (mic && mic.length) this.port.postMessage(mic.slice(0))
    const out = outputs[0][0]
    if (out) {
      let w = 0
      while (w < out.length && this.queue.length) {
        const head = this.queue[0]
        const n = Math.min(out.length - w, head.length - this.offset)
        out.set(head.subarray(this.offset, this.offset + n), w)
        w += n
        this.offset += n
        if (this.offset >= head.length) {
          this.queue.shift()
          this.queued -= head.length
          this.offset = 0
        }
      }
      for (; w < out.length; w++) out[w] = 0 // underrun → silence
    }
    return true
  }
}
registerProcessor("call-bridge", CallBridge)
`

/** Linear resampler; passthrough when rates match. */
function resample(input: Float32Array, from: number, to: number): Float32Array {
  if (from === to) return input
  const outLen = Math.round((input.length * to) / from)
  const out = new Float32Array(outLen)
  const step = (input.length - 1) / Math.max(1, outLen - 1)
  for (let i = 0; i < outLen; i++) {
    const pos = i * step
    const i0 = Math.floor(pos)
    const i1 = Math.min(i0 + 1, input.length - 1)
    const frac = pos - i0
    out[i] = input[i0] * (1 - frac) + input[i1] * frac
  }
  return out
}

export type CallAudioHandle = {
  /** Close the socket (= hang up) and release mic/audio resources. */
  stop: () => void
  setMuted: (m: boolean) => void
}

export type CallAudioCallbacks = {
  /** The server's `start` control frame arrived — media path is live. */
  onStart?: (info: Record<string, unknown>) => void
  /** Socket closed (peer hangup, network, or our stop()). */
  onClose?: () => void
}

export function isCallAudioSupported(): boolean {
  return (
    typeof navigator !== "undefined" &&
    !!navigator.mediaDevices?.getUserMedia &&
    typeof AudioWorkletNode !== "undefined"
  )
}

/** Open the mic + the call-audio WebSocket and bridge both directions.
 * Must be called from a user gesture (mic permission + autoplay policy). */
export async function startCallAudio(
  wsUrl: string,
  cb: CallAudioCallbacks = {},
): Promise<CallAudioHandle> {
  const stream = await navigator.mediaDevices.getUserMedia({
    audio: {
      channelCount: 1,
      echoCancellation: true,
      noiseSuppression: true,
      autoGainControl: true,
    },
  })

  let ctx: AudioContext
  try {
    ctx = new AudioContext({ sampleRate: WA_RATE })
  } catch {
    ctx = new AudioContext() // resampler bridges the gap
  }
  const ctxRate = ctx.sampleRate

  const workletUrl = URL.createObjectURL(new Blob([WORKLET_SRC], { type: "application/javascript" }))
  try {
    await ctx.audioWorklet.addModule(workletUrl)
  } finally {
    URL.revokeObjectURL(workletUrl)
  }
  const node = new AudioWorkletNode(ctx, "call-bridge", {
    numberOfInputs: 1,
    numberOfOutputs: 1,
    outputChannelCount: [1],
  })
  const src = ctx.createMediaStreamSource(stream)
  src.connect(node)
  node.connect(ctx.destination)

  const ws = new WebSocket(wsUrl)
  ws.binaryType = "arraybuffer"

  let muted = false
  let closed = false
  // Don't stream the mic until the server's `start` frame arrives (media path
  // live). On an OUTBOUND dial the socket opens immediately but nothing drains
  // it until the peer answers — capturing during the ring would pile seconds of
  // audio into the WS buffer and dump it all at connect (huge latency + "old
  // phrases" replaying). Drop mic blocks until started.
  let started = false

  // Mic capture: context-rate Float32 blocks → 16 kHz → s16le 640 B frames.
  let pending = new Float32Array(0)
  node.port.onmessage = (e: MessageEvent) => {
    if (!started || ws.readyState !== WebSocket.OPEN) return
    const block = resample(e.data as Float32Array, ctxRate, WA_RATE)
    const merged = new Float32Array(pending.length + block.length)
    merged.set(pending)
    merged.set(block, pending.length)
    let off = 0
    while (merged.length - off >= FRAME_SAMPLES) {
      const bytes = new Int16Array(FRAME_SAMPLES)
      if (!muted) {
        for (let i = 0; i < FRAME_SAMPLES; i++) {
          const s = Math.max(-1, Math.min(1, merged[off + i]))
          bytes[i] = s < 0 ? s * 0x8000 : s * 0x7fff
        }
      }
      ws.send(bytes.buffer)
      off += FRAME_SAMPLES
    }
    pending = merged.slice(off)
  }

  // Inbound: s16le frames @16 kHz → Float32 @context rate → playback queue.
  ws.onmessage = (e: MessageEvent) => {
    if (typeof e.data === "string") {
      try {
        const info = JSON.parse(e.data)
        if (info?.event === "start") {
          started = true // media path live — begin streaming the mic now
          pending = new Float32Array(0) // drop anything captured during the ring
          cb.onStart?.(info)
        }
      } catch {
        /* ignore malformed control frames */
      }
      return
    }
    const ints = new Int16Array(e.data as ArrayBuffer)
    const floats = new Float32Array(ints.length)
    for (let i = 0; i < ints.length; i++) floats[i] = ints[i] / 0x8000
    node.port.postMessage(resample(floats, WA_RATE, ctxRate))
  }

  const cleanup = () => {
    if (closed) return
    closed = true
    node.port.onmessage = null
    try {
      src.disconnect()
      node.disconnect()
    } catch {
      /* already gone */
    }
    stream.getTracks().forEach((t) => t.stop())
    void ctx.close().catch(() => {})
    cb.onClose?.()
  }
  ws.onclose = cleanup
  ws.onerror = () => {
    if (ws.readyState !== WebSocket.OPEN) cleanup()
  }

  // Autoplay policies can leave a fresh context suspended until resumed.
  void ctx.resume().catch(() => {})

  return {
    stop: () => {
      try {
        ws.close()
      } finally {
        cleanup()
      }
    },
    setMuted: (m: boolean) => {
      muted = m
    },
  }
}
