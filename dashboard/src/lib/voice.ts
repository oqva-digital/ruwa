// Browser-side voice-note recording → Ogg/Opus, the only container WhatsApp
// (web + Cloud API) accepts for push-to-talk. MediaRecorder can't be used: it
// yields webm/opus on Chrome and mp4/aac on Safari. opus-recorder encodes with
// a libopus WASM worker (wasm is inlined in the worker script, so one asset).
//
// The worker script is served from the Vite bundle via `?url` (hashed asset,
// same origin) — it doubles as the AudioWorklet module, so no copy to public/.
import encoderPath from "opus-recorder/dist/encoderWorker.min.js?url"

export const VOICE_MIME = "audio/ogg; codecs=opus"

/** Lazy module handle: the recorder core is ~8 KB, only loaded on first use. */
let recorderMod: Promise<typeof import("opus-recorder")> | null = null
export function preloadVoiceRecorder() {
  recorderMod ??= import("opus-recorder")
  return recorderMod
}

export function isVoiceSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    !!navigator.mediaDevices?.getUserMedia &&
    typeof WebAssembly !== "undefined" &&
    !!(window.AudioContext || (window as unknown as { webkitAudioContext?: unknown }).webkitAudioContext)
  )
}

export interface VoiceRecording {
  /** Stop and resolve with the finished Ogg/Opus blob. */
  stop(): Promise<Blob>
  /** Stop and throw the audio away (releases the mic). */
  cancel(): Promise<void>
}

/**
 * Start recording from the default microphone. Must be called from a user
 * gesture (click/tap) — browsers gate AudioContext + getUserMedia on it.
 * Rejects with a DOMException `NotAllowedError` when the mic is denied.
 */
export async function startVoiceRecording(): Promise<VoiceRecording> {
  const { default: Recorder } = await preloadVoiceRecorder()
  const rec = new Recorder({
    encoderPath,
    // Voice-optimised opus, mono 16 kHz at ~32 kbps: what WhatsApp itself uses.
    encoderApplication: 2048,
    encoderSampleRate: 16000,
    encoderBitRate: 32000,
    numberOfChannels: 1,
    mediaTrackConstraints: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
    streamPages: false,
  })
  let bytes: Uint8Array | null = null
  const stopped = new Promise<void>((res) => {
    rec.onstop = () => res()
  })
  rec.ondataavailable = (data) => {
    bytes = data
  }
  const closeQuietly = async () => {
    try {
      await rec.close()
    } catch {
      /* already closed / never opened */
    }
  }
  try {
    await rec.start()
  } catch (e) {
    // Release the AudioContext the constructor opened (mic denied, no device…).
    await closeQuietly()
    throw e
  }
  let finished = false
  async function finish(): Promise<Blob> {
    if (!finished) {
      finished = true
      await rec.stop()
      await stopped
      await closeQuietly()
    }
    if (!bytes) throw new Error("no audio captured")
    const copy = new Uint8Array(bytes)
    return new Blob([copy], { type: VOICE_MIME })
  }
  return {
    stop: finish,
    cancel: async () => {
      await finish().catch(() => {})
    },
  }
}

/** "0:07" style elapsed-time label. */
export function fmtElapsed(sec: number): string {
  const m = Math.floor(sec / 60)
  const s = Math.floor(sec % 60)
  return `${m}:${s.toString().padStart(2, "0")}`
}
