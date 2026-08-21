// Minimal typings for opus-recorder (ships no .d.ts). Only the surface the
// console uses — see node_modules/opus-recorder/README.md for the full API.
declare module "opus-recorder" {
  export interface OpusRecorderConfig {
    bufferLength?: number
    encoderPath?: string
    mediaTrackConstraints?: boolean | MediaTrackConstraints
    monitorGain?: number
    numberOfChannels?: number
    recordingGain?: number
    encoderApplication?: 2048 | 2049 | 2051
    encoderBitRate?: number
    encoderComplexity?: number
    encoderFrameSize?: number
    encoderSampleRate?: 8000 | 12000 | 16000 | 24000 | 48000
    maxFramesPerPage?: number
    originalSampleRateOverride?: number
    resampleQuality?: number
    streamPages?: boolean
  }
  export default class Recorder {
    constructor(config?: OpusRecorderConfig)
    static isRecordingSupported(): boolean
    static version: string
    state: "inactive" | "loading" | "recording" | "paused"
    encodedSamplePosition: number
    start(): Promise<void>
    stop(): Promise<void>
    pause(flush?: boolean): Promise<void> | void
    resume(): void
    close(): Promise<void>
    setRecordingGain(gain: number): void
    setMonitorGain(gain: number): void
    ondataavailable: (data: Uint8Array) => void
    onstart: () => void
    onstop: () => void
    onpause: () => void
    onresume: () => void
  }
}

// Vite `?url` import of the encoder worker (it is a plain script, not a module).
declare module "opus-recorder/dist/encoderWorker.min.js?url" {
  const url: string
  export default url
}
