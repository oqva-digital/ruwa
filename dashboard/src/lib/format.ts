// Status → semantic mapping + liveness + time formatting (ported from the RUWA
// prototype's data.jsx). The "frozen" verdict is ruwa's value prop: a socket
// that reports connected but hasn't received a frame in a while.

import type { SessionStatus } from "./types"

export type StatusKey = "ok" | "progress" | "warn" | "frozen" | "down" | "blocked" | "neutral"

export interface StatusMeta {
  st: StatusKey
  label: string
  icon: string
}

export function statusMeta(status: SessionStatus | string): StatusMeta {
  switch (status) {
    case "connected": return { st: "ok", label: "connected", icon: "wifi" }
    case "connecting": return { st: "progress", label: "connecting", icon: "refresh" }
    case "pending": return { st: "progress", label: "pending", icon: "clock" }
    case "awaiting_qr": return { st: "progress", label: "awaiting qr", icon: "qr" }
    case "disconnected": return { st: "down", label: "disconnected", icon: "wifiOff" }
    case "logged_out": return { st: "down", label: "logged out", icon: "power" }
    case "proxy_error": return { st: "down", label: "proxy error", icon: "alert" }
    case "blocked": return { st: "blocked", label: "blocked", icon: "ban" }
    default: return { st: "neutral", label: String(status), icon: "dot" }
  }
}

/** Threshold (seconds) past which a connected socket is treated as frozen. */
export const FROZEN_AFTER_SEC = 75

export interface Liveness {
  kind: "live" | "frozen" | "down" | "progress"
  label: string
  cls: string
}

export function liveness(status: SessionStatus | string, lastRxSec: number | null): Liveness {
  if (status === "disconnected" || status === "logged_out" || status === "proxy_error" || status === "blocked")
    return { kind: "down", label: "down", cls: "chip-down" }
  if (status === "connecting" || status === "pending" || status === "awaiting_qr")
    return { kind: "progress", label: status === "awaiting_qr" ? "awaiting qr" : "connecting", cls: "chip-progress" }
  const frozen = lastRxSec != null && lastRxSec >= FROZEN_AFTER_SEC
  if (frozen) return { kind: "frozen", label: "frozen · " + fmtAgeShort(lastRxSec), cls: "chip-frozen" }
  return { kind: "live", label: "live · " + fmtAgeShort(lastRxSec), cls: "chip-live" }
}

/** Seconds since a unix timestamp, or null. */
export function ageSec(unixSec: number | null | undefined): number | null {
  if (unixSec == null || unixSec === 0) return null
  return Math.max(0, Math.floor(Date.now() / 1000) - unixSec)
}

export function fmtAgeShort(sec: number | null): string {
  if (sec == null) return "—"
  if (sec < 120) return sec + "s"
  if (sec < 3600) return Math.floor(sec / 60) + "m"
  if (sec < 86400) return Math.floor(sec / 3600) + "h"
  return Math.floor(sec / 86400) + "d"
}

export function fmtAgeLong(sec: number | null): string {
  if (sec == null) return "never"
  if (sec < 60) return sec + "s ago"
  if (sec < 3600) return Math.floor(sec / 60) + "m ago"
  if (sec < 86400) return Math.floor(sec / 3600) + "h ago"
  return Math.floor(sec / 86400) + "d ago"
}

export function fmtTs(unixSec: number): string {
  return new Date(unixSec * 1000).toLocaleString()
}

export function fmtNum(n: number): string {
  return n.toLocaleString()
}
