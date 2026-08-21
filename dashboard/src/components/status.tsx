import {
  Wifi,
  WifiOff,
  RefreshCw,
  Clock,
  QrCode,
  Power,
  TriangleAlert,
  Ban,
  Circle,
  Cloud,
  Smartphone,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { statusMeta, liveness, type StatusKey } from "@/lib/format"
import type { SessionStatus } from "@/lib/types"

const ICONS: Record<string, typeof Wifi> = {
  wifi: Wifi,
  wifiOff: WifiOff,
  refresh: RefreshCw,
  clock: Clock,
  qr: QrCode,
  power: Power,
  alert: TriangleAlert,
  ban: Ban,
  dot: Circle,
}

/** Pill status badge — color tint via [data-st] (index.css), plus word + icon. */
export function StatusBadge({ status }: { status: SessionStatus | string }) {
  const m = statusMeta(status)
  const Ico = ICONS[m.icon] ?? Circle
  return (
    <span
      data-st={m.st}
      className="inline-flex h-5 items-center gap-1.5 rounded-full px-2 text-[11.5px] font-medium leading-none"
    >
      <Ico className="h-3 w-3" />
      {m.label}
    </span>
  )
}

/** Liveness chip — "live · 8s" / pulsing "frozen · 92s" / "down". The frozen
 *  pulse is the signal we want an operator to catch across the room. */
export function LivenessChip({
  status,
  lastRxSec,
  kind,
  className,
}: {
  status: SessionStatus | string
  lastRxSec: number | null
  kind?: string
  className?: string
}) {
  const lv = liveness(status, lastRxSec, kind)
  return (
    <span className={cn("chip", lv.cls, className)}>
      <span className={cn("dot", lv.kind === "frozen" && "pulse-dot")} />
      {lv.label}
    </span>
  )
}

/** Bare status dot (for the switcher / compact rows). */
export function StatusDot({ st, pulse }: { st: StatusKey; pulse?: boolean }) {
  return (
    <span
      className={cn("dot inline-block h-[7px] w-[7px] flex-none rounded-full", pulse && "pulse-dot")}
      style={{ background: `hsl(var(--st-${st === "neutral" ? "progress" : st}))` }}
    />
  )
}

/** Session backend pill — "web" (WhatsApp Web socket) or "cloud" (Meta Cloud API). */
export function KindBadge({ kind, className }: { kind?: string | null; className?: string }) {
  const cloud = kind === "cloud"
  const Ico = cloud ? Cloud : Smartphone
  return (
    <span
      data-st={cloud ? "progress" : "neutral"}
      className={cn("inline-flex h-5 items-center gap-1 rounded-full px-2 text-[11px] font-medium leading-none", className)}
      title={cloud ? "Meta WhatsApp Cloud API" : "WhatsApp Web (linked device)"}
    >
      <Ico className="h-3 w-3" />
      {cloud ? "cloud" : "web"}
    </span>
  )
}
