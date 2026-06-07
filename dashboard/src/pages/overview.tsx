import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  Plug, RefreshCw, Database, QrCode, Power, Wifi, WifiOff, Snowflake,
  TriangleAlert, Activity, Terminal,
} from "lucide-react"
import { api } from "@/lib/api"
import { fmtAgeShort, fmtAgeLong, liveness } from "@/lib/format"
import type { SessionMeta, SessionHealth } from "@/lib/types"
import { StatusBadge, LivenessChip } from "@/components/status"
import { confirmDialog, promptDialog } from "@/components/confirm"
import { StatCard, SectionCard, JsonBlock, CollapsibleSection } from "@/components/ui-bits"
import { Button } from "@/components/ui/button"
import type { InstancePage } from "@/components/shell"

export function OverviewPage({
  inst, onNav, readonly,
}: {
  inst: SessionMeta
  onNav: (p: InstancePage) => void
  readonly: boolean
}) {
  const qc = useQueryClient()
  const health = useQuery<SessionHealth>({
    queryKey: ["health", inst.id],
    queryFn: () => api.sessionHealth(inst.id),
    refetchInterval: 5000,
  })

  const h = health.data
  const lastRxSec = h?.seconds_since_rx ?? null
  const lv = liveness(inst.status, lastRxSec)
  const stColor = lv.kind === "live" ? "ok" : lv.kind === "frozen" ? "frozen" : lv.kind === "down" ? "down" : "progress"
  const LiveIco = lv.kind === "frozen" ? Snowflake : lv.kind === "live" ? Wifi : WifiOff

  async function act(label: string, fn: () => Promise<unknown>, ok: string) {
    try {
      await fn()
      toast.success(ok, { description: inst.label ?? inst.id })
      qc.invalidateQueries({ queryKey: ["sessions"] })
      qc.invalidateQueries({ queryKey: ["health", inst.id] })
    } catch (e) {
      toast.error(label + " failed", { description: e instanceof Error ? e.message : "" })
    }
  }

  return (
    <div>
      {/* header */}
      <div className="mb-3.5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="mb-1 flex items-center gap-2.5">
            <h1 className="text-xl font-semibold tracking-tight">{inst.label || "(no label)"}</h1>
            <StatusBadge status={inst.status} />
            {lv.kind === "frozen" && <LivenessChip status={inst.status} lastRxSec={lastRxSec} />}
          </div>
          <div className="mono text-[11px] text-muted-foreground">{inst.jid ?? "not paired"}</div>
        </div>
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" variant="outline" disabled={readonly} onClick={() => act("Connect", () => api.connect(inst.id), "Connecting…")}>
            <Plug className="h-3.5 w-3.5" /> Connect
          </Button>
          <Button size="sm" variant="outline" disabled={readonly} onClick={() => act("Reconnect", () => api.connect(inst.id), "Reconnect queued")}>
            <RefreshCw className="h-3.5 w-3.5" /> Reconnect
          </Button>
          <Button size="sm" variant="outline" disabled={readonly} onClick={async () => {
            const url = await promptDialog({ title: "Set proxy", message: "Blank to clear. Takes effect on reconnect.", defaultValue: inst.proxy_url ?? "", placeholder: "http://user:pass@host:port", confirmLabel: "Save" })
            if (url !== null) act("Set proxy", () => api.setProxy(inst.id, url.trim() || null), "Proxy set (reconnect to apply)")
          }}>
            <Database className="h-3.5 w-3.5" /> Set proxy
          </Button>
          <Button size="sm" variant="outline" onClick={() => onNav("pairing")}>
            <QrCode className="h-3.5 w-3.5" /> Pair
          </Button>
          <Button size="sm" variant="destructive" disabled={readonly} onClick={async () => {
            if (await confirmDialog({ title: "Log out this device?", message: `"${inst.label ?? inst.id}" will be unlinked.`, confirmLabel: "Logout", danger: true })) act("Logout", () => api.logout(inst.id), "Logged out")
          }}>
            <Power className="h-3.5 w-3.5" /> Logout
          </Button>
        </div>
      </div>

      {/* body: stat grid + liveness panel */}
      <div className="grid grid-cols-1 items-start gap-4 lg:grid-cols-[1fr_320px]">
        <div className="flex flex-col gap-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
            <StatCard label="Last rx" value={fmtAgeShort(lastRxSec)} accent={`hsl(var(--st-${stColor}))`} />
            <StatCard label="Liveness" value={lv.kind === "live" ? "LIVE" : lv.kind.toUpperCase()} accent={`hsl(var(--st-${stColor}))`} />
            <StatCard label="Reconnects" value={h?.reconnect_count ?? "—"} />
            <StatCard label="Prekeys" value={h?.prekeys_available ?? "—"} accent={h && h.prekeys_available < 20 ? "hsl(var(--st-warn))" : undefined} />
            <StatCard label="Proxy" value={h?.proxy_configured ? "configured" : "none"} />
            <StatCard label="WA blocked" value={inst.status === "blocked" ? "YES" : "No"} accent={inst.status === "blocked" ? "hsl(var(--st-down))" : undefined} />
          </div>
          <CollapsibleSection title="Raw health JSON" icon={Terminal}>
            {h ? <JsonBlock data={h} /> : <div className="text-xs text-muted-foreground">loading…</div>}
          </CollapsibleSection>
        </div>

        <SectionCard title="Socket liveness" icon={Activity}>
          <div className="p-4">
            <div className="flex items-center gap-3">
              <div
                className="grid h-10 w-10 place-items-center rounded-[10px]"
                style={{ background: `hsl(var(--st-${stColor}) / .14)`, color: `hsl(var(--st-${stColor}))` }}
              >
                <LiveIco className={"h-5 w-5" + (lv.kind === "frozen" ? " pulse-dot" : "")} />
              </div>
              <div>
                <div className="text-[15px] font-semibold" style={{ color: `hsl(var(--st-${stColor}))` }}>
                  {lv.kind === "live" ? "Live" : lv.kind === "frozen" ? "Looks frozen" : lv.kind === "down" ? "Down" : "Connecting"}
                </div>
                <div className="text-xs text-muted-foreground">
                  {lv.kind === "live"
                    ? `last frame ${fmtAgeLong(lastRxSec)}`
                    : lv.kind === "frozen"
                      ? `no inbound for ${lastRxSec}s`
                      : lv.kind === "down"
                        ? "socket closed"
                        : "establishing…"}
                </div>
              </div>
            </div>
            {lv.kind === "frozen" && (
              <div className="mt-3 flex gap-2 rounded-md border border-st-frozen/25 bg-st-frozen/10 px-3 py-2.5">
                <TriangleAlert className="mt-0.5 h-3.5 w-3.5 flex-none text-st-frozen" />
                <div className="text-[13px] text-st-frozen">
                  Socket is open but receiving nothing. The rx-idle watchdog force-reconnects at 75s.
                </div>
              </div>
            )}
            <div className="my-3.5 h-px bg-border" />
            <div className="flex flex-col gap-2">
              {[
                ["Reconnect count", h?.reconnect_count ?? "—"],
                ["Prekeys available", h?.prekeys_available ?? "—"],
                ["Proxy", h?.proxy_configured ? "configured" : "none"],
                ["JID", inst.jid ?? "—"],
              ].map(([k, v]) => (
                <div key={k} className="flex justify-between gap-3">
                  <span className="text-xs text-muted-foreground">{k}</span>
                  <span className="mono truncate text-[11px]">{v}</span>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>
      </div>
    </div>
  )
}
