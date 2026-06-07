import { useMemo, useState } from "react"
import { useQuery, keepPreviousData } from "@tanstack/react-query"
import { RefreshCw, Terminal } from "lucide-react"
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts"
import { api } from "@/lib/api"
import type { SessionMeta, SessionHealth } from "@/lib/types"
import { fmtAgeShort, fmtNum } from "@/lib/format"
import { StatCard, SectionCard, CollapsibleSection } from "@/components/ui-bits"
import { Button } from "@/components/ui/button"
import { cn } from "@/lib/utils"

const TREND_WINDOWS = [
  { label: "1h", secs: 3_600 },
  { label: "6h", secs: 21_600 },
  { label: "24h", secs: 86_400 },
  { label: "7d", secs: 604_800 },
]

const TREND_SERIES: { name: string; label: string; kind?: "bytes" | "ms"; down?: boolean }[] = [
  { name: "ruwa_sessions_connected", label: "Sessions connected" },
  { name: "ruwa_messages_in_total", label: "Messages in" },
  { name: "ruwa_messages_out_total", label: "Messages out" },
  { name: "ruwa_reconnects_total", label: "Reconnects" },
  { name: "ruwa_decrypt_failures_total", label: "Decrypt failures", down: true },
  { name: "ruwa_webhook_failed_total", label: "Webhooks failed", down: true },
  { name: "ruwa_process_resident_memory_bytes", label: "RAM (RSS)", kind: "bytes" },
  { name: "ruwa_http_request_duration_ms_avg", label: "Avg latency", kind: "ms" },
]

function SeriesChart({
  name, label, since, kind, down,
}: { name: string; label: string; since: number; kind?: "bytes" | "ms"; down?: boolean }) {
  const q = useQuery({
    queryKey: ["mhist", name, since],
    queryFn: () => api.metricsHistory(name, since, 2000),
    refetchInterval: 30_000,
    // Soft refresh: keep the current chart visible while a refetch or a
    // window switch loads, instead of blanking to a "loading…" placeholder.
    placeholderData: keepPreviousData,
  })
  const pts = q.data?.points ?? []
  const last = pts.length ? pts[pts.length - 1].value : undefined
  const color = down ? "var(--st-down)" : "var(--primary)"
  const fmtVal = (v: number) =>
    kind === "bytes" ? fmtBytes(v) : kind === "ms" ? v.toFixed(0) + " ms" : fmtNum(v)
  return (
    <div className="rounded-lg border bg-card/40 p-3">
      <div className="mb-1 flex items-baseline justify-between">
        <span className="text-xs font-medium text-muted-foreground">{label}</span>
        <span className="mono text-sm font-semibold tabular-nums">{last != null ? fmtVal(last) : "—"}</span>
      </div>
      <div className="h-24">
        {pts.length === 0 ? (
          <div className="flex h-full items-center justify-center text-[11px] text-muted-foreground">
            {q.isLoading ? "loading…" : "no samples yet"}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={pts} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
              <defs>
                <linearGradient id={`g-${name}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={`hsl(${color})`} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={`hsl(${color})`} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="ts" hide />
              <YAxis hide domain={["auto", "auto"]} />
              <Tooltip
                contentStyle={{
                  fontSize: 11, padding: "4px 8px", borderRadius: 6,
                  background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))",
                }}
                labelFormatter={(ts) => new Date(Number(ts) * 1000).toLocaleString()}
                formatter={(v) => [fmtVal(Number(v)), label]}
              />
              <Area
                type="monotone" dataKey="value" stroke={`hsl(${color})`} strokeWidth={1.5}
                fill={`url(#g-${name})`} isAnimationActive={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}

function Trends() {
  const [win, setWin] = useState(TREND_WINDOWS[1]) // default 6h
  // Stable per window selection — recomputing from Date.now() on every render
  // would change each chart's queryKey constantly and cause spurious refetches
  // (the "hard reload" flicker). The chart still grows as the interval refetch
  // pulls new points; only the window's left edge is pinned at selection time.
  const since = useMemo(() => Math.floor(Date.now() / 1000) - win.secs, [win])
  return (
    <SectionCard
      title="Trends"
      className="mb-5"
      action={
        <div className="flex gap-1">
          {TREND_WINDOWS.map((w) => (
            <button
              key={w.label}
              onClick={() => setWin(w)}
              className={cn(
                "rounded-md px-2 py-0.5 text-[11px] font-medium",
                w.label === win.label
                  ? "border border-primary/40 text-primary"
                  : "border border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              {w.label}
            </button>
          ))}
        </div>
      }
    >
      <div className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
        {TREND_SERIES.map((s) => (
          <SeriesChart key={s.name} {...s} since={since} />
        ))}
      </div>
      <p className="px-4 pb-3 text-[11px] text-muted-foreground">
        Persisted from the in-memory <code>/metrics</code> every ~60s — survives restarts/deploys.
        Cumulative counters reset to 0 on restart (shown as a drop).
      </p>
    </SectionCard>
  )
}

function parseMetrics(text: string): Record<string, number> {
  const out: Record<string, number> = {}
  for (const line of text.split("\n")) {
    if (!line || line.startsWith("#")) continue
    const sp = line.lastIndexOf(" ")
    if (sp < 0) continue
    const name = line.slice(0, sp).trim()
    const val = Number(line.slice(sp + 1))
    if (!Number.isNaN(val)) out[name] = val
  }
  return out
}
function fmtBytes(b?: number) {
  if (b == null) return "—"
  if (b > 1 << 30) return (b / (1 << 30)).toFixed(1) + " GB"
  return (b / (1 << 20)).toFixed(0) + " MB"
}
function fmtUptime(s?: number) {
  if (s == null) return "—"
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60)
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`
}

export function MetricsPage({ scope, inst }: { scope: "global" | "instance"; inst?: SessionMeta }) {
  if (scope === "instance" && inst) return <InstanceMetrics inst={inst} />
  return <GlobalMetrics />
}

function GlobalMetrics() {
  const q = useQuery({ queryKey: ["metrics"], queryFn: api.metricsText, refetchInterval: 5000 })
  const m = q.data ? parseMetrics(q.data) : {}
  const reqs = m["ruwa_http_requests_total"]
  const avg = m["ruwa_http_request_duration_ms_avg"]

  return (
    <div>
      <div className="mb-4 flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Metrics</h1>
          <div className="mt-0.5 text-xs text-muted-foreground">Fleet aggregate · /metrics (Prometheus, bearer-authed)</div>
        </div>
        <Button size="sm" variant="outline" onClick={() => q.refetch()}><RefreshCw className="h-3.5 w-3.5" /> Refresh</Button>
      </div>

      {q.isError && <div className="text-sm text-destructive">{(q.error as Error)?.message}</div>}

      <Trends />

      <Group label="Domain">
        <StatCard
          label="Sessions"
          value={`${m["ruwa_sessions_connected"] ?? 0} / ${m["ruwa_sessions_total"] ?? 0}`}
          sub={<span className="text-xs text-muted-foreground">connected / total</span>}
          info="WhatsApp sessions registered in this instance: how many currently hold a live connection vs. how many exist in total."
        />
        <StatCard
          label="Messages in"
          value={fmtNum(m["ruwa_messages_in_total"] ?? 0)}
          info="Inbound message stanzas received on the socket since this process started. Counts every <message> node before decryption — including protocol/system messages and retries — so it runs higher than the messages shown in chats. Resets to 0 on restart."
        />
        <StatCard
          label="Messages out"
          value={fmtNum(m["ruwa_messages_out_total"] ?? 0)}
          info="Outbound messages handed to the socket since process start — text, media, reactions, edits, revokes, and retry resends all count. Resets to 0 on restart."
        />
        <StatCard
          label="Decrypt failures"
          value={fmtNum(m["ruwa_decrypt_failures_total"] ?? 0)}
          accent={m["ruwa_decrypt_failures_total"] ? "hsl(var(--st-down))" : undefined}
          info="Inbound messages that could not be decrypted and were persisted as undecryptable. Cumulative since process start; > 0 turns red."
        />
        <StatCard
          label="Reconnects"
          value={fmtNum(m["ruwa_reconnects_total"] ?? 0)}
          info="WebSocket reconnect attempts across all sessions since process start."
        />
        <StatCard
          label="Prekey refills"
          value={fmtNum(m["ruwa_prekey_refills_total"] ?? 0)}
          info="One-time-prekey replenishment batches generated and uploaded to WhatsApp since process start."
        />
        <StatCard
          label="Webhooks delivered"
          value={fmtNum(m["ruwa_webhook_delivered_total"] ?? 0)}
          accent="hsl(var(--st-ok))"
          info="Webhook deliveries that ultimately returned 2xx (possibly after retries). Cumulative since process start."
        />
        <StatCard
          label="Webhooks failed"
          value={fmtNum(m["ruwa_webhook_failed_total"] ?? 0)}
          accent={m["ruwa_webhook_failed_total"] ? "hsl(var(--st-down))" : undefined}
          info="Webhook deliveries dropped after exhausting every retry attempt. Cumulative since process start; > 0 turns red."
        />
      </Group>

      <Group label="System / runtime">
        <StatCard
          label="RAM (RSS)"
          value={fmtBytes(m["ruwa_process_resident_memory_bytes"])}
          sub={m["ruwa_process_resident_memory_bytes"] == null ? <span className="text-xs text-muted-foreground">Linux only</span> : undefined}
          info="Resident set size — physical memory the process currently holds. Read from /proc on Linux; unavailable on macOS/Windows dev hosts (shows —)."
        />
        <StatCard
          label="CPU seconds"
          value={m["ruwa_process_cpu_seconds_total"]?.toFixed(0) ?? "—"}
          sub={<span className="text-xs text-muted-foreground">{m["ruwa_process_cpu_seconds_total"] == null ? "Linux only" : "→ %CPU via rate"}</span>}
          info="Cumulative CPU time (user + system) the process has consumed since boot. This is a counter, not a live percentage — derive %CPU from its rate over time. Linux only."
        />
        <StatCard
          label="Uptime"
          value={fmtUptime(m["ruwa_process_uptime_seconds"])}
          info="Time elapsed since this process started serving."
        />
        <StatCard
          label="Open FDs"
          value={m["ruwa_process_open_fds"] ?? "—"}
          sub={m["ruwa_process_open_fds"] == null ? <span className="text-xs text-muted-foreground">Linux only</span> : undefined}
          info="Open file descriptors held by the process — sockets, files, and pipes. A steady climb signals a leak. Linux only (shows — on macOS/Windows)."
        />
        <StatCard
          label="HTTP requests"
          value={fmtNum(reqs ?? 0)}
          info="Total HTTP requests served by this instance since process start — every /, /v1/* and /metrics call."
        />
        <StatCard
          label="Avg response time"
          value={avg != null ? avg.toFixed(1) + " ms" : "—"}
          accent={avg != null && avg > 100 ? "hsl(var(--st-warn))" : undefined}
          info="Mean HTTP response time since process start: total request duration ÷ request count. Turns amber above 100 ms."
        />
      </Group>

      <CollapsibleSection title="Raw /metrics" icon={Terminal}>
        <pre className="json max-h-80 overflow-auto text-[11px]">{q.data ?? "loading…"}</pre>
      </CollapsibleSection>
    </div>
  )
}

function InstanceMetrics({ inst }: { inst: SessionMeta }) {
  const h = useQuery<SessionHealth>({ queryKey: ["health", inst.id], queryFn: () => api.sessionHealth(inst.id), refetchInterval: 5000 })
  const d = h.data
  return (
    <div>
      <div className="mb-4">
        <h1 className="text-xl font-semibold tracking-tight">Metrics</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Scoped to {inst.label ?? inst.id}</div>
      </div>
      <Group label="This instance">
        <StatCard label="Last rx" value={fmtAgeShort(d?.seconds_since_rx ?? null)} />
        <StatCard label="Reconnects" value={d?.reconnect_count ?? "—"} />
        <StatCard label="Prekeys available" value={d?.prekeys_available ?? "—"} accent={d && d.prekeys_available < 20 ? "hsl(var(--st-warn))" : undefined} />
        <StatCard label="Connected" value={d?.connected ? "yes" : "no"} accent={d?.connected ? "hsl(var(--st-ok))" : "hsl(var(--st-down))"} />
        <StatCard label="Proxy" value={d?.proxy_configured ? "configured" : "none"} />
      </Group>
      <p className="text-xs text-muted-foreground">Fleet-wide counters are on the global Metrics page (process RAM/CPU/latency, message totals, webhook health).</p>
    </div>
  )
}

function Group({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <SectionCard title={label} className="mb-5">
      <div className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-3 lg:grid-cols-4">{children}</div>
    </SectionCard>
  )
}
