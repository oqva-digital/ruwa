import { useEffect, useMemo, useRef, useState } from "react"
import {
  Pause, Play, Trash2, Download, ChevronRight, Search, Radio,
} from "lucide-react"
import { api, streamEvents } from "@/lib/api"
import type { SessionEvent, SessionMeta } from "@/lib/types"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"

interface LogRow {
  id: number
  ts: number
  session: string
  ev: SessionEvent
}

const TYPE_TINT: Record<string, string> = {
  message: "progress",
  message_sent: "ok",
  message_delivered: "ok",
  connected: "ok",
  connecting: "progress",
  qr: "progress",
  paired: "ok",
  disconnected: "down",
  logged_out: "down",
  blocked: "blocked",
}

function summarize(ev: SessionEvent): string {
  const o = ev as Record<string, unknown>
  if (typeof o.body === "object" && o.body && "text" in o.body) return String((o.body as Record<string, unknown>).text)
  if (typeof o.reason === "string") return o.reason
  if (typeof o.id === "string") return o.id
  return ""
}
function chatOf(ev: SessionEvent): string {
  const o = ev as Record<string, unknown>
  return String(o.chat ?? o.from ?? o.jid ?? "")
}

export function LogsPage({
  scope, instances, label,
}: {
  scope: "global" | "instance"
  instances: SessionMeta[]
  label?: string
}) {
  const ids = instances.map((i) => i.id)
  const [rows, setRows] = useState<LogRow[]>([])
  const [paused, setPaused] = useState(false)
  const [q, setQ] = useState("")
  const [types, setTypes] = useState<Set<string>>(new Set())
  const [expanded, setExpanded] = useState<number | null>(null)
  const [autoScroll, setAutoScroll] = useState(true)
  // Per-instance SSE connection state, so the page can tell "connected but idle"
  // apart from "failed to connect" (they otherwise look identical).
  const [conn, setConn] = useState<Record<string, { state: "connecting" | "open" | "error"; err?: string }>>({})
  const pausedRef = useRef(paused)
  pausedRef.current = paused
  const counter = useRef(0)
  const bottomRef = useRef<HTMLDivElement>(null)
  const labelFor = useMemo(() => {
    const m = new Map(instances.map((i) => [i.id, i.label || i.id]))
    return (id: string) => m.get(id) ?? id
  }, [instances])

  useEffect(() => {
    let cancelled = false
    setRows([])
    setConn(Object.fromEntries(ids.map((id) => [id, { state: "connecting" as const }])))

    // Seed from the persisted event log so past activity shows immediately and
    // survives reloads, then prepend it before any live rows that arrive while
    // the fetch is in flight. History is best-effort — if it fails, the live
    // stream still works exactly as before.
    Promise.all(
      ids.map((id) =>
        api
          .eventHistory(id, { limit: 200 })
          .then((hist) => hist.map((h) => ({ session: id, ts: h.ts, ev: h.ev })))
          .catch(() => []),
      ),
    ).then((perInstance) => {
      if (cancelled) return
      const seed = perInstance
        .flat()
        .sort((a, b) => a.ts - b.ts)
        .map((r) => ({ id: counter.current++, ...r }))
      if (seed.length) setRows((live) => [...seed, ...live].slice(-800))
    })

    const stops = ids.map((id) =>
      streamEvents(
        id,
        (ev) => {
          if (pausedRef.current) return
          setRows((prev) => {
            const next = [...prev, { id: counter.current++, ts: Date.now(), session: id, ev }]
            return next.length > 800 ? next.slice(next.length - 800) : next
          })
        },
        (e) => setConn((c) => ({ ...c, [id]: { state: "error", err: e instanceof Error ? e.message : String(e) } })),
        () => setConn((c) => ({ ...c, [id]: { state: "open" } })),
      ),
    )
    return () => {
      cancelled = true
      stops.forEach((s) => s())
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ids.join(",")])

  const connList = Object.values(conn)
  const openCount = connList.filter((c) => c.state === "open").length
  const errs = connList.filter((c) => c.state === "error")

  useEffect(() => {
    if (autoScroll && !paused) bottomRef.current?.scrollIntoView({ block: "end" })
  }, [rows, autoScroll, paused])

  const seenTypes = useMemo(() => Array.from(new Set(rows.map((r) => r.ev.type))).sort(), [rows])
  const filtered = rows.filter((r) => {
    if (types.size && !types.has(r.ev.type)) return false
    if (q) {
      const hay = (r.session + " " + r.ev.type + " " + chatOf(r.ev) + " " + summarize(r.ev)).toLowerCase()
      if (!hay.includes(q.toLowerCase())) return false
    }
    return true
  })

  function download() {
    const ndjson = filtered.map((r) => JSON.stringify({ ts: r.ts, session: r.session, ...r.ev })).join("\n")
    const url = URL.createObjectURL(new Blob([ndjson], { type: "application/x-ndjson" }))
    const a = document.createElement("a")
    a.href = url
    a.download = "ruwa-events.ndjson"
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Logs</h1>
          <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
            <Radio className={cn("h-3 w-3", errs.length ? "text-st-down" : openCount ? "text-st-ok" : "text-st-warn")} />
            {scope === "global"
              ? `${openCount}/${ids.length} streaming`
              : errs.length
                ? "stream failed"
                : openCount
                  ? `${label} · live`
                  : `${label} · connecting…`}
            {" · "}{filtered.length} events
            {errs.length > 0 && <span className="text-st-down">· {errs.length} failed</span>}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter…" className="w-[180px] pl-8" />
          </div>
          <Button size="sm" variant="outline" onClick={() => setPaused((p) => !p)}>
            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button size="sm" variant="outline" onClick={() => setRows([])}>
            <Trash2 className="h-3.5 w-3.5" /> Clear
          </Button>
          <Button size="sm" variant="outline" onClick={download}>
            <Download className="h-3.5 w-3.5" /> NDJSON
          </Button>
          <button
            onClick={() => setAutoScroll((a) => !a)}
            className={cn("rounded-md border px-2.5 py-1 text-xs", autoScroll ? "border-primary/40 text-primary" : "text-muted-foreground")}
          >
            auto-scroll
          </button>
        </div>
      </div>

      {seenTypes.length > 0 && (
        <div className="mb-2 flex flex-wrap gap-1.5">
          {seenTypes.map((t) => {
            const on = types.has(t)
            return (
              <button
                key={t}
                data-st={on ? TYPE_TINT[t] ?? "neutral" : undefined}
                onClick={() =>
                  setTypes((s) => {
                    const n = new Set(s)
                    n.has(t) ? n.delete(t) : n.add(t)
                    return n
                  })
                }
                className={cn(
                  "rounded-full px-2.5 py-0.5 text-[11px] font-medium",
                  !on && "border border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {t}
              </button>
            )
          })}
        </div>
      )}

      <Card className="min-h-0 flex-1 overflow-auto p-0">
        {filtered.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-1.5 px-6 text-center text-sm text-muted-foreground">
            {rows.length > 0 ? (
              <span>No events match the current filter.</span>
            ) : ids.length === 0 ? (
              <span>No sessions to stream. Create or connect a session first.</span>
            ) : errs.length === ids.length ? (
              <>
                <span className="text-st-down">Stream failed: {errs[0]?.err}</span>
                <span className="text-xs">Check the API token and that the session still exists.</span>
              </>
            ) : paused ? (
              <span>paused</span>
            ) : openCount === 0 ? (
              <span>connecting…</span>
            ) : (
              <>
                <span>Connected — no events recorded yet</span>
                <span className="max-w-sm text-xs leading-relaxed">
                  This is a live feed of session activity (connect/disconnect, QR, inbound &amp; outbound
                  messages, delivery receipts). New events stream in as they happen and are saved, so
                  they&apos;ll still be here after a reload. Send or receive a message to see one.
                </span>
              </>
            )}
          </div>
        ) : (
          <div className="divide-y divide-border/60">
            {filtered.map((r) => {
              const open = expanded === r.id
              return (
                <div key={r.id}>
                  <button
                    onClick={() => setExpanded(open ? null : r.id)}
                    className="flex w-full items-center gap-3 px-3 py-1.5 text-left hover:bg-accent/40"
                  >
                    <ChevronRight className={cn("h-3.5 w-3.5 flex-none text-muted-foreground transition-transform", open && "rotate-90")} />
                    <span className="mono w-[78px] flex-none text-[11px] text-muted-foreground">
                      {new Date(r.ts).toLocaleTimeString()}
                    </span>
                    <span
                      data-st={TYPE_TINT[r.ev.type] ?? "neutral"}
                      className="inline-flex h-[18px] flex-none items-center rounded-full px-2 text-[10.5px] font-medium"
                    >
                      {r.ev.type}
                    </span>
                    {scope === "global" && (
                      <span className="mono w-[120px] flex-none truncate text-[11px] text-muted-foreground">{labelFor(r.session)}</span>
                    )}
                    <span className="mono flex-none truncate text-[11px] text-muted-foreground" style={{ maxWidth: 160 }}>
                      {chatOf(r.ev)}
                    </span>
                    <span className="truncate text-[12px]">{summarize(r.ev)}</span>
                  </button>
                  {open && (
                    <div className="px-3 pb-2 pl-10">
                      <pre className="json text-[11px]">{JSON.stringify(r.ev, null, 2)}</pre>
                    </div>
                  )}
                </div>
              )
            })}
            <div ref={bottomRef} />
          </div>
        )}
      </Card>
    </div>
  )
}
