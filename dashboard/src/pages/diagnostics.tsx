import { useMemo, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { RefreshCw, Search, Download, Pause, Play } from "lucide-react"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"

const LEVELS = [
  { key: "", label: "All" },
  { key: "info", label: "Info+" },
  { key: "warn", label: "Warn+" },
  { key: "error", label: "Error" },
]
const LEVEL_TINT: Record<string, string> = {
  ERROR: "down",
  WARN: "warn",
  INFO: "progress",
  DEBUG: "neutral",
  TRACE: "neutral",
}

/** Server process-log viewer — the in-house persistent log ring (GET /v1/logs).
 *  Distinct from the per-session activity feed on the Logs page; this is the
 *  server's own tracing output (warn/error/info), surviving restarts/deploys. */
export function DiagnosticsPage() {
  const [level, setLevel] = useState("")
  const [q, setQ] = useState("")
  const [paused, setPaused] = useState(false)
  const query = useQuery({
    queryKey: ["serverlogs", level],
    queryFn: () => api.serverLogs({ level: level || undefined, limit: 500 }),
    refetchInterval: paused ? false : 5000,
  })
  const rows = query.data?.logs ?? []
  const filtered = useMemo(() => {
    if (!q) return rows
    const needle = q.toLowerCase()
    return rows.filter((r) =>
      (r.message + " " + r.target + " " + r.level).toLowerCase().includes(needle),
    )
  }, [rows, q])

  function download() {
    const ndjson = filtered.map((r) => JSON.stringify(r)).join("\n")
    const url = URL.createObjectURL(new Blob([ndjson], { type: "application/x-ndjson" }))
    const a = document.createElement("a")
    a.href = url
    a.download = "ruwa-server-logs.ndjson"
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Diagnostics</h1>
          <div className="mt-0.5 text-xs text-muted-foreground">
            Server process logs · persisted, survives restarts · {filtered.length} lines
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex gap-1">
            {LEVELS.map((l) => (
              <button
                key={l.key}
                onClick={() => setLevel(l.key)}
                className={cn(
                  "rounded-md px-2.5 py-1 text-xs font-medium",
                  l.key === level
                    ? "border border-primary/40 text-primary"
                    : "border border-border text-muted-foreground hover:text-foreground",
                )}
              >
                {l.label}
              </button>
            ))}
          </div>
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="filter…"
              className="w-[180px] pl-8"
            />
          </div>
          <Button size="sm" variant="outline" onClick={() => setPaused((p) => !p)}>
            {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            {paused ? "Resume" : "Pause"}
          </Button>
          <Button size="sm" variant="outline" onClick={() => query.refetch()}>
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button size="sm" variant="outline" onClick={download}>
            <Download className="h-3.5 w-3.5" /> NDJSON
          </Button>
        </div>
      </div>

      <Card className="min-h-0 flex-1 overflow-auto p-0">
        {query.isError ? (
          <div className="flex h-full items-center justify-center text-sm text-destructive">
            {(query.error as Error)?.message}
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-1.5 px-6 text-center text-sm text-muted-foreground">
            {query.isLoading
              ? "loading…"
              : rows.length
                ? "No lines match the filter."
                : "No server logs captured yet."}
          </div>
        ) : (
          <div className="divide-y divide-border/60 font-mono text-[11.5px]">
            {filtered.map((r) => (
              <div key={r.id} className="flex items-start gap-3 px-3 py-1 hover:bg-accent/40">
                <span className="w-[112px] flex-none text-muted-foreground">
                  {new Date(r.ts).toLocaleTimeString()}
                </span>
                <span
                  data-st={LEVEL_TINT[r.level] ?? "neutral"}
                  className="inline-flex h-[16px] w-[48px] flex-none items-center justify-center rounded px-1 text-[10px] font-semibold"
                >
                  {r.level}
                </span>
                <span className="w-[120px] flex-none truncate text-muted-foreground" title={r.target}>
                  {r.target}
                </span>
                <span className="min-w-0 flex-1 whitespace-pre-wrap break-words">{r.message}</span>
              </div>
            ))}
          </div>
        )}
      </Card>
    </div>
  )
}
