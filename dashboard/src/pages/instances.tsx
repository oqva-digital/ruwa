import { useMemo, useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  Search, Plus, Upload, MoreHorizontal, ExternalLink, Plug, Power, Trash2,
  Snowflake, Inbox, Copy, CheckCircle2, TriangleAlert, Loader2, Pencil,
} from "lucide-react"
import { Textarea } from "@/components/ui/textarea"
import { api, ApiError } from "@/lib/api"
import type { SessionMeta, SessionHealth } from "@/lib/types"
import { cn } from "@/lib/utils"
import { StatusBadge, LivenessChip } from "@/components/status"
import { confirmDialog } from "@/components/confirm"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

function jidPhone(jid: string | null): string {
  if (!jid) return "—"
  const user = jid.split("@")[0]?.split(":")[0] ?? ""
  return user ? "+" + user : "—"
}

type Filter = "all" | "connected" | "frozen" | "down"

export function InstancesPage({ onOpen, readonly }: { onOpen: (id: string) => void; readonly: boolean }) {
  const qc = useQueryClient()
  const [q, setQ] = useState("")
  const [filter, setFilter] = useState<Filter>("all")
  const [showCreate, setShowCreate] = useState(false)
  const [showImport, setShowImport] = useState(false)
  const [createdKey, setCreatedKey] = useState<string | null>(null)

  const sessions = useQuery({
    queryKey: ["sessions"],
    queryFn: api.listSessions,
    refetchInterval: 8000,
  })

  const list = sessions.data ?? []
  const filtered = useMemo(() => {
    const term = q.toLowerCase()
    return list.filter((s) => {
      const matchesTerm =
        !term ||
        (s.label ?? "").toLowerCase().includes(term) ||
        s.id.toLowerCase().includes(term) ||
        (s.jid ?? "").includes(term)
      const matchesFilter =
        filter === "all" ||
        (filter === "connected" && s.status === "connected") ||
        (filter === "down" && s.status !== "connected" && s.status !== "connecting") ||
        filter === "frozen" // frozen needs per-row health; we don't hard-filter it here
      return matchesTerm && matchesFilter
    })
  }, [list, q, filter])

  const connected = list.filter((s) => s.status === "connected").length

  return (
    <div>
      <div className="mb-4 flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Instances</h1>
          <div className="mt-0.5 text-xs text-muted-foreground">
            {list.length} sessions · {connected} connected
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search label, id, phone…"
              className="w-[230px] pl-8"
            />
          </div>
          <div className="flex rounded-md bg-muted p-0.5">
            {(["all", "connected", "frozen", "down"] as Filter[]).map((f) => (
              <button
                key={f}
                onClick={() => setFilter(f)}
                className={cn(
                  "rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors",
                  filter === f ? "bg-card text-foreground shadow-sm" : "text-muted-foreground",
                )}
              >
                {f === "connected" ? "live" : f}
              </button>
            ))}
          </div>
          <Button variant="outline" disabled={readonly} onClick={() => setShowImport(true)}>
            <Upload className="h-4 w-4" /> Import from Evolution
          </Button>
          <Tooltip>
            <TooltipTrigger asChild>
              <span>
                <Button disabled={readonly} onClick={() => setShowCreate(true)}>
                  <Plus className="h-4 w-4" /> Create instance
                </Button>
              </span>
            </TooltipTrigger>
            {readonly && <TooltipContent>Disabled in readonly mode</TooltipContent>}
          </Tooltip>
        </div>
      </div>

      <Card className="overflow-hidden p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Label</TableHead>
                <TableHead>Instance id</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Phone / JID</TableHead>
                <TableHead>Last rx</TableHead>
                <TableHead className="text-right">Recon.</TableHead>
                <TableHead className="text-center">Hook</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {sessions.isLoading &&
                Array.from({ length: 4 }).map((_, i) => (
                  <TableRow key={i}>
                    <TableCell colSpan={8}>
                      <div className="skeleton h-5 w-full" />
                    </TableCell>
                  </TableRow>
                ))}
              {filtered.map((s) => (
                <InstanceRow
                  key={s.id}
                  s={s}
                  filter={filter}
                  readonly={readonly}
                  onOpen={onOpen}
                  onChanged={() => qc.invalidateQueries({ queryKey: ["sessions"] })}
                />
              ))}
            </TableBody>
          </Table>
        </div>
        {!sessions.isLoading && filtered.length === 0 && (
          <div className="flex flex-col items-center gap-2 py-14 text-center">
            <Inbox className="h-7 w-7 text-muted-foreground" />
            <div className="text-sm font-medium">No instances match</div>
            <div className="text-xs text-muted-foreground">Try a different search/filter, or create a session.</div>
            <Button className="mt-2" disabled={readonly} onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4" /> Create instance
            </Button>
          </div>
        )}
        {sessions.isError && (
          <div className="px-4 py-3 text-xs text-destructive">
            {(sessions.error as Error)?.message ?? "Failed to load sessions"}
          </div>
        )}
      </Card>

      <div className="mt-2.5 flex items-center gap-1.5 text-xs text-muted-foreground">
        <Snowflake className="h-3 w-3 text-st-frozen" />
        <span>
          A <span className="font-medium text-st-frozen">frozen</span> row reads <b>connected</b> but its last inbound
          frame is stale (the masked-dead case) — the rx-idle watchdog force-reconnects.
        </span>
      </div>

      <CreateDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(key) => {
          setShowCreate(false)
          setCreatedKey(key)
          qc.invalidateQueries({ queryKey: ["sessions"] })
        }}
      />
      <ImportDialog
        open={showImport}
        onClose={() => setShowImport(false)}
        onImported={(key) => {
          setShowImport(false)
          setCreatedKey(key)
          qc.invalidateQueries({ queryKey: ["sessions"] })
        }}
      />
      <KeyDialog apiKey={createdKey} onClose={() => setCreatedKey(null)} />
    </div>
  )
}

function InstanceRow({
  s, filter, readonly, onOpen, onChanged,
}: {
  s: SessionMeta
  filter: Filter
  readonly: boolean
  onOpen: (id: string) => void
  onChanged: () => void
}) {
  const health = useQuery<SessionHealth>({
    queryKey: ["health", s.id],
    queryFn: () => api.sessionHealth(s.id),
    refetchInterval: 6000,
  })
  const webhook = useQuery({
    queryKey: ["webhook", s.id],
    queryFn: () => api.getWebhook(s.id).then(() => true).catch((e) => {
      if (e instanceof ApiError && e.status === 404) return false
      throw e
    }),
    staleTime: 60_000,
  })

  const lastRxSec = health.data?.seconds_since_rx ?? null
  const recon = health.data?.reconnect_count ?? 0
  const frozen = s.status === "connected" && lastRxSec != null && lastRxSec >= 75

  const [renaming, setRenaming] = useState(false)
  const [renameVal, setRenameVal] = useState(s.label ?? "")
  const [renameBusy, setRenameBusy] = useState(false)

  // soft filter for "frozen" (needs health, resolved client-side)
  if (filter === "frozen" && !frozen) return null

  async function act(label: string, fn: () => Promise<unknown>, ok: string) {
    try {
      await fn()
      toast.success(ok, { description: s.label ?? s.id })
      onChanged()
    } catch (e) {
      toast.error(label + " failed", { description: e instanceof Error ? e.message : "" })
    }
  }

  async function submitRename() {
    setRenameBusy(true)
    try {
      await api.setLabel(s.id, renameVal.trim() || null)
      toast.success("Renamed", { description: renameVal.trim() || "(no label)" })
      setRenaming(false)
      onChanged()
    } catch (e) {
      toast.error("Rename failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setRenameBusy(false)
    }
  }

  return (
    <>
    <TableRow className="cursor-pointer" onClick={() => onOpen(s.id)}>
      <TableCell className="font-medium">{s.label || "(no label)"}</TableCell>
      <TableCell>
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="mono text-[11px]">{s.id.length > 20 ? s.id.slice(0, 19) + "…" : s.id}</span>
          </TooltipTrigger>
          <TooltipContent className="mono">{s.id}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell><StatusBadge status={s.status} /></TableCell>
      <TableCell><span className="mono text-[11px] text-muted-foreground">{jidPhone(s.jid)}</span></TableCell>
      <TableCell>
        {health.isLoading ? (
          <span className="text-xs text-muted-foreground">…</span>
        ) : (
          <LivenessChip status={s.status} lastRxSec={lastRxSec} />
        )}
      </TableCell>
      <TableCell className="mono tnum text-right">{recon}</TableCell>
      <TableCell className="text-center">
        <Tooltip>
          <TooltipTrigger asChild>
            <span
              className="inline-block h-[7px] w-[7px] rounded-full"
              style={{ background: webhook.data ? "hsl(var(--st-ok))" : "hsl(var(--muted-foreground) / .4)" }}
            />
          </TooltipTrigger>
          <TooltipContent>{webhook.data ? "Webhook configured" : "No webhook"}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell onClick={(e) => e.stopPropagation()}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button size="icon" variant="ghost" className="h-7 w-7">
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => onOpen(s.id)}>
              <ExternalLink className="h-4 w-4" /> Open
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={readonly}
              onClick={() => { setRenameVal(s.label ?? ""); setRenaming(true) }}
            >
              <Pencil className="h-4 w-4" /> Rename
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={readonly}
              onClick={() => act("Connect", () => api.connect(s.id), "Connecting…")}
            >
              <Plug className="h-4 w-4" /> Connect
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              disabled={readonly}
              onClick={async () => {
                if (await confirmDialog({ title: "Log out this device?", message: `"${s.label ?? s.id}" will be unlinked.`, confirmLabel: "Logout", danger: true }))
                  act("Logout", () => api.logout(s.id), "Logged out")
              }}
            >
              <Power className="h-4 w-4" /> Logout
            </DropdownMenuItem>
            <DropdownMenuItem
              variant="destructive"
              disabled={readonly}
              onClick={async () => {
                if (await confirmDialog({ title: "Delete instance?", message: `"${s.label ?? s.id}" will be removed permanently.`, confirmLabel: "Delete", danger: true }))
                  act("Delete", () => api.deleteSession(s.id), "Instance deleted")
              }}
            >
              <Trash2 className="h-4 w-4" /> Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
    <Dialog open={renaming} onOpenChange={(o) => !o && setRenaming(false)}>
      <DialogContent onClick={(e) => e.stopPropagation()}>
        <DialogHeader>
          <DialogTitle>Rename instance</DialogTitle>
          <DialogDescription>
            A ruwa-side label to identify this instance. It has no effect on the WhatsApp account name.
          </DialogDescription>
        </DialogHeader>
        <div className="py-1">
          <Label className="mb-1.5 block">Label</Label>
          <Input
            value={renameVal}
            onChange={(e) => setRenameVal(e.target.value)}
            placeholder="e.g. Main Account"
            autoFocus
            onKeyDown={(e) => { if (e.key === "Enter" && !renameBusy) submitRename() }}
          />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setRenaming(false)} disabled={renameBusy}>Cancel</Button>
          <Button onClick={submitRename} disabled={renameBusy}>
            {renameBusy && <Loader2 className="h-4 w-4 animate-spin" />} Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    </>
  )
}

function CreateDialog({
  open, onClose, onCreated,
}: {
  open: boolean
  onClose: () => void
  onCreated: (key: string) => void
}) {
  const [label, setLabel] = useState("")
  const [proxy, setProxy] = useState("")
  const [busy, setBusy] = useState(false)

  async function create() {
    setBusy(true)
    try {
      const res = await api.createSession(label.trim() || null, proxy.trim() || null)
      onCreated(res.api_key ?? "")
      setLabel("")
      setProxy("")
    } catch (e) {
      toast.error("Create failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create instance</DialogTitle>
          <DialogDescription>Spins up a new WhatsApp session. The API key is shown once.</DialogDescription>
        </DialogHeader>
        <div className="space-y-3.5 py-1">
          <div>
            <Label className="mb-1.5 block">Label</Label>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Main Account" autoFocus />
          </div>
          <div>
            <Label className="mb-1.5 block">Proxy URL <span className="text-muted-foreground">· optional</span></Label>
            <Input className="mono text-xs" value={proxy} onChange={(e) => setProxy(e.target.value)} placeholder="http://user:pass@host:port" />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button disabled={busy} onClick={create}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Create
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function ImportDialog({
  open, onClose, onImported,
}: {
  open: boolean
  onClose: () => void
  onImported: (key: string) => void
}) {
  const [label, setLabel] = useState("")
  const [creds, setCreds] = useState("")
  const [busy, setBusy] = useState(false)

  async function run() {
    let parsed: unknown
    try {
      parsed = JSON.parse(creds)
    } catch {
      toast.error("Invalid JSON", { description: "Paste the Baileys/Evolution creds blob" })
      return
    }
    // accept either a bare creds object or { creds: {...} }
    const body = (parsed && typeof parsed === "object" && "creds" in parsed)
      ? (parsed as { creds: unknown }).creds
      : parsed
    setBusy(true)
    try {
      const res = await api.importSession(label.trim() || null, body)
      onImported(res.api_key ?? "")
      setLabel(""); setCreds("")
    } catch (e) {
      toast.error("Import failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-[520px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><Upload className="h-4 w-4" /> Import from Evolution</DialogTitle>
          <DialogDescription>
            Migrate a paired session without re-pairing. Paste the Baileys <span className="mono text-[11px]">creds</span> blob
            (Evolution stores it in <span className="mono text-[11px]">Session.creds</span>). It logs in directly — no QR.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3.5 py-1">
          <div>
            <Label className="mb-1.5 block">Label <span className="text-muted-foreground">· optional</span></Label>
            <Input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Support Line" />
          </div>
          <div>
            <Label className="mb-1.5 block">Creds JSON</Label>
            <Textarea value={creds} onChange={(e) => setCreds(e.target.value)} placeholder='{"noiseKey":…,"signedIdentityKey":…,"me":{…},…}' className="mono h-40 text-[11px]" />
          </div>
          <div className="flex items-start gap-2 rounded-md border border-st-warn/25 bg-st-warn/10 px-3 py-2.5">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 flex-none text-st-warn" />
            <div className="text-[13px] text-st-warn">This is a <b>move</b> — stop the source instance (delete its Evolution DB row) so WhatsApp doesn't bounce one of two live sockets.</div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button disabled={busy || !creds.trim()} onClick={run}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />} Import
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function KeyDialog({ apiKey, onClose }: { apiKey: string | null; onClose: () => void }) {
  const [copied, setCopied] = useState(false)
  return (
    <Dialog open={!!apiKey} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-[480px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <CheckCircle2 className="h-[18px] w-[18px] text-st-ok" /> Session created
          </DialogTitle>
          <DialogDescription>Per-tenant API key — scoped to this instance.</DialogDescription>
        </DialogHeader>
        <div>
          <Label className="mb-1.5 block">API key</Label>
          <div className="flex items-center gap-2">
            <Input readOnly value={apiKey ?? ""} className="mono text-xs" type="password" />
            <Button
              size="icon"
              variant="outline"
              onClick={() => {
                navigator.clipboard.writeText(apiKey ?? "").then(() => {
                  setCopied(true)
                  setTimeout(() => setCopied(false), 1500)
                })
              }}
            >
              {copied ? <CheckCircle2 className="h-4 w-4 text-st-ok" /> : <Copy className="h-4 w-4" />}
            </Button>
          </div>
          <div className="mt-3.5 flex items-start gap-2 rounded-md border border-st-warn/25 bg-st-warn/10 px-3 py-2.5">
            <TriangleAlert className="mt-0.5 h-3.5 w-3.5 flex-none text-st-warn" />
            <div className="text-[13px] text-st-warn">
              Shown <b>only once</b>. Store it now — you can't retrieve it later, only rotate.
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button onClick={onClose}>I've saved it</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
