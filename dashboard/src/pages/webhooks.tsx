import { useEffect, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"
import { Webhook, Trash2, Save, KeyRound } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import type { SessionMeta } from "@/lib/types"
import { cn } from "@/lib/utils"
import { confirmDialog } from "@/components/confirm"
import { SectionCard } from "@/components/ui-bits"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"

const EVENT_TYPES = ["message", "message_sent", "message_delivered", "syncing", "connected", "disconnected", "qr", "paired"]

export function WebhooksPage({ inst, readonly }: { inst: SessionMeta; readonly: boolean }) {
  const [url, setUrl] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [events, setEvents] = useState<Set<string>>(new Set())
  const [secret, setSecret] = useState("")
  const [hasSecret, setHasSecret] = useState(false)
  const [busy, setBusy] = useState(false)

  const cfg = useQuery({
    queryKey: ["webhook", inst.id],
    queryFn: () =>
      api.getWebhook(inst.id).catch((e) => {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }),
  })

  useEffect(() => {
    const w = cfg.data
    if (w) {
      setUrl(w.url ?? "")
      setEnabled(w.enabled ?? true)
      setEvents(new Set(w.events ?? []))
      setHasSecret(!!w.has_secret)
    }
  }, [cfg.data])

  async function save() {
    if (!/^https?:\/\//.test(url.trim())) {
      toast.error("URL must be http(s)")
      return
    }
    setBusy(true)
    try {
      await api.setWebhook(inst.id, {
        url: url.trim(),
        enabled,
        events: Array.from(events),
        ...(secret ? { secret } : {}),
      })
      toast.success("Webhook saved")
      setSecret("")
      cfg.refetch()
    } catch (e) {
      toast.error("Save failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }
  async function remove() {
    if (!(await confirmDialog({ title: "Delete webhook?", confirmLabel: "Delete", danger: true }))) return
    try {
      await api.deleteWebhook(inst.id)
      toast.success("Webhook removed")
      setUrl(""); setEvents(new Set()); setHasSecret(false)
      cfg.refetch()
    } catch (e) {
      toast.error("Delete failed", { description: e instanceof Error ? e.message : "" })
    }
  }

  return (
    <div className="mx-auto max-w-[680px]">
      <div className="mb-4">
        <h1 className="text-xl font-semibold tracking-tight">Webhooks</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Delivery endpoint for {inst.label ?? inst.id}</div>
      </div>

      <SectionCard title="Configuration" icon={Webhook}>
        <div className="space-y-4 p-4">
          <div>
            <Label className="mb-1.5 block">Delivery URL</Label>
            <Input className="mono text-xs" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/hook" />
          </div>
          <div>
            <Label className="mb-1.5 block">Events <span className="text-muted-foreground">· empty = all</span></Label>
            <div className="flex flex-wrap gap-1.5">
              {EVENT_TYPES.map((t) => {
                const on = events.has(t)
                return (
                  <button
                    key={t}
                    data-st={on ? "progress" : undefined}
                    onClick={() => setEvents((s) => { const n = new Set(s); n.has(t) ? n.delete(t) : n.add(t); return n })}
                    className={cn("rounded-full px-2.5 py-0.5 text-[11px] font-medium", !on && "border border-border text-muted-foreground")}
                  >
                    {t}
                  </button>
                )
              })}
            </div>
          </div>
          <div>
            <Label className="mb-1.5 block flex items-center gap-1.5"><KeyRound className="h-3.5 w-3.5" /> Signing secret</Label>
            <div className="flex items-center gap-2">
              <Input
                type="password"
                className="mono text-xs"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                placeholder={hasSecret ? "•••••••• (set — leave blank to keep)" : "optional HMAC secret"}
              />
              {hasSecret && <span data-st="ok" className="whitespace-nowrap rounded-full px-2 py-0.5 text-[11px] font-medium">set ✓</span>}
            </div>
            <p className="mt-1.5 text-xs text-muted-foreground">X-Ruwa-Signature = HMAC-SHA256(secret, body). Write-only — never echoed.</p>
          </div>
          <div className="flex items-center justify-between">
            <Label>Enabled</Label>
            <Switch checked={enabled} onCheckedChange={setEnabled} />
          </div>
          <div className="flex items-center justify-end gap-2 border-t pt-3">
            {cfg.data && (
              <Button variant="destructive" size="sm" disabled={readonly} onClick={remove}>
                <Trash2 className="h-3.5 w-3.5" /> Delete
              </Button>
            )}
            <Button disabled={readonly || busy} onClick={save}>
              <Save className="h-4 w-4" /> Save
            </Button>
          </div>
        </div>
      </SectionCard>

      <Card className="mt-4 gap-2 p-4">
        <div className="text-xs font-medium text-muted-foreground">Delivery health</div>
        <div className="flex gap-8">
          <div><div className="text-xs text-muted-foreground">Delivered</div><div className="mono tnum text-lg font-semibold text-st-ok">—</div></div>
          <div><div className="text-xs text-muted-foreground">Failed</div><div className="mono tnum text-lg font-semibold">—</div></div>
        </div>
        <p className="text-xs text-muted-foreground">Counters from /metrics (ruwa_webhook_delivered/failed_total) — see the Metrics page.</p>
      </Card>
    </div>
  )
}
