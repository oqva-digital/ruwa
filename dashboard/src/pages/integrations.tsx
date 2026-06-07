import { useEffect, useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"
import { Database, Save, Trash2, HardDrive, Bell } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import type { SessionMeta } from "@/lib/types"
import { cn } from "@/lib/utils"
import { confirmDialog } from "@/components/confirm"
import { SectionCard } from "@/components/ui-bits"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"

export function IntegrationsPage({ inst, readonly }: { inst: SessionMeta; readonly: boolean }) {
  const [url, setUrl] = useState("")
  const [mode, setMode] = useState("list")
  const [key, setKey] = useState("")
  const [enabled, setEnabled] = useState(true)
  const [busy, setBusy] = useState(false)
  const [online, setOnline] = useState(!!inst.mark_online)

  async function toggleOnline(next: boolean) {
    setOnline(next) // optimistic
    try {
      await api.setMarkOnline(inst.id, next)
      toast.success(next ? "Appearing online — phone notifications silenced" : "Phone notifications enabled")
    } catch (e) {
      setOnline(!next)
      toast.error(e instanceof ApiError ? e.message : "Failed to update")
    }
  }

  const cfg = useQuery({
    queryKey: ["redis", inst.id],
    queryFn: () =>
      api.getRedis(inst.id).catch((e) => {
        if (e instanceof ApiError && e.status === 404) return null
        throw e
      }),
  })
  const server = useQuery({ queryKey: ["server-config"], queryFn: () => api.config() })
  useEffect(() => {
    const r = cfg.data
    if (r) { setUrl(r.url ?? ""); setMode(r.mode ?? "list"); setKey(r.key ?? ""); setEnabled(r.enabled ?? true) }
  }, [cfg.data])

  async function save() {
    if (!/^rediss?:\/\//.test(url.trim())) { toast.error("URL must be redis:// or rediss://"); return }
    if (!key.trim()) { toast.error("Key/channel required"); return }
    setBusy(true)
    try {
      await api.setRedis(inst.id, { url: url.trim(), mode, key: key.trim(), enabled, events: [] })
      toast.success("Redis egress saved")
      cfg.refetch()
    } catch (e) {
      toast.error("Save failed", { description: e instanceof Error ? e.message : "" })
    } finally { setBusy(false) }
  }
  async function remove() {
    if (!(await confirmDialog({ title: "Remove Redis egress?", confirmLabel: "Remove", danger: true }))) return
    try { await api.deleteRedis(inst.id); toast.success("Removed"); setUrl(""); setKey(""); cfg.refetch() }
    catch (e) { toast.error("Delete failed", { description: e instanceof Error ? e.message : "" }) }
  }

  return (
    <div className="mx-auto max-w-[680px] space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Integrations</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Egress + storage for {inst.label ?? inst.id}</div>
      </div>

      <SectionCard title="Phone notifications" icon={Bell}>
        <div className="flex items-center justify-between gap-4 p-4">
          <div>
            <div className="text-[13px] font-medium">Appear online</div>
            <div className="text-xs text-muted-foreground">
              On → companion shows as online and WhatsApp <b>silences your phone's notifications</b>.
              Off (default) → your phone keeps notifying. Message reception is unaffected either way.
            </div>
          </div>
          <Switch checked={online} disabled={readonly} onCheckedChange={toggleOnline} />
        </div>
      </SectionCard>

      <SectionCard title="Redis queue" icon={Database}>
        <div className="space-y-4 p-4">
          <div>
            <Label className="mb-1.5 block">Connection URL <span className="text-muted-foreground">· password redacted on read</span></Label>
            <Input className="mono text-xs" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="redis://:***@host:6379" />
          </div>
          <div className="flex gap-4">
            <div className="flex-1">
              <Label className="mb-1.5 block">Mode</Label>
              <div className="flex rounded-md bg-muted p-0.5">
                {[["list", "List (RPUSH)"], ["pubsub", "Pub/Sub (PUBLISH)"]].map(([v, l]) => (
                  <button key={v} onClick={() => setMode(v)} className={cn("flex-1 rounded px-2.5 py-1 text-xs font-medium", mode === v ? "bg-card text-foreground shadow-sm" : "text-muted-foreground")}>{l}</button>
                ))}
              </div>
            </div>
            <div className="flex-1">
              <Label className="mb-1.5 block">{mode === "pubsub" ? "Channel" : "Key"}</Label>
              <Input className="mono text-xs" value={key} onChange={(e) => setKey(e.target.value)} placeholder="ruwa:events" />
            </div>
          </div>
          <div className="flex items-center justify-between"><Label>Enabled</Label><Switch checked={enabled} onCheckedChange={setEnabled} /></div>
          <div className="flex items-center justify-end gap-2 border-t pt-3">
            {cfg.data && <Button variant="destructive" size="sm" disabled={readonly} onClick={remove}><Trash2 className="h-3.5 w-3.5" /> Remove</Button>}
            <Button disabled={readonly || busy} onClick={save}><Save className="h-4 w-4" /> Save</Button>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="Media storage" icon={HardDrive}>
        <div className="space-y-3 p-4">
          {(() => {
            const m = server.data?.media
            if (!m) return <p className="text-[13px] text-muted-foreground">Loading…</p>
            const isS3 = m.mode === "s3"
            return (
              <>
                <div className="flex items-center gap-2">
                  <span data-st={isS3 ? "ok" : "neutral"} className="inline-flex w-fit rounded-full px-2 py-0.5 text-[11px] font-medium">
                    {isS3 ? "S3-compatible (R2/MinIO)" : "Database (BYTEA)"}
                  </span>
                  <span className="text-[11px] text-muted-foreground">server-wide</span>
                </div>
                {isS3 ? (
                  <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs">
                    <dt className="text-muted-foreground">Bucket</dt><dd className="mono">{m.bucket}</dd>
                    <dt className="text-muted-foreground">Endpoint</dt><dd className="mono break-all">{m.endpoint}</dd>
                    <dt className="text-muted-foreground">Region</dt><dd className="mono">{m.region}</dd>
                    <dt className="text-muted-foreground">Public URL</dt><dd className="mono break-all">{m.public_base_url || "— (path-style)"}</dd>
                  </dl>
                ) : (
                  <p className="text-[13px] text-muted-foreground">Media bytes are stored in the database. Set <span className="mono text-xs">RUWA_MEDIA_STORE=s3</span> + the <span className="mono text-xs">RUWA_S3_*</span> env to offload to S3/R2/MinIO.</p>
                )}
                <p className="text-[11px] text-muted-foreground">Configured server-side (one store for all instances) via <span className="mono">RUWA_MEDIA_STORE</span> + <span className="mono">RUWA_S3_*</span>.</p>
              </>
            )
          })()}
        </div>
      </SectionCard>
    </div>
  )
}
