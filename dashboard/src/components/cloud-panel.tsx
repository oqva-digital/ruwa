import { useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Cloud, Plug, RefreshCw, KeyRound, Loader2, Copy, CheckCircle2, Webhook } from "lucide-react"
import { api } from "@/lib/api"
import type { SessionMeta, SessionHealth } from "@/lib/types"
import { fmtAgeLong } from "@/lib/format"
import { cloudWebhookUrl, validateCloudForm, cloudFormToInput, EMPTY_CLOUD, type CloudForm } from "@/lib/cloud"
import { StatusBadge } from "@/components/status"
import { SectionCard } from "@/components/ui-bits"
import { CloudFields } from "@/components/cloud-fields"
import { Button } from "@/components/ui/button"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog"

/** Compact "Cloud API" panel shown for kind=cloud sessions instead of the QR /
 *  socket-liveness views: identifiers, the validated number, the webhook URL
 *  and connect / re-validate / edit-credentials actions. */
export function CloudApiPanel({ inst, readonly, className }: { inst: SessionMeta; readonly: boolean; className?: string }) {
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [copied, setCopied] = useState(false)
  const health = useQuery<SessionHealth>({
    queryKey: ["health", inst.id],
    queryFn: () => api.sessionHealth(inst.id),
    refetchInterval: 6000,
  })
  const c = inst.cloud
  const number = c?.display_phone_number
    ? "+" + c.display_phone_number.replace(/\D/g, "")
    : inst.jid ? "+" + inst.jid.split("@")[0].split(":")[0] : null
  const hookUrl = cloudWebhookUrl()
  const connected = inst.status === "connected"

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

  const rows: [string, React.ReactNode][] = [
    ["Phone number id", c?.phone_number_id ?? "—"],
    ["WABA id", c?.waba_id ?? "—"],
    ["Number", number ?? (connected ? "—" : "validate to resolve")],
    ["Verified name", c?.verified_name ?? inst.push_name ?? "—"],
    ["Graph version", c?.graph_version ?? "—"],
    ["Last webhook", health.data ? fmtAgeLong(health.data.seconds_since_rx) : "…"],
  ]

  return (
    <SectionCard title="Cloud API" icon={Cloud} className={className} action={<StatusBadge status={inst.status} />}>
      <div className="p-4">
        <div className="flex flex-col gap-2">
          {rows.map(([k, v]) => (
            <div key={k} className="flex justify-between gap-3">
              <span className="text-xs text-muted-foreground">{k}</span>
              <span className="mono truncate text-[11px]">{v}</span>
            </div>
          ))}
        </div>
        <div className="my-3.5 h-px bg-border" />
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="flex items-center gap-1.5 text-xs text-muted-foreground"><Webhook className="h-3 w-3" /> Webhook callback URL</span>
          <Button
            size="sm" variant="ghost" className="h-6 px-2 text-[11px]"
            onClick={() => navigator.clipboard.writeText(hookUrl).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}
          >
            {copied ? <CheckCircle2 className="h-3 w-3 text-st-ok" /> : <Copy className="h-3 w-3" />} copy
          </Button>
        </div>
        <div className="mono select-all break-all text-[11px] text-muted-foreground">{hookUrl}</div>
        <div className="mt-3.5 flex flex-wrap gap-1.5">
          {/* `connect` is a no-op on an already-connected session; re-validation
              (e.g. after a token rotation) must go through `reconnect`. */}
          <Button size="sm" disabled={readonly} onClick={() => act(connected ? "Re-validate" : "Connect", () => (connected ? api.reconnect(inst.id) : api.connect(inst.id)), connected ? "Re-validating credentials…" : "Validating credentials…")}>
            {connected ? <RefreshCw className="h-3.5 w-3.5" /> : <Plug className="h-3.5 w-3.5" />}
            {connected ? "Re-validate" : "Connect"}
          </Button>
          <Button size="sm" variant="outline" disabled={readonly} onClick={() => setEditing(true)}>
            <KeyRound className="h-3.5 w-3.5" /> Edit credentials
          </Button>
        </div>
      </div>
      <CloudCredsDialog
        inst={inst}
        open={editing}
        onClose={() => setEditing(false)}
        onSaved={() => { setEditing(false); qc.invalidateQueries({ queryKey: ["sessions"] }) }}
      />
    </SectionCard>
  )
}

function CloudCredsDialog({
  inst, open, onClose, onSaved,
}: {
  inst: SessionMeta
  open: boolean
  onClose: () => void
  onSaved: () => void
}) {
  const [form, setForm] = useState<CloudForm>(() => ({
    ...EMPTY_CLOUD,
    phone_number_id: inst.cloud?.phone_number_id ?? "",
    waba_id: inst.cloud?.waba_id ?? "",
    graph_version: inst.cloud?.graph_version ?? EMPTY_CLOUD.graph_version,
  }))
  const [touched, setTouched] = useState(false)
  const [busy, setBusy] = useState(false)
  const errors = validateCloudForm(form, false)
  const hasErrors = Object.keys(errors).length > 0

  async function save() {
    setTouched(true)
    if (hasErrors) return
    const body = cloudFormToInput(form, false)
    // The number is pre-filled; only send it when actually changed (re-pointing
    // a session at another number is a master-token-only operation server-side).
    if (body.phone_number_id === inst.cloud?.phone_number_id) delete body.phone_number_id
    if (Object.keys(body).length === 0) { toast.error("Nothing to update"); return }
    setBusy(true)
    try {
      await api.updateCloud(inst.id, body)
      toast.success("Credentials updated", { description: "Use Re-validate to check them against Graph." })
      setForm((f) => ({ ...f, access_token: "", app_secret: "" }))
      onSaved()
    } catch (e) {
      toast.error("Update failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-[560px]">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><KeyRound className="h-4 w-4" /> Cloud API credentials</DialogTitle>
          <DialogDescription>
            Only the fields you fill in are replaced. Secrets are stored sealed and never shown back.
          </DialogDescription>
        </DialogHeader>
        <div className="max-h-[70vh] space-y-3.5 overflow-y-auto py-1 pr-0.5">
          <CloudFields c={form} onChange={setForm} errors={touched ? errors : {}} forCreate={false} />
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={save} disabled={busy || (touched && hasErrors)}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />} Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
