import { useState } from "react"
import { Copy, CheckCircle2 } from "lucide-react"
import { cn } from "@/lib/utils"
import {
  cloudWebhookUrl, kapsoWebhookUrl, GRAPH_VERSION_DEFAULT,
  type CloudForm, type CloudFormErrors, type KapsoForm, type KapsoFormErrors,
} from "@/lib/cloud"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"

/** Cloud credential inputs shared by Create and Edit-credentials. */
export function CloudFields({
  c, onChange, errors, forCreate,
}: {
  c: CloudForm
  onChange: (next: CloudForm) => void
  errors: CloudFormErrors
  forCreate: boolean
}) {
  const [copied, setCopied] = useState(false)
  const set = (k: keyof CloudForm) => (e: React.ChangeEvent<HTMLInputElement>) => onChange({ ...c, [k]: e.target.value })
  const field = (
    k: keyof CloudForm, label: string, opts: { optional?: boolean; secret?: boolean; placeholder?: string; hint?: string; mono?: boolean } = {},
  ) => (
    <div>
      <Label className="mb-1.5 block">
        {label} {opts.optional && <span className="text-muted-foreground">· optional</span>}
      </Label>
      <Input
        className={cn(opts.mono !== false && "mono text-xs")}
        type={opts.secret ? "password" : "text"}
        autoComplete={opts.secret ? "new-password" : "off"}
        value={c[k]}
        onChange={set(k)}
        placeholder={opts.placeholder}
        aria-invalid={!!errors[k]}
      />
      {errors[k] ? (
        <p className="mt-1 text-[12px] text-st-down">{errors[k]}</p>
      ) : opts.hint ? (
        <p className="mt-1 text-[12px] text-muted-foreground">{opts.hint}</p>
      ) : null}
    </div>
  )
  const hookUrl = cloudWebhookUrl()
  return (
    <>
      <div className="grid grid-cols-2 gap-3">
        {field("phone_number_id", "Phone number id", { placeholder: "106540352242922", hint: "Meta → WhatsApp → API setup" })}
        {field("waba_id", "WABA id", { optional: true, placeholder: "102290129340398", hint: "Business account id — only needed for templates" })}
      </div>
      {field("access_token", forCreate ? "Access token" : "Access token (blank keeps current)", {
        secret: true, placeholder: "EAAG…", hint: "Permanent System-User token with whatsapp_business_messaging + _management",
      })}
      <div className="grid grid-cols-2 gap-3">
        {field("app_secret", forCreate ? "App secret" : "App secret (blank keeps current)", {
          secret: true, optional: true, placeholder: "app secret", hint: "Verifies X-Hub-Signature-256 on webhooks",
        })}
        {field("verify_token", "Verify token", { optional: true, placeholder: "my-verify-token", hint: "Echoed by the webhook GET challenge — ignored if the server sets RUWA_CLOUD_VERIFY_TOKEN" })}
      </div>
      <div className="grid grid-cols-2 gap-3">
        {field("graph_version", "Graph version", { placeholder: GRAPH_VERSION_DEFAULT })}
      </div>
      <WebhookUrlBlock
        url={hookUrl}
        copied={copied}
        onCopy={() => navigator.clipboard.writeText(hookUrl).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}
      >
        In the Meta App dashboard → WhatsApp → Configuration, set this Callback URL and the verify token above
        (or the server-wide <span className="mono">RUWA_CLOUD_VERIFY_TOKEN</span>, which takes precedence when set),
        then subscribe to the <span className="mono">messages</span> field. Requires a public HTTPS origin.
      </WebhookUrlBlock>
    </>
  )
}

/** A copyable webhook-URL panel — shared by the Meta and Kapso field sets. */
function WebhookUrlBlock({
  url, label = "Webhook callback URL", copied, onCopy, children,
}: {
  url: string
  label?: string
  copied: boolean
  onCopy: () => void
  children?: React.ReactNode
}) {
  return (
    <div className="rounded-md border border-border/60 bg-muted/40 px-3 py-2.5">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="text-[12px] font-medium">{label}</span>
        <Button size="sm" variant="ghost" className="h-6 px-2 text-[11px]" onClick={onCopy}>
          {copied ? <CheckCircle2 className="h-3 w-3 text-st-ok" /> : <Copy className="h-3 w-3" />} copy
        </Button>
      </div>
      <div className="mono select-all break-all text-[11px] text-muted-foreground">{url}</div>
      {children ? <p className="mt-1.5 text-[11.5px] text-muted-foreground">{children}</p> : null}
    </div>
  )
}

const KAPSO_LANGS = [
  { v: "none", label: "— none —" },
  { v: "en", label: "English (en)" },
  { v: "es", label: "Español (es)" },
  { v: "pt", label: "Português (pt)" },
  { v: "hi", label: "हिन्दी (hi)" },
  { v: "id", label: "Bahasa Indonesia (id)" },
  { v: "ar", label: "العربية (ar)" },
]

/** Kapso Business Platform config — the customer connects their own number via a
 *  hosted setup link, so there are no Meta credential fields here. */
export function KapsoFields({
  k, onChange, errors,
}: {
  k: KapsoForm
  onChange: (next: KapsoForm) => void
  errors: KapsoFormErrors
}) {
  const [copied, setCopied] = useState(false)
  const hookUrl = kapsoWebhookUrl()
  const set = <K extends keyof KapsoForm>(key: K, v: KapsoForm[K]) => onChange({ ...k, [key]: v })
  return (
    <>
      <div className="rounded-md border border-border/60 bg-muted/40 px-3 py-2.5 text-[11.5px] text-muted-foreground">
        <span className="font-medium text-foreground">Kapso Business Platform</span> — the customer connects their own
        number via a hosted link; no Meta credentials needed here. After you create the session you get a setup link to
        send them; Kapso tells ruwa when the number is live.
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label className="mb-1.5 block">Connection type</Label>
          <Select value={k.connection_type} onValueChange={(v) => set("connection_type", v as KapsoForm["connection_type"])}>
            <SelectTrigger className="w-full text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="dedicated" className="text-xs">dedicated</SelectItem>
              <SelectItem value="coexistence" className="text-xs">coexistence</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <Label className="mb-1.5 block">Language <span className="text-muted-foreground">· optional</span></Label>
          <Select value={k.language || "none"} onValueChange={(v) => set("language", v === "none" ? "" : v)}>
            <SelectTrigger className="w-full text-xs"><SelectValue /></SelectTrigger>
            <SelectContent>
              {KAPSO_LANGS.map((l) => (
                <SelectItem key={l.v} value={l.v} className="text-xs">{l.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>
      <div>
        <Label className="mb-1.5 block">Country codes <span className="text-muted-foreground">· optional</span></Label>
        <Input
          className="mono text-xs"
          value={k.country_isos}
          onChange={(e) => set("country_isos", e.target.value)}
          placeholder="BR US"
          aria-invalid={!!errors.country_isos}
        />
        {errors.country_isos ? (
          <p className="mt-1 text-[12px] text-st-down">{errors.country_isos}</p>
        ) : (
          <p className="mt-1 text-[12px] text-muted-foreground">ISO country codes, e.g. BR US</p>
        )}
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label className="mb-1.5 block">Graph version</Label>
          <Input
            className="mono text-xs"
            value={k.graph_version}
            onChange={(e) => set("graph_version", e.target.value)}
            placeholder={GRAPH_VERSION_DEFAULT}
            aria-invalid={!!errors.graph_version}
          />
          {errors.graph_version && <p className="mt-1 text-[12px] text-st-down">{errors.graph_version}</p>}
        </div>
      </div>
      <label className="flex items-center gap-2 text-[13px]">
        <Checkbox
          checked={k.provision_phone_number}
          onCheckedChange={(v) => set("provision_phone_number", v === true)}
        />
        Let Kapso provision a number
      </label>
      <WebhookUrlBlock
        url={hookUrl}
        label="Message webhook URL"
        copied={copied}
        onCopy={() => navigator.clipboard.writeText(hookUrl).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}
      >
        ruwa registers this URL with Kapso automatically once the number connects. Shown here for reference.
      </WebhookUrlBlock>
    </>
  )
}
