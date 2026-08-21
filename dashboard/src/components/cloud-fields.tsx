import { useState } from "react"
import { Copy, CheckCircle2 } from "lucide-react"
import { cn } from "@/lib/utils"
import { cloudWebhookUrl, GRAPH_VERSION_DEFAULT, type CloudForm, type CloudFormErrors } from "@/lib/cloud"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"

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
      <div className="rounded-md border border-border/60 bg-muted/40 px-3 py-2.5">
        <div className="mb-1 flex items-center justify-between gap-2">
          <span className="text-[12px] font-medium">Webhook callback URL</span>
          <Button
            size="sm" variant="ghost" className="h-6 px-2 text-[11px]"
            onClick={() => navigator.clipboard.writeText(hookUrl).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })}
          >
            {copied ? <CheckCircle2 className="h-3 w-3 text-st-ok" /> : <Copy className="h-3 w-3" />} copy
          </Button>
        </div>
        <div className="mono select-all break-all text-[11px] text-muted-foreground">{hookUrl}</div>
        <p className="mt-1.5 text-[11.5px] text-muted-foreground">
          In the Meta App dashboard → WhatsApp → Configuration, set this Callback URL and the verify token above
          (or the server-wide <span className="mono">RUWA_CLOUD_VERIFY_TOKEN</span>, which takes precedence when set),
          then subscribe to the <span className="mono">messages</span> field. Requires a public HTTPS origin.
        </p>
      </div>
    </>
  )
}
