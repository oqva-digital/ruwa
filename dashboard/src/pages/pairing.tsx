import { useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { RefreshCw, Check, Zap, Plug, Loader2, QrCode, Smartphone } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import type { SessionMeta, SessionHealth } from "@/lib/types"
import { StatusBadge } from "@/components/status"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

type Method = "qr" | "phone"

export function PairingPage({ inst }: { inst: SessionMeta }) {
  const qc = useQueryClient()
  const [method, setMethod] = useState<Method>("qr")
  const health = useQuery<SessionHealth>({
    queryKey: ["health", inst.id],
    queryFn: () => api.sessionHealth(inst.id),
    refetchInterval: 2500,
  })
  const connected = health.data?.connected ?? inst.status === "connected"

  const qr = useQuery({
    queryKey: ["qr", inst.id],
    queryFn: () =>
      api.getQr(inst.id).catch((e) => {
        if (e instanceof ApiError && e.status === 404) return null // none yet
        throw e
      }),
    enabled: !connected && method === "qr",
    refetchInterval: 2500,
  })

  async function connect() {
    try {
      await api.connect(inst.id)
      toast.success("Connecting…", { description: inst.label ?? inst.id })
      qc.invalidateQueries({ queryKey: ["health", inst.id] })
    } catch (e) {
      toast.error("Connect failed", { description: e instanceof Error ? e.message : "" })
    }
  }

  return (
    <div>
      <div className="mb-4">
        <h1 className="text-xl font-semibold tracking-tight">Pairing</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Link a device for {inst.label ?? inst.id}</div>
      </div>

      <Card className="mx-auto flex max-w-[420px] flex-col items-center gap-4 p-6">
        <div className="self-start">
          <StatusBadge status={inst.status} />
        </div>

        {connected ? (
          <ConnectedView jid={inst.jid} />
        ) : (
          <>
            <MethodToggle method={method} onChange={setMethod} />
            {method === "qr" ? (
              <QrPane
                svg={qr.data?.svg_base64}
                fetching={qr.isFetching}
                onConnect={connect}
                onRefresh={() => qr.refetch()}
              />
            ) : (
              <PhonePane sessionId={inst.id} />
            )}
          </>
        )}
      </Card>
    </div>
  )
}

function MethodToggle({ method, onChange }: { method: Method; onChange: (m: Method) => void }) {
  const opt = (m: Method, icon: React.ReactNode, label: string) => (
    <button
      type="button"
      onClick={() => onChange(m)}
      className={`flex flex-1 items-center justify-center gap-1.5 rounded-md px-3 py-1.5 text-[13px] font-medium transition-colors ${
        method === m ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
      }`}
    >
      {icon}
      {label}
    </button>
  )
  return (
    <div className="flex w-full gap-1 rounded-lg bg-secondary p-1">
      {opt("qr", <QrCode className="h-3.5 w-3.5" />, "QR code")}
      {opt("phone", <Smartphone className="h-3.5 w-3.5" />, "Phone number")}
    </div>
  )
}

function ConnectedView({ jid }: { jid?: string | null }) {
  return (
    <div className="flex flex-col items-center justify-center gap-4 py-6">
      <div className="grid h-[88px] w-[88px] place-items-center rounded-full bg-st-ok/15 text-st-ok">
        <Check className="h-11 w-11" strokeWidth={2.4} />
      </div>
      <div className="text-center">
        <div className="text-[17px] font-semibold text-st-ok">Connected</div>
        {jid && <div className="mono mt-1 text-xs text-muted-foreground">{jid.split(":")[0]}</div>}
      </div>
      <div className="flex items-center gap-2.5 self-stretch rounded-md bg-secondary px-3 py-2.5">
        <Zap className="h-3.5 w-3.5 text-st-ok" />
        <span className="text-[13px]">Session is live and streaming events.</span>
      </div>
    </div>
  )
}

function QrPane({
  svg,
  fetching,
  onConnect,
  onRefresh,
}: {
  svg?: string
  fetching: boolean
  onConnect: () => void
  onRefresh: () => void
}) {
  if (svg) {
    return (
      <>
        <div className="rounded-xl bg-white p-3">
          <img src={`data:image/svg+xml;base64,${svg}`} alt="Pairing QR" className="block h-[230px] w-[230px]" />
        </div>
        <div className="flex items-center justify-center gap-2 text-[13px] font-medium">
          <span className="dot h-[7px] w-[7px] rounded-full bg-st-progress" />
          Scanning… <span className="text-xs text-muted-foreground">auto-refreshing</span>
        </div>
        <ol className="self-stretch space-y-0.5 pl-4 text-[12.5px] leading-relaxed text-muted-foreground">
          <li>Open <b className="text-foreground">WhatsApp</b> on the phone</li>
          <li><b className="text-foreground">Settings → Linked devices</b></li>
          <li>Tap <b className="text-foreground">Link a device</b> and scan</li>
        </ol>
        <Button variant="outline" className="self-stretch" onClick={onRefresh}>
          <RefreshCw className="h-4 w-4" /> Refresh code
        </Button>
      </>
    )
  }
  return (
    <div className="flex flex-col items-center gap-4 py-8 text-center">
      {fetching ? (
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      ) : (
        <>
          <p className="text-sm text-muted-foreground">No QR yet — start the connection to generate one.</p>
          <Button onClick={onConnect}>
            <Plug className="h-4 w-4" /> Connect
          </Button>
        </>
      )}
    </div>
  )
}

/** Client-side mirror of the server's phone validation (digits, intl, >6, no leading 0). */
function normalizePhone(raw: string): { digits: string; error?: string } {
  const digits = raw.replace(/\D/g, "")
  if (digits.length <= 6) return { digits, error: "Enter a full international number" }
  if (digits.startsWith("0")) return { digits, error: "Use the international form (no leading 0)" }
  return { digits }
}

function PhonePane({ sessionId }: { sessionId: string }) {
  const [phone, setPhone] = useState("")
  const [code, setCode] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const { digits, error: phoneError } = normalizePhone(phone)
  const canSubmit = !phoneError && !loading

  async function getCode() {
    setError(null)
    setCode(null)
    setLoading(true)
    try {
      // Ensure the socket is coming up (idempotent), then request the code —
      // retry briefly while the Noise handshake settles ("not connected").
      await api.connect(sessionId)
      let lastErr: unknown
      for (let i = 0; i < 8; i++) {
        try {
          const r = await api.pairPhone(sessionId, digits)
          setCode(r.code)
          setLoading(false)
          return
        } catch (e) {
          lastErr = e
          const msg = e instanceof Error ? e.message : ""
          // A real validation error (not the transient "not connected") — stop.
          if (e instanceof ApiError && e.status === 400 && !/not connected/i.test(msg)) {
            throw e
          }
          await new Promise((res) => setTimeout(res, 1500))
        }
      }
      throw lastErr
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not get a pairing code")
      setLoading(false)
    }
  }

  if (code) {
    return (
      <div className="flex flex-col items-center gap-4 py-2">
        <div className="text-center">
          <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Your pairing code</div>
          <div className="mono mt-2 select-all text-[34px] font-semibold tracking-[0.18em] tabular-nums">
            {code}
          </div>
        </div>
        <div className="flex items-center justify-center gap-2 text-[13px] font-medium">
          <span className="dot h-[7px] w-[7px] rounded-full bg-st-progress" />
          Waiting for you to enter it…
        </div>
        <ol className="self-stretch space-y-0.5 pl-4 text-[12.5px] leading-relaxed text-muted-foreground">
          <li>Open <b className="text-foreground">WhatsApp</b> on the phone</li>
          <li><b className="text-foreground">Settings → Linked devices → Link a device</b></li>
          <li>Tap <b className="text-foreground">Link with phone number instead</b></li>
          <li>Enter the code above</li>
        </ol>
        <Button variant="outline" className="self-stretch" onClick={getCode} disabled={loading}>
          <RefreshCw className="h-4 w-4" /> New code
        </Button>
      </div>
    )
  }

  return (
    <div className="flex w-full flex-col items-stretch gap-3 py-2">
      <div className="space-y-1.5">
        <label className="text-[13px] font-medium">Phone number</label>
        <Input
          className="mono"
          value={phone}
          onChange={(e) => setPhone(e.target.value)}
          placeholder="e.g. 1 555 123 4567"
          inputMode="tel"
          autoFocus
          onKeyDown={(e) => {
            if (e.key === "Enter" && canSubmit) getCode()
          }}
        />
        <p className="text-[12px] text-muted-foreground">
          {phone && phoneError ? (
            <span className="text-st-down">{phoneError}</span>
          ) : (
            "International format, digits only — country code first, no leading 0."
          )}
        </p>
      </div>
      {error && (
        <div className="rounded-md bg-st-down/10 px-3 py-2 text-[12.5px] text-st-down">{error}</div>
      )}
      <Button onClick={getCode} disabled={!canSubmit}>
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Smartphone className="h-4 w-4" />}
        {loading ? "Requesting…" : "Get pairing code"}
      </Button>
      <p className="text-center text-[11.5px] text-muted-foreground">
        The code is valid for a couple of minutes — have the phone ready.
      </p>
    </div>
  )
}
