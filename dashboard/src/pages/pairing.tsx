import { useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { RefreshCw, Check, Zap, Plug, Loader2 } from "lucide-react"
import { api, ApiError } from "@/lib/api"
import type { SessionMeta, SessionHealth } from "@/lib/types"
import { StatusBadge } from "@/components/status"
import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"

export function PairingPage({ inst }: { inst: SessionMeta }) {
  const qc = useQueryClient()
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
    enabled: !connected,
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
          <div className="flex flex-col items-center justify-center gap-4 py-6">
            <div className="grid h-[88px] w-[88px] place-items-center rounded-full bg-st-ok/15 text-st-ok">
              <Check className="h-11 w-11" strokeWidth={2.4} />
            </div>
            <div className="text-center">
              <div className="text-[17px] font-semibold text-st-ok">Connected</div>
              {inst.jid && <div className="mono mt-1 text-xs text-muted-foreground">{inst.jid.split(":")[0]}</div>}
            </div>
            <div className="flex items-center gap-2.5 self-stretch rounded-md bg-secondary px-3 py-2.5">
              <Zap className="h-3.5 w-3.5 text-st-ok" />
              <span className="text-[13px]">Session is live and streaming events.</span>
            </div>
          </div>
        ) : qr.data?.svg_base64 ? (
          <>
            <div className="rounded-xl bg-white p-3">
              <img
                src={`data:image/svg+xml;base64,${qr.data.svg_base64}`}
                alt="Pairing QR"
                className="block h-[230px] w-[230px]"
              />
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
            <Button variant="outline" className="self-stretch" onClick={() => qr.refetch()}>
              <RefreshCw className="h-4 w-4" /> Refresh code
            </Button>
          </>
        ) : (
          <div className="flex flex-col items-center gap-4 py-8 text-center">
            {qr.isFetching ? (
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            ) : (
              <>
                <p className="text-sm text-muted-foreground">No QR yet — start the connection to generate one.</p>
                <Button onClick={connect}>
                  <Plug className="h-4 w-4" /> Connect
                </Button>
              </>
            )}
          </div>
        )}
      </Card>
    </div>
  )
}
