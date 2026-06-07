import { useState } from "react"
import { MessageSquare, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card } from "@/components/ui/card"
import { api, setAuth } from "@/lib/api"

export function AuthGate({ onConnect }: { onConnect: () => void }) {
  const [token, setToken] = useState("")
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState<string | null>(null)
  const [version, setVersion] = useState<string | null>(null)

  async function connect() {
    setBusy(true)
    setErr(null)
    setVersion(null)
    // The console is served same-origin by the ruwa binary, so the API base is
    // always this origin ("" → relative requests). No base URL to ask for.
    setAuth("", token)
    try {
      const h = await api.health()
      setVersion(h.version)
      // brief beat so the "v… ✓" pill is visible, then enter.
      setTimeout(onConnect, 350)
    } catch (e) {
      setErr(e instanceof Error ? e.message : "connection failed")
      setBusy(false)
    }
  }

  return (
    <div className="flex h-full items-center justify-center bg-background p-6">
      <Card className="w-full max-w-[420px] p-6">
        <div className="mb-5 flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary/15 text-primary">
            <MessageSquare className="h-4 w-4" />
          </div>
          <div>
            <div className="text-base font-semibold leading-none">RUWA Console</div>
            <div className="mt-1 text-xs text-muted-foreground">Rust WhatsApp · ops console</div>
          </div>
        </div>

        <div className="space-y-3.5">
          <div>
            <Label htmlFor="token" className="mb-1.5 block text-xs">Global token</Label>
            <Input
              id="token"
              type="password"
              autoFocus
              className="mono text-xs"
              placeholder="RUWA_API_TOKEN"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !busy && connect()}
            />
          </div>

          <Button className="w-full" disabled={busy} onClick={connect}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            {busy ? "Connecting…" : "Connect"}
          </Button>

          {version && (
            <div className="text-center text-xs font-medium text-st-ok">v{version} ✓</div>
          )}
          {err && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
              {err}
            </div>
          )}
          {!err && !version && (
            <p className="text-center text-xs text-muted-foreground">
              Superuser admin token, or a per-session key.
            </p>
          )}
        </div>
      </Card>
    </div>
  )
}
