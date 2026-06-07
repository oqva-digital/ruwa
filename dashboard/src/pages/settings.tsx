import { useQuery } from "@tanstack/react-query"
import { Sun, Moon, Plug, ShieldCheck, Info, LogOut } from "lucide-react"
import { api, getBase, clearAuth } from "@/lib/api"
import { SectionCard } from "@/components/ui-bits"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4 border-b py-3 last:border-b-0">
      <div>
        <div className="text-[13px] font-medium">{label}</div>
        {hint && <div className="text-xs text-muted-foreground">{hint}</div>}
      </div>
      <div className="flex items-center gap-2">{children}</div>
    </div>
  )
}

export function SettingsPage({
  theme, onToggleTheme, onLogout,
}: {
  theme: string
  onToggleTheme: () => void
  onLogout: () => void
}) {
  const health = useQuery({ queryKey: ["health-v"], queryFn: api.health, staleTime: 30_000 })

  return (
    <div className="mx-auto max-w-[660px] space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Settings</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Console preferences (stored locally in this browser)</div>
      </div>

      <SectionCard title="Connection" icon={Plug}>
        <div className="px-4">
          <Row label="Base URL" hint="blank = same origin">
            <Input className="mono w-[280px] text-xs" defaultValue={getBase()} readOnly />
          </Row>
          <Row label="Admin token" hint="superuser, all instances">
            <Button size="sm" variant="outline" onClick={onLogout}><LogOut className="h-3.5 w-3.5" /> Re-enter / clear</Button>
          </Row>
        </div>
      </SectionCard>

      <SectionCard title="Preferences" icon={Sun}>
        <div className="px-4">
          <Row label="Theme" hint="dark is the default">
            <Button size="sm" variant="outline" onClick={onToggleTheme}>
              {theme === "dark" ? <Sun className="h-3.5 w-3.5" /> : <Moon className="h-3.5 w-3.5" />}
              {theme === "dark" ? "Light" : "Dark"}
            </Button>
          </Row>
          <Row label="SSE auto-reconnect" hint="resume the live stream on drop">
            <Switch defaultChecked />
          </Row>
        </div>
      </SectionCard>

      <SectionCard title="Server" icon={ShieldCheck}>
        <div className="px-4">
          <Row label="Version" hint="reported by GET /health">
            <span data-st="ok" className="rounded-full px-2 py-0.5 text-[11px] font-medium mono">v{health.data?.version ?? "…"}</span>
          </Row>
          <Row label="Server mode" hint="RUWA_READONLY gate">
            <span className="text-[13px] text-muted-foreground">read/write</span>
          </Row>
        </div>
      </SectionCard>

      <SectionCard title="About" icon={Info}>
        <div className="space-y-1 px-4 py-3 text-[13px] text-muted-foreground">
          <div><b className="text-foreground">RUWA</b> — Rust WhatsApp. An in-house WhatsApp API (whatsmeow port) + this ops console.</div>
          <div className="mono text-xs">github.com/oqva-digital · /v1 bearer API · SSE events · Prometheus /metrics</div>
        </div>
      </SectionCard>
    </div>
  )
}

export { clearAuth }
