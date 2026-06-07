import { useEffect, useState } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { AuthGate } from "@/pages/auth-gate"
import { InstancesPage } from "@/pages/instances"
import { OverviewPage } from "@/pages/overview"
import { PairingPage } from "@/pages/pairing"
import { LogsPage } from "@/pages/logs"
import { DiagnosticsPage } from "@/pages/diagnostics"
import { MessagingPage } from "@/pages/messaging"
import { ContactsPage } from "@/pages/contacts"
import { ProfilePage } from "@/pages/profile"
import { WebhooksPage } from "@/pages/webhooks"
import { IntegrationsPage } from "@/pages/integrations"
import { MetricsPage } from "@/pages/metrics"
import { SettingsPage } from "@/pages/settings"
import {
  GlobalTopBar, InstanceTopBar, InstanceSidebar,
  type GlobalPage, type InstancePage,
} from "@/components/shell"
import { api, clearAuth, streamEvents } from "@/lib/api"

function ls(key: string, fallback: string) {
  return localStorage.getItem(key) || fallback
}

function App() {
  const [authed, setAuthed] = useState(() => !!localStorage.getItem("ruwa_token"))
  const [theme, setTheme] = useState(() => ls("ruwa_theme", "dark"))
  const [level, setLevel] = useState(() => ls("ruwa_level", "global"))
  const [gpage, setGpage] = useState<GlobalPage>(() => ls("ruwa_gpage", "instances") as GlobalPage)
  const [ipage, setIpage] = useState<InstancePage>(() => ls("ruwa_ipage", "overview") as InstancePage)
  const [instId, setInstId] = useState(() => localStorage.getItem("ruwa_inst") || "")
  const [collapsed, setCollapsed] = useState(false)
  const [mobileNav, setMobileNav] = useState(false)
  const [readonly] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark")
    localStorage.setItem("ruwa_theme", theme)
  }, [theme])
  useEffect(() => void localStorage.setItem("ruwa_level", level), [level])
  useEffect(() => void localStorage.setItem("ruwa_gpage", gpage), [gpage])
  useEffect(() => void localStorage.setItem("ruwa_ipage", ipage), [ipage])
  useEffect(() => void localStorage.setItem("ruwa_inst", instId), [instId])

  const sessions = useQuery({ queryKey: ["sessions"], queryFn: api.listSessions, enabled: authed, refetchInterval: 8000 })
  const healthQ = useQuery({ queryKey: ["health-v"], queryFn: api.health, enabled: authed, staleTime: 30_000 })
  const list = sessions.data ?? []
  const current = list.find((i) => i.id === instId) || list[0]

  const curHealth = useQuery({
    queryKey: ["health", current?.id],
    queryFn: () => api.sessionHealth(current!.id),
    enabled: authed && level === "instance" && !!current,
    refetchInterval: 6000,
  })

  // Live updates: subscribe to the current instance's event stream and refresh
  // the affected queries as events arrive, so new messages/receipts/status
  // changes show up without a manual reload. invalidate is a soft refresh —
  // react-query refetches while keeping current data on screen (paired with
  // keepPreviousData on the message/chat queries).
  const qc = useQueryClient()
  useEffect(() => {
    if (!authed || level !== "instance" || !current) return
    const id = current.id
    const stop = streamEvents(id, (ev) => {
      const t = (ev?.type as string) || ""
      if (
        t.startsWith("message") ||
        t.includes("receipt") ||
        t.includes("delivered") ||
        t.includes("read")
      ) {
        qc.invalidateQueries({ queryKey: ["messages", id] })
        qc.invalidateQueries({ queryKey: ["chats", id] })
      } else {
        // connection lifecycle: connected / disconnected / paired / qr / …
        qc.invalidateQueries({ queryKey: ["health", id] })
        qc.invalidateQueries({ queryKey: ["sessions"] })
      }
    })
    return stop
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authed, level, current?.id, qc])

  const logout = () => { clearAuth(); setAuthed(false) }

  if (!authed) {
    return <AuthGate onConnect={() => { localStorage.setItem("ruwa_authed", "1"); setAuthed(true) }} />
  }

  const toggleTheme = () => setTheme((t) => (t === "dark" ? "light" : "dark"))
  const enterInstance = (id: string) => { setInstId(id); setLevel("instance"); setIpage("overview") }
  const goGlobal = (p: GlobalPage) => { setLevel("global"); setGpage(p) }

  const connected = list.filter((s) => s.status === "connected").length
  const down = list.filter((s) => s.status !== "connected" && s.status !== "connecting").length
  const clusterBase = {
    healthy: connected, total: list.length, frozen: 0, down,
    readonly, theme, version: healthQ.data?.version ?? null, onToggleTheme: toggleTheme,
  }

  // ---------- GLOBAL ----------
  if (level === "global") {
    let body
    const fullHeight = gpage === "logs" || gpage === "diagnostics"
    if (gpage === "instances") body = <InstancesPage onOpen={enterInstance} readonly={readonly} />
    else if (gpage === "metrics") body = <MetricsPage scope="global" />
    else if (gpage === "logs") body = <LogsPage scope="global" instances={list} />
    else if (gpage === "diagnostics") body = <DiagnosticsPage />
    else body = <SettingsPage theme={theme} onToggleTheme={toggleTheme} onLogout={logout} />
    return (
      <div className="flex h-full flex-col overflow-hidden">
        <GlobalTopBar gpage={gpage} onNav={setGpage} cluster={clusterBase} />
        <main className={"flex min-h-0 flex-1 flex-col " + (fullHeight ? "overflow-hidden p-4 sm:p-6" : "overflow-auto px-4 pb-10 pt-5 sm:px-6")}>{body}</main>
      </div>
    )
  }

  // ---------- INSTANCE ----------
  if (!current) {
    return (
      <div className="flex h-full flex-col overflow-hidden">
        <GlobalTopBar gpage="instances" onNav={(p) => goGlobal(p)} cluster={clusterBase} />
        <main className="flex flex-1 items-center justify-center text-sm text-muted-foreground">No instance selected.</main>
      </div>
    )
  }

  const lastRxSec = curHealth.data?.seconds_since_rx ?? null
  const fullHeight = ipage === "logs" || ipage === "messaging"
  let body
  if (ipage === "overview") body = <OverviewPage inst={current} onNav={setIpage} readonly={readonly} />
  else if (ipage === "pairing") body = <PairingPage inst={current} />
  else if (ipage === "messaging") body = <MessagingPage inst={current} />
  else if (ipage === "contacts") body = <ContactsPage inst={current} readonly={readonly} />
  else if (ipage === "logs") body = <LogsPage scope="instance" instances={[current]} label={current.label ?? current.id} />
  else if (ipage === "metrics") body = <MetricsPage scope="instance" inst={current} />
  else if (ipage === "webhooks") body = <WebhooksPage inst={current} readonly={readonly} />
  else if (ipage === "integrations") body = <IntegrationsPage inst={current} readonly={readonly} />
  else if (ipage === "profile") body = <ProfilePage inst={current} readonly={readonly} />

  return (
    <div className="flex h-full flex-col overflow-hidden">
      <InstanceTopBar
        instances={list}
        current={current}
        onPick={setInstId}
        onBack={() => goGlobal("instances")}
        lastRxSec={lastRxSec}
        cluster={{ ...clusterBase, onSettings: () => goGlobal("settings") }}
        onMenu={() => setMobileNav(true)}
      />
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <InstanceSidebar
          ipage={ipage}
          onNav={(p) => { setIpage(p); setMobileNav(false) }}
          collapsed={collapsed}
          onToggle={() => setCollapsed((c) => !c)}
          mobileOpen={mobileNav}
          onMobileClose={() => setMobileNav(false)}
        />
        <main className={"flex min-w-0 flex-1 flex-col " + (fullHeight ? "overflow-hidden p-4 sm:p-6" : "overflow-auto px-4 pb-10 pt-5 sm:px-6")}>
          {body}
        </main>
      </div>
    </div>
  )
}

export default App
