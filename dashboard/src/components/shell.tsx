import { useState } from "react"
import {
  LayoutGrid,
  BarChart3,
  ScrollText,
  Stethoscope,
  Settings,
  Activity,
  QrCode,
  MessageSquare,
  Users,
  Webhook,
  Database,
  UserCircle,
  Wifi,
  Lock,
  Sun,
  Moon,
  ChevronRight,
  ArrowLeft,
  ChevronsUpDown,
  Check,
  PanelLeft,
  Menu,
  type LucideIcon,
} from "lucide-react"
import { cn } from "@/lib/utils"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { Button } from "@/components/ui/button"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command"
import { LivenessChip, StatusDot } from "@/components/status"
import { ageSec, liveness } from "@/lib/format"
import type { SessionMeta } from "@/lib/types"

export type GlobalPage = "instances" | "metrics" | "logs" | "diagnostics" | "settings"
export type InstancePage =
  | "overview" | "pairing" | "messaging" | "contacts"
  | "logs" | "metrics" | "webhooks" | "integrations" | "profile"

export const GLOBAL_NAV: { key: GlobalPage; label: string; icon: LucideIcon }[] = [
  { key: "instances", label: "Instances", icon: LayoutGrid },
  { key: "metrics", label: "Metrics", icon: BarChart3 },
  { key: "logs", label: "Logs", icon: ScrollText },
  { key: "diagnostics", label: "Diagnostics", icon: Stethoscope },
  { key: "settings", label: "Settings", icon: Settings },
]
export const INSTANCE_NAV: { key: InstancePage; label: string; icon: LucideIcon }[] = [
  { key: "overview", label: "Overview", icon: Activity },
  { key: "pairing", label: "Pairing", icon: QrCode },
  { key: "messaging", label: "Messaging", icon: MessageSquare },
  { key: "contacts", label: "Contacts", icon: Users },
  { key: "logs", label: "Logs", icon: ScrollText },
  { key: "metrics", label: "Metrics", icon: BarChart3 },
  { key: "webhooks", label: "Webhooks", icon: Webhook },
  { key: "integrations", label: "Integrations", icon: Database },
  { key: "profile", label: "Profile", icon: UserCircle },
]

function Brand({ onClick }: { onClick: () => void }) {
  return (
    <button onClick={onClick} className="flex items-center gap-2.5">
      <div className="flex h-[26px] w-[26px] flex-none place-items-center justify-center rounded-[7px] bg-primary text-sm font-bold text-white">R</div>
      <div className="hidden whitespace-nowrap text-[15px] font-bold tracking-wide sm:block">
        RUWA <span className="font-normal tracking-normal text-muted-foreground">Console</span>
      </div>
    </button>
  )
}

interface ClusterProps {
  healthy: number
  total: number
  frozen: number
  down: number
  readonly: boolean
  theme: string
  version: string | null
  onToggleTheme: () => void
  onSettings: () => void
}

function RightCluster({ healthy, total, frozen, down, readonly, theme, version, onToggleTheme, onSettings }: ClusterProps) {
  return (
    <div className="flex items-center gap-2.5">
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="flex items-center gap-1.5 text-[12.5px] font-medium">
            <Wifi className="h-3.5 w-3.5 text-st-ok" />
            <span className="mono tnum">{healthy}/{total}</span>
            <span className="hidden text-muted-foreground sm:inline">connected</span>
          </div>
        </TooltipTrigger>
        <TooltipContent>{healthy} healthy · {frozen} frozen · {down} down</TooltipContent>
      </Tooltip>
      {readonly && (
        <span data-st="warn" className="inline-flex h-5 items-center gap-1 rounded-full px-2 text-[11.5px] font-medium">
          <Lock className="h-3 w-3" /> readonly
        </span>
      )}
      <div className="h-[22px] w-px bg-border" />
      <Tooltip>
        <TooltipTrigger asChild>
          <Button size="icon" variant="ghost" className="h-8 w-8" onClick={onToggleTheme}>
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </Button>
        </TooltipTrigger>
        <TooltipContent>{theme === "dark" ? "Switch to light" : "Switch to dark"}</TooltipContent>
      </Tooltip>
      {version && (
        <span data-st="ok" className="hidden h-5 items-center gap-1.5 rounded-full px-2 text-[11.5px] font-medium sm:inline-flex">
          <span className="dot h-1.5 w-1.5 rounded-full bg-st-ok" /> <span className="mono">v{version}</span>
        </span>
      )}
      <Button size="icon" variant="ghost" className="h-8 w-8" onClick={onSettings}>
        <Settings className="h-4 w-4" />
      </Button>
    </div>
  )
}

export function GlobalTopBar({
  gpage, onNav, cluster,
}: {
  gpage: GlobalPage
  onNav: (p: GlobalPage) => void
  cluster: Omit<ClusterProps, "onSettings">
}) {
  return (
    <header className="flex h-[52px] flex-none items-center gap-2 border-b bg-background px-3 sm:gap-[18px] sm:px-4">
      <Brand onClick={() => onNav("instances")} />
      <div className="hidden h-[22px] w-px bg-border sm:block" />
      <nav className="no-scrollbar flex min-w-0 flex-1 items-stretch gap-0.5 self-stretch overflow-x-auto">
        {GLOBAL_NAV.map((n) => {
          const active = gpage === n.key
          const Ico = n.icon
          return (
            <button
              key={n.key}
              onClick={() => onNav(n.key)}
              className={cn(
                "-mb-px flex flex-none items-center gap-1.5 whitespace-nowrap border-b-2 px-2.5 text-[13px] font-medium transition-colors",
                active ? "border-primary text-foreground" : "border-transparent text-muted-foreground hover:text-foreground",
              )}
            >
              <Ico className="h-[15px] w-[15px]" /> {n.label}
            </button>
          )
        })}
      </nav>
      <RightCluster {...cluster} onSettings={() => onNav("settings")} />
    </header>
  )
}

function InstanceSwitcher({
  instances, current, onPick,
}: {
  instances: SessionMeta[]
  current: SessionMeta
  onPick: (id: string) => void
}) {
  const [open, setOpen] = useState(false)
  const lk = liveness(current.status, ageSec(current.updated_at)).kind
  const stKey = lk === "live" ? "ok" : lk === "frozen" ? "frozen" : lk === "down" ? "down" : "progress"
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button className="flex min-w-0 items-center gap-2 rounded-md px-1.5 py-1 text-sm font-semibold hover:bg-accent">
          <StatusDot st={stKey} pulse={lk === "frozen"} />
          <span className="truncate">{current.label || current.id}</span>
          <ChevronsUpDown className="h-[13px] w-[13px] flex-none text-muted-foreground" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-[300px] p-0" align="start">
        <Command>
          <CommandInput placeholder="Switch instance…" />
          <CommandList>
            <CommandEmpty>No match</CommandEmpty>
            <CommandGroup>
              {instances.map((i) => (
                <CommandItem
                  key={i.id}
                  value={`${i.label} ${i.id}`}
                  onSelect={() => { onPick(i.id); setOpen(false) }}
                  className="gap-2.5"
                >
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-[13px]">{i.label || "(no label)"}</div>
                    <div className="mono truncate text-[11px] text-muted-foreground">{i.id}</div>
                  </div>
                  {i.id === current.id && <Check className="h-3.5 w-3.5 text-primary" />}
                </CommandItem>
              ))}
            </CommandGroup>
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}

export function InstanceTopBar({
  instances, current, onPick, onBack, lastRxSec, cluster, onMenu,
}: {
  instances: SessionMeta[]
  current: SessionMeta
  onPick: (id: string) => void
  onBack: () => void
  lastRxSec: number | null
  cluster: ClusterProps
  onMenu: () => void
}) {
  return (
    <header className="flex h-[52px] flex-none items-center gap-1.5 border-b bg-background px-3 sm:px-4">
      {/* Mobile: open the instance sidebar drawer. */}
      <Button size="icon" variant="ghost" className="h-8 w-8 flex-none md:hidden" onClick={onMenu} aria-label="Open menu">
        <Menu className="h-4 w-4" />
      </Button>
      <Brand onClick={onBack} />
      <div className="mx-1 hidden h-[22px] w-px bg-border sm:block" />
      <Button size="sm" variant="outline" className="h-8 flex-none gap-1.5 px-2 sm:px-2.5" onClick={onBack}>
        <ArrowLeft className="h-4 w-4" /> <span className="hidden sm:inline">Dashboard</span>
      </Button>
      <ChevronRight className="hidden h-[13px] w-[13px] flex-none text-muted-foreground/60 sm:block" />
      <InstanceSwitcher instances={instances} current={current} onPick={onPick} />
      <div className="hidden sm:block">
        <LivenessChip status={current.status} lastRxSec={lastRxSec} />
      </div>
      <div className="flex-1" />
      <RightCluster {...cluster} />
    </header>
  )
}

export function InstanceSidebar({
  ipage, onNav, collapsed, onToggle, mobileOpen, onMobileClose,
}: {
  ipage: InstancePage
  onNav: (p: InstancePage) => void
  collapsed: boolean
  onToggle: () => void
  mobileOpen: boolean
  onMobileClose: () => void
}) {
  return (
    <>
      {/* Mobile backdrop — tap to dismiss the drawer. */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={onMobileClose}
          aria-hidden
        />
      )}
      <aside
        className={cn(
          "flex h-full flex-col border-r border-sidebar-border bg-sidebar",
          // Mobile: off-canvas drawer sliding in from the left (labels always shown).
          "fixed inset-y-0 left-0 z-50 w-[240px] transition-transform duration-200",
          mobileOpen ? "translate-x-0" : "-translate-x-full",
          // Desktop (md+): inline, width-collapsible rail.
          "md:static md:z-auto md:translate-x-0 md:flex-none md:transition-[width] md:duration-150",
          collapsed ? "md:w-14" : "md:w-[200px]",
        )}
      >
        <nav className="flex flex-1 flex-col gap-0.5 overflow-y-auto p-2">
          {INSTANCE_NAV.map((n) => {
            const active = ipage === n.key
            const Ico = n.icon
            const btn = (
              <button
                key={n.key}
                onClick={() => onNav(n.key)}
                className={cn(
                  "relative flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium",
                  // Icon-only centering applies only to the collapsed desktop rail.
                  collapsed && "md:justify-center md:px-0",
                  active
                    ? "bg-sidebar-accent text-sidebar-primary"
                    : "text-sidebar-foreground hover:bg-sidebar-accent/60",
                )}
              >
                {active && <span className="absolute inset-y-2 left-0 w-[2.5px] rounded bg-sidebar-primary" />}
                <Ico className="h-4 w-4 flex-none" />
                {/* Label hides only on the collapsed desktop rail — always shown in the mobile drawer. */}
                <span className={cn(collapsed && "md:hidden")}>{n.label}</span>
              </button>
            )
            return collapsed ? (
              <Tooltip key={n.key}>
                <TooltipTrigger asChild>{btn}</TooltipTrigger>
                {/* Tooltip is a desktop-rail affordance; suppress on touch. */}
                <TooltipContent side="right" className="hidden md:block">{n.label}</TooltipContent>
              </Tooltip>
            ) : (
              btn
            )
          })}
        </nav>
        {/* Collapse toggle is desktop-only; the mobile drawer is full or dismissed. */}
        <div className="hidden border-t border-sidebar-border p-2 md:block">
          <button
            onClick={onToggle}
            className={cn(
              "flex w-full items-center gap-2.5 rounded-md py-2 text-[13px] text-muted-foreground hover:bg-sidebar-accent/60",
              collapsed ? "justify-center px-0" : "px-2.5",
            )}
          >
            <PanelLeft className="h-4 w-4" />
            {!collapsed && <span>Collapse</span>}
          </button>
        </div>
      </aside>
    </>
  )
}
