import { useState, type ReactNode } from "react"
import { ChevronRight, Info, type LucideIcon } from "lucide-react"
import { cn } from "@/lib/utils"
import { Card } from "@/components/ui/card"
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip"

/** Small stat card: label + big tabular-nums value (+ optional accent color).
 *  Pass `info` to attach an ⓘ tooltip explaining what the metric measures. */
export function StatCard({
  label, value, accent, sub, info,
}: {
  label: string
  value: ReactNode
  accent?: string
  sub?: ReactNode
  info?: ReactNode
}) {
  return (
    <Card className="gap-1.5 p-3.5">
      <div className="flex items-center gap-1 text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
        <span>{label}</span>
        {info && (
          <Tooltip>
            <TooltipTrigger className="inline-flex cursor-help text-muted-foreground/60 hover:text-foreground">
              <Info className="h-3 w-3" />
            </TooltipTrigger>
            <TooltipContent className="max-w-[260px] text-balance normal-case">{info}</TooltipContent>
          </Tooltip>
        )}
      </div>
      <div className="mono tnum truncate text-lg font-semibold" style={accent ? { color: accent } : undefined}>
        {value}
      </div>
      {sub}
    </Card>
  )
}

/** Card with a titled header bar + optional right action. */
export function SectionCard({
  title, icon: Icon, action, children, className,
}: {
  title: string
  icon?: LucideIcon
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <Card className={cn("gap-0 overflow-hidden p-0", className)}>
      <div className="flex items-center justify-between gap-2 border-b px-4 py-2.5">
        <div className="flex items-center gap-2 text-[15px] font-semibold">
          {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
          {title}
        </div>
        {action}
      </div>
      {children}
    </Card>
  )
}

/** JSON block with light syntax highlighting (escaped → safe). */
function highlight(json: string): string {
  const esc = json.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
  return esc.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (m) => {
      let cls = "n"
      if (/^"/.test(m)) cls = /:$/.test(m) ? "k" : "s"
      else if (/true|false|null/.test(m)) cls = "b"
      return `<span class="${cls}">${m}</span>`
    },
  )
}

export function JsonBlock({ data }: { data: unknown }) {
  const text = JSON.stringify(data, null, 2)
  return <pre className="json" dangerouslySetInnerHTML={{ __html: highlight(text) }} />
}

/** A header you click to expand/collapse content (raw-JSON, helpers…). */
export function CollapsibleSection({
  title, icon: Icon, defaultOpen = false, children,
}: {
  title: string
  icon?: LucideIcon
  defaultOpen?: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <Card className="gap-0 overflow-hidden p-0">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-2 px-4 py-2.5 text-[13px] font-medium hover:bg-accent/50"
      >
        <ChevronRight className={cn("h-4 w-4 text-muted-foreground transition-transform", open && "rotate-90")} />
        {Icon && <Icon className="h-4 w-4 text-muted-foreground" />}
        {title}
      </button>
      {open && <div className="border-t p-4">{children}</div>}
    </Card>
  )
}
