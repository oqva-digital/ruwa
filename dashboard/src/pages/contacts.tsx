import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"
import { SearchCheck, Ban, Loader2 } from "lucide-react"
import { api } from "@/lib/api"
import type { SessionMeta, OnWhatsAppResult } from "@/lib/types"
import { cn } from "@/lib/utils"
import { SectionCard } from "@/components/ui-bits"
import { Card } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"

type Tab = "contacts" | "chats" | "groups"

export function ContactsPage({ inst, readonly }: { inst: SessionMeta; readonly: boolean }) {
  const [tab, setTab] = useState<Tab>("contacts")
  const [numbers, setNumbers] = useState("")
  const [checking, setChecking] = useState(false)
  const [results, setResults] = useState<OnWhatsAppResult[] | null>(null)

  const data = useQuery({
    queryKey: [tab, inst.id],
    queryFn: () =>
      tab === "contacts" ? api.contacts(inst.id) : tab === "chats" ? api.chats(inst.id) : api.groups(inst.id),
  })

  async function check() {
    const list = numbers.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
    if (!list.length) return
    setChecking(true)
    try {
      setResults(await api.onWhatsApp(inst.id, list))
    } catch (e) {
      toast.error("onWhatsApp failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setChecking(false)
    }
  }
  async function block(jid: string) {
    try { await api.blockContact(inst.id, jid); toast.success("Blocked", { description: jid }) }
    catch (e) { toast.error("Block failed", { description: e instanceof Error ? e.message : "" }) }
  }

  const cols = tab === "groups" ? ["jid", "subject", "creator"] : tab === "chats" ? ["jid", "name"] : ["jid", "full_name", "push_name"]
  const rows = (data.data ?? []) as Record<string, unknown>[]

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Contacts</h1>
        <div className="mt-0.5 text-xs text-muted-foreground">Directory + tools for {inst.label ?? inst.id}</div>
      </div>

      <SectionCard title="onWhatsApp check" icon={SearchCheck}>
        <div className="space-y-3 p-4">
          <Textarea value={numbers} onChange={(e) => setNumbers(e.target.value)} placeholder="Paste numbers (one per line or comma-separated)…" className="mono h-20 text-xs" />
          <div className="flex justify-end">
            <Button size="sm" disabled={checking} onClick={check}>
              {checking ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <SearchCheck className="h-3.5 w-3.5" />} Check
            </Button>
          </div>
          {results && (
            <div className="space-y-1">
              {results.map((r) => (
                <div key={r.query} className="flex items-center gap-3 text-[13px]">
                  <span className="mono w-36 text-muted-foreground">{r.query}</span>
                  <span data-st={r.exists ? "ok" : "neutral"} className="rounded-full px-2 py-0.5 text-[11px] font-medium">{r.exists ? "✓ exists" : "not on WA"}</span>
                  {r.jid && <span className="mono text-[11px] text-muted-foreground">{r.jid}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </SectionCard>

      <div className="flex rounded-md bg-muted p-0.5 w-fit">
        {(["contacts", "chats", "groups"] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={cn("rounded px-3 py-1 text-xs font-medium capitalize", tab === t ? "bg-card text-foreground shadow-sm" : "text-muted-foreground")}>{t}</button>
        ))}
      </div>

      <Card className="overflow-hidden p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                {cols.map((c) => <TableHead key={c} className="capitalize">{c.replace("_", " ")}</TableHead>)}
                {tab === "contacts" && <TableHead className="w-10" />}
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.isLoading && <TableRow><TableCell colSpan={cols.length + 1}><div className="skeleton h-5 w-full" /></TableCell></TableRow>}
              {rows.map((r, i) => (
                <TableRow key={(r.jid as string) ?? i}>
                  {cols.map((c) => (
                    <TableCell key={c} className={c === "jid" ? "mono text-[11px] text-muted-foreground" : "text-[13px]"}>
                      {String(r[c] ?? "—")}
                    </TableCell>
                  ))}
                  {tab === "contacts" && (
                    <TableCell>
                      <Button size="icon" variant="ghost" className="h-7 w-7" disabled={readonly} onClick={() => block(String(r.jid))} title="Block">
                        <Ban className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  )}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {data.data && rows.length === 0 && <div className="py-10 text-center text-xs text-muted-foreground">no {tab}</div>}
      </Card>
    </div>
  )
}
