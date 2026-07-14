import { useEffect, useRef, useState } from "react"
import { useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query"
import { toast } from "sonner"
import { Search, Send, SmilePlus, Trash2, Pencil, MessageSquare } from "lucide-react"
import { api } from "@/lib/api"
import type { SessionMeta, MessageRow } from "@/lib/types"
import { fmtTs } from "@/lib/format"
import { cn } from "@/lib/utils"
import { confirmDialog, promptDialog } from "@/components/confirm"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"

interface ChatRow {
  jid: string
  name?: string | null
  last_msg_ts?: number | null
  pinned?: boolean
  [k: string]: unknown
}

const MEDIA_TYPES = new Set(["image", "video", "audio", "ptt", "voice", "sticker", "document"])

/**
 * Renders a media message inline. The bytes are bearer-authed, so we fetch them
 * as a blob (object URL) rather than pointing an <img>/<video> at the endpoint.
 * The object URL is revoked on unmount to avoid leaking memory as you scroll.
 */
function MediaBubble({ inst, chat, m }: { inst: SessionMeta; chat: string; m: MessageRow }) {
  const [url, setUrl] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    let made: string | null = null
    setUrl(null)
    setErr(null)
    api
      .mediaBlobUrl(inst.id, chat, m.message_id)
      .then((u) => {
        if (cancelled) { URL.revokeObjectURL(u); return }
        made = u
        setUrl(u)
      })
      .catch((e) => !cancelled && setErr(e instanceof Error ? e.message : "load failed"))
    return () => {
      cancelled = true
      if (made) URL.revokeObjectURL(made)
    }
  }, [inst.id, chat, m.message_id])

  if (err) return <span className="text-[11px] text-muted-foreground">[{m.msg_type} — {err}]</span>
  if (!url) return <span className="text-[11px] text-muted-foreground">loading {m.msg_type}…</span>

  if (m.msg_type === "image")
    return <img src={url} alt="" className="max-h-72 max-w-full rounded" />
  if (m.msg_type === "sticker")
    return <img src={url} alt="" className="max-h-32 max-w-full" />
  if (m.msg_type === "video")
    return <video src={url} controls className="max-h-72 max-w-full rounded" />
  if (m.msg_type === "audio" || m.msg_type === "ptt" || m.msg_type === "voice")
    return <audio src={url} controls className="h-9 max-w-full" />
  // document (and any other downloadable blob)
  return (
    <a href={url} download className="text-[13px] underline">
      Download {m.msg_type}
    </a>
  )
}

export function MessagingPage({ inst }: { inst: SessionMeta }) {
  const qc = useQueryClient()
  const [sel, setSel] = useState<string | null>(null)
  const [q, setQ] = useState("")
  const scrollRef = useRef<HTMLDivElement>(null)
  const contentRef = useRef<HTMLDivElement>(null)
  // Whether to keep the view pinned to the newest message. Stays true until the
  // user scrolls up to read history; reset every time the chat changes.
  const stick = useRef(true)

  const chats = useQuery({ queryKey: ["chats", inst.id], queryFn: () => api.chats(inst.id) as Promise<ChatRow[]> })
  const contacts = useQuery({ queryKey: ["contacts", inst.id], queryFn: () => api.contacts(inst.id) })
  const messages = useQuery({
    queryKey: ["messages", inst.id, sel],
    queryFn: () => api.listMessages(inst.id, sel ?? undefined),
    enabled: !!sel,
    // Live updates arrive via the SSE→invalidate bridge in App; keep a slow
    // poll as a fallback. The 5s value is no longer the primary freshness path.
    refetchInterval: sel ? 15000 : false,
    // Soft refresh: keep the open conversation visible while switching chats or
    // refetching, instead of flashing an empty pane.
    placeholderData: keepPreviousData,
  })

  // jid → display name, from the contact directory. Used to label message
  // senders (the backend only resolves names for the chat list, not per-message).
  const nameByJid = new Map<string, string>()
  for (const c of contacts.data ?? []) {
    const n = c.full_name || c.push_name
    if (n) nameByJid.set(c.jid, n)
  }
  const nameOf = (jid?: string | null) => (jid ? nameByJid.get(jid) ?? jid.split("@")[0] : "")

  const chatList = (chats.data ?? [])
    .filter((c) => !q || (c.name ?? "").toLowerCase().includes(q.toLowerCase()) || c.jid.includes(q))
    // Most recent activity on top (pinned chats stay above the rest), so a chat
    // that just received a message pops to the top after the SSE-driven refetch.
    .sort((a, b) => {
      if (!!a.pinned !== !!b.pinned) return a.pinned ? -1 : 1
      return (b.last_msg_ts ?? 0) - (a.last_msg_ts ?? 0)
    })
  const rows = (messages.data ?? []).slice().reverse()
  const lastMsgId = rows.length ? rows[rows.length - 1].message_id : null

  // Reset the auto-scroll intent whenever you switch into a different chat.
  useEffect(() => {
    stick.current = true
  }, [sel])

  // Keep the conversation pinned to the latest message. A ResizeObserver lets
  // us re-scroll as content grows *after* the initial render — crucially when
  // MediaBubble images/videos finish loading and push the bottom down. We only
  // pin when the user is already at the bottom (stick), so scrolling up to read
  // history is never yanked back down.
  useEffect(() => {
    const el = scrollRef.current
    const content = contentRef.current
    if (!el || !content) return
    const pin = () => {
      if (stick.current) el.scrollTop = el.scrollHeight
    }
    pin()
    const ro = new ResizeObserver(pin)
    ro.observe(content)
    return () => ro.disconnect()
  }, [sel])

  // Snap to the newest message whenever one arrives (only if the user is pinned
  // to the bottom — scrolling up to read history is never yanked down). Explicit
  // and deterministic, on top of the ResizeObserver that handles late media.
  useEffect(() => {
    const el = scrollRef.current
    if (el && stick.current) el.scrollTop = el.scrollHeight
  }, [lastMsgId])

  function onHistoryScroll() {
    const el = scrollRef.current
    if (!el) return
    stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40
  }

  async function doReact(m: MessageRow) {
    const emoji = await promptDialog({ title: "React to message", defaultValue: "👍", placeholder: "emoji (blank removes)", confirmLabel: "React" })
    if (emoji === null || !sel) return
    try {
      await api.react(inst.id, sel, m.message_id, m.from_me, emoji, m.sender_jid)
      toast.success("Reacted")
    } catch (e) {
      toast.error("React failed", { description: e instanceof Error ? e.message : "" })
    }
  }
  async function doEdit(m: MessageRow) {
    if (!sel) return
    const text = await promptDialog({ title: "Edit message", defaultValue: m.body_text ?? "", placeholder: "new text", confirmLabel: "Save" })
    if (text === null || !text.trim()) return
    try {
      await api.edit(inst.id, sel, m.message_id, text)
      toast.success("Edited")
      setTimeout(() => qc.invalidateQueries({ queryKey: ["messages", inst.id, sel] }), 400)
    } catch (e) {
      toast.error("Edit failed", { description: e instanceof Error ? e.message : "" })
    }
  }
  async function doRevoke(m: MessageRow) {
    if (!sel || !(await confirmDialog({ title: "Revoke message?", message: "Deletes it for everyone.", confirmLabel: "Revoke", danger: true }))) return
    try {
      await api.revoke(inst.id, sel, m.message_id)
      toast.success("Revoked")
      setTimeout(() => qc.invalidateQueries({ queryKey: ["messages", inst.id, sel] }), 400)
    } catch (e) {
      toast.error("Revoke failed", { description: e instanceof Error ? e.message : "" })
    }
  }

  return (
    <Card className="grid min-h-0 flex-1 grid-cols-[260px_1fr] overflow-hidden p-0">
      {/* chat list */}
      <div className="flex min-h-0 flex-col border-r">
        <div className="relative border-b p-2">
          <Search className="absolute left-4 top-4 h-3.5 w-3.5 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search chats…" className="pl-8" />
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {chats.isLoading && <div className="p-3 text-xs text-muted-foreground">loading…</div>}
          {chatList.map((c) => (
            <button
              key={c.jid}
              onClick={() => setSel(c.jid)}
              className={cn(
                "flex w-full flex-col items-start gap-0.5 border-b border-border/50 px-3 py-2 text-left hover:bg-accent/40",
                sel === c.jid && "bg-accent/60",
              )}
            >
              <span className="w-full truncate text-[13px] font-medium">{c.name || nameByJid.get(c.jid) || c.jid.split("@")[0]}</span>
              <span className="mono w-full truncate text-[11px] text-muted-foreground">{c.jid}</span>
            </button>
          ))}
          {chats.data && chatList.length === 0 && <div className="p-3 text-xs text-muted-foreground">no chats</div>}
        </div>
      </div>

      {/* history + composer */}
      <div className="flex min-h-0 min-w-0 flex-col">
        {!sel ? (
          <div className="flex flex-1 flex-col items-center justify-center gap-2 text-muted-foreground">
            <MessageSquare className="h-7 w-7" />
            <span className="text-sm">Pick a chat to view its history.</span>
          </div>
        ) : (
          <>
            <div className="flex min-w-0 items-center gap-2 border-b px-4 py-2.5">
              <span className="truncate text-sm font-medium">{nameOf(sel)}</span>
              <span className="mono truncate text-xs text-muted-foreground">{sel}</span>
            </div>
            <div ref={scrollRef} onScroll={onHistoryScroll} className="min-h-0 flex-1 overflow-auto">
              <div ref={contentRef} className="space-y-1 p-4">
              {messages.isLoading && <div className="text-xs text-muted-foreground">loading…</div>}
              {rows.map((m) => (
                <div key={m.message_id} className={cn("group flex min-w-0 flex-col", m.from_me ? "items-end" : "items-start")}>
                  <div
                    className={cn(
                      "max-w-[78%] overflow-hidden whitespace-pre-wrap break-words rounded-lg px-2.5 py-1.5 text-[13px]",
                      m.from_me ? "bg-primary/20" : "bg-secondary",
                    )}
                  >
                    {m.quoted && (
                      <div className="mb-1 border-l-2 border-primary/60 pl-1.5 text-[11px] opacity-80">
                        {m.quoted.participant && (
                          <div className="truncate font-medium">{nameOf(m.quoted.participant)}</div>
                        )}
                        <div className="truncate">
                          {rows.find((r) => r.message_id === m.quoted?.stanza_id)?.body_text ??
                            m.quoted.text ??
                            "[message]"}
                        </div>
                      </div>
                    )}
                    {m.revoked || m.msg_type === "revoked" ? (
                      <span className="italic text-muted-foreground">This message was deleted</span>
                    ) : MEDIA_TYPES.has(m.msg_type) ? (
                      <div className="flex flex-col gap-1">
                        <MediaBubble inst={inst} chat={sel} m={m} />
                        {m.body_text && <span>{m.body_text}</span>}
                      </div>
                    ) : (
                      m.body_text ?? <span className="text-muted-foreground">[{m.msg_type}]</span>
                    )}
                  </div>
                  <div className="mono mt-0.5 flex max-w-full items-center gap-1.5 text-[10px] text-muted-foreground">
                    <span className="truncate">{m.from_me ? "me" : nameOf(m.sender_jid)}</span>·<span className="shrink-0">{fmtTs(m.timestamp)}</span>
                    {(m.edited || m.msg_type === "edited") && <span className="shrink-0 italic">· edited</span>}
                    <span className="opacity-0 transition-opacity group-hover:opacity-100">
                      <button onClick={() => doReact(m)} className="ml-1 hover:text-foreground"><SmilePlus className="inline h-3 w-3" /></button>
                      {m.from_me && !m.revoked && m.msg_type !== "revoked" && (
                        <>
                          {/* Edit only applies to text; WhatsApp rejects it past 15 min (the API says so). */}
                          {!MEDIA_TYPES.has(m.msg_type) && (
                            <button onClick={() => doEdit(m)} className="ml-1.5 hover:text-foreground"><Pencil className="inline h-3 w-3" /></button>
                          )}
                          <button onClick={() => doRevoke(m)} className="ml-1.5 hover:text-destructive"><Trash2 className="inline h-3 w-3" /></button>
                        </>
                      )}
                    </span>
                  </div>
                </div>
              ))}
              </div>
            </div>
            <Composer inst={inst} to={sel} onSent={() => setTimeout(() => qc.invalidateQueries({ queryKey: ["messages", inst.id, sel] }), 400)} />
          </>
        )}
      </div>
    </Card>
  )
}

type CType = "text" | "location" | "contact" | "poll" | "event"

function Composer({ inst, to, onSent }: { inst: SessionMeta; to: string; onSent: () => void }) {
  const [tab, setTab] = useState<CType>("text")
  const [busy, setBusy] = useState(false)
  const [text, setText] = useState("")
  const [f, setF] = useState<Record<string, string>>({})
  const set = (k: string, v: string) => setF((s) => ({ ...s, [k]: v }))

  async function send() {
    setBusy(true)
    try {
      if (tab === "text") {
        if (!text.trim()) return
        await api.sendText(inst.id, to, text); setText("")
      } else if (tab === "location") {
        await api.sendLocation(inst.id, to, { latitude: Number(f.lat), longitude: Number(f.lng), name: f.name, address: f.address })
      } else if (tab === "contact") {
        await api.sendContact(inst.id, to, { display_name: f.cname, phone: f.cphone })
      } else if (tab === "poll") {
        await api.sendPoll(inst.id, to, { name: f.pq, options: (f.popts || "").split("\n").map((s) => s.trim()).filter(Boolean) })
      } else if (tab === "event") {
        await api.sendEvent(inst.id, to, {
          name: f.ename, description: f.edesc, location: f.eloc,
          start_time: f.estart ? Math.floor(new Date(f.estart).getTime() / 1000) : Math.floor(Date.now() / 1000),
          end_time: f.eend ? Math.floor(new Date(f.eend).getTime() / 1000) : undefined,
        })
      }
      toast.success("Sent"); onSent()
    } catch (e) {
      toast.error("Send failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="border-t p-3">
      <div className="mb-2 flex gap-1">
        {(["text", "location", "contact", "poll", "event"] as CType[]).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium capitalize", tab === t ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground")}>{t}</button>
        ))}
      </div>
      {tab === "text" && (
        <div className="flex items-center gap-2">
          <Input value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), send())} placeholder="Message… (Enter to send)" />
          <Button disabled={busy || !text.trim()} onClick={send}><Send className="h-4 w-4" /> Send</Button>
        </div>
      )}
      {tab === "location" && (
        <Fields onSend={send} busy={busy}>
          <Input className="text-xs" placeholder="latitude" onChange={(e) => set("lat", e.target.value)} />
          <Input className="text-xs" placeholder="longitude" onChange={(e) => set("lng", e.target.value)} />
          <Input className="text-xs" placeholder="name (optional)" onChange={(e) => set("name", e.target.value)} />
          <Input className="text-xs" placeholder="address (optional)" onChange={(e) => set("address", e.target.value)} />
        </Fields>
      )}
      {tab === "contact" && (
        <Fields onSend={send} busy={busy}>
          <Input className="text-xs" placeholder="display name" onChange={(e) => set("cname", e.target.value)} />
          <Input className="text-xs" placeholder="phone (E.164)" onChange={(e) => set("cphone", e.target.value)} />
        </Fields>
      )}
      {tab === "poll" && (
        <Fields onSend={send} busy={busy}>
          <Input className="text-xs" placeholder="question" onChange={(e) => set("pq", e.target.value)} />
          <Textarea className="text-xs" placeholder="options (one per line)" onChange={(e) => set("popts", e.target.value)} />
        </Fields>
      )}
      {tab === "event" && (
        <Fields onSend={send} busy={busy}>
          <Input className="text-xs" placeholder="title" onChange={(e) => set("ename", e.target.value)} />
          <Input className="text-xs" placeholder="description (optional)" onChange={(e) => set("edesc", e.target.value)} />
          <Input className="text-xs" placeholder="location (optional)" onChange={(e) => set("eloc", e.target.value)} />
          <Input className="text-xs" type="datetime-local" onChange={(e) => set("estart", e.target.value)} />
          <Input className="text-xs" type="datetime-local" onChange={(e) => set("eend", e.target.value)} />
        </Fields>
      )}
    </div>
  )
}

function Fields({ children, onSend, busy }: { children: React.ReactNode; onSend: () => void; busy: boolean }) {
  return (
    <div className="space-y-2">
      <div className="grid grid-cols-2 gap-2">{children}</div>
      <div className="flex justify-end">
        <Button size="sm" disabled={busy} onClick={onSend}><Send className="h-3.5 w-3.5" /> Send</Button>
      </div>
    </div>
  )
}
