import { useEffect, useMemo, useRef, useState } from "react"
import { useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query"
import { toast } from "sonner"
import {
  Search, Send, SmilePlus, Trash2, Pencil, MessageSquare, MessageSquarePlus, Loader2,
  LayoutTemplate, MousePointerClick, RefreshCw, Sparkles, Mic, Paperclip, Square, X, Undo2, Check,
} from "lucide-react"
import { api, ApiError } from "@/lib/api"
import type { SessionMeta, MessageRow, TemplateRow, ImproveMode, MediaSendType } from "@/lib/types"
import { isCloud } from "@/lib/types"
import { fmtTs } from "@/lib/format"
import { cn } from "@/lib/utils"
import { templateBodyText, countBodyParams, fillTemplateBody } from "@/lib/cloud"
import {
  VOICE_MIME, fmtElapsed, isVoiceSupported, preloadVoiceRecorder, startVoiceRecording, type VoiceRecording,
} from "@/lib/voice"
import { confirmDialog, promptDialog } from "@/components/confirm"
import { JsonBlock } from "@/components/ui-bits"
import { Card } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"

interface ChatRow {
  jid: string
  name?: string | null
  last_msg_ts?: number | null
  pinned?: boolean
  [k: string]: unknown
}

const nowSec = () => Math.floor(Date.now() / 1000)

const MEDIA_TYPES = new Set(["image", "video", "audio", "ptt", "voice", "sticker", "document"])
/** Cloud-API structured types: outbound templates/interactive prompts and the
 *  inbound taps they produce (`button` = template quick-reply, `interactive` =
 *  button_reply/list_reply). Rendered as a labelled bubble, not `[type]`. */
const STRUCTURED_TYPES = new Set(["template", "interactive", "button", "button_reply", "list_reply"])

/**
 * Bubble for template / interactive / button rows. The list endpoint carries
 * `msg_type` + `body_text` (template rows persist `<template:name>`); if the row
 * also has a structured field (`template`, `interactive`, `button`, `payload`)
 * we show it as JSON so nothing is hidden.
 */
function StructuredBubble({ m }: { m: MessageRow }) {
  const kind = m.msg_type
  let label = kind
  let text = m.body_text ?? ""
  const tm = /^<template:([^>]+)>$/.exec(text)
  if (kind === "template" && tm) { label = "template"; text = tm[1] }
  else if (kind === "button") label = "quick reply"
  else if (kind === "interactive" && !m.from_me) label = "reply"
  else if (kind === "button_reply" || kind === "list_reply") label = kind.replace("_", " ")
  const extra = (["template", "interactive", "button", "payload"] as const)
    .map((k) => m[k])
    .find((v) => v && typeof v === "object")
  return (
    <div className="flex flex-col gap-1">
      <span className="inline-flex w-fit items-center gap-1 rounded-full bg-background/60 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
        {kind === "template" ? <LayoutTemplate className="h-2.5 w-2.5" /> : <MousePointerClick className="h-2.5 w-2.5" />}
        {label}
      </span>
      {text ? <span className={cn(kind === "template" && tm && "mono text-xs")}>{text}</span> : <span className="text-muted-foreground">[{kind}]</span>}
      {extra ? <div className="max-w-full overflow-x-auto text-[10px]"><JsonBlock data={extra} /></div> : null}
    </div>
  )
}

/**
 * If the search box holds something that looks like a phone number (digits with
 * optional +, spaces, dashes, parens), return the bare E.164 digits; else null.
 * Drives the "start a new chat" affordance for numbers not yet in the chat list.
 */
function asPhoneDigits(q: string): string | null {
  const t = q.trim()
  if (!t || !/^\+?[\d\s().-]+$/.test(t)) return null
  const digits = t.replace(/\D/g, "")
  return digits.length >= 7 && digits.length <= 15 ? digits : null
}

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
  // A chat opened from a typed phone number that has no row in `chats` yet
  // (WhatsApp lets you message any number — no saved contact required). Kept
  // in the list until the first message lands and the chats query catches up.
  const [draft, setDraft] = useState<ChatRow | null>(null)
  const [starting, setStarting] = useState(false)
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

  const phone = asPhoneDigits(q)
  const known = new Set((chats.data ?? []).map((c) => c.jid))
  // Offer "new chat" only when the typed number isn't already a chat.
  const canStart = !!phone && ![...known].some((j) => j.split("@")[0] === phone)

  const cloud = isCloud(inst)

  async function startChat() {
    if (!phone || starting) return
    // Cloud API has no onWhatsApp lookup (501): open the draft directly and let
    // the first send tell us (Graph rejects unknown numbers).
    if (cloud) {
      const jid = `${phone}@s.whatsapp.net`
      setDraft({ jid, name: null, last_msg_ts: Math.floor(Date.now() / 1000) })
      setSel(jid)
      setQ("")
      return
    }
    setStarting(true)
    try {
      const [r] = await api.onWhatsApp(inst.id, [phone])
      if (!r?.exists || !r.jid) {
        toast.error("Not on WhatsApp", { description: `+${phone} has no WhatsApp account` })
        return
      }
      setDraft({ jid: r.jid, name: null, last_msg_ts: Math.floor(Date.now() / 1000) })
      setSel(r.jid)
      setQ("")
    } catch (e) {
      toast.error("Lookup failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setStarting(false)
    }
  }

  const baseChats = chats.data ?? []
  const chatList = (draft && !known.has(draft.jid) ? [draft, ...baseChats] : baseChats)
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
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && canStart && (e.preventDefault(), startChat())}
            placeholder="Search chats or type a number…"
            className="pl-8"
          />
        </div>
        <div className="min-h-0 flex-1 overflow-auto">
          {canStart && (
            <button
              onClick={startChat}
              disabled={starting}
              className="flex w-full items-center gap-2 border-b border-border/50 px-3 py-2 text-left text-[13px] hover:bg-accent/40 disabled:opacity-60"
            >
              {starting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <MessageSquarePlus className="h-3.5 w-3.5" />}
              <span className="truncate">
                New chat with <span className="mono">+{phone}</span>
              </span>
            </button>
          )}
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
          {chats.data && chatList.length === 0 && !canStart && (
            <div className="p-3 text-xs text-muted-foreground">
              {q ? "no match — type a full phone number to start a new chat" : "no chats"}
            </div>
          )}
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
                    ) : STRUCTURED_TYPES.has(m.msg_type) ? (
                      <StructuredBubble m={m} />
                    ) : (
                      m.body_text ?? <span className="text-muted-foreground">[{m.msg_type}]</span>
                    )}
                  </div>
                  <div className="mono mt-0.5 flex max-w-full items-center gap-1.5 text-[10px] text-muted-foreground">
                    <span className="truncate">{m.from_me ? "me" : nameOf(m.sender_jid)}</span>·<span className="shrink-0">{fmtTs(m.timestamp)}</span>
                    {(m.edited || m.msg_type === "edited") && <span className="shrink-0 italic">· edited</span>}
                    <span className="opacity-0 transition-opacity group-hover:opacity-100">
                      <button onClick={() => doReact(m)} className="ml-1 hover:text-foreground"><SmilePlus className="inline h-3 w-3" /></button>
                      {/* Cloud API has no edit/revoke (501) — only web sessions get these. */}
                      {!cloud && m.from_me && !m.revoked && m.msg_type !== "revoked" && (
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
            <Composer
              key={inst.id}
              inst={inst}
              to={sel}
              onSent={() =>
                setTimeout(() => {
                  qc.invalidateQueries({ queryKey: ["messages", inst.id, sel] })
                  // A brand-new chat only shows up in the list once its first
                  // message is persisted; refresh so the draft row becomes real.
                  qc.invalidateQueries({ queryKey: ["chats", inst.id] })
                }, 400)
              }
            />
          </>
        )}
      </div>
    </Card>
  )
}

type CType = "text" | "location" | "contact" | "poll" | "event" | "template" | "interactive"

const WEB_TABS: CType[] = ["text", "location", "contact", "poll", "event"]
// Cloud API: no polls/events; templates + interactive buttons instead.
const CLOUD_TABS: CType[] = ["text", "template", "interactive", "location", "contact"]

/** ✨ Improve menu entries → `mode` of POST /v1/ai/improve-text. */
const AI_MODES: { mode: ImproveMode; label: string }[] = [
  { mode: "improve", label: "Improve" },
  { mode: "formal", label: "More formal" },
  { mode: "casual", label: "More casual" },
  { mode: "shorter", label: "Shorter" },
  { mode: "grammar", label: "Fix grammar" },
  { mode: "translate", label: "Translate…" },
  { mode: "custom", label: "Custom…" },
]

/** Map a picked file's MIME to the multipart `type` (stickers aren't offered). */
function mediaTypeOf(mime: string): MediaSendType {
  if (mime.startsWith("image/")) return "image"
  if (mime.startsWith("video/")) return "video"
  if (mime.startsWith("audio/")) return "audio"
  return "document"
}

function Composer({ inst, to, onSent }: { inst: SessionMeta; to: string; onSent: () => void }) {
  const cloud = isCloud(inst)
  const tabs = cloud ? CLOUD_TABS : WEB_TABS
  const [tab, setTab] = useState<CType>("text")
  const [busy, setBusy] = useState(false)
  const [text, setText] = useState("")
  // ── ✨ AI assistant ──
  // Shared query key with Settings → saving there flips the button on here.
  const ai = useQuery({
    queryKey: ["ai-settings"],
    queryFn: () => api.getAiSettings().catch((e) => {
      // Older servers without the endpoint: behave as "not configured".
      if (e instanceof ApiError && e.status === 404) return null
      throw e
    }),
    staleTime: 60_000,
  })
  const aiReady = !!ai.data?.configured
  const [aiBusy, setAiBusy] = useState(false)
  const [aiPreview, setAiPreview] = useState<{ text: string; label: string } | null>(null)
  // Draft as it was before the last "Use" — one-click Undo.
  const [aiUndo, setAiUndo] = useState<string | null>(null)
  // ── 🎤 voice note ──
  const voiceOk = useMemo(() => isVoiceSupported(), [])
  const recRef = useRef<VoiceRecording | null>(null)
  const [recording, setRecording] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [voice, setVoice] = useState<{ blob: Blob; url: string } | null>(null)
  // ── 📎 attach ──
  const fileRef = useRef<HTMLInputElement>(null)

  // Warm the recorder module (~8 KB) so the first tap starts within the user
  // gesture window Safari requires for AudioContext.
  useEffect(() => {
    if (voiceOk) preloadVoiceRecorder().catch(() => {})
  }, [voiceOk])
  // Elapsed-time ticker while recording.
  useEffect(() => {
    if (!recording) return
    const t0 = Date.now()
    const iv = setInterval(() => setElapsed(Math.floor((Date.now() - t0) / 1000)), 250)
    return () => clearInterval(iv)
  }, [recording])
  // Switching chats (or unmounting) drops any in-flight recording/preview so a
  // note recorded for one contact can't land in another.
  useEffect(() => {
    return () => {
      recRef.current?.cancel()
      recRef.current = null
      setRecording(false)
      setVoice((v) => { if (v) URL.revokeObjectURL(v.url); return null })
    }
  }, [to])

  async function aiRun(mode: ImproveMode) {
    const draft = text.trim()
    if (!draft) { toast.error("Type a draft first"); return }
    let language: string | undefined
    let instruction: string | undefined
    let label = AI_MODES.find((m) => m.mode === mode)?.label ?? mode
    if (mode === "translate") {
      const l = await promptDialog({ title: "Translate to…", placeholder: "language, e.g. en, pt-BR, Spanish", confirmLabel: "Translate" })
      if (!l?.trim()) return
      language = l.trim()
      label = `Translate → ${language}`
    } else if (mode === "custom") {
      const i = await promptDialog({ title: "Custom instruction", placeholder: "e.g. add a friendly greeting and ask for a confirmation", confirmLabel: "Rewrite" })
      if (!i?.trim()) return
      instruction = i.trim().slice(0, 500)
      label = "Custom"
    }
    setAiBusy(true)
    try {
      const r = await api.improveText({ text: draft, mode, ...(language ? { language } : {}), ...(instruction ? { instruction } : {}) })
      setAiPreview({ text: r.text, label })
    } catch (e) {
      const msg = e instanceof Error ? e.message : ""
      toast.error(e instanceof ApiError && e.status === 422 ? "AI declined to rewrite this text" : "AI request failed", { description: msg })
    } finally {
      setAiBusy(false)
    }
  }
  function aiUse() {
    if (!aiPreview) return
    setAiUndo(text)
    setText(aiPreview.text)
    setAiPreview(null)
  }
  function aiRevert() {
    if (aiUndo === null) return
    setText(aiUndo)
    setAiUndo(null)
  }

  async function recStart() {
    if (recording || recRef.current) return
    try {
      const r = await startVoiceRecording()
      recRef.current = r
      setElapsed(0)
      setRecording(true)
    } catch (e) {
      const name = e instanceof DOMException ? e.name : ""
      if (name === "NotAllowedError" || name === "SecurityError")
        toast.error("Microphone access denied", { description: "Allow the microphone for this site and try again." })
      else if (name === "NotFoundError")
        toast.error("No microphone found")
      else
        toast.error("Could not start recording", { description: e instanceof Error ? e.message : "" })
    }
  }
  async function recStop() {
    const r = recRef.current
    if (!r) return
    recRef.current = null
    setRecording(false)
    try {
      const blob = await r.stop()
      if (blob.size === 0) { toast.error("Nothing recorded"); return }
      setVoice({ blob, url: URL.createObjectURL(blob) })
    } catch (e) {
      toast.error("Recording failed", { description: e instanceof Error ? e.message : "" })
    }
  }
  async function recCancel() {
    const r = recRef.current
    recRef.current = null
    setRecording(false)
    await r?.cancel()
  }
  function voiceDiscard() {
    setVoice((v) => { if (v) URL.revokeObjectURL(v.url); return null })
  }
  async function voiceSend() {
    if (!voice) return
    setBusy(true)
    try {
      await api.sendMediaMultipart(inst.id, {
        to, type: "ptt", file: voice.blob, mime: VOICE_MIME, filename: `voice-${Date.now()}.ogg`,
      })
      voiceDiscard()
      toast.success("Voice note sent"); onSent()
    } catch (e) {
      toast.error("Send failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }

  async function attachSend(file: File) {
    const mime = file.type || "application/octet-stream"
    const type = mediaTypeOf(mime)
    const caption = text.trim()
    setBusy(true)
    try {
      await api.sendMediaMultipart(inst.id, {
        to, type, file, mime, filename: file.name || `file-${Date.now()}`,
        // Audio has no caption on WhatsApp; keep the draft in that case.
        ...(caption && type !== "audio" ? { caption } : {}),
      })
      if (caption && type !== "audio") { setText(""); setAiUndo(null) }
      toast.success(`${type[0].toUpperCase()}${type.slice(1)} sent`); onSent()
    } catch (e) {
      toast.error("Send failed", { description: e instanceof Error ? e.message : "" })
    } finally {
      setBusy(false)
    }
  }
  const [f, setF] = useState<Record<string, string>>({})
  const set = (k: string, v: string) => setF((s) => ({ ...s, [k]: v }))
  // template state
  const [tplKey, setTplKey] = useState<string>("")
  const [tplParams, setTplParams] = useState<string[]>([])
  // interactive-buttons state
  const [ibody, setIbody] = useState("")
  const [ibtns, setIbtns] = useState<string[]>(["", "", ""])

  const templates = useQuery({
    queryKey: ["templates", inst.id],
    queryFn: () => api.listTemplates(inst.id, { status: "APPROVED", limit: 100 }),
    enabled: cloud && tab === "template",
    staleTime: 60_000,
  })
  const tplList: TemplateRow[] = useMemo(() => templates.data?.templates ?? [], [templates.data])
  const tplOf = (key: string) => tplList.find((t) => `${t.name}::${t.language}` === key)
  const tpl = tplOf(tplKey)
  const tplBody = tpl ? templateBodyText(tpl) : null
  const nParams = countBodyParams(tplBody)
  const btnTitles = ibtns.map((b) => b.trim()).filter(Boolean)
  const tplReady = !!tpl && tplParams.slice(0, nParams).every((p) => p.trim().length > 0) && tplParams.length >= nParams

  function pickTemplate(key: string) {
    setTplKey(key)
    const t = tplOf(key)
    setTplParams(Array.from({ length: countBodyParams(t ? templateBodyText(t) : null) }, () => ""))
  }

  async function send() {
    setBusy(true)
    try {
      if (tab === "text") {
        if (!text.trim()) return
        await api.sendText(inst.id, to, text); setText(""); setAiUndo(null); setAiPreview(null)
      } else if (tab === "location") {
        await api.sendLocation(inst.id, to, { latitude: Number(f.lat), longitude: Number(f.lng), name: f.name, address: f.address })
      } else if (tab === "contact") {
        await api.sendContact(inst.id, to, { display_name: f.cname, phone: f.cphone })
      } else if (tab === "poll") {
        await api.sendPoll(inst.id, to, { name: f.pq, options: (f.popts || "").split("\n").map((s) => s.trim()).filter(Boolean) })
      } else if (tab === "event") {
        await api.sendEvent(inst.id, to, {
          name: f.ename, description: f.edesc, location: f.eloc,
          start_time: f.estart ? Math.floor(new Date(f.estart).getTime() / 1000) : nowSec(),
          end_time: f.eend ? Math.floor(new Date(f.eend).getTime() / 1000) : undefined,
        })
      } else if (tab === "template") {
        if (!tpl) { toast.error("Pick a template"); return }
        if (!tplReady) { toast.error("Fill every body parameter"); return }
        await api.sendTemplate(inst.id, to, {
          name: tpl.name,
          language: tpl.language,
          ...(nParams > 0 ? { body_params: tplParams.slice(0, nParams).map((p) => p.trim()) } : {}),
        })
      } else if (tab === "interactive") {
        if (!ibody.trim()) { toast.error("Body text is required"); return }
        if (btnTitles.length === 0) { toast.error("Add at least one button"); return }
        await api.sendInteractive(inst.id, to, {
          type: "button",
          body: ibody.trim(),
          buttons: btnTitles.map((title, i) => ({ id: `btn_${i + 1}`, title: title.slice(0, 20) })),
        })
        setIbody(""); setIbtns(["", "", ""])
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
        {tabs.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={cn("rounded-md px-2 py-0.5 text-[11px] font-medium capitalize", tab === t ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground")}>
            {t === "interactive" ? "buttons" : t}
          </button>
        ))}
      </div>
      {tab === "text" && (
        <div className="space-y-2">
          {aiPreview && (
            <div className="rounded-md border border-primary/40 bg-primary/5 p-2.5">
              <div className="mb-1 flex items-center gap-1.5 text-[11px] font-medium text-muted-foreground">
                <Sparkles className="h-3 w-3" /> {aiPreview.label} · suggestion
              </div>
              <div className="whitespace-pre-wrap break-words text-[13px]">{aiPreview.text}</div>
              <div className="mt-2 flex justify-end gap-1.5">
                <Button size="xs" variant="ghost" onClick={() => setAiPreview(null)}><X className="h-3 w-3" /> Discard</Button>
                <Button size="xs" onClick={aiUse}><Check className="h-3 w-3" /> Use</Button>
              </div>
            </div>
          )}
          {voice && (
            <div className="flex items-center gap-2 rounded-md border bg-secondary/40 p-2">
              <Mic className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              <audio src={voice.url} controls className="h-9 min-w-0 flex-1" />
              <Button size="sm" variant="ghost" onClick={voiceDiscard} disabled={busy}><Trash2 className="h-3.5 w-3.5" /> Discard</Button>
              <Button size="sm" onClick={voiceSend} disabled={busy}>
                {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />} Send
              </Button>
            </div>
          )}
          {recording ? (
            <div className="flex items-center gap-2">
              <span className="flex h-9 min-w-0 flex-1 items-center gap-2 rounded-md border border-st-down/40 bg-st-down/10 px-3 text-[13px]">
                <span className="h-2 w-2 animate-pulse rounded-full bg-st-down" />
                <span>Recording…</span>
                <span className="mono tnum text-muted-foreground">{fmtElapsed(elapsed)}</span>
              </span>
              <Button variant="outline" onClick={recCancel} title="Cancel recording"><X className="h-4 w-4" /> Cancel</Button>
              <Button onClick={recStop} title="Stop and preview"><Square className="h-3.5 w-3.5 fill-current" /> Stop</Button>
            </div>
          ) : (
            <div className="flex items-end gap-2">
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0]
                  e.target.value = ""
                  if (f) attachSend(f)
                }}
              />
              <Button size="icon" variant="ghost" className="shrink-0" onClick={() => fileRef.current?.click()} disabled={busy} title="Attach a file (caption = current draft)">
                <Paperclip className="h-4 w-4" />
              </Button>
              {voiceOk && (
                <Button size="icon" variant="ghost" className="shrink-0" onClick={recStart} disabled={busy || !!voice} title={voice ? "Send or discard the current voice note first" : "Record a voice note"}>
                  <Mic className="h-4 w-4" />
                </Button>
              )}
              <Textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                // `isComposing`: Enter inside an IME composition (accents, CJK) commits
                // the candidate, it must not send the half-typed draft.
                onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing && (e.preventDefault(), send())}
                placeholder="Message… (Enter to send, Shift+Enter for a new line)"
                rows={1}
                className="max-h-40 min-h-9 resize-none py-2 text-sm"
              />
              <DropdownMenu>
                <Tooltip>
                  <TooltipTrigger asChild>
                    {/* span so the tooltip still shows while the button is disabled */}
                    <span className="inline-flex shrink-0">
                      <DropdownMenuTrigger asChild>
                        <Button size="icon" variant="outline" disabled={!aiReady || aiBusy || !text.trim()} title={aiReady ? "Improve with AI" : undefined} aria-label="Improve with AI">
                          {aiBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
                        </Button>
                      </DropdownMenuTrigger>
                    </span>
                  </TooltipTrigger>
                  {!aiReady && <TooltipContent>Configure the AI assistant in Settings</TooltipContent>}
                </Tooltip>
                <DropdownMenuContent align="end">
                  {AI_MODES.filter((m) => m.mode !== "translate" && m.mode !== "custom").map((m) => (
                    <DropdownMenuItem key={m.mode} className="text-xs" onClick={() => aiRun(m.mode)}>{m.label}</DropdownMenuItem>
                  ))}
                  <DropdownMenuSeparator />
                  {AI_MODES.filter((m) => m.mode === "translate" || m.mode === "custom").map((m) => (
                    <DropdownMenuItem key={m.mode} className="text-xs" onClick={() => aiRun(m.mode)}>{m.label}</DropdownMenuItem>
                  ))}
                  {aiUndo !== null && (
                    <>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem className="text-xs" onClick={aiRevert}><Undo2 className="h-3.5 w-3.5" /> Undo last rewrite</DropdownMenuItem>
                    </>
                  )}
                </DropdownMenuContent>
              </DropdownMenu>
              <Button className="shrink-0" disabled={busy || !text.trim()} onClick={send}><Send className="h-4 w-4" /> Send</Button>
            </div>
          )}
          {aiUndo !== null && !aiPreview && (
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
              <Sparkles className="h-3 w-3" /> Draft replaced by AI.
              <button onClick={aiRevert} className="inline-flex items-center gap-1 underline hover:text-foreground"><Undo2 className="h-3 w-3" /> Undo</button>
            </div>
          )}
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
      {tab === "template" && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Select value={tplKey} onValueChange={pickTemplate} disabled={templates.isLoading || tplList.length === 0}>
              <SelectTrigger size="sm" className="w-full min-w-0 flex-1 text-xs">
                <SelectValue placeholder={
                  templates.isLoading ? "Loading approved templates…"
                    : templates.isError ? "Failed to load templates"
                      : tplList.length === 0 ? "No approved templates" : "Pick a template…"
                } />
              </SelectTrigger>
              <SelectContent>
                {tplList.map((t) => (
                  <SelectItem key={`${t.name}::${t.language}`} value={`${t.name}::${t.language}`} className="text-xs">
                    <span className="mono">{t.name}</span>
                    <span className="text-muted-foreground"> · {t.language}</span>
                    {t.category && <span className="text-muted-foreground"> · {t.category.toLowerCase()}</span>}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button size="icon" variant="ghost" className="h-8 w-8" onClick={() => templates.refetch()} title="Reload templates">
              <RefreshCw className={cn("h-3.5 w-3.5", templates.isFetching && "animate-spin")} />
            </Button>
          </div>
          {templates.isError && (
            <div className="rounded-md bg-st-down/10 px-3 py-2 text-[12px] text-st-down">
              {templates.error instanceof Error ? templates.error.message : "Could not load templates"}
            </div>
          )}
          {tpl && (
            <>
              {tplBody && (
                <div className="whitespace-pre-wrap rounded-md bg-secondary px-3 py-2 text-[12.5px]">
                  {fillTemplateBody(tplBody, tplParams)}
                </div>
              )}
              {nParams > 0 && (
                <div className="grid grid-cols-2 gap-2">
                  {Array.from({ length: nParams }, (_, i) => (
                    <Input
                      key={i}
                      className="text-xs"
                      placeholder={`{{${i + 1}}}`}
                      value={tplParams[i] ?? ""}
                      onChange={(e) => setTplParams((p) => { const n = [...p]; n[i] = e.target.value; return n })}
                    />
                  ))}
                </div>
              )}
              <div className="flex items-center justify-between gap-2">
                <span className="text-[11px] text-muted-foreground">
                  Templates work outside the 24h customer-service window. Header/button parameters aren't supported here yet.
                </span>
                <Button size="sm" disabled={busy || !tplReady} onClick={send}><Send className="h-3.5 w-3.5" /> Send</Button>
              </div>
            </>
          )}
        </div>
      )}
      {tab === "interactive" && (
        <div className="space-y-2">
          <Textarea className="min-h-[56px] text-xs" placeholder="body text (required)" value={ibody} onChange={(e) => setIbody(e.target.value)} />
          <div className="grid grid-cols-3 gap-2">
            {ibtns.map((b, i) => (
              <Input
                key={i}
                className="text-xs"
                placeholder={`button ${i + 1}${i === 0 ? "" : " (optional)"}`}
                maxLength={20}
                value={b}
                onChange={(e) => setIbtns((p) => { const n = [...p]; n[i] = e.target.value; return n })}
              />
            ))}
          </div>
          <div className="flex items-center justify-between gap-2">
            <span className="text-[11px] text-muted-foreground">Up to 3 reply buttons, 20 chars each. Only inside the 24h window.</span>
            <Button size="sm" disabled={busy || !ibody.trim() || btnTitles.length === 0} onClick={send}><Send className="h-3.5 w-3.5" /> Send</Button>
          </div>
        </div>
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
