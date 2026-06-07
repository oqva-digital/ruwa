#!/usr/bin/env node
/**
 * ruwa-mcp — an MCP server exposing ruwa (RUWA, Rust WhatsApp) as agent tools.
 * A thin wrapper over the /v1 HTTP API, so any MCP client (Claude Desktop/Code)
 * can drive WhatsApp end-to-end: create + pair instances, send every message
 * type, read chats/contacts, act human (typing, read receipts), wire webhooks.
 *
 * Config (env): RUWA_BASE_URL (default http://localhost:8080), RUWA_API_TOKEN.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js"
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js"
import { z } from "zod"
import { writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { search as ragSearch, ensureIndex as ragEnsureIndex } from "./rag.js"
import { deepBackfill } from "./backfill.js"

const BASE = (process.env.RUWA_BASE_URL || "http://localhost:8080").replace(/\/$/, "")
const TOKEN = process.env.RUWA_API_TOKEN || ""

async function call(method: string, path: string, body?: unknown): Promise<unknown> {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      authorization: `Bearer ${TOKEN}`,
      ...(body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${text.slice(0, 300)}`)
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function ok(data: unknown) {
  return { content: [{ type: "text" as const, text: typeof data === "string" ? data : JSON.stringify(data, null, 2) }] }
}
function err(e: unknown) {
  return { content: [{ type: "text" as const, text: `Error: ${e instanceof Error ? e.message : String(e)}` }], isError: true }
}
const enc = encodeURIComponent

const server = new McpServer({ name: "ruwa", version: "0.2.0" })

// ── Instance lifecycle ──────────────────────────────────────────────────────

server.tool(
  "create_session",
  "Create a new WhatsApp session (instance). Returns its id; then call get_qr to pair it by scanning the QR in WhatsApp → Linked devices.",
  {
    label: z.string().optional().describe("human-friendly label for the instance"),
    proxy: z.string().optional().describe("optional egress proxy URL (socks5/socks5h/http)"),
  },
  async ({ label, proxy }) => {
    try { return ok(await call("POST", "/v1/sessions", { label, proxy })) } catch (e) { return err(e) }
  },
)

server.tool(
  "get_qr",
  "Get the pairing QR for a session. Returns the QR payload string — render it as a QR code for the user to scan in WhatsApp → Linked devices → Link a device.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try {
      const r = (await call("GET", `/v1/sessions/${enc(session_id)}/qr`)) as { qr?: string }
      return ok({
        qr: r?.qr ?? r,
        note: "Render this string as a QR code; the user scans it once to pair. Then poll session_health until connected=true.",
      })
    } catch (e) { return err(e) }
  },
)

server.tool(
  "connect_session",
  "(Re)connect a paired session that is disconnected — kicks off the connect/handshake.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/connect`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "logout_session",
  "Log out / unlink a session from WhatsApp (the linked device is removed; re-pairing needs a new QR).",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/logout`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "delete_session",
  "Delete a session and all its local data. Destructive and irreversible — confirm with the user first.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("DELETE", `/v1/sessions/${enc(session_id)}`)) } catch (e) { return err(e) }
  },
)

// ── Reads / context ─────────────────────────────────────────────────────────

server.tool(
  "list_sessions",
  "List all WhatsApp sessions (instances) with status, label, and JID.",
  {},
  async () => { try { return ok(await call("GET", "/v1/sessions")) } catch (e) { return err(e) } },
)

server.tool(
  "session_health",
  "Liveness/health for one session: status, connected, last-rx age, reconnect count, prekeys.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("GET", `/v1/sessions/${enc(session_id)}/health`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "list_chats",
  "List the chats/conversations for a session.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("GET", `/v1/sessions/${enc(session_id)}/chats`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "list_messages",
  "List or full-text-search messages. With q: a ranked full-text search over message bodies (BM25 relevance order, case- and accent-insensitive; multiple words are ANDed). Without q: recent messages newest-first. Optionally scope to a chat JID; paginate with limit + before (a unix timestamp; only older messages are considered).",
  {
    session_id: z.string(),
    chat: z.string().optional().describe("chat JID to filter by"),
    q: z.string().optional().describe("full-text query; ranked by relevance, case/accent-insensitive, words ANDed"),
    limit: z.number().optional().describe("max messages (default 50, max 500)"),
    before: z.number().optional().describe("unix timestamp; only messages older than this are searched/listed"),
  },
  async ({ session_id, chat, q, limit, before }) => {
    try {
      const p = new URLSearchParams()
      if (chat) p.set("chat", chat)
      if (q) p.set("q", q)
      if (limit !== undefined) p.set("limit", String(limit))
      if (before !== undefined) p.set("before", String(before))
      const qs = p.toString() ? `?${p}` : ""
      return ok(await call("GET", `/v1/sessions/${enc(session_id)}/messages${qs}`))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "get_message_context",
  "Get the messages around a specific message in a chat (N before + the target + N after), chronologically — for reading the surrounding conversation.",
  {
    session_id: z.string(),
    chat: z.string().describe("chat JID the message is in"),
    msg_id: z.string(),
    before: z.number().optional().describe("messages before the target (default 5, max 50)"),
    after: z.number().optional().describe("messages after the target (default 5, max 50)"),
  },
  async ({ session_id, chat, msg_id, before, after }) => {
    try {
      const p = new URLSearchParams()
      if (before !== undefined) p.set("before", String(before))
      if (after !== undefined) p.set("after", String(after))
      const qs = p.toString() ? `?${p}` : ""
      return ok(await call(
        "GET",
        `/v1/sessions/${enc(session_id)}/messages/${enc(chat)}/${enc(msg_id)}/context${qs}`,
      ))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "search_conversations",
  "Semantic search over a session's WhatsApp messages by MEANING (not just keywords) — finds relevant messages even when they use different words than the query (paraphrase, synonyms, other languages). Use this to answer 'find the conversation about X' / 'what did we discuss regarding Y'. Returns the top matches with a relevance score; follow up with get_message_context on a hit to read the surrounding conversation, then summarize. Runs a LOCAL embedding model — nothing leaves the host. The FIRST call for a session downloads a small model (~120MB) and embeds the message history, so it can take a while; later calls are fast and only embed new messages. For exact word/phrase lookups, list_messages(q=) is cheaper.",
  {
    session_id: z.string(),
    query: z.string().describe("what to look for, in natural language"),
    limit: z.number().optional().describe("max matches to return (default 10, max 100)"),
    chat: z.string().optional().describe("restrict to a single chat JID"),
  },
  async ({ session_id, query, limit, chat }) => {
    try {
      const { stats, hits } = await ragSearch(call, session_id, query, { limit, chat })
      return ok({
        hits,
        indexed: stats.indexed,
        note: "Scores are cosine similarity (higher = closer). Call get_message_context(chat, msg_id) on a hit to read around it.",
      })
    } catch (e) { return err(e) }
  },
)

server.tool(
  "reindex_conversations",
  "Build or refresh the local semantic-search index for a session (embeds any messages not yet indexed). Optional warm-up — search_conversations does this automatically — but useful to pre-build the index after a history backfill. Runs a local model; nothing leaves the host.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await ragEnsureIndex(call, session_id)) } catch (e) { return err(e) }
  },
)

server.tool(
  "list_contacts",
  "List or search contacts. Pass q to filter by name or phone number (case-insensitive); omit for all.",
  {
    session_id: z.string(),
    q: z.string().optional().describe("filter contacts by name or number"),
  },
  async ({ session_id, q }) => {
    try {
      const qs = q ? `?q=${enc(q)}` : ""
      return ok(await call("GET", `/v1/sessions/${enc(session_id)}/contacts${qs}`))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "download_media",
  "Download the media attached to a message and save it to a local temp file; returns the file path (open it or pass it to another tool).",
  {
    session_id: z.string(),
    chat: z.string().describe("chat JID the message is in"),
    msg_id: z.string(),
  },
  async ({ session_id, chat, msg_id }) => {
    try {
      const url = `${BASE}/v1/sessions/${enc(session_id)}/messages/${enc(chat)}/${enc(msg_id)}/media`
      const res = await fetch(url, { headers: { authorization: `Bearer ${TOKEN}` } })
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`)
      const ctype = res.headers.get("content-type") || "application/octet-stream"
      const ext = ctype.split("/")[1]?.split(";")[0]?.replace(/[^a-z0-9]/gi, "") || "bin"
      const buf = Buffer.from(await res.arrayBuffer())
      const path = join(tmpdir(), `ruwa-${msg_id.replace(/[^A-Za-z0-9]/g, "")}.${ext}`)
      writeFileSync(path, buf)
      return ok({ path, content_type: ctype, bytes: buf.length })
    } catch (e) { return err(e) }
  },
)

server.tool(
  "list_groups",
  "List the groups a session is a member of.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("GET", `/v1/sessions/${enc(session_id)}/groups`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "on_whatsapp",
  "Check which phone numbers are registered on WhatsApp (a real round-trip).",
  { session_id: z.string(), numbers: z.array(z.string()).describe("phone numbers to check") },
  async ({ session_id, numbers }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/onwhatsapp`, { numbers })) } catch (e) { return err(e) }
  },
)

// ── Sending ─────────────────────────────────────────────────────────────────

server.tool(
  "send_text",
  "Send a WhatsApp text message. `to` is a bare phone (E.164, no +) or a full JID. Optionally @mention numbers or quote a message.",
  {
    session_id: z.string(),
    to: z.string().describe("recipient: bare phone (no +) or full JID"),
    text: z.string(),
    mentions: z.array(z.string()).optional().describe("JIDs to @mention (must also appear as @<number> in text)"),
    quoted_id: z.string().optional().describe("message id to quote/reply to"),
  },
  async ({ session_id, to, text, mentions, quoted_id }) => {
    try {
      const body: Record<string, unknown> = { to, text }
      if (mentions?.length) body.mentions = mentions
      if (quoted_id) body.quoted = { id: quoted_id }
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages`, body))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "send_media",
  "Send media (image/video/audio/ptt/document/sticker). `file_path` must be readable by the ruwa server.",
  {
    session_id: z.string(),
    to: z.string(),
    type: z.enum(["image", "video", "audio", "ptt", "voice", "document", "sticker"]),
    file_path: z.string().describe("server-readable path to the media file"),
    mime: z.string().describe("MIME type, e.g. image/jpeg"),
    caption: z.string().optional(),
    filename: z.string().optional().describe("display filename (documents)"),
  },
  async ({ session_id, to, type, file_path, mime, caption, filename }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/media`, { to, type, file_path, mime, caption, filename }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "send_location",
  "Send a location pin.",
  {
    session_id: z.string(),
    to: z.string(),
    latitude: z.number(),
    longitude: z.number(),
    name: z.string().optional(),
    address: z.string().optional(),
  },
  async ({ session_id, to, latitude, longitude, name, address }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/location`, { to, latitude, longitude, name, address }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "send_contact",
  "Send a contact card (vCard). Provide a phone (a card is generated) or a raw vcard.",
  {
    session_id: z.string(),
    to: z.string(),
    display_name: z.string(),
    phone: z.string().optional(),
    vcard: z.string().optional().describe("raw vCard text (overrides phone)"),
  },
  async ({ session_id, to, display_name, phone, vcard }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/contact`, { to, display_name, phone, vcard }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "send_poll",
  "Send a poll.",
  {
    session_id: z.string(),
    to: z.string(),
    name: z.string().describe("the poll question"),
    options: z.array(z.string()).describe("answer options"),
    selectable_count: z.number().optional().describe("how many options a voter may pick (default 1)"),
  },
  async ({ session_id, to, name, options, selectable_count }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/poll`, { to, name, options, selectable_count: selectable_count ?? 1 }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "send_reaction",
  "React to a message with an emoji (empty emoji removes the reaction).",
  {
    session_id: z.string(),
    to: z.string().describe("chat JID"),
    msg_id: z.string(),
    from_me: z.boolean().describe("true if the target message was sent by this session"),
    emoji: z.string().describe("the emoji, or empty string to remove"),
    participant: z.string().optional().describe("original sender JID (groups only)"),
  },
  async ({ session_id, to, msg_id, from_me, emoji, participant }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/react`, { to, msg_id, from_me, emoji, participant }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "edit_message",
  "Edit a previously-sent text message.",
  {
    session_id: z.string(),
    to: z.string().describe("chat JID"),
    msg_id: z.string(),
    from_me: z.boolean(),
    text: z.string().describe("the new message text"),
    participant: z.string().optional(),
  },
  async ({ session_id, to, msg_id, from_me, text, participant }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/edit`, { to, msg_id, from_me, text, participant }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "revoke_message",
  "Revoke (delete for everyone) a message.",
  {
    session_id: z.string(),
    to: z.string().describe("chat JID"),
    msg_id: z.string(),
    from_me: z.boolean(),
    participant: z.string().optional(),
  },
  async ({ session_id, to, msg_id, from_me, participant }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/revoke`, { to, msg_id, from_me, participant }))
    } catch (e) { return err(e) }
  },
)

// ── Human-like chat actions ─────────────────────────────────────────────────

server.tool(
  "mark_read",
  "Send read receipts (blue ticks) for one or more message ids in a chat.",
  {
    session_id: z.string(),
    chat: z.string().describe("chat JID"),
    ids: z.array(z.string()).describe("message ids to mark read"),
    participant: z.string().optional().describe("original sender JID (groups only)"),
  },
  async ({ session_id, chat, ids, participant }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/chats/${enc(chat)}/read`, { ids, participant }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "set_typing",
  "Show or clear the typing indicator in a chat ('composing' = typing, 'paused' = stopped).",
  {
    session_id: z.string(),
    chat: z.string().describe("chat JID"),
    state: z.enum(["composing", "paused"]),
  },
  async ({ session_id, chat, state }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/chats/${enc(chat)}/typing`, { state }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "set_presence",
  "Set this session's global presence ('available' = online, 'unavailable' = offline).",
  { session_id: z.string(), state: z.enum(["available", "unavailable"]) },
  async ({ session_id, state }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/presence`, { state })) } catch (e) { return err(e) }
  },
)

// ── Events ──────────────────────────────────────────────────────────────────

server.tool(
  "set_webhook",
  "Register (or update) a webhook so inbound messages and events are POSTed to a URL. Each delivery is HMAC-signed if a secret is set.",
  {
    session_id: z.string(),
    url: z.string().describe("the endpoint to receive event POSTs"),
    events: z.array(z.string()).optional().describe("event types to deliver, e.g. ['message','message_delivered','connected']; omit for all"),
    secret: z.string().optional().describe("HMAC-SHA256 secret for X-Ruwa-Signature"),
    enabled: z.boolean().optional().describe("default true"),
  },
  async ({ session_id, url, events, secret, enabled }) => {
    try {
      return ok(await call("PUT", `/v1/sessions/${enc(session_id)}/webhook`, { url, events, secret, enabled: enabled ?? true }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "get_session",
  "Get one session's details: status, JID, label, proxy, mark-online.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("GET", `/v1/sessions/${enc(session_id)}`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "backfill_history",
  "Pull older message history for a chat from WhatsApp (so list_messages/search can see further back).",
  {
    session_id: z.string(),
    chat: z.string().describe("chat JID to backfill"),
    count: z.number().optional().describe("how many older messages to request"),
  },
  async ({ session_id, chat, count }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/history/backfill`, { chat, count }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "sync_history",
  "Deep-backfill a chat: repeatedly pull older history until WhatsApp stops returning anything older (the start of the conversation) or the round budget is hit. Use this to load a chat's full history before searching/summarizing it. Needs a CONNECTED session and runs several seconds. Returns { rounds, added, reachedStart, ... }; if reachedStart is false, call again to go deeper. After it finishes, call reindex_conversations so semantic search sees the new messages.",
  {
    session_id: z.string(),
    chat: z.string().describe("chat JID to deep-backfill"),
    count: z.number().optional().describe("messages requested per round (default 50)"),
    max_rounds: z.number().optional().describe("max rounds this call (default 8, max 100); resumable"),
  },
  async ({ session_id, chat, count, max_rounds }) => {
    try {
      return ok(await deepBackfill(call, session_id, chat, { count, maxRounds: max_rounds }))
    } catch (e) { return err(e) }
  },
)

// ── Contacts & profile ──────────────────────────────────────────────────────

server.tool(
  "get_contact_picture",
  "Fetch a contact's (or group's) profile-picture URL. Returns { jid, url } (url null if none/hidden). Needs a live connection.",
  {
    session_id: z.string(),
    jid: z.string().describe("contact or group JID"),
    preview: z.boolean().optional().describe("true = small thumbnail instead of full image"),
  },
  async ({ session_id, jid, preview }) => {
    try {
      const qs = preview ? "?preview=true" : ""
      return ok(await call("GET", `/v1/sessions/${enc(session_id)}/contacts/${enc(jid)}/picture${qs}`))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "block_contact",
  "Block a contact.",
  { session_id: z.string(), jid: z.string() },
  async ({ session_id, jid }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/contacts/${enc(jid)}/block`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "unblock_contact",
  "Unblock a contact.",
  { session_id: z.string(), jid: z.string() },
  async ({ session_id, jid }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/contacts/${enc(jid)}/unblock`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "set_profile",
  "Update this account's own profile: display name, about/status text, and/or picture (base64 JPEG).",
  {
    session_id: z.string(),
    name: z.string().optional(),
    status: z.string().optional().describe("the about/status text"),
    picture: z.string().optional().describe("base64-encoded JPEG for the profile photo"),
  },
  async ({ session_id, name, status, picture }) => {
    try {
      return ok(await call("PUT", `/v1/sessions/${enc(session_id)}/profile`, { name, status, picture }))
    } catch (e) { return err(e) }
  },
)

// ── Multiple webhooks ───────────────────────────────────────────────────────

server.tool(
  "list_webhooks",
  "List all webhooks for a session (the primary plus any labelled ones).",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("GET", `/v1/sessions/${enc(session_id)}/webhooks`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "add_webhook",
  "Add an additional (labelled) webhook destination — a session can have many, each delivered independently. The primary is managed via set_webhook.",
  {
    session_id: z.string(),
    label: z.string().describe("unique label, 1–64 of [A-Za-z0-9_-]"),
    url: z.string(),
    events: z.array(z.string()).optional().describe("event-type allowlist; omit for all"),
    secret: z.string().optional().describe("HMAC-SHA256 signing secret"),
    enabled: z.boolean().optional(),
  },
  async ({ session_id, label, url, events, secret, enabled }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/webhooks`, { label, url, events, secret, enabled }))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "delete_webhook",
  "Remove one labelled webhook (use set_webhook to clear the primary).",
  { session_id: z.string(), label: z.string() },
  async ({ session_id, label }) => {
    try { return ok(await call("DELETE", `/v1/sessions/${enc(session_id)}/webhooks/${enc(label)}`)) } catch (e) { return err(e) }
  },
)

const transport = new StdioServerTransport()
await server.connect(transport)
console.error(`ruwa-mcp connected → ${BASE} (35 tools)`)
