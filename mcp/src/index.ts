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

const cloudCredsShape = {
  phone_number_id: z.string().optional().describe("Meta phone number id (e.g. 106540352242922) — required for kind=cloud"),
  waba_id: z.string().optional().describe("WhatsApp Business Account id — required to list/create templates"),
  access_token: z.string().optional().describe("Graph API access token (System User token recommended) — required for kind=cloud"),
  app_secret: z.string().optional().describe("Meta app secret, used to verify inbound webhook signatures (strongly recommended)"),
  verify_token: z.string().optional().describe("token Meta sends on webhook subscription verification (GET /v1/cloud/webhook)"),
  graph_version: z.string().optional().describe("Graph API version, default v25.0"),
}

// Kapso-provider create fields (used instead of the Meta credentials above when
// provider='kapso'): the customer connects their own number via a hosted link.
const kapsoCreateShape = {
  connection_type: z.enum(["dedicated", "coexistence"]).optional().describe("kapso: 'dedicated' (number used only for the API) or 'coexistence' (keep using the number in the WhatsApp app). Default 'dedicated'."),
  country_isos: z.array(z.string()).optional().describe("kapso: ISO-3166 alpha-2 country codes to offer in embedded-signup, e.g. [\"BR\",\"US\"]"),
  language: z.string().optional().describe("kapso: setup-flow UI language — one of en/es/pt/hi/id/ar"),
  provision_phone_number: z.boolean().optional().describe("kapso: let Kapso provision a phone number for the customer (default true)"),
  success_redirect_url: z.string().optional().describe("kapso: where to send the customer after a successful connect"),
  failure_redirect_url: z.string().optional().describe("kapso: where to send the customer after a failed connect"),
}

server.tool(
  "create_session",
  "Create a new WhatsApp session (instance). Returns its id. kind='web' (default): a WhatsApp Web linked device — pair it with get_qr (scan a QR) or pair_phone (enter an 8-char code) in WhatsApp → Linked devices. kind='cloud': an official WhatsApp Business Platform number, selected by `provider`:\n • provider='meta' (default): paste the Meta Cloud API credentials in `cloud` (phone_number_id + access_token required, waba_id needed for templates), then call connect_session to validate them. Point the Meta webhook at <ruwa origin>/v1/cloud/webhook.\n • provider='kapso': ruwa acts as a BSP on the Kapso Business Platform — no Meta credentials. Pass the optional kapso fields (connection_type, country_isos, language, provision_phone_number, success_redirect_url, failure_redirect_url); the response carries cloud.setup_link. Send that link to the customer to complete Meta embedded-signup; a Kapso project-webhook then flips the session from 'pending_onboarding' to 'connected'. Use kapso_setup_link to regenerate the link while still pending.\nCloud sessions can only initiate conversations with approved templates (send_template); free-form sends work only inside the 24h customer-service window after the contact last wrote.",
  {
    label: z.string().optional().describe("human-friendly label for the instance"),
    proxy: z.string().optional().describe("optional egress proxy URL (socks5/socks5h/http)"),
    kind: z.enum(["web", "cloud"]).optional().describe("session backend: 'web' (linked device, default) or 'cloud' (official Cloud API)"),
    provider: z.enum(["meta", "kapso"]).optional().describe("cloud backend: 'meta' (default — direct Meta credentials) or 'kapso' (Kapso Business Platform, hosted setup link)"),
    cloud: z.object(cloudCredsShape).optional().describe("Meta Cloud API credentials — used when kind='cloud' and provider!='kapso'"),
    ...kapsoCreateShape,
  },
  async ({ label, proxy, kind, provider, cloud, ...kapso }) => {
    try {
      const body: Record<string, unknown> = { label, proxy }
      if (kind) body.kind = kind
      if (provider === "kapso") {
        body.kind = "cloud"
        const c: Record<string, unknown> = { provider: "kapso" }
        for (const [k, v] of Object.entries(kapso)) if (v !== undefined) c[k] = v
        body.cloud = c
      } else if (cloud) {
        body.cloud = cloud
      }
      const res = (await call("POST", "/v1/sessions", body)) as { cloud?: { provider?: string; setup_link?: string } }
      if (res?.cloud?.provider === "kapso" && res.cloud.setup_link) {
        return {
          content: [{
            type: "text" as const,
            text: `Send this setup link to the customer: ${res.cloud.setup_link}\n\n${JSON.stringify(res, null, 2)}`,
          }],
        }
      }
      return ok(res)
    } catch (e) { return err(e) }
  },
)

server.tool(
  "kapso_setup_link",
  "Regenerate the Kapso onboarding setup link for a cloud session that is still 'pending_onboarding' (provider='kapso' only). Returns the new setup_link to hand to the customer. 409 once the session is connected; 501 for a Meta-provider or web session.",
  { session: z.string().describe("session id") },
  async ({ session }) => {
    try {
      const r = (await call("POST", `/v1/sessions/${enc(session)}/cloud/setup-link`)) as { setup_link?: string }
      return ok(r?.setup_link ? { setup_link: r.setup_link, note: `Send this link to the customer: ${r.setup_link}` } : r)
    } catch (e) { return err(e) }
  },
)

server.tool(
  "update_cloud_creds",
  "Update the Meta Cloud API credentials of a cloud session (kind='cloud' only; 501 on web sessions). Only the fields you pass are replaced (e.g. rotate access_token). Call reconnect_session afterwards to re-validate the new credentials against Graph (connect_session is a no-op on an already-connected session). Changing phone_number_id needs the master API token and fails with 409 if another session already owns that number.",
  { session_id: z.string(), ...cloudCredsShape },
  async ({ session_id, ...cloud }) => {
    try {
      const body: Record<string, unknown> = {}
      for (const [k, v] of Object.entries(cloud)) if (v !== undefined) body[k] = v
      return ok(await call("PUT", `/v1/sessions/${enc(session_id)}/cloud`, body))
    } catch (e) { return err(e) }
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
  "pair_phone",
  "Pair a session by phone number ('Link with phone number') instead of scanning a QR. Returns an 8-char code (XXXX-XXXX) the user types in WhatsApp → Linked devices → Link a device → 'Link with phone number instead'. The session must be connected first (call connect_session, then wait ~2s). The code is valid for a couple of minutes; then poll session_health until connected=true.",
  {
    session_id: z.string(),
    phone: z.string().describe("international phone number, digits only (e.g. 15551234567) — no leading 0"),
    client_display_name: z.string().optional().describe("display name shown on the phone, formatted 'Browser (OS)'; defaults to 'Chrome (Linux)'"),
  },
  async ({ session_id, phone, client_display_name }) => {
    try {
      const r = (await call("POST", `/v1/sessions/${enc(session_id)}/pair-phone`, { phone, client_display_name })) as { code?: string }
      return ok({
        code: r?.code ?? r,
        note: "Give this code to the user to enter in WhatsApp → Linked devices → Link a device → 'Link with phone number instead'. Then poll session_health until connected=true.",
      })
    } catch (e) { return err(e) }
  },
)

server.tool(
  "connect_session",
  "(Re)connect a session that is disconnected — web: kicks off the connect/handshake of a paired device; cloud: validates the Cloud API credentials against Graph and marks the session connected.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/connect`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "reconnect_session",
  "Force a fresh (re)connect even when the session is already connected — web: bounces the live socket and re-logs-in (\"rekey\", heals stuck sessions); cloud: re-validates the Cloud API credentials against Graph (use after update_cloud_creds; connect_session would be a no-op while connected).",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/reconnect`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "rename_session",
  "Rename an instance — sets its ruwa-side display label. This is purely an organizational name; it has no effect on the WhatsApp account/profile name (that's controlled by the phone). Pass an empty label to clear it.",
  {
    session_id: z.string(),
    label: z.string().describe("new label for the instance (empty string clears it)"),
  },
  async ({ session_id, label }) => {
    try { return ok(await call("POST", `/v1/sessions/${enc(session_id)}/label`, { label: label || null })) } catch (e) { return err(e) }
  },
)

server.tool(
  "logout_session",
  "Log out / unlink a session from WhatsApp (web: the linked device is removed; re-pairing needs a new QR. cloud: marks the session logged out, credentials are kept — connect_session re-validates).",
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
  "list_calls",
  "List the WhatsApp voice calls currently ringing on a session (call_id, from, is_video, audio_rates); empty when none. Web sessions only. Note: answering/placing a call streams live 16 kHz PCM audio over a WebSocket (…/calls/:id/audio and …/calls/dial) — that runs outside MCP; this tool is the control plane (see who's calling, then reject or answer via the WS). See docs/CALLS.md.",
  { session_id: z.string() },
  async ({ session_id }) => {
    try { return ok(await call("GET", `/v1/sessions/${enc(session_id)}/calls`)) } catch (e) { return err(e) }
  },
)

server.tool(
  "reject_call",
  "Decline a ringing WhatsApp voice call. call_id comes from a call_offer event or list_calls; peer is the caller's JID (or bare digits). Web sessions only.",
  {
    session_id: z.string(),
    call_id: z.string(),
    peer: z.string().describe("caller JID or bare phone digits (from the call_offer event)"),
  },
  async ({ session_id, call_id, peer }) => {
    try {
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/calls/${enc(call_id)}/reject`, { peer }))
    } catch (e) { return err(e) }
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
  "list_templates",
  "List the message templates of a cloud session's WhatsApp Business Account (kind='cloud' only; needs waba_id; 501 on web sessions). Returns {templates:[{id,name,language,status,category,components}], next}. Only APPROVED templates can be sent with send_template — templates are the only way to start a conversation outside the 24h customer-service window.",
  {
    session_id: z.string(),
    status: z.string().optional().describe("filter by status, e.g. APPROVED | PENDING | REJECTED"),
    limit: z.number().optional().describe("page size (default 50)"),
    after: z.string().optional().describe("pagination cursor from a previous result's `next`"),
  },
  async ({ session_id, status, limit, after }) => {
    try {
      const q = new URLSearchParams()
      if (status) q.set("status", status)
      if (limit !== undefined) q.set("limit", String(limit))
      if (after) q.set("after", after)
      const qs = q.toString()
      return ok(await call("GET", `/v1/sessions/${enc(session_id)}/templates${qs ? `?${qs}` : ""}`))
    } catch (e) { return err(e) }
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
  "send_template",
  "Send an approved message template (Meta Cloud API, kind='cloud' only; 501 on web sessions). Templates are REQUIRED to initiate a conversation: Cloud API only allows free-form messages (send_text/send_media/…) within 24h of the contact's last inbound message; outside that window Graph rejects them (error 131047) and you must send a template. Discover names/languages/components with list_templates. Pass body_params for positional {{1}},{{2}} body variables; header for a text/media header; buttons for quick_reply/url button parameters — or pass `components` (Cloud-native array) verbatim to override all of those.",
  {
    session_id: z.string(),
    to: z.string().describe("recipient phone number in international format, digits only (e.g. 5511999999999) or JID"),
    name: z.string().describe("template name, e.g. order_update"),
    language: z.string().describe("template language code, e.g. pt_BR, en_US"),
    body_params: z.array(z.string()).optional().describe("positional text params for the body {{1}}, {{2}}, …"),
    header: z.object({
      type: z.enum(["text", "image", "video", "document"]),
      text: z.string().optional().describe("header text param (type=text)"),
      link: z.string().optional().describe("public media URL (type=image|video|document)"),
      media_id: z.string().optional().describe("previously uploaded Cloud media id (alternative to link)"),
      filename: z.string().optional().describe("document filename (type=document)"),
    }).optional().describe("header parameter"),
    buttons: z.array(z.object({
      index: z.number().describe("button position, 0-based"),
      sub_type: z.enum(["quick_reply", "url", "copy_code"]),
      payload: z.string().optional().describe("quick_reply payload echoed back when tapped"),
      text: z.string().optional().describe("url suffix / coupon code param"),
    })).optional().describe("button parameters"),
    components: z.array(z.any()).optional().describe("escape hatch: Cloud API `components` array used verbatim (body_params/header/buttons ignored)"),
    reply_to: z.string().optional().describe("wamid of the message to quote"),
  },
  async ({ session_id, to, name, language, body_params, header, buttons, components, reply_to }) => {
    try {
      const body: Record<string, unknown> = { to, name, language }
      if (body_params) body.body_params = body_params
      if (header) body.header = header
      if (buttons) body.buttons = buttons
      if (components) body.components = components
      if (reply_to) body.reply_to = reply_to
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/template`, body))
    } catch (e) { return err(e) }
  },
)

server.tool(
  "send_interactive",
  "Send an interactive message (Meta Cloud API, kind='cloud' only; 501 on web sessions): reply buttons (type=button, ≤3 buttons), a list menu (type=list, button label + sections/rows), or a call-to-action URL (type=cta_url). Free-form, so only allowed inside the 24h customer-service window (otherwise use send_template). The contact's tap comes back as an inbound 'interactive' message with the chosen id/title.",
  {
    session_id: z.string(),
    to: z.string().describe("recipient phone number, digits only, or JID"),
    type: z.enum(["button", "list", "cta_url"]),
    body: z.string().describe("main text"),
    header: z.object({ type: z.literal("text"), text: z.string() }).optional().describe("optional text header"),
    footer: z.string().optional(),
    buttons: z.array(z.object({ id: z.string(), title: z.string().describe("≤20 chars") })).optional().describe("type=button: up to 3 reply buttons"),
    button: z.string().optional().describe("type=list: label of the button that opens the list"),
    sections: z.array(z.object({
      title: z.string().optional(),
      rows: z.array(z.object({ id: z.string(), title: z.string(), description: z.string().optional() })),
    })).optional().describe("type=list: sections with rows (≤10 rows total)"),
    cta: z.object({ display_text: z.string(), url: z.string() }).optional().describe("type=cta_url: the button"),
    reply_to: z.string().optional().describe("wamid of the message to quote"),
  },
  async ({ session_id, to, type, body, header, footer, buttons, button, sections, cta, reply_to }) => {
    try {
      const payload: Record<string, unknown> = { to, type, body }
      if (header) payload.header = header
      if (footer !== undefined) payload.footer = footer
      if (buttons) payload.buttons = buttons
      if (button !== undefined) payload.button = button
      if (sections) payload.sections = sections
      if (cta) payload.cta = cta
      if (reply_to) payload.reply_to = reply_to
      return ok(await call("POST", `/v1/sessions/${enc(session_id)}/messages/interactive`, payload))
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
console.error(`ruwa-mcp connected → ${BASE} (45 tools)`)
