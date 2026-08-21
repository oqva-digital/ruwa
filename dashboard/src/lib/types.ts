// Neutral types mirroring ruwa's /v1 JSON shapes.

export type SessionStatus =
  | "pending"
  | "connecting"
  | "awaiting_qr"
  | "syncing"
  | "connected"
  | "disconnected"
  | "proxy_error"
  | "logged_out"
  | "blocked"

/** Backend kind: `web` = WhatsApp Web multi-device socket (QR/phone pairing);
 *  `cloud` = Meta WhatsApp Cloud API (Graph credentials, inbound via webhook). */
export type SessionKind = "web" | "cloud"

/** Non-secret Cloud API metadata echoed on cloud sessions (never the token/secret). */
export interface CloudMeta {
  phone_number_id: string
  waba_id?: string | null
  graph_version?: string | null
  display_phone_number?: string | null
  verified_name?: string | null
}

/** Cloud credentials as sent on create / PUT /cloud. Every field optional on
 *  update (only provided ones replace); create requires phone_number_id and
 *  access_token (waba_id only for template management). */
export interface CloudCredsInput {
  phone_number_id?: string
  waba_id?: string
  access_token?: string
  app_secret?: string
  verify_token?: string
  graph_version?: string
}

export interface SessionMeta {
  id: string
  label: string | null
  status: SessionStatus
  jid: string | null
  /** Optional so older servers keep typechecking; absent ⇒ web. */
  kind?: SessionKind
  cloud?: CloudMeta | null
  /** WhatsApp account display name (push name). Read-only — owned by the phone,
   *  synced down to companions; ruwa can't change it. */
  push_name?: string | null
  proxy_url: string | null
  /** true → announce "available" (online); WhatsApp then silences the phone's
   *  notifications. false (default) → phone keeps notifying. */
  mark_online?: boolean
  created_at: number
  updated_at: number
}

export const isCloud = (s: Pick<SessionMeta, "kind"> | null | undefined): boolean => s?.kind === "cloud"

export interface SessionWithKey extends SessionMeta {
  /** Returned ONCE on create. */
  api_key?: string
}

export interface SessionHealth {
  id: string
  status: SessionStatus
  connected: boolean
  jid: string | null
  /** Unix seconds of the last inbound frame, or null. */
  last_rx: number | null
  /** Server-computed age of the last inbound frame, in seconds. */
  seconds_since_rx: number | null
  reconnect_count: number
  prekeys_available: number
  proxy_configured: boolean
}

/** The message a reply is quoting. Present only on reply messages. */
export interface QuotedRef {
  stanza_id: string | null
  participant: string | null
  text: string | null
}

export interface MessageRow {
  message_id: string
  chat_jid: string
  sender_jid: string
  from_me: boolean
  msg_type: string
  body_text: string | null
  /** True when the message was edited and the new text applied in place. */
  edited?: boolean
  /** True when the message was deleted for everyone. `body_text` is cleared with it. */
  revoked?: boolean
  quoted?: QuotedRef | null
  timestamp: number
  [k: string]: unknown
}

export interface ContactRow {
  jid: string
  full_name?: string | null
  push_name?: string | null
  [k: string]: unknown
}

export interface OnWhatsAppResult {
  query: string
  jid: string | null
  exists: boolean
}

export interface WebhookConfig {
  url: string
  enabled: boolean
  events: string[]
  has_secret?: boolean
}

/** One SSE event from GET /v1/sessions/:id/events. */
export interface SessionEvent {
  type: string
  [k: string]: unknown
}

/** One persisted event from GET /v1/sessions/:id/events/history (oldest-first).
 *  `id` is the durable row id (keyset cursor); `ts` is unix milliseconds. */
export interface EventHistoryRow {
  id: number
  ts: number
  ev: SessionEvent
}

/** One point of a persisted metric series (GET /v1/metrics/history). `ts` is
 *  unix SECONDS; `value` the reading at that second. */
export interface MetricPoint {
  ts: number
  value: number
}

/** One persisted server-process log line (GET /v1/logs). `ts` is unix ms. */
export interface ServerLogRow {
  id: number
  ts: number
  level: string
  target: string
  message: string
}

// ── Cloud API: templates + interactive (neutral shapes; no Graph types leak) ──

/** One component of a message template as returned by GET /templates
 *  (`type` HEADER|BODY|FOOTER|BUTTONS; BODY carries `text` with `{{n}}` slots). */
export interface TemplateComponent {
  type: string
  format?: string
  text?: string
  buttons?: { type: string; text?: string; url?: string; phone_number?: string; [k: string]: unknown }[]
  example?: unknown
  [k: string]: unknown
}

export interface TemplateRow {
  id: string
  name: string
  language: string
  status: string
  category: string
  components: TemplateComponent[]
}

export interface TemplatePage {
  templates: TemplateRow[]
  next: string | null
}

export interface TemplateHeaderParam {
  type: "text" | "image" | "video" | "document"
  text?: string
  link?: string
  media_id?: string
  filename?: string
}

export interface TemplateButtonParam {
  index: number
  sub_type: "quick_reply" | "url" | string
  payload?: string
  text?: string
}

/** Body of POST /messages/template (minus `to`). */
export interface TemplateSendBody {
  name: string
  language: string
  body_params?: string[]
  header?: TemplateHeaderParam
  buttons?: TemplateButtonParam[]
  /** Escape hatch: Cloud-native components used verbatim (body_params/header/buttons ignored). */
  components?: unknown[]
  reply_to?: string
}

export interface InteractiveButton {
  id: string
  title: string
}
export interface InteractiveSection {
  title?: string
  rows: { id: string; title: string; description?: string }[]
}

/** Body of POST /messages/interactive (minus `to`). */
export interface InteractiveSendBody {
  type: "button" | "list" | "cta_url"
  body: string
  header?: { type: "text"; text: string }
  footer?: string
  buttons?: InteractiveButton[]
  button?: string
  sections?: InteractiveSection[]
  cta?: { display_text: string; url: string }
  reply_to?: string
}

// ── AI text assistant (server-side, admin-only; key never returned) ──
export type AiProvider = "anthropic" | "openai"

/** GET/PUT /v1/settings/ai response. `api_key_hint` is the masked tail ("••••abcd"). */
export interface AiSettings {
  configured: boolean
  provider: AiProvider | null
  model: string | null
  base_url: string | null
  system_prompt: string | null
  api_key_hint: string | null
}

/** PUT /v1/settings/ai body. `api_key` omitted = keep the stored one. */
export interface AiSettingsInput {
  provider: AiProvider
  api_key?: string
  model?: string
  base_url?: string | null
  system_prompt?: string | null
}

export interface AiTestResult {
  ok: boolean
  provider: AiProvider
  model: string
  latency_ms: number
  reply: string
}

export type ImproveMode = "improve" | "formal" | "casual" | "shorter" | "grammar" | "translate" | "custom"

export interface ImproveTextInput {
  text: string
  mode?: ImproveMode
  /** Target language for `translate` (e.g. "en", "pt-BR"). */
  language?: string
  /** Required for `custom` (≤ 500 chars). */
  instruction?: string
}

export interface ImproveTextResult {
  text: string
  provider: AiProvider
  model: string
}

/** `type` field of the multipart media send; `ptt` = WhatsApp voice note. */
export type MediaSendType = "image" | "video" | "audio" | "ptt" | "voice" | "document" | "sticker"
