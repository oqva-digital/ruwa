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

export interface SessionMeta {
  id: string
  label: string | null
  status: SessionStatus
  jid: string | null
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
