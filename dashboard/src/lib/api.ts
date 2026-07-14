// ruwa /v1 API client. Bearer-auth; base URL + token in localStorage (set in the
// Auth gate). SSE uses fetch-streaming (EventSource can't send an auth header).
import type {
  ContactRow,
  EventHistoryRow,
  MessageRow,
  MetricPoint,
  OnWhatsAppResult,
  ServerLogRow,
  SessionEvent,
  SessionHealth,
  SessionMeta,
  SessionWithKey,
  WebhookConfig,
} from "./types"

const LS_BASE = "ruwa_base"
const LS_TOKEN = "ruwa_token"

export function getBase(): string {
  return (localStorage.getItem(LS_BASE) || "").replace(/\/$/, "")
}
export function getToken(): string {
  return localStorage.getItem(LS_TOKEN) || ""
}
export function setAuth(base: string, token: string) {
  localStorage.setItem(LS_BASE, base.trim().replace(/\/$/, ""))
  localStorage.setItem(LS_TOKEN, token.trim())
}
export function clearAuth() {
  localStorage.removeItem(LS_TOKEN)
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function req<T>(
  method: string,
  path: string,
  body?: unknown,
  opts: { raw?: boolean } = {},
): Promise<T> {
  const headers: Record<string, string> = { authorization: `Bearer ${getToken()}` }
  if (body !== undefined) headers["content-type"] = "application/json"
  const res = await fetch(getBase() + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const text = await res.text()
  if (opts.raw) {
    if (!res.ok) throw new ApiError(res.status, text || `HTTP ${res.status}`)
    return text as unknown as T
  }
  let data: unknown
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = text
  }
  if (!res.ok) {
    const msg =
      (data && typeof data === "object" && "error" in data
        ? String((data as { error: unknown }).error)
        : null) || `HTTP ${res.status}`
    throw new ApiError(res.status, msg)
  }
  return data as T
}

export interface HealthResp {
  status: string
  version: string
}

/** Server-wide config (non-secret) from GET /v1/config. */
export interface ServerConfig {
  version: string
  media: {
    mode: "db" | "s3"
    endpoint?: string
    bucket?: string
    region?: string
    public_base_url?: string | null
  }
}

export const api = {
  // ── global ──
  health: () => req<HealthResp>("GET", "/health"),
  config: () => req<ServerConfig>("GET", "/v1/config"),
  metricsText: () => req<string>("GET", "/metrics", undefined, { raw: true }),

  // ── persisted observability (survive restarts; in-house, no Grafana) ──
  metricsSeries: () => req<string[]>("GET", "/v1/metrics/series"),
  metricsHistory: (name: string, since?: number, limit?: number) => {
    const p = new URLSearchParams({ name })
    if (since != null) p.set("since", String(since))
    if (limit != null) p.set("limit", String(limit))
    return req<{ name: string; points: MetricPoint[] }>("GET", `/v1/metrics/history?${p}`)
  },
  serverLogs: (opts?: { level?: string; before?: number; limit?: number }) => {
    const p = new URLSearchParams()
    if (opts?.level) p.set("level", opts.level)
    if (opts?.before != null) p.set("before", String(opts.before))
    if (opts?.limit != null) p.set("limit", String(opts.limit))
    const qs = p.toString()
    return req<{ logs: ServerLogRow[] }>("GET", `/v1/logs${qs ? "?" + qs : ""}`)
  },

  // ── sessions / instances ──
  listSessions: () => req<SessionMeta[]>("GET", "/v1/sessions"),
  getSession: (id: string) => req<SessionMeta>("GET", `/v1/sessions/${id}`),
  /** Persist the session's online-presence preference. true = appear online
   *  (silences the phone's notifications); false = phone keeps notifying. */
  setMarkOnline: (id: string, mark_online: boolean) =>
    req<SessionMeta>("POST", `/v1/sessions/${id}/mark-online`, { mark_online }),
  createSession: (label: string | null, proxy?: string | null) =>
    req<SessionWithKey>("POST", "/v1/sessions", { label, proxy: proxy || null }),
  deleteSession: (id: string) =>
    req<void>("DELETE", `/v1/sessions/${id}?force=1`),
  /** Migrate a paired Baileys/Evolution session (no QR) from its `creds` blob. */
  importSession: (label: string | null, creds: unknown) =>
    req<SessionWithKey>("POST", "/v1/sessions/import", { label, creds }),
  sessionHealth: (id: string) =>
    req<SessionHealth>("GET", `/v1/sessions/${id}/health`),
  connect: (id: string) => req<unknown>("POST", `/v1/sessions/${id}/connect`),
  // Force a real reconnect ("rekey"): bounces the live socket and re-logs-in
  // without re-pairing. Unlike `connect` (a no-op when already connected), this
  // always bounces — used to heal sessions stuck on undecryptable inbound.
  reconnect: (id: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/reconnect`),
  logout: (id: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/logout`, { confirm: true }),
  setProxy: (id: string, proxy: string | null) =>
    req<unknown>("POST", `/v1/sessions/${id}/proxy`, { proxy }),
  /** Rename an instance (ruwa-side label only; no WhatsApp effect). Blank clears it. */
  setLabel: (id: string, label: string | null) =>
    req<SessionMeta>("POST", `/v1/sessions/${id}/label`, { label }),
  getQr: (id: string) =>
    req<{ qr: string; svg_base64: string }>("GET", `/v1/sessions/${id}/qr`),
  /** Request an 8-char phone-number pairing code ("Link with phone number"),
   *  the alternative to scanning a QR. Session must be connected first. */
  pairPhone: (id: string, phone: string, clientDisplayName?: string) =>
    req<{ code: string }>("POST", `/v1/sessions/${id}/pair-phone`, {
      phone,
      client_display_name: clientDisplayName || null,
    }),
  /** Persisted event history (durable backing for the live SSE feed), oldest-first. */
  eventHistory: (id: string, opts?: { before?: number; limit?: number; type?: string }) => {
    const p = new URLSearchParams()
    if (opts?.before != null) p.set("before", String(opts.before))
    if (opts?.limit != null) p.set("limit", String(opts.limit))
    if (opts?.type) p.set("type", opts.type)
    const qs = p.toString()
    return req<EventHistoryRow[]>("GET", `/v1/sessions/${id}/events/history${qs ? `?${qs}` : ""}`)
  },

  // ── messaging ──
  listMessages: (id: string, chat?: string) =>
    req<MessageRow[]>(
      "GET",
      `/v1/sessions/${id}/messages${chat ? `?chat=${encodeURIComponent(chat)}` : ""}`,
    ),
  /**
   * Fetch a message's media (the server downloads + decrypts on demand) as an
   * object URL. We must fetch via JS — the endpoint is bearer-authed, so an
   * `<img src>` can't reach it. Caller is responsible for URL.revokeObjectURL.
   */
  mediaBlobUrl: async (id: string, chat: string, msgid: string): Promise<string> => {
    const res = await fetch(
      `${getBase()}/v1/sessions/${id}/messages/${encodeURIComponent(chat)}/${encodeURIComponent(msgid)}/media`,
      { headers: { authorization: `Bearer ${getToken()}` } },
    )
    if (!res.ok) throw new ApiError(res.status, (await res.text()) || `HTTP ${res.status}`)
    return URL.createObjectURL(await res.blob())
  },
  sendText: (id: string, to: string, text: string) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages`, { to, text }),
  react: (id: string, to: string, msg_id: string, from_me: boolean, emoji: string, participant?: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/messages/react`, { to, msg_id, from_me, emoji, participant }),
  revoke: (id: string, to: string, msg_id: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/messages/revoke`, { to, msg_id, from_me: true }),
  edit: (id: string, to: string, msg_id: string, text: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/messages/edit`, { to, msg_id, text, from_me: true }),
  sendLocation: (id: string, to: string, body: { latitude: number; longitude: number; name?: string; address?: string }) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages/location`, { to, ...body }),
  sendContact: (id: string, to: string, body: { display_name: string; phone?: string; vcard?: string }) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages/contact`, { to, ...body }),
  sendPoll: (id: string, to: string, body: { name: string; options: string[]; selectable_count?: number }) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages/poll`, { to, ...body }),
  sendEvent: (id: string, to: string, body: { name: string; description?: string; location?: string; start_time: number; end_time?: number }) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages/event`, { to, ...body }),

  // ── directory ──
  contacts: (id: string) => req<ContactRow[]>("GET", `/v1/sessions/${id}/contacts`),
  chats: (id: string) => req<Record<string, unknown>[]>("GET", `/v1/sessions/${id}/chats`),
  groups: (id: string) => req<Record<string, unknown>[]>("GET", `/v1/sessions/${id}/groups`),
  onWhatsApp: (id: string, numbers: string[]) =>
    req<OnWhatsAppResult[]>("POST", `/v1/sessions/${id}/onwhatsapp`, { numbers }),
  blockContact: (id: string, jid: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/contacts/${encodeURIComponent(jid)}/block`),
  unblockContact: (id: string, jid: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/contacts/${encodeURIComponent(jid)}/unblock`),

  // ── profile ──
  setProfile: (id: string, body: { name?: string; status?: string; picture?: string }) =>
    req<{ applied: string[] }>("PUT", `/v1/sessions/${id}/profile`, body),

  // ── webhooks / egress ──
  getWebhook: (id: string) => req<WebhookConfig>("GET", `/v1/sessions/${id}/webhook`),
  setWebhook: (id: string, body: { url: string; enabled: boolean; events: string[]; secret?: string }) =>
    req<WebhookConfig>("PUT", `/v1/sessions/${id}/webhook`, body),
  deleteWebhook: (id: string) => req<void>("DELETE", `/v1/sessions/${id}/webhook`),

  getRedis: (id: string) =>
    req<{ url: string; mode: string; key: string; enabled: boolean; events?: string[] }>(
      "GET", `/v1/sessions/${id}/egress/redis`,
    ),
  setRedis: (id: string, body: { url: string; mode: string; key: string; enabled: boolean; events: string[] }) =>
    req<unknown>("PUT", `/v1/sessions/${id}/egress/redis`, body),
  deleteRedis: (id: string) => req<void>("DELETE", `/v1/sessions/${id}/egress/redis`),
}

/**
 * Subscribe to a session's SSE event stream. Returns an abort fn.
 * Uses fetch-streaming so we can send the bearer header.
 */
export function streamEvents(
  id: string,
  onEvent: (ev: SessionEvent) => void,
  onError?: (e: unknown) => void,
  onOpen?: () => void,
): () => void {
  const ctrl = new AbortController()
  ;(async () => {
    try {
      const res = await fetch(getBase() + `/v1/sessions/${id}/events`, {
        headers: { authorization: `Bearer ${getToken()}` },
        signal: ctrl.signal,
      })
      // A non-2xx response (e.g. 401 bad token, 404 unknown session) still has a
      // body, so without this guard we'd silently read an error page as if it
      // were an empty event stream — the page would look idle, not broken.
      if (!res.ok) throw new Error(`stream ${res.status} ${res.statusText}`.trim())
      if (!res.body) throw new Error("no stream body")
      onOpen?.()
      const reader = res.body.getReader()
      const dec = new TextDecoder()
      let buf = ""
      for (;;) {
        const { value, done } = await reader.read()
        if (done) break
        buf += dec.decode(value, { stream: true })
        let i: number
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const block = buf.slice(0, i)
          buf = buf.slice(i + 2)
          const line = block.split("\n").find((l) => l.startsWith("data:"))
          if (line) {
            try {
              onEvent(JSON.parse(line.slice(5).trim()))
            } catch {
              /* ignore malformed frame */
            }
          }
        }
      }
    } catch (e) {
      if (!ctrl.signal.aborted) onError?.(e)
    }
  })()
  return () => ctrl.abort()
}
