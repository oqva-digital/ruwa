// ruwa /v1 API client. Bearer-auth; base URL + token in localStorage (set in the
// Auth gate). SSE uses fetch-streaming (EventSource can't send an auth header).
import type {
  AiSettings,
  AiSettingsInput,
  AiTestResult,
  CallInfo,
  CloudCredsInput,
  ImproveTextInput,
  ImproveTextResult,
  MediaSendType,
  ContactRow,
  InteractiveSendBody,
  EventHistoryRow,
  MessageRow,
  MetricPoint,
  OnWhatsAppResult,
  ServerLogRow,
  SessionEvent,
  SessionHealth,
  SessionMeta,
  SessionKind,
  SessionWithKey,
  TemplatePage,
  TemplateSendBody,
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
  /** Create a session. `kind` defaults to `web` server-side; `cloud` sessions
   *  carry Meta Cloud API credentials and need no QR/pairing. */
  createSession: (opts: { label: string | null; proxy?: string | null; kind?: SessionKind; cloud?: CloudCredsInput }) =>
    req<SessionWithKey>("POST", "/v1/sessions", {
      label: opts.label,
      proxy: opts.proxy || null,
      ...(opts.kind ? { kind: opts.kind } : {}),
      ...(opts.cloud ? { cloud: opts.cloud } : {}),
    }),
  /** Replace Cloud API credentials/metadata (only provided fields change). 501 on web sessions. */
  updateCloud: (id: string, cloud: CloudCredsInput) =>
    req<SessionMeta>("PUT", `/v1/sessions/${id}/cloud`, cloud),
  /** Regenerate the Kapso onboarding setup link (kapso sessions still pending only). */
  regenKapsoSetupLink: (id: string) =>
    req<{ setup_link: string }>("POST", `/v1/sessions/${id}/cloud/setup-link`),
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
  /** Non-sensitive proxy breakdown (scheme/host/port/hints; never the password). */
  getProxy: (id: string) =>
    req<{ configured: boolean; proxy?: { scheme: string; host: string; port: number | null; has_auth: boolean; hints: Record<string, string>; masked: string } }>(
      "GET", `/v1/sessions/${id}/proxy`),
  /** Heartbeat the proxy: reachability, latency, and the exit IP WhatsApp sees. */
  checkProxy: (id: string) =>
    req<{ ok: boolean; via_proxy: boolean; status?: number; latency_ms: number; exit_ip?: string | null; error?: string }>(
      "POST", `/v1/sessions/${id}/proxy/check`),
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
  /**
   * Send a media file as multipart/form-data: field `file` (binary) + field
   * `metadata` (JSON string). `type: "ptt"` = WhatsApp voice note (must be
   * Ogg/Opus); `caption` only applies to image/video/document.
   */
  sendMediaMultipart: async (
    id: string,
    opts: { to: string; type: MediaSendType; file: Blob; filename: string; mime: string; caption?: string },
  ): Promise<{ id: string; timestamp?: number; status?: string }> => {
    const fd = new FormData()
    fd.append("file", opts.file, opts.filename)
    fd.append(
      "metadata",
      JSON.stringify({
        to: opts.to,
        type: opts.type,
        mime: opts.mime,
        filename: opts.filename,
        ...(opts.caption ? { caption: opts.caption } : {}),
      }),
    )
    // No content-type header: the browser sets multipart/form-data + boundary.
    const res = await fetch(`${getBase()}/v1/sessions/${id}/messages/media/multipart`, {
      method: "POST",
      headers: { authorization: `Bearer ${getToken()}` },
      body: fd,
    })
    const text = await res.text()
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
    return data as { id: string; timestamp?: number; status?: string }
  },
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
  sendPoll: (id: string, to: string, body: { name: string; options: string[]; selectable_count?: number; end_time?: number; quiz_answer?: string }) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages/poll`, { to, ...body }),
  sendEvent: (id: string, to: string, body: { name: string; description?: string; location?: string; start_time: number; end_time?: number }) =>
    req<{ id: string }>("POST", `/v1/sessions/${id}/messages/event`, { to, ...body }),

  // ── cloud-only sends (501 on web sessions) ──
  sendTemplate: (id: string, to: string, body: TemplateSendBody) =>
    req<{ id: string; timestamp?: number; status?: string }>("POST", `/v1/sessions/${id}/messages/template`, { to, ...body }),
  sendInteractive: (id: string, to: string, body: InteractiveSendBody) =>
    req<{ id: string; timestamp?: number; status?: string }>("POST", `/v1/sessions/${id}/messages/interactive`, { to, ...body }),
  /** Message templates of the session's WABA (proxied from Graph). */
  listTemplates: (id: string, opts?: { status?: string; limit?: number; after?: string }) => {
    const p = new URLSearchParams()
    if (opts?.status) p.set("status", opts.status)
    if (opts?.limit != null) p.set("limit", String(opts.limit))
    if (opts?.after) p.set("after", opts.after)
    const qs = p.toString()
    return req<TemplatePage>("GET", `/v1/sessions/${id}/templates${qs ? "?" + qs : ""}`)
  },

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

  // ── calls (web sessions only) ──
  listCalls: (id: string) => req<CallInfo[]>("GET", `/v1/sessions/${id}/calls`),
  rejectCall: (id: string, callId: string, peer: string) =>
    req<unknown>("POST", `/v1/sessions/${id}/calls/${encodeURIComponent(callId)}/reject`, { peer }),
  /** WS URL for the call audio bridge. Browsers can't set WS headers, so the
   * bearer rides as `?token=` (the endpoint accepts either). */
  callAudioUrl: (id: string, callId: string) =>
    `${getBase().replace(/^http/, "ws")}/v1/sessions/${id}/calls/${encodeURIComponent(callId)}/audio?token=${encodeURIComponent(getToken())}`,
  /** WS URL that PLACES an outbound call to `peer` and bridges its audio. The
   * `start` control frame arrives only once the peer answers. */
  dialAudioUrl: (id: string, peer: string) =>
    `${getBase().replace(/^http/, "ws")}/v1/sessions/${id}/calls/dial?peer=${encodeURIComponent(peer)}&token=${encodeURIComponent(getToken())}`,

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

  // ── AI text assistant (server-wide, admin token; key stored sealed server-side) ──
  getAiSettings: () => req<AiSettings>("GET", "/v1/settings/ai"),
  putAiSettings: (body: AiSettingsInput) => req<AiSettings>("PUT", "/v1/settings/ai", body),
  deleteAiSettings: () => req<void>("DELETE", "/v1/settings/ai"),
  /** Round-trips a tiny "Reply with OK" prompt through the configured provider. */
  testAiSettings: () => req<AiTestResult>("POST", "/v1/settings/ai/test"),
  /** Rewrite a draft. 400 when the assistant isn't configured, 422 if the model declines. */
  improveText: (body: ImproveTextInput) => req<ImproveTextResult>("POST", "/v1/ai/improve-text", body),
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
