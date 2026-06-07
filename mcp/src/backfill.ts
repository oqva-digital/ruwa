/**
 * backfill.ts — "pull all history" for a chat, driven entirely from the MCP
 * sidecar over the existing /v1 endpoints (no core change).
 *
 * The core's POST /history/backfill anchors on the chat's CURRENT oldest stored
 * message and asks the phone for `count` messages immediately before it; the
 * results arrive asynchronously over the live socket and land in the store. So a
 * deep backfill is just: request older → wait for older messages to appear →
 * repeat, until the phone stops delivering anything older (we've reached the
 * start of the conversation) or a round budget is hit.
 *
 * It is best-effort and live-dependent: it needs a connected session, and a
 * round that times out waiting is treated as "no more history". Each call is
 * bounded; if `reachedStart` is false the agent can call again to go deeper
 * (the core re-anchors on the new oldest each time).
 */
export type Call = (method: string, path: string, body?: unknown) => Promise<unknown>

type MsgRow = { message_id: string; timestamp: number; body_text: string | null }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))
const enc = encodeURIComponent

/** The oldest stored message timestamp for a chat, or null if the chat is empty.
 *  Pages newest-first to the end. */
export async function findOldestTimestamp(call: Call, sessionId: string, chat: string): Promise<number | null> {
  let before = Number.MAX_SAFE_INTEGER
  let oldest: number | null = null
  for (let guard = 0; guard < 400; guard++) {
    const page = (await call(
      "GET",
      `/v1/sessions/${enc(sessionId)}/messages?chat=${enc(chat)}&limit=500&before=${before}`,
    )) as MsgRow[]
    if (!Array.isArray(page) || page.length === 0) break
    oldest = page[page.length - 1].timestamp
    if (page.length < 500) break
    before = oldest
  }
  return oldest
}

export type DeepBackfillOpts = {
  count?: number // messages to request per round (default 50)
  maxRounds?: number // hard cap on rounds this call (default 8)
  probeDelayMs?: number // wait between arrival probes (default 1500)
  perRoundProbes?: number // probes before a round is declared stale (default 6)
}

export type DeepBackfillResult = {
  rounds: number
  added: number
  oldestTimestampStart: number
  oldestTimestampNow: number
  reachedStart: boolean // phone stopped returning older messages
}

/** Loop backfill until the phone stops delivering older messages (or budget). */
export async function deepBackfill(
  call: Call,
  sessionId: string,
  chat: string,
  opts: DeepBackfillOpts = {},
): Promise<DeepBackfillResult> {
  const count = opts.count ?? 50
  const maxRounds = Math.min(Math.max(opts.maxRounds ?? 8, 1), 100)
  const probeDelayMs = opts.probeDelayMs ?? 1500
  const perRoundProbes = opts.perRoundProbes ?? 6

  const start = await findOldestTimestamp(call, sessionId, chat)
  if (start === null) {
    throw new Error(`no stored messages for chat ${chat} to anchor a history pull — open/receive the chat first`)
  }
  let oldest = start
  let rounds = 0
  let added = 0
  let stale = 0

  while (rounds < maxRounds) {
    rounds++
    await call("POST", `/v1/sessions/${enc(sessionId)}/history/backfill`, { chat, count })

    // Poll for messages older than the current oldest to show up.
    let got: MsgRow[] | null = null
    for (let p = 0; p < perRoundProbes; p++) {
      await sleep(probeDelayMs)
      const older = (await call(
        "GET",
        `/v1/sessions/${enc(sessionId)}/messages?chat=${enc(chat)}&limit=${count + 20}&before=${oldest}`,
      )) as MsgRow[]
      if (Array.isArray(older) && older.length > 0) {
        got = older
        break
      }
    }

    if (!got) {
      // One grace round in case of socket lag before concluding we're done.
      stale++
      if (stale >= 2) break
      continue
    }
    stale = 0
    const minTs = Math.min(...got.map((m) => m.timestamp))
    added += got.length
    if (minTs >= oldest) break // safety: didn't actually advance
    oldest = minTs
  }

  return {
    rounds,
    added,
    oldestTimestampStart: start,
    oldestTimestampNow: oldest,
    reachedStart: stale >= 2,
  }
}
