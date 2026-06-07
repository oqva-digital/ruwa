/**
 * rag.ts — local, in-house semantic search over a session's WhatsApp messages.
 *
 * Design (deliberately dependency-light, privacy-preserving):
 *   - Embeddings are computed by a *local* model via the OPTIONAL
 *     `@huggingface/transformers` package (ONNX, runs on CPU). Message text
 *     NEVER leaves the host. The dependency is lazy-imported, so the other MCP
 *     tools work even when it isn't installed.
 *   - The vector store is in-house: a flat array of L2-normalized Float32
 *     vectors with brute-force cosine (= dot product) top-k. No vector DB. For
 *     per-session corpora (thousands–tens of thousands of messages) this is
 *     sub-100ms and needs zero infrastructure.
 *   - The index is persisted to disk so the (CPU-expensive) embedding pass is a
 *     one-time warm-up; subsequent runs only embed messages newer than the
 *     stored cursor.
 *
 * Default model is multilingual (the corpus is largely Portuguese). Override
 * with RUWA_EMBED_MODEL. e5 models expect "query:"/"passage:" prefixes.
 */
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs"
import { homedir } from "node:os"
import { join } from "node:path"

export type Call = (method: string, path: string, body?: unknown) => Promise<unknown>

type MsgRow = {
  chat_jid: string
  message_id: string
  sender_jid: string
  from_me: boolean
  timestamp: number
  msg_type: string
  body_text: string | null
}

type IndexItem = {
  message_id: string
  chat_jid: string
  sender_jid: string
  timestamp: number
  from_me: boolean
  text: string
  vec: number[] // L2-normalized embedding
}

type IndexFile = {
  model: string
  dim: number
  cursor: number // max message timestamp embedded so far
  items: IndexItem[]
}

// ── config ───────────────────────────────────────────────────────────────────
const MODEL = process.env.RUWA_EMBED_MODEL || "Xenova/multilingual-e5-small"
const INDEX_DIR =
  process.env.RUWA_MCP_INDEX_DIR || join(homedir(), ".cache", "ruwa-mcp")
// Model weights live in their own stable dir so changing the index location
// never forces a multi-hundred-MB re-download.
const MODEL_CACHE_DIR =
  process.env.RUWA_MODEL_CACHE_DIR || join(homedir(), ".cache", "ruwa-mcp", "models")
// Bound the index so a runaway corpus can't exhaust memory/disk.
const MAX_ITEMS = Number(process.env.RUWA_INDEX_MAX || 20000)
const FETCH_PAGE = 500 // core's max page size
const EMBED_BATCH = 32

// e5-family models need these prefixes; harmless for most other models, but
// skip them if the operator points at a non-e5 model.
const USE_E5_PREFIX = /e5/i.test(MODEL)
const asQuery = (t: string) => (USE_E5_PREFIX ? `query: ${t}` : t)
const asPassage = (t: string) => (USE_E5_PREFIX ? `passage: ${t}` : t)

// ── pure vector helpers (no model needed — unit-testable) ─────────────────────

/** Dot product. For L2-normalized inputs this equals cosine similarity. */
export function dot(a: Float32Array | number[], b: Float32Array | number[]): number {
  let s = 0
  const n = Math.min(a.length, b.length)
  for (let i = 0; i < n; i++) s += a[i] * b[i]
  return s
}

/** Top-k by score, descending. Simple partial selection over a small k. */
export function topK<T>(items: T[], score: (t: T) => number, k: number): Array<{ item: T; score: number }> {
  const scored = items.map((item) => ({ item, score: score(item) }))
  scored.sort((x, y) => y.score - x.score)
  return scored.slice(0, k)
}

// ── embedder (lazy, optional dependency) ──────────────────────────────────────
let embedderPromise: Promise<(texts: string[]) => Promise<number[][]>> | null = null

async function getEmbedder(): Promise<(texts: string[]) => Promise<number[][]>> {
  if (embedderPromise) return embedderPromise
  embedderPromise = (async () => {
    let transformers: any
    try {
      // Variable specifier so tsc doesn't require the optional dep at build time.
      const modName = "@huggingface/transformers"
      transformers = await import(modName)
    } catch {
      throw new Error(
        "Semantic search isn't enabled yet — it needs a local embedding model (kept " +
          "optional so the base install stays small). Enable it with ONE command in the " +
          "ruwa-mcp directory:\n\n    npm run setup-search\n\n" +
          "That installs the local embedder and pre-downloads the model (~200MB, one-time, " +
          "runs entirely on this machine — nothing leaves the host). Then `npm run build` and " +
          "retry. (For exact word/phrase matches you can use list_messages with `q=` instead, " +
          "which needs no setup.)",
      )
    }
    const { pipeline, env } = transformers
    // Cache model weights in a stable dir so they download once.
    env.cacheDir = MODEL_CACHE_DIR
    const extractor = await pipeline("feature-extraction", MODEL)
    return async (texts: string[]) => {
      const out = await extractor(texts, { pooling: "mean", normalize: true })
      return out.tolist() as number[][]
    }
  })()
  return embedderPromise
}

async function embedBatched(texts: string[]): Promise<number[][]> {
  const embed = await getEmbedder()
  const out: number[][] = []
  for (let i = 0; i < texts.length; i += EMBED_BATCH) {
    const batch = texts.slice(i, i + EMBED_BATCH)
    out.push(...(await embed(batch)))
  }
  return out
}

// ── persistence ───────────────────────────────────────────────────────────────
const memCache = new Map<string, IndexFile>()

function indexPath(sessionId: string): string {
  const safe = sessionId.replace(/[^a-zA-Z0-9_-]/g, "_")
  return join(INDEX_DIR, `${safe}.json`)
}

function loadIndex(sessionId: string): IndexFile {
  const cached = memCache.get(sessionId)
  if (cached) return cached
  const path = indexPath(sessionId)
  if (existsSync(path)) {
    try {
      const parsed = JSON.parse(readFileSync(path, "utf8")) as IndexFile
      // Discard a stale index built with a different model (dims/space differ).
      if (parsed.model === MODEL && Array.isArray(parsed.items)) {
        memCache.set(sessionId, parsed)
        return parsed
      }
    } catch {
      /* fall through to a fresh index */
    }
  }
  const fresh: IndexFile = { model: MODEL, dim: 0, cursor: -1, items: [] }
  memCache.set(sessionId, fresh)
  return fresh
}

function saveIndex(sessionId: string, idx: IndexFile): void {
  mkdirSync(INDEX_DIR, { recursive: true })
  writeFileSync(indexPath(sessionId), JSON.stringify(idx))
}

// ── corpus fetch ───────────────────────────────────────────────────────────────

/** Pull messages with non-empty bodies that are newer than `cursor`, paging
 *  from newest backwards until we cross into already-indexed territory. */
async function fetchNewMessages(call: Call, sessionId: string, cursor: number): Promise<MsgRow[]> {
  const out: MsgRow[] = []
  let before = Number.MAX_SAFE_INTEGER
  // Loop bounded by MAX_ITEMS worth of pages — never unbounded.
  for (let guard = 0; guard < Math.ceil(MAX_ITEMS / FETCH_PAGE) + 1; guard++) {
    const page = (await call(
      "GET",
      `/v1/sessions/${encodeURIComponent(sessionId)}/messages?limit=${FETCH_PAGE}&before=${before}`,
    )) as MsgRow[]
    if (!Array.isArray(page) || page.length === 0) break
    for (const r of page) {
      if (r.timestamp > cursor && r.body_text && r.body_text.trim()) out.push(r)
    }
    const oldest = page[page.length - 1].timestamp
    if (oldest <= cursor || page.length < FETCH_PAGE || out.length >= MAX_ITEMS) break
    before = oldest
  }
  return out
}

// ── public API ─────────────────────────────────────────────────────────────────

export type IndexStats = {
  model: string
  indexed: number
  added: number
  cursor: number
  capped: boolean
}

/** Bring the session's vector index up to date with new messages. Idempotent. */
export async function ensureIndex(call: Call, sessionId: string): Promise<IndexStats> {
  const idx = loadIndex(sessionId)
  const seen = new Set(idx.items.map((i) => i.message_id))
  const room = MAX_ITEMS - idx.items.length
  let fresh = (await fetchNewMessages(call, sessionId, idx.cursor)).filter((m) => !seen.has(m.message_id))
  const capped = fresh.length > room
  if (capped) fresh = fresh.slice(0, Math.max(0, room))

  if (fresh.length > 0) {
    const vecs = await embedBatched(fresh.map((m) => asPassage(m.body_text as string)))
    for (let i = 0; i < fresh.length; i++) {
      const m = fresh[i]
      idx.items.push({
        message_id: m.message_id,
        chat_jid: m.chat_jid,
        sender_jid: m.sender_jid,
        timestamp: m.timestamp,
        from_me: m.from_me,
        text: m.body_text as string,
        vec: vecs[i],
      })
    }
    idx.dim = vecs[0]?.length ?? idx.dim
    idx.cursor = idx.items.reduce((mx, it) => Math.max(mx, it.timestamp), idx.cursor)
    saveIndex(sessionId, idx)
  }
  return { model: idx.model, indexed: idx.items.length, added: fresh.length, cursor: idx.cursor, capped }
}

export type SearchHit = {
  message_id: string
  chat_jid: string
  sender_jid: string
  timestamp: number
  from_me: boolean
  text: string
  score: number
}

/** Semantic search: embed the query, cosine top-k over the session index. */
export async function search(
  call: Call,
  sessionId: string,
  query: string,
  opts: { limit?: number; chat?: string } = {},
): Promise<{ stats: IndexStats; hits: SearchHit[] }> {
  const stats = await ensureIndex(call, sessionId)
  const idx = loadIndex(sessionId)
  const limit = Math.min(Math.max(opts.limit ?? 10, 1), 100)
  const [qv] = await embedBatched([asQuery(query)])
  const qvec = Float32Array.from(qv)

  const pool = opts.chat ? idx.items.filter((i) => i.chat_jid === opts.chat) : idx.items
  const hits = topK(pool, (it) => dot(qvec, it.vec), limit).map(({ item, score }) => ({
    message_id: item.message_id,
    chat_jid: item.chat_jid,
    sender_jid: item.sender_jid,
    timestamp: item.timestamp,
    from_me: item.from_me,
    text: item.text,
    score: Math.round(score * 1000) / 1000,
  }))
  return { stats, hits }
}
