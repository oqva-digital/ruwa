#!/usr/bin/env node
/**
 * setup-search — one-command opt-in for ruwa-mcp semantic search.
 *
 *   npm run setup-search
 *
 * Installs the local embedding runtime (@huggingface/transformers) into this
 * MCP install and pre-downloads the default model so the first
 * `search_conversations` call is instant. Kept out of the default dependencies
 * on purpose: the base MCP stays tiny, and only users who want semantic search
 * pull the ~200MB ML runtime. Everything runs locally — nothing leaves the host.
 */
import { spawnSync } from "node:child_process"
import { fileURLToPath } from "node:url"
import { dirname, join } from "node:path"

const PKG = "@huggingface/transformers"
const here = dirname(fileURLToPath(import.meta.url))
const mcpRoot = join(here, "..")
const model = process.env.RUWA_EMBED_MODEL || "Xenova/multilingual-e5-small"

const log = (m) => console.log(`\x1b[1;36m==>\x1b[0m ${m}`)

// 1) Install the embedder locally (not saved to package.json — keeps the repo lean).
log(`Installing the local embedding runtime (${PKG}) — this is a one-time ~200MB download…`)
const install = spawnSync(
  process.platform === "win32" ? "npm.cmd" : "npm",
  ["install", "--no-save", PKG],
  { cwd: mcpRoot, stdio: "inherit" },
)
if (install.status !== 0) {
  console.error("\x1b[1;31merror:\x1b[0m install failed. Check your network/npm and retry.")
  process.exit(install.status ?? 1)
}

// 2) Pre-download the model so the first search doesn't pay the download cost.
log(`Pre-downloading the embedding model (${model})…`)
try {
  const t = await import(PKG)
  t.env.cacheDir =
    process.env.RUWA_MODEL_CACHE_DIR ||
    join(process.env.HOME || process.env.USERPROFILE || ".", ".cache", "ruwa-mcp", "models")
  const extractor = await t.pipeline("feature-extraction", model)
  await extractor(["warmup"], { pooling: "mean", normalize: true })
  log("Model ready.")
} catch (e) {
  // Non-fatal: the model will download lazily on first search instead.
  console.warn(`\x1b[1;33mnote:\x1b[0m couldn't pre-warm the model (${e?.message ?? e}). ` +
    `It'll download on first use instead.`)
}

console.log(`
  ✅ Semantic search is enabled.

  Rebuild if you haven't:  npm run build
  Then ask your agent:     "semantically search <session> for <topic>"
`)
