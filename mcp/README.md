# ruwa-mcp

An **MCP server** exposing ruwa (RUWA — Rust WhatsApp) as agent tools, so any MCP
client (Claude Desktop, Claude Code, …) can drive WhatsApp. A thin wrapper over
the `/v1` HTTP API — the ruwa core stays lean.

## Tools (38)

An agent can run a WhatsApp account end-to-end — spin up an instance, pair it,
read/search history (keyword **and** semantic), hold a conversation, manage
contacts/profile, and wire up event delivery.

**Instance lifecycle**
- `create_session` — create a new instance (optional label + proxy)
- `get_qr` — pairing QR payload to scan in WhatsApp → Linked devices
- `get_session` — one instance's status / JID / proxy
- `connect_session` — (re)connect a disconnected session
- `logout_session` — unlink the device
- `delete_session` — delete an instance + its data (destructive)

**Read / search / context**
- `list_sessions` · `session_health` · `list_chats` · `list_groups`
- `list_messages` (filter by chat, ranked full-text search `q`, paginate) · `get_message_context` (window around a message)
- `search_conversations` (semantic / meaning-based search) · `reindex_conversations` (warm the index)
- `list_contacts` (search by name/number) · `on_whatsapp` (real round-trip check)
- `download_media` (save a message's media to a local file)
- `backfill_history` (pull older history once) · `sync_history` (deep-backfill a chat to its start)

**Send**
- `send_text` (with @mentions + quote/reply) · `send_media` · `send_location`
- `send_contact` · `send_poll` · `send_reaction` · `edit_message` · `revoke_message`

**Act human**
- `mark_read` (blue ticks) · `set_typing` (composing/paused) · `set_presence`

**Contacts & profile**
- `block_contact` · `unblock_contact` · `get_contact_picture` · `set_profile` (own name/status/picture)

**Events / webhooks**
- `set_webhook` (primary) · `add_webhook` (labelled) · `list_webhooks` · `delete_webhook` — HMAC-signed event delivery; many per session

## Quick install (one command)

Point Claude Code at this README and it can set itself up. Build, then register
with the CLI — no hand-editing JSON:

```sh
cd mcp && npm install && npm run build

# from the repo root — registers the server with Claude Code:
claude mcp add ruwa \
  --env RUWA_BASE_URL=http://localhost:8080 \
  --env RUWA_API_TOKEN=your-admin-token \
  -- node "$(pwd)/mcp/dist/index.js"
```

That's it — restart Claude and ask *"which ruwa sessions are connected?"*.

**Other clients (Claude Desktop, Cursor), prerequisites, and troubleshooting:**
see **[INSTALL.md](INSTALL.md)**.

## Manual config

If your client wants JSON (Claude Desktop `claude_desktop_config.json`, or
`~/.claude.json`):

```json
{
  "mcpServers": {
    "ruwa": {
      "command": "node",
      "args": ["/abs/path/to/ruwa/mcp/dist/index.js"],
      "env": {
        "RUWA_BASE_URL": "http://localhost:8080",
        "RUWA_API_TOKEN": "your-admin-token"
      }
    }
  }
}
```

Then ask your agent: *"which ruwa sessions are connected?"* or *"send 'oi' from
session X to 5511999999999"*.

## Semantic search (RAG)

`search_conversations` finds messages by **meaning**, not just keywords — so
*"find the conversation about the war"* matches *"Putin discursou sobre a guerra
na Ucrânia"* even with no shared words, across languages. The typical agent flow
is retrieve → read around the hit (`get_message_context`) → summarize.

It runs a **local** embedding model — **message text never leaves the host**. The
embedder is kept out of the default install (so the base MCP stays tiny); enable
it with one command:

```sh
cd mcp && npm run setup-search   # installs the embedder + pre-downloads the model
```

You don't have to remember this up front: if you call `search_conversations`
before enabling it, the tool replies with exactly this command. Every other tool
works without it. The first call for a session downloads a small model
(~120 MB, default `Xenova/multilingual-e5-small`) and embeds the history (a
one-time warm-up); later calls only embed new messages. The vector index is
in-house brute-force cosine — no vector DB. Pair with `backfill_history` to
deepen the searchable corpus first.

Knobs (all optional):

| Env | Default | What |
|-----|---------|------|
| `RUWA_EMBED_MODEL` | `Xenova/multilingual-e5-small` | embedding model (any transformers.js feature-extraction model) |
| `RUWA_MCP_INDEX_DIR` | `~/.cache/ruwa-mcp` | where per-session vector indexes are stored |
| `RUWA_MODEL_CACHE_DIR` | `~/.cache/ruwa-mcp/models` | downloaded model weights |
| `RUWA_INDEX_MAX` | `20000` | cap on messages indexed per session |

## Why

Turns ruwa into **WhatsApp for AI agents** — the natural seam for an
agent layer to talk to ruwa (tools instead of REST glue).
