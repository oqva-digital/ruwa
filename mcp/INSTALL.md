# Installing ruwa as an MCP server

`ruwa-mcp` exposes a running [ruwa](../README.md) server to any **Model Context
Protocol** client (Claude Code, Claude Desktop, Cursor, …) as 38 tools, so an AI
agent can create WhatsApp instances, pair them, send messages, search history by
meaning, and more.

It's a thin stdio wrapper over ruwa's `/v1` HTTP API — it does **not** talk to
WhatsApp directly; it calls your ruwa server, which you run separately.

```
MCP client (Claude/Cursor)  ──stdio──▶  ruwa-mcp (node)  ──HTTP /v1──▶  ruwa server  ──▶  WhatsApp
```

## 1. Prerequisites

- **Node.js 18+** (`node --version`).
- **A running ruwa server** reachable from this machine, and its **admin token**
  (`RUWA_API_TOKEN`). The admin token is required — the MCP server uses admin
  routes like `create_session` / `list_sessions`.
  - Local: `RUWA_API_TOKEN=$(openssl rand -hex 32) cargo run --release` (note the
    token; ruwa listens on `http://localhost:8080`).
  - Remote: use your deployment's URL (e.g. `https://ruwa.example.com`) and the
    `RUWA_API_TOKEN` you set there.

## 2. Build

```sh
cd mcp
npm install
npm run build      # → dist/index.js
```

## 3. Register with your MCP client

You need two env vars in every case:

| Var | Example | Notes |
|---|---|---|
| `RUWA_BASE_URL` | `http://localhost:8080` | your ruwa server's base URL (no trailing slash) |
| `RUWA_API_TOKEN` | `…` | ruwa **admin** token |

### Claude Code (CLI — easiest)

From the repo root:

```sh
claude mcp add ruwa \
  --env RUWA_BASE_URL=http://localhost:8080 \
  --env RUWA_API_TOKEN=your-admin-token \
  -- node "$(pwd)/mcp/dist/index.js"
```

Add `-s user` to make it available in every project, or `-s project` to write a
shared `.mcp.json` into the repo. Verify with `claude mcp list`, then restart Claude.

### Claude Desktop (JSON)

Edit `claude_desktop_config.json`:

- macOS — `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows — `%APPDATA%\Claude\claude_desktop_config.json`
- Linux — `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "ruwa": {
      "command": "node",
      "args": ["/absolute/path/to/ruwa/mcp/dist/index.js"],
      "env": {
        "RUWA_BASE_URL": "http://localhost:8080",
        "RUWA_API_TOKEN": "your-admin-token"
      }
    }
  }
}
```

Use an **absolute** path to `dist/index.js`. Restart Claude Desktop.

### Cursor

Global `~/.cursor/mcp.json` (or per-project `.cursor/mcp.json`) — same shape as
Claude Desktop:

```json
{
  "mcpServers": {
    "ruwa": {
      "command": "node",
      "args": ["/absolute/path/to/ruwa/mcp/dist/index.js"],
      "env": {
        "RUWA_BASE_URL": "http://localhost:8080",
        "RUWA_API_TOKEN": "your-admin-token"
      }
    }
  }
}
```

### Any other MCP client

The server speaks MCP over **stdio**. Launch it as `node /abs/path/to/mcp/dist/index.js`
with `RUWA_BASE_URL` and `RUWA_API_TOKEN` in the environment, and point your client's
stdio-server config at that command.

## 4. Verify

Restart the client and ask the agent something like:

> *"Which ruwa sessions are connected?"*

or, end-to-end:

> *"Create a new WhatsApp instance labeled 'support', show me the QR to scan, and
> once it's connected send 'oi 👋' to 5511999999999."*

The agent should call `list_sessions` / `create_session` / `get_qr` / `send_text`.

## 5. Tools

38 tools across instance lifecycle, sending, human-like actions, reads (keyword
**and** semantic search, plus deep history backfill), and webhooks — see
[`README.md`](README.md#tools-38) for the full list. Semantic search needs one
optional dependency; see the README's **Semantic search (RAG)** section.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Tools don't appear | Restart the client after editing config. Confirm the path to `dist/index.js` is absolute and you ran `npm run build`. |
| `Error: HTTP 401` | Wrong/missing `RUWA_API_TOKEN`, or you used a per-session key instead of the **admin** token. |
| `fetch failed` / `ECONNREFUSED` | `RUWA_BASE_URL` is wrong or the ruwa server isn't running / not reachable from this machine. Test: `curl $RUWA_BASE_URL/health`. |
| `create_session` works but `get_qr` says "no QR" | The session is still connecting — wait a second and retry; QR appears once ruwa reaches the pairing step. |
| Node errors on launch | Ensure Node 18+. Re-run `npm install && npm run build`. |

## Security notes

- The MCP server holds your **admin token** — anyone who can use these tools can
  create/delete sessions and send messages from your numbers. Keep the config
  private.
- Prefer a dedicated ruwa instance (or a scoped deployment) for agent use rather
  than pointing agents at production sessions you can't afford to disrupt.
