# Getting started with ruwa

**ruwa** lets you control a WhatsApp account from code or from an AI assistant:
send and receive messages, read and search your chat history (by keyword *and* by
meaning), and wire up automations — all from your own machine or server. It links
to WhatsApp the same way "WhatsApp Web" / Linked Devices does: you scan a QR code
once with your phone.

> You keep one phone as the "main" device; ruwa is an extra linked device, just
> like WhatsApp on a laptop. Your messages stay between you and WhatsApp — ruwa
> runs on your own hardware.

There are a few ways to set it up. Pick one.

---

## Option A — One-line install, no Docker (recommended)

Downloads a prebuilt binary and runs ruwa as a **background service** (starts on
login) — no Docker, no Rust, nothing to keep open. macOS and Linux:

```sh
curl -fsSL https://raw.githubusercontent.com/oqva-digital/ruwa/main/install.sh | bash
```

It prints your dashboard URL and API token when done. Manage it with:

```sh
ruwactl status     # is it running?
ruwactl logs       # follow logs
ruwactl token      # print the API token
ruwactl stop|start|restart
```

Then open the dashboard, paste the token, create an instance, and scan the QR on
your phone (**WhatsApp → Settings → Linked devices → Link a device**).

> **While the repo is private:** the one-liner needs auth. Install the GitHub CLI,
> run `gh auth login`, then run the installer from a clone: `./install.sh` (it
> uses `gh` to fetch the binary). Once the repo is public, the `curl … | bash`
> line works as-is. Windows: download `ruwa-windows-x64.exe` from the Releases
> page and run it.

---

## Option B — Let Claude set it up for you

If you have **[Claude Code](https://claude.com/claude-code)** (the AI coding
assistant), you don't have to follow any steps by hand — it'll do the whole setup.
Just install Claude Code, then in a terminal:

```sh
git clone https://github.com/oqva-digital/ruwa.git
cd ruwa
claude
```

Once Claude Code opens in the `ruwa` folder, paste this:

> Set up ruwa for me on this machine using the easiest method for my system
> (prefer the prebuilt binary / install.sh over Docker). Generate a secure API token,
> start the server, confirm it's healthy, then walk me through pairing my
> WhatsApp by showing me the QR code to scan. After it's connected, send a test
> message to my own number so I know it works. Finally, set up the ruwa MCP
> server so I can control WhatsApp by just chatting with you.

Claude will read this repo, do the setup, and guide you through scanning the QR
and sending your first message. If anything goes wrong it will explain and fix it.

---

## Option C — Docker (~5–15 min)

If you'd rather use containers, the only thing to install is
**[Docker](https://www.docker.com/products/docker-desktop/)**.

**1. Get the code**
```sh
git clone https://github.com/oqva-digital/ruwa.git
cd ruwa
```

**2. Create your config**
```sh
cp .env.example .env
# put a strong admin token in .env:
echo "RUWA_API_TOKEN=$(openssl rand -hex 32)" >> .env
```
(Keep that token — it's the password for your ruwa server.)

**3. Start it** (first run compiles the server, so it takes a few minutes)
```sh
docker compose up -d --build
```

**4. Open the dashboard** at <http://localhost:8080> and paste your token when
asked. (Find it again any time with `grep RUWA_API_TOKEN .env`.)

**5. Pair your WhatsApp**
- In the dashboard, create a new instance.
- A **QR code** appears.
- On your phone: **WhatsApp → Settings → Linked devices → Link a device**, and
  scan the QR.
- Wait until the instance shows **connected**.

**6. Send a test message** — from the dashboard, or via the API:
```sh
TOKEN=$(grep RUWA_API_TOKEN .env | cut -d= -f2)
# replace <id> with your instance id (shown in the dashboard), and the number
# with your own (country code + number, no + or spaces):
curl -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
     -d '{"to":"5511999999999","text":"hello from ruwa"}' \
     http://localhost:8080/v1/sessions/<id>/messages
```

To stop it: `docker compose down` (your data persists). To update later:
`git pull && docker compose up -d --build`.

---

## Talk to your WhatsApp through Claude (the fun part)

Once ruwa is running and paired, you can drive it by **chatting with Claude** —
no code. Claude can list your chats, search them by meaning, send messages, and
more, through ruwa's built-in MCP server.

Quick version:
```sh
cd mcp
npm install && npm run build
TOKEN=$(grep RUWA_API_TOKEN ../.env | cut -d= -f2)
claude mcp add ruwa \
  --env RUWA_BASE_URL=http://localhost:8080 \
  --env RUWA_API_TOKEN="$TOKEN" \
  -- node "$(pwd)/dist/index.js"
```
Restart Claude Code, then try: *"which ruwa chats do I have?"* or *"find the
conversation about the trip and summarize it."*

Full MCP setup (other clients, semantic-search model, troubleshooting):
[`mcp/INSTALL.md`](mcp/INSTALL.md) and the **Semantic search** section of
[`mcp/README.md`](mcp/README.md).

---

## What you can do with it

- **Send everything** — text (with @mentions, replies), images/video/audio,
  documents, locations, contacts, polls, reactions; edit and delete.
- **Read & search** — list chats and messages, keyword search, and **semantic
  search** ("find the conversation about X" even with different words).
- **Act human** — typing indicators, read receipts, presence.
- **Automate** — get a webhook (or live stream) for every incoming message.
- **Multiple numbers** — run many WhatsApp accounts from one server.

## Where to go next

- **[README.md](README.md)** — what ruwa is and why, full feature list.
- **[DEPLOY.md](DEPLOY.md)** — running it in the cloud (e.g. Railway) for 24/7 use.
- **[SPEC.md](SPEC.md)** — the full HTTP API and protocol design.

## Is this allowed / safe?

ruwa speaks WhatsApp's own multi-device protocol directly (no third-party
WhatsApp library). Like any unofficial client, use it on accounts you control and
within WhatsApp's terms. Your data lives on your machine; nothing is sent to us.
