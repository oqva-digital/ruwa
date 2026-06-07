# CLAUDE.md — briefing for any AI agent working on ruwa

You are working on `ruwa`: a from-scratch Rust port of
[whatsmeow](https://github.com/tulir/whatsmeow), exposed as an HTTP API.
**No Baileys, no whatsmeow runtime, no FFI.** The core protocol, production
hardening, and Evolution feature-parity work have all shipped.

## Read first

1. `README.md` — what ruwa is, its features, and when to use it.
2. `SPEC.md` — the design contract: the API + protocol design and acceptance criteria.

Then read the source files relevant to your task.

## Hard rules

- **Never use Baileys, whatsmeow, or any third-party WhatsApp library.**
  Crypto primitives from RustCrypto / dalek / snow / hkdf / md-5 / aes-gcm
  / cbc / hmac / sha2 / curve25519-dalek / x25519-dalek are fine; protocol
  logic must be ours.
- **`main` is protected and always deployable** (it auto-deploys). **Never commit
  directly to `main`.** Do all work on a short-lived feature branch (or a fork),
  open a PR into `main`, and merge **only after CI is green**. See *Git workflow*.
- **Every commit compiles + tests pass.** `cargo check` + `cargo test` +
  `cargo clippy --all-targets -- -D warnings` all green. No commits that break
  the tree, ever.
- **`src/` stays at ≤10 files.** main, api, session, store, error, protocol,
  crypto, media, egress, plus protocol/tokens.rs. No new files: grow an
  existing module instead.
- **No CLI.** All behavior reachable via HTTP under `/v1/*` (bearer auth).
- **Never put protobuf types in the public HTTP API.** Translate to neutral
  structs in `api.rs`.
- **Tests live alongside source** as `#[cfg(test)] mod tests { ... }`.
  Live-WA tests must be gated `#[ignore]` + `RUWA_LIVE_TEST=1`.

## Git workflow

`main` auto-deploys to production, so it must always build and pass tests.

1. Branch off `main`: `git checkout -b feat/<short-name>` (or fork the repo).
2. Make focused commits — **one logical change per commit**, clear messages.
   Stage explicit files; never `git add -A`.
3. Push the branch and open a **pull request into `main`**.
4. CI (`.github/workflows/ci.yml`) runs `cargo check`/`test`/`clippy` — it must
   pass. Get the PR reviewed.
5. Merge into `main` only when CI is green. Releases are cut by tagging `v*`,
   which triggers the prebuilt-binary build (`.github/workflows/release.yml`).

## Reference fetching

```sh
# Go source from whatsmeow:
gh api repos/tulir/whatsmeow/contents/<path>.go -q .content | base64 -d

# Raw .proto (strip go_package before placing):
curl -fsSL https://raw.githubusercontent.com/tulir/whatsmeow/main/proto/<pkg>/<file>.proto \
  | grep -v 'option go_package' > proto/<pkg>/<file>.proto
```

**Debugging against upstream:** when chasing a protocol bug, compare against the
whatsmeow source the relevant module was ported from (use the `gh api` recipe
above), and scan whatsmeow's later commits for an analogous fix.

## Codebase shape

```
src/
  main.rs                 # bootstrap (env, axum listen)
  api.rs                  # HTTP routes + bearer auth
  session.rs              # SessionManager, Session, IQ builders/parsers,
                          #   process_inbound_node, ClientPayload, app state
  store.rs                # SQLite + migrations
  error.rs                # error types + IntoResponse
  protocol.rs             # binary nodes, Noise XX, frame socket,
                          #   NoiseSocket, connect_wa, do_handshake
  protocol/tokens.rs      # 1280 vendored WA dictionary tokens
  crypto.rs               # identity, prekeys, signal (full subset),
                          #   senderkey, hkdf
  media.rs                # media enc + upload/download, per-type builders,
                          #   in-house SigV4 + S3/R2/MinIO client
  egress.rs               # event fan-out: SSE serializer, webhook delivery
                          #   (HMAC, retry, metrics), in-house Redis (RESP) client

migrations/0001_initial.sql   # full schema
proto/                         # vendored .proto files
SPEC.md                        # design contract
mcp/                           # MCP server (WhatsApp-for-agents) over the /v1 API
dashboard/                     # the ruwa Console SPA (Vite + React)
```

`SessionManager` is the multi-tenant registry. Every per-tenant op flows
through `manager.get(id)?` → `Arc<Session>`.

## Testing conventions

- Unit tests next to source: `#[cfg(test)] mod tests` at file end.
- HTTP tests use `tower::ServiceExt::oneshot` + an in-memory `Store::open(":memory:")`.
- Live-WA tests gated `#[ignore]` + check `RUWA_LIVE_TEST=1` at runtime.

## When you change something

1. Run `cargo check && cargo test && cargo clippy --all-targets -- -D warnings`.
2. If any of those fail, fix BEFORE committing — never commit a broken tree.
3. Commit with a clear, focused message; PR into `main` (never push to `main`).
