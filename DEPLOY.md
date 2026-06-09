# Deploying RUWA (ruwa)

RUWA ships as a single self-contained binary (see [`Dockerfile`](Dockerfile)):
a multi-stage build (no protobuf-compiler/libpq needed — protoc is vendored,
the Postgres client is pure-Rust), running as a non-root user, persisting state
on a mounted volume at `/data`.

## Configuration (env)

| Var | Required | Default | Notes |
|-----|----------|---------|-------|
| `RUWA_API_TOKEN` | **yes (prod)** | random (logged) | Bearer token for `/v1/*`. |
| `RUWA_STORE` | no | `/data/ruwa.db` (Docker) | SQLite path, **or** a `postgres://…` URL. |
| `RUWA_DB_ENCRYPTION_KEY` | recommended | off | base64 of 32 bytes → AES-256-GCM at rest for secret columns. Generate: `openssl rand -base64 32`. |
| `RUWA_BIND` / `PORT` | no | `0.0.0.0:8080` / `$PORT` | Bind address; honors a platform `$PORT` if `RUWA_BIND` is unset. |
| `RUWA_READONLY` | no | off | `1` → mutating routes return 403. |
| `RUWA_MEDIA_STORE` | no | `db` | `s3` + `RUWA_S3_*` to offload media to S3/R2/MinIO. |
| `RUWA_RETENTION_*` | no | off | optional background pruning. |

Health check: `GET /health` (unauthenticated) → `{"status":"ok"}`.

## Railway

The production instance runs on Railway (project **ruwa**, workspace
RUWA). Persistence is **SQLite on a Railway Volume mounted at `/data`** — the
proven path; the Postgres backend exists but is far less exercised.

**First-time setup (one-off):**
1. New project + service built from this repo's `Dockerfile`.
2. Attach a **Volume** mounted at `/data` (without it, pairing is wiped on every redeploy).
3. Set service variables: `RUWA_API_TOKEN`, `RUWA_DB_ENCRYPTION_KEY`.
4. Generate a public domain. If `/health` 502s, set the service's target port to `8080`.

**Auto-deploy on push (recommended):** in the Railway dashboard →
service → **Settings → Source → Connect Repo** → pick `oqva-digital/ruwa`,
branch `main`, enable **auto-deploy**. Every push to `main` then builds + deploys.

**Zero-downtime deploys & session leasing:** Railway runs the old and new
instances in parallel for a few seconds on each deploy. With a **shared
(Postgres) store**, both would connect the same WhatsApp sockets and fight
(`stream:error conflict=replaced`), leaving sessions parked Disconnected.
**Cross-instance leasing** fixes this: the new instance waits for the old one to
release its lease, then connects (a clean handoff). It now **defaults ON whenever
`RUWA_STORE` is a `postgres://` URL** (override with `RUWA_LEASING=0`/`1`). On a
single-instance SQLite+Volume setup there's no real overlap (the Volume attaches
to one instance at a time), so it stays off.

**Manual deploy (CLI):** from a repo clone linked to the project:
```sh
railway up --service <service-id>
```

> ⚠️ The CLI links projects by directory in its global config. If a working dir
> was previously `railway link`ed to a different project,
> `railway up` there deploys *that* project — re-link first.

## Pairing a session (after deploy)

```sh
URL=https://<your-domain>; TOK=<RUWA_API_TOKEN>
curl -s -X POST -H "authorization: Bearer $TOK" $URL/v1/sessions -d '{"label":"main"}'   # → {id}
curl -s -X POST -H "authorization: Bearer $TOK" $URL/v1/sessions/$ID/connect
curl -s -H "authorization: Bearer $TOK" $URL/v1/sessions/$ID/qr                          # scan svg_base64
```

Per-session egress proxy (residential/SOCKS): `POST /v1/sessions/$ID/proxy {"proxy":"socks5://user:pass@host:1080"}`.
