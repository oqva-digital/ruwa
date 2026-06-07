# RUWA Console

The ops dashboard for **RUWA (Rust WhatsApp)** — a real Vite + React + TypeScript
+ Tailwind v4 + shadcn/ui SPA, wired to ruwa's `/v1` API + SSE.

## Run (dev)

```sh
# 1. start ruwa (the Rust backend) on :8080 in the repo root
cargo run                      # serves /v1, /health, /metrics

# 2. start the dashboard
cd dashboard
npm install
npm run dev                    # http://localhost:5173
```

The dev server proxies `/v1`, `/health`, `/metrics` → `http://localhost:8080`
(see `vite.config.ts`), so leave the Base URL **blank** in the Auth gate and
paste your admin token (the value of `RUWA_API_TOKEN`).

## Build (prod)

```sh
npm run build                  # → dist/ (static SPA)
```

Deploy `dist/` anywhere static (Vercel/Netlify/CF Pages) and point the Auth
gate's Base URL at your ruwa host (CORS is enabled on the backend), **or** have
ruwa serve `dist/`.

## Layout

- `src/lib/` — `api.ts` (typed `/v1` client + SSE fetch-stream), `types.ts`,
  `format.ts` (status/liveness/`FROZEN_AFTER_SEC`).
- `src/components/` — `shell.tsx` (master-detail nav), `status.tsx`
  (StatusBadge + pulsing-frozen LivenessChip), `ui-bits.tsx`, `ui/` (shadcn).
- `src/pages/` — the 12 pages (auth, instances, overview, pairing, logs,
  messaging, contacts, profile, webhooks, integrations, metrics, settings).
- `src/index.css` — the GitHub-dark shadcn theme + the bespoke ruwa status layer.

