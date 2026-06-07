# AGENTS.md

Briefing entry-point for any AI coding agent (Codex, Cursor, Aider, Cline,
Continue, etc.) — the canonical content lives in [CLAUDE.md](./CLAUDE.md).
Read that first; this file is a stable alias so non-Claude tools find the
right rules without guessing.

Quick orientation:

- **What this repo is**: a from-scratch Rust port of `whatsmeow`,
  exposed as an HTTP API. No Baileys/whatsmeow runtime deps.
- **Read order**: `README.md` → `SPEC.md` → source.
- **Hard rule**: every commit compiles, tests pass, clippy clean
  (`cargo check && cargo test && cargo clippy --all-targets -- -D warnings`).
- **Never commit to `main`** — it auto-deploys. Work on a feature branch (or
  fork) and open a PR into `main`; merge only when CI is green.
- **No CLI**; everything is `/v1/*` HTTP with bearer-token auth.
- **`src/` stays at ≤10 files**; grow an existing module rather than adding one.
- **Tests next to source** as `#[cfg(test)] mod tests`. Live-WA tests
  gated `#[ignore]` + `RUWA_LIVE_TEST=1`.

Full conventions, file map, git workflow, and reference-fetching recipes:
[CLAUDE.md](./CLAUDE.md).
