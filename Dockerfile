# syntax=docker/dockerfile:1

# ---- builder ----------------------------------------------------------------
# Bundled SQLite compiles C (needs gcc, present in the rust image); native-tls
# links system OpenSSL (needs libssl-dev + pkg-config). protoc is vendored by
# the build (protoc-bin-vendored), so no protobuf-compiler package is needed.
FROM rust:1-bookworm AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# build.rs reads proto/ + migrations are include_str!'d, so copy the whole tree.
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked \
    && cp target/release/ruwa /usr/local/bin/ruwa

# ---- dashboard (ruwa Console — Vite/React SPA) ------------------------------
FROM node:22-bookworm-slim AS dashboard
WORKDIR /dash
COPY dashboard/package.json dashboard/package-lock.json ./
RUN npm ci
COPY dashboard/ ./
RUN npm run build   # → /dash/dist (index.html + assets/)

# ---- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3 curl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /data
COPY --from=builder /usr/local/bin/ruwa /usr/local/bin/ruwa
# Bake the built ruwa Console SPA; the binary serves it from RUWA_WEB_DIR.
COPY --from=dashboard /dash/dist /srv/ruwa/web

# Run as root: Railway mounts the persistent volume at /data root-owned, so a
# non-root user can't create the SQLite db on it. (Managed-PaaS sandbox; the
# container is the only tenant.)
WORKDIR /data
# Listen on all interfaces inside the container; persist the DB on the volume.
ENV RUWA_BIND=0.0.0.0:8080 \
    RUWA_STORE=/data/ruwa.db \
    RUWA_WEB_DIR=/srv/ruwa/web
EXPOSE 8080

# Liveness: the unauthenticated /health endpoint.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["/bin/sh", "-c", "curl -fsS http://127.0.0.1:8080/health >/dev/null || exit 1"]

ENTRYPOINT ["ruwa"]
