#!/usr/bin/env bash
# ruwa installer — downloads a prebuilt ruwa binary and runs it as a background
# service (no Docker, no Rust). macOS (launchd) and Linux (systemd --user).
#
#   curl -fsSL https://raw.githubusercontent.com/oqva-digital/ruwa/main/install.sh | bash
#   # or, from a clone:  ./install.sh
#
# While the repo is private, downloads use the GitHub CLI (`gh auth login`
# first). Once public, it falls back to anonymous release downloads.
#
# Env overrides: RUWA_VERSION (default: latest), RUWA_PORT (default 8080),
#   RUWA_API_TOKEN (default: generated), RUWA_REPO (default oqva-digital/ruwa),
#   RUWA_PREFIX (install dir, default ~/.local/bin).
set -euo pipefail

REPO="${RUWA_REPO:-oqva-digital/ruwa}"
VERSION="${RUWA_VERSION:-latest}"
PORT="${RUWA_PORT:-8080}"
PREFIX="${RUWA_PREFIX:-$HOME/.local/bin}"
DATA_DIR="$HOME/.local/share/ruwa"
CONF_DIR="$HOME/.config/ruwa"
LOG_FILE="$DATA_DIR/ruwa.log"
BIN="$PREFIX/ruwa"

say() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# ── detect platform ───────────────────────────────────────────────────────────
os="$(uname -s)"; arch="$(uname -m)"
case "$os" in
  Darwin) case "$arch" in
            arm64) asset="ruwa-macos-arm64" ;;
            x86_64) asset="ruwa-macos-x64" ;;
            *) die "unsupported macOS arch: $arch" ;;
          esac ;;
  Linux)  case "$arch" in
            x86_64|amd64) asset="ruwa-linux-x64" ;;
            *) die "unsupported Linux arch: $arch (only x86_64 binaries are published)" ;;
          esac ;;
  *) die "unsupported OS: $os (Windows: download the .exe from the Releases page)" ;;
esac

# ── download the binary ───────────────────────────────────────────────────────
mkdir -p "$PREFIX" "$DATA_DIR" "$CONF_DIR"
say "Downloading $asset ($VERSION) from $REPO"
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  # Note: no bash array here — `"${arr[@]}"` on an empty array trips `set -u`
  # on macOS's bash 3.2. `latest` is implicit when no tag is passed.
  if [ "$VERSION" = "latest" ]; then
    gh release download --repo "$REPO" --pattern "$asset" --output "$BIN" --clobber \
      || die "gh release download failed — is there a published release with asset '$asset'?"
  else
    gh release download "$VERSION" --repo "$REPO" --pattern "$asset" --output "$BIN" --clobber \
      || die "gh release download failed for $VERSION — is there a release with asset '$asset'?"
  fi
else
  if [ "$VERSION" = "latest" ]; then
    url="https://github.com/$REPO/releases/latest/download/$asset"
  else
    url="https://github.com/$REPO/releases/download/$VERSION/$asset"
  fi
  curl -fSL "$url" -o "$BIN" \
    || die "download failed. If the repo is private, install the GitHub CLI and run 'gh auth login', then re-run."
fi
chmod +x "$BIN"
say "Installed binary → $BIN"

# ── config (token + store) ────────────────────────────────────────────────────
gen_token() { head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
TOKEN="${RUWA_API_TOKEN:-$(gen_token)}"
ENV_FILE="$CONF_DIR/ruwa.env"
cat > "$ENV_FILE" <<EOF
RUWA_API_TOKEN=$TOKEN
RUWA_BIND=127.0.0.1:$PORT
RUWA_STORE=$DATA_DIR/ruwa.db
RUST_LOG=info
EOF
chmod 600 "$ENV_FILE"
say "Wrote config → $ENV_FILE"

# ── background service ────────────────────────────────────────────────────────
if [ "$os" = "Darwin" ]; then
  PLIST="$HOME/Library/LaunchAgents/dev.oqva.ruwa.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.oqva.ruwa</string>
  <key>ProgramArguments</key><array><string>$BIN</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>RUWA_API_TOKEN</key><string>$TOKEN</string>
    <key>RUWA_BIND</key><string>127.0.0.1:$PORT</string>
    <key>RUWA_STORE</key><string>$DATA_DIR/ruwa.db</string>
    <key>RUST_LOG</key><string>info</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG_FILE</string>
  <key>StandardErrorPath</key><string>$LOG_FILE</string>
</dict></plist>
EOF
  launchctl unload "$PLIST" >/dev/null 2>&1 || true
  launchctl load "$PLIST"
  say "Registered launchd service (starts on login)."
else
  UNIT_DIR="$HOME/.config/systemd/user"
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_DIR/ruwa.service" <<EOF
[Unit]
Description=ruwa WhatsApp API
After=network-online.target

[Service]
ExecStart=$BIN
EnvironmentFile=$ENV_FILE
Restart=always
RestartSec=3

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable --now ruwa.service
  loginctl enable-linger "$USER" >/dev/null 2>&1 || true
  say "Registered systemd --user service (starts on login)."
fi

# ── done ──────────────────────────────────────────────────────────────────────
sleep 1
cat <<EOF

  ruwa is running in the background.

  Dashboard:  http://localhost:$PORT
  API token:  $TOKEN

  Manage it:  ruwactl status | logs | stop | start | restart | token | url
  (installed alongside the binary in $PREFIX)

  Next: open the dashboard, paste the token, create an instance, and scan the QR
  on your phone (WhatsApp → Linked devices). See GETTING_STARTED.md.
EOF

# Install the ruwactl helper. From a clone it sits next to this script; via
# `curl | bash` there's no local copy (and BASH_SOURCE is unset under `set -u`),
# so fetch it from the repo.
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
if [ -n "${SELF_DIR:-}" ] && [ -f "$SELF_DIR/scripts/ruwactl" ]; then
  cp "$SELF_DIR/scripts/ruwactl" "$PREFIX/ruwactl"
else
  curl -fsSL "https://raw.githubusercontent.com/$REPO/main/scripts/ruwactl" -o "$PREFIX/ruwactl" 2>/dev/null || true
fi
[ -f "$PREFIX/ruwactl" ] && chmod +x "$PREFIX/ruwactl" || true

case ":$PATH:" in *":$PREFIX:"*) ;; *) printf '\n  Note: add %s to your PATH.\n' "$PREFIX" ;; esac
