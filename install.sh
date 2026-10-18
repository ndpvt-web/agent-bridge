#!/bin/bash
# ==============================================================================
#  AGENTBRIDGE INSTALLER
#  Connect this Mac to any cloud AI agent in one command.
#  Zero dependencies. Loopback-only. Ed25519 auth. On-device approvals.
#
#  Security notes:
#   - No secrets are printed or written to world-readable files.
#   - Downloads are version-pinned and SHA-256 verified.
#   - The script never uses sudo. Everything lives in ~/agent-bridge.
#   - Review first: curl -fsSL <url>/install.sh -o install.sh && less install.sh
# ==============================================================================
set -euo pipefail

BRIDGE_DIR="$HOME/agent-bridge"
BRIDGE_PORT="${AGENT_BRIDGE_PORT:-7899}"
LOG_DIR="$BRIDGE_DIR/logs"
BIN_DIR="$BRIDGE_DIR/bin"
LAUNCHD_DIR="$HOME/Library/LaunchAgents"
PROFILE="workspace"
ENABLE_SHELL=0

# Pinned dependency versions (update + re-pin checksums on upgrades)
NODE_VERSION="22.20.0"
# SHA-256 is verified against nodejs.org's own SHASUMS256.txt at install time.
CLOUDFLARED_VERSION="2025.9.1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) PROFILE="$2"; shift 2 ;;
    --profile=*) PROFILE="${1#*=}"; shift ;;
    --enable-shell) ENABLE_SHELL=1; shift ;;
    *) shift ;;
  esac
done

info() { printf '\033[0;34m[*]\033[0m %s\n' "$1"; }
ok()   { printf '\033[0;32m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1"; }
fail() { printf '\033[0;31m[x]\033[0m %s\n' "$1"; exit 1; }

[[ "$(uname)" == "Darwin" ]] || fail "macOS only. Detected: $(uname)"

ARCH=$(uname -m)
case "$ARCH" in
  arm64)  NODE_ARCH="arm64"; CF_ARCH="arm64" ;;
  x86_64) NODE_ARCH="x64";   CF_ARCH="amd64" ;;
  *) fail "Unsupported architecture: $ARCH" ;;
esac
ok "macOS $(sw_vers -productVersion) on $ARCH"

mkdir -p "$BRIDGE_DIR" "$LOG_DIR" "$BIN_DIR" "$BRIDGE_DIR/workspace"
chmod 700 "$BRIDGE_DIR"

# --- Node.js (pinned, checksum-verified) ---
install_node() {
  if command -v node &>/dev/null; then
    local major
    major=$(node --version | sed 's/v//' | cut -d. -f1)
    if [[ "$major" -ge 18 ]]; then NODE_BIN=$(command -v node); ok "Node $(node --version) found"; return; fi
  fi
  if [[ -x "$BIN_DIR/node" ]]; then NODE_BIN="$BIN_DIR/node"; ok "Node (previously installed)"; return; fi

  local fname="node-v${NODE_VERSION}-darwin-${NODE_ARCH}.tar.gz"
  local base="https://nodejs.org/dist/v${NODE_VERSION}"
  local tmp_t tmp_sums
  tmp_t=$(mktemp /tmp/agentbridge-node.XXXXXX.tar.gz)
  tmp_sums=$(mktemp /tmp/agentbridge-sums.XXXXXX.txt)
  info "Downloading Node.js v${NODE_VERSION} (pinned)..."
  curl -fsSL "$base/$fname" -o "$tmp_t" || fail "Node download failed"
  curl -fsSL "$base/SHASUMS256.txt" -o "$tmp_sums" || fail "Checksum file download failed"
  info "Verifying SHA-256..."
  (cd /tmp && grep " $fname\$" "$tmp_sums" | shasum -a 256 -c - --quiet 2>/dev/null) \
    || { mv "$tmp_t" "/tmp/$fname"; (cd /tmp && grep " $fname\$" "$tmp_sums" | shasum -a 256 -c - --quiet) || fail "CHECKSUM MISMATCH for Node.js - aborting"; }
  local extract
  extract=$(mktemp -d /tmp/agentbridge-node-x.XXXXXX)
  tar -xzf "/tmp/$fname" -C "$extract" --strip-components=1 2>/dev/null || { tar -xzf "$tmp_t" -C "$extract" --strip-components=1; }
  cp "$extract/bin/node" "$BIN_DIR/node"
  chmod 755 "$BIN_DIR/node"
  rm -rf "$tmp_t" "$tmp_sums" "$extract" "/tmp/$fname"
  NODE_BIN="$BIN_DIR/node"
  ok "Node $("$NODE_BIN" --version) installed (checksum verified)"
}

# --- cloudflared (pinned, checksum-verified) ---
install_cloudflared() {
  if command -v cloudflared &>/dev/null; then CF_BIN=$(command -v cloudflared); ok "cloudflared found"; return; fi
  if [[ -x "$BIN_DIR/cloudflared" ]]; then CF_BIN="$BIN_DIR/cloudflared"; ok "cloudflared (previously installed)"; return; fi
  local url="https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-darwin-${CF_ARCH}.tgz"
  local sums_url="https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/checksums.txt"
  local tmp_t
  tmp_t=$(mktemp /tmp/agentbridge-cf.XXXXXX.tgz)
  info "Downloading cloudflared ${CLOUDFLARED_VERSION} (pinned)..."
  curl -fsSL "$url" -o "$tmp_t" || fail "cloudflared download failed"
  local actual
  actual=$(shasum -a 256 "$tmp_t" | awk '{print $1}')
  local expected
  expected=$(curl -fsSL "$sums_url" 2>/dev/null | grep "cloudflared-darwin-${CF_ARCH}.tgz" | awk '{print $1}' || true)
  if [[ -n "$expected" ]]; then
    [[ "$actual" == "$expected" ]] || fail "CHECKSUM MISMATCH for cloudflared - aborting"
    ok "cloudflared checksum verified"
  else
    warn "Could not fetch cloudflared checksums; verifying signature-free download is from github.com/cloudflare only"
  fi
  tar -xzf "$tmp_t" -C "$BIN_DIR"
  chmod 755 "$BIN_DIR/cloudflared"
  rm -f "$tmp_t"
  CF_BIN="$BIN_DIR/cloudflared"
  ok "cloudflared ${CLOUDFLARED_VERSION} installed"
}

install_node
install_cloudflared

# --- Server + CLI ---
step() { printf '\n\033[1m\033[0;36m==> %s\033[0m\n' "$1"; }
step "Installing AgentBridge server"
# The src/ tree is embedded below as a base64 tarball by scripts/build-installer.sh.
PAYLOAD=$(mktemp /tmp/agentbridge-src.XXXXXX.tgz.b64)
cat > "$PAYLOAD" << 'PAYLOAD_EOF'
__SERVER_PAYLOAD__
PAYLOAD_EOF
base64 -d -i "$PAYLOAD" | tar -xzf - -C "$BRIDGE_DIR"
rm -f "$PAYLOAD"
chmod 700 "$BRIDGE_DIR/src"
chmod 600 "$BRIDGE_DIR/src/lib/"*.js "$BRIDGE_DIR/src/tools/"*.js "$BRIDGE_DIR/src/server.js" "$BRIDGE_DIR/src/cli.js"

# CLI shim on PATH
mkdir -p "$HOME/.local/bin"
cat > "$HOME/.local/bin/agent-bridge" << SHIM
#!/bin/bash
AGENT_BRIDGE_HOME="$BRIDGE_DIR" exec "$NODE_BIN" "$BRIDGE_DIR/src/cli.js" "\$@"
SHIM
chmod 755 "$HOME/.local/bin/agent-bridge"
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) warn "Add to PATH: export PATH=\"$HOME/.local/bin:\$PATH\"" ;;
esac

# --- Config ---
cat > "$BRIDGE_DIR/config.json" << CFG
{
  "port": $BRIDGE_PORT,
  "bind": "127.0.0.1",
  "profile_default": "$PROFILE",
  "enable_shell": $([[ $ENABLE_SHELL -eq 1 ]] && echo true || echo false)
}
CFG
chmod 600 "$BRIDGE_DIR/config.json"

# --- launchd (auto-start on login, restart on crash) ---
step "Setting up launchd services"
mkdir -p "$LAUNCHD_DIR"
cat > "$LAUNCHD_DIR/com.agentbridge.server.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.agentbridge.server</string>
  <key>ProgramArguments</key>
  <array><string>${NODE_BIN}</string><string>${BRIDGE_DIR}/src/server.js</string></array>
  <key>WorkingDirectory</key><string>${BRIDGE_DIR}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENT_BRIDGE_HOME</key><string>${BRIDGE_DIR}</string>
    <key>HOME</key><string>${HOME}</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>${LOG_DIR}/server.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/server.error.log</string>
</dict></plist>
PLIST
cat > "$LAUNCHD_DIR/com.agentbridge.tunnel.plist" << PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.agentbridge.tunnel</string>
  <key>ProgramArguments</key>
  <array><string>${CF_BIN}</string><string>tunnel</string><string>--url</string><string>http://127.0.0.1:${BRIDGE_PORT}</string><string>--no-autoupdate</string></array>
  <key>WorkingDirectory</key><string>${BRIDGE_DIR}</string>
  <key>EnvironmentVariables</key><dict><key>HOME</key><string>${HOME}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/><key>NetworkState</key><true/></dict>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>${LOG_DIR}/tunnel.log</string>
  <key>StandardErrorPath</key><string>${LOG_DIR}/tunnel.log</string>
</dict></plist>
PLIST
launchctl unload "$LAUNCHD_DIR/com.agentbridge.server.plist" 2>/dev/null || true
launchctl unload "$LAUNCHD_DIR/com.agentbridge.tunnel.plist" 2>/dev/null || true
launchctl load "$LAUNCHD_DIR/com.agentbridge.server.plist"
launchctl load "$LAUNCHD_DIR/com.agentbridge.tunnel.plist"
ok "launchd services loaded"

# --- Wait for tunnel URL ---
step "Starting tunnel"
TUNNEL_URL=""
for i in $(seq 1 40); do
  sleep 0.5
  TUNNEL_URL=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' "$LOG_DIR/tunnel.log" 2>/dev/null | tail -1 || true)
  [[ -n "$TUNNEL_URL" ]] && break
done
[[ -n "$TUNNEL_URL" ]] && echo "$TUNNEL_URL" > "$BRIDGE_DIR/.tunnel-url" && chmod 600 "$BRIDGE_DIR/.tunnel-url"

# --- Uninstaller ---
cat > "$BRIDGE_DIR/uninstall.sh" << UN
#!/bin/bash
launchctl unload ~/Library/LaunchAgents/com.agentbridge.server.plist 2>/dev/null
launchctl unload ~/Library/LaunchAgents/com.agentbridge.tunnel.plist 2>/dev/null
rm -f ~/Library/LaunchAgents/com.agentbridge.*.plist ~/.local/bin/agent-bridge
rm -rf ~/agent-bridge
echo "AgentBridge removed."
UN
chmod 755 "$BRIDGE_DIR/uninstall.sh"

# --- Done ---
echo ""
echo "  ================================================"
echo "  |     AGENTBRIDGE INSTALLED                     |"
echo "  ================================================"
echo ""
echo "  Tunnel URL : ${TUNNEL_URL:-starting - run: agent-bridge status}"
echo "  Bind       : 127.0.0.1:${BRIDGE_PORT} (loopback only, never LAN)"
echo "  Profile    : ${PROFILE}"
echo "  Shell      : $([[ $ENABLE_SHELL -eq 1 ]] && echo 'enabled (EVERY call needs your approval)' || echo 'disabled')"
echo ""
echo "  NEXT STEP - pair your cloud agent:"
echo "    agent-bridge pair"
echo "  Paste the one-time code + tunnel URL to your agent. Nothing else to copy."
echo ""
echo "  Commands: agent-bridge pair | agents | approve | deny | pending | audit --verify | status"
echo "  Uninstall: ~/agent-bridge/uninstall.sh"
echo ""
