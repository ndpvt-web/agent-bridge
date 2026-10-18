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

# Pinned dependency versions AND their SHA-256 hashes, embedded in this
# installer. Verification is fail-closed: a checksum mismatch aborts the
# install. To upgrade, change the version and its two hashes together.
NODE_VERSION="22.20.0"
NODE_SHA256_ARM64="cc04a76a09f79290194c0646f48fec40354d88969bec467789a5d55dd097f949"
NODE_SHA256_X64="00df9c5df3e4ec6848c26b70fb47bf96492f342f4bed6b17f12d99b3a45eeecc"
CLOUDFLARED_VERSION="2025.9.1"
CF_SHA256_ARM64="0c20739ccab70c804e97b824a048e2028869c01e8c795b0033dd66b61962d491"
CF_SHA256_AMD64="3d205852967f91823798dd909cc8e0a10c07db7ab0a9f0a7b5fd21a0e7766e82"

# --- Input validation (values are interpolated into config + plists) ---
case "$PROFILE" in readonly|workspace|developer) ;; *) fail "Unknown --profile '$PROFILE' (want readonly|workspace|developer)";; esac
case "$BRIDGE_PORT" in ''|*[!0-9]*) fail "AGENT_BRIDGE_PORT must be numeric";; esac
[[ "$BRIDGE_PORT" -ge 1024 && "$BRIDGE_PORT" -le 65535 ]] || fail "AGENT_BRIDGE_PORT out of range"
case "$HOME" in *[\&\<\>]*) fail "HOME contains characters unsafe for plist XML";; esac

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
  if [[ -x "$BIN_DIR/node" ]]; then NODE_BIN="$BIN_DIR/node"; ok "Node (previously installed, pinned)"; return; fi
  if command -v node &>/dev/null; then
    local major
    major=$(node --version | sed 's/v//' | cut -d. -f1)
    if [[ "$major" -ge 18 ]]; then
      NODE_BIN=$(command -v node)
      warn "Using system Node $(node --version) (NOT pinned/verified). Remove it from PATH to force the pinned download."
      return
    fi
  fi

  local fname="node-v${NODE_VERSION}-darwin-${NODE_ARCH}.tar.gz"
  local expected
  if [[ "$NODE_ARCH" == "arm64" ]]; then expected="$NODE_SHA256_ARM64"; else expected="$NODE_SHA256_X64"; fi
  local work
  work=$(mktemp -d) || fail "mktemp failed"
  info "Downloading Node.js v${NODE_VERSION} (pinned)..."
  curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/$fname" -o "$work/node.tar.gz" || fail "Node download failed"
  info "Verifying SHA-256 against the hash pinned in this installer..."
  local actual
  actual=$(shasum -a 256 "$work/node.tar.gz" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || fail "CHECKSUM MISMATCH for Node.js (got $actual) - aborting"
  mkdir -p "$work/x"
  tar -xzf "$work/node.tar.gz" -C "$work/x" --strip-components=1
  cp "$work/x/bin/node" "$BIN_DIR/node"
  chmod 755 "$BIN_DIR/node"
  rm -rf "$work"
  NODE_BIN="$BIN_DIR/node"
  ok "Node $("$NODE_BIN" --version) installed (pinned hash verified)"
}

# --- cloudflared (pinned, checksum-verified) ---
install_cloudflared() {
  if [[ -x "$BIN_DIR/cloudflared" ]]; then CF_BIN="$BIN_DIR/cloudflared"; ok "cloudflared (previously installed, pinned)"; return; fi
  if command -v cloudflared &>/dev/null; then
    CF_BIN=$(command -v cloudflared)
    warn "Using system cloudflared (NOT pinned/verified). Remove it from PATH to force the pinned download."
    return
  fi
  local expected
  if [[ "$CF_ARCH" == "arm64" ]]; then expected="$CF_SHA256_ARM64"; else expected="$CF_SHA256_AMD64"; fi
  local work
  work=$(mktemp -d) || fail "mktemp failed"
  info "Downloading cloudflared ${CLOUDFLARED_VERSION} (pinned)..."
  curl -fsSL "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-darwin-${CF_ARCH}.tgz" -o "$work/cf.tgz" || fail "cloudflared download failed"
  local actual
  actual=$(shasum -a 256 "$work/cf.tgz" | awk '{print $1}')
  [[ "$actual" == "$expected" ]] || fail "CHECKSUM MISMATCH for cloudflared (got $actual) - aborting"
  tar -xzf "$work/cf.tgz" -C "$BIN_DIR"
  chmod 755 "$BIN_DIR/cloudflared"
  rm -rf "$work"
  CF_BIN="$BIN_DIR/cloudflared"
  ok "cloudflared ${CLOUDFLARED_VERSION} installed (pinned hash verified)"
}

install_node
install_cloudflared

# --- Server + CLI ---
step() { printf '\n\033[1m\033[0;36m==> %s\033[0m\n' "$1"; }
step "Installing AgentBridge server"
# The src/ tree is embedded below as a base64 tarball by scripts/build-installer.sh.
WORK=$(mktemp -d) || fail "mktemp failed"
cat > "$WORK/payload.b64" << 'PAYLOAD_EOF'
__SERVER_PAYLOAD__
PAYLOAD_EOF
base64 -d -i "$WORK/payload.b64" | tar -xzf - -C "$BRIDGE_DIR"
rm -rf "$WORK"
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

# --- Config (never silently clobber an existing install's choices) ---
if [[ -f "$BRIDGE_DIR/config.json" ]]; then
  ok "Existing config.json kept (edit it directly to change settings)"
else
cat > "$BRIDGE_DIR/config.json" << CFG
{
  "port": $BRIDGE_PORT,
  "bind": "127.0.0.1",
  "profile_default": "$PROFILE",
  "enable_shell": $([[ $ENABLE_SHELL -eq 1 ]] && echo true || echo false)
}
CFG
chmod 600 "$BRIDGE_DIR/config.json"
fi

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
cat > "$BRIDGE_DIR/uninstall.sh" << 'UN'
#!/bin/bash
set -e
echo "This disconnects all agents and removes the bridge, its keys and logs."
echo "Your workspace, trash and versions are KEPT unless you pass --purge."
read -r -p "Continue? [y/N] " a
[[ "$a" == "y" || "$a" == "Y" ]] || { echo "Aborted."; exit 1; }
launchctl unload ~/Library/LaunchAgents/com.agentbridge.server.plist 2>/dev/null || true
launchctl unload ~/Library/LaunchAgents/com.agentbridge.tunnel.plist 2>/dev/null || true
rm -f ~/Library/LaunchAgents/com.agentbridge.server.plist ~/Library/LaunchAgents/com.agentbridge.tunnel.plist ~/.local/bin/agent-bridge
if [[ "${1:-}" == "--purge" ]]; then
  rm -rf ~/agent-bridge
  echo "AgentBridge and all data removed."
else
  rm -rf ~/agent-bridge/src ~/agent-bridge/secrets ~/agent-bridge/approvals ~/agent-bridge/logs ~/agent-bridge/bin ~/agent-bridge/config.json ~/agent-bridge/.tunnel-url
  echo "AgentBridge removed. Kept: ~/agent-bridge/{workspace,trash,versions}"
fi
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
