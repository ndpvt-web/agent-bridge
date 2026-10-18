#!/bin/bash
# Installer end-to-end test on Linux: fake HOME, stubbed macOS bits, system
# node/cloudflared as the PATH fallback. Verifies config generation, strict
# --profile validation, payload extraction, plists, and the uninstaller.
set -uo pipefail
cd "$(dirname "$0")/.."
PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "  PASS  $1"; else FAIL=$((FAIL+1)); echo "  FAIL  $1 (want [$3] got [$2])"; fi }

FAKE=$(mktemp -d)
STUBS="$FAKE/stubs"
mkdir -p "$STUBS" "$FAKE/home"

# --- stubs ---
uname() { if [ "${1:-}" = "-m" ]; then echo arm64; else echo Darwin; fi; }
sw_vers() { echo "15.1"; }
launchctl() { return 0; }
export -f uname sw_vers launchctl
export PATH="$STUBS:$PATH"
# fake cloudflared and node on PATH (fallback path, no downloads)
printf '#!/bin/bash\necho cloudflared 2025.9.1\n' > "$STUBS/cloudflared"
chmod +x "$STUBS/cloudflared"
ln -s "$(command -v node)" "$STUBS/node"

run_install() {
  (export HOME="$FAKE/home"; export -f uname sw_vers launchctl; bash ./dist/install-agent-bridge.sh "$@") 
}

echo "=== installer: bad profile rejected ==="
OUT=$(run_install --profile bogus 2>&1); RC=$?
check "bogus profile fails" "$([ $RC -ne 0 ] && echo y)" "y"
check "no config written" "$([ -f "$FAKE/home/agent-bridge/config.json" ] && echo y || echo n)" "n"

echo "=== installer: profile injection rejected ==="
OUT=$(run_install --profile 'readonly", "bind": "0.0.0.0", "z":"' 2>&1); RC=$?
check "injection fails" "$([ $RC -ne 0 ] && echo y)" "y"

echo "=== installer: bad port rejected ==="
OUT=$(AGENT_BRIDGE_PORT=abc run_install 2>&1); RC=$?
check "non-numeric port fails" "$([ $RC -ne 0 ] && echo y)" "y"
OUT=$(AGENT_BRIDGE_PORT=80 run_install 2>&1); RC=$?
check "port 80 fails" "$([ $RC -ne 0 ] && echo y)" "y"

echo "=== installer: happy path ==="
OUT=$(run_install --profile developer 2>&1); RC=$?
check "install succeeds" "$RC" "0"
CFG="$FAKE/home/agent-bridge/config.json"
check "config exists" "$([ -f "$CFG" ] && echo y)" "y"
check "config mode 600" "$(stat -c %a "$CFG" 2>/dev/null)" "600"
check "config valid JSON" "$(node -e "JSON.parse(require('fs').readFileSync('$CFG','utf8')); console.log('y')" 2>/dev/null)" "y"
check "config profile" "$(node -p "JSON.parse(require('fs').readFileSync('$CFG','utf8')).profile_default" 2>/dev/null)" "developer"
check "config bind loopback" "$(node -p "JSON.parse(require('fs').readFileSync('$CFG','utf8')).bind" 2>/dev/null)" "127.0.0.1"
check "no injected keys" "$(node -p "Object.keys(JSON.parse(require('fs').readFileSync('$CFG','utf8'))).join(',')" 2>/dev/null)" "port,bind,profile_default,enable_shell"
check "src extracted" "$([ -f "$FAKE/home/agent-bridge/src/server.js" ] && echo y)" "y"
check "src perms locked" "$(stat -c %a "$FAKE/home/agent-bridge/src/server.js")" "600"
check "server plists written" "$(ls "$FAKE/home/Library/LaunchAgents/" 2>/dev/null | wc -l)" "2"
check "uninstaller written" "$([ -x "$FAKE/home/agent-bridge/uninstall.sh" ] && echo y)" "y"

echo "=== installer: re-run keeps config ==="
echo '{"port":7999}' > "$CFG"; chmod 600 "$CFG"
OUT=$(run_install 2>&1); RC=$?
check "re-run succeeds" "$RC" "0"
check "existing config kept" "$(node -p "JSON.parse(require('fs').readFileSync('$CFG','utf8')).port" 2>/dev/null)" "7999"

echo "=== uninstaller: keeps workspace, purge removes all ==="
mkdir -p "$FAKE/home/agent-bridge/workspace" && touch "$FAKE/home/agent-bridge/workspace/keep.txt"
OUT=$(echo y | (export HOME="$FAKE/home"; bash "$FAKE/home/agent-bridge/uninstall.sh") 2>&1)
check "workspace kept" "$([ -f "$FAKE/home/agent-bridge/workspace/keep.txt" ] && echo y)" "y"
check "src removed" "$([ -d "$FAKE/home/agent-bridge/src" ] && echo y || echo n)" "n"
OUT=$(echo y | (export HOME="$FAKE/home"; bash "$FAKE/home/agent-bridge/uninstall.sh" --purge) 2>&1)
check "purge removes everything" "$([ -d "$FAKE/home/agent-bridge" ] && echo y || echo n)" "n"

echo ""
echo "INSTALLER E2E: $PASS passed, $FAIL failed"
rm -rf "$FAKE"
[ "$FAIL" -eq 0 ]
