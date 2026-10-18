#!/bin/bash
# Installer end-to-end test on Linux: fake HOME, stubbed macOS bits, and
# pre-seeded pinned-binary stubs in the install's bin/ (there is NO PATH
# fallback anymore - only the pinned, hash-verified builds are used).
# Verifies config generation, strict --profile/--mode validation, payload
# extraction, plists, effective-config banner, and the uninstaller.
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

# Pre-seed the pinned-binary stubs the installer would have downloaded
# (marker files must match the pins in install.sh).
PIN_NODE=$(grep -oP '^NODE_VERSION="\K[^"]+' install.sh)
PIN_CF=$(grep -oP '^CLOUDFLARED_VERSION="\K[^"]+' install.sh)
seed_bins() {
  mkdir -p "$FAKE/home/agent-bridge/bin"
  ln -sf "$(command -v node)" "$FAKE/home/agent-bridge/bin/node"
  echo "$PIN_NODE" > "$FAKE/home/agent-bridge/bin/.node-version"
  printf '#!/bin/bash\necho cloudflared %s\n' "$PIN_CF" > "$FAKE/home/agent-bridge/bin/cloudflared"
  chmod +x "$FAKE/home/agent-bridge/bin/cloudflared"
  echo "$PIN_CF" > "$FAKE/home/agent-bridge/bin/.cloudflared-version"
}

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

echo "=== installer: unknown flag rejected ==="
OUT=$(run_install --frob 2>&1); RC=$?
check "unknown flag fails" "$([ $RC -ne 0 ] && echo y)" "y"

echo "=== installer: happy path ==="
seed_bins
OUT=$(run_install --profile developer 2>&1); RC=$?
check "install succeeds" "$RC" "0"
CFG="$FAKE/home/agent-bridge/config.json"
check "config exists" "$([ -f "$CFG" ] && echo y)" "y"
check "config mode 600" "$(stat -c %a "$CFG" 2>/dev/null)" "600"
check "config valid JSON" "$(node -e "JSON.parse(require('fs').readFileSync('$CFG','utf8')); console.log('y')" 2>/dev/null)" "y"
check "config profile" "$(node -p "JSON.parse(require('fs').readFileSync('$CFG','utf8')).profile_default" 2>/dev/null)" "developer"
check "config bind loopback" "$(node -p "JSON.parse(require('fs').readFileSync('$CFG','utf8')).bind" 2>/dev/null)" "127.0.0.1"
check "no injected keys" "$(node -p "Object.keys(JSON.parse(require('fs').readFileSync('$CFG','utf8'))).join(',')" 2>/dev/null)" "port,bind,profile_default,enable_shell,mode"
check "src extracted" "$([ -f "$FAKE/home/agent-bridge/src/server.js" ] && echo y)" "y"
check "src perms locked" "$(stat -c %a "$FAKE/home/agent-bridge/src/server.js")" "600"
check "server plists written" "$(ls "$FAKE/home/Library/LaunchAgents/" 2>/dev/null | wc -l)" "2"
check "uninstaller written" "$([ -x "$FAKE/home/agent-bridge/uninstall.sh" ] && echo y)" "y"

echo "=== installer: re-run keeps config, banner shows EFFECTIVE config ==="
echo '{"port":7999,"mode":"full","profile_default":"readonly","enable_shell":true}' > "$CFG"; chmod 600 "$CFG"
OUT=$(run_install --profile developer --mode limited 2>&1); RC=$?
check "re-run succeeds" "$RC" "0"
check "existing config kept" "$(node -p "JSON.parse(require('fs').readFileSync('$CFG','utf8')).port" 2>/dev/null)" "7999"
check "banner mode from config, not flags" "$(echo "$OUT" | grep -c 'Mode       : full')" "1"
check "banner profile from config, not flags" "$(echo "$OUT" | grep -c 'Profile    : readonly')" "1"

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
