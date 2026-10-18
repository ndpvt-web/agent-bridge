#!/bin/bash
# Build a self-contained install.sh with the src/ tree embedded.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="${1:-./dist/install-agent-bridge.sh}"
mkdir -p "$(dirname "$OUT")"
PAYLOAD=$(tar -czf - src | base64)
awk -v payload="$PAYLOAD" '
  /^__SERVER_PAYLOAD__$/ { print payload; next }
  { print }
' install.sh > "$OUT"
chmod 755 "$OUT"
echo "Built $OUT ($(wc -c < "$OUT") bytes)"
