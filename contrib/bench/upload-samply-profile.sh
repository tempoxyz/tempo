#!/usr/bin/env bash
# Upload a samply profile (.json.gz) to Firefox Profiler.
# Prints the (shortened) profile URL to stdout.
# Usage: upload-samply-profile.sh <profile.json.gz>
#
# Same approach as reth's .github/workflows/bench.yml

set -euo pipefail

PROFILE="$1"
PROFILER_API="https://api.profiler.firefox.com"
ACCEPT="Accept: application/vnd.firefox-profiler+json;version=1.0"

# Upload compressed profile → get JWT
JWT=$(curl -sf -X POST \
  -H "Content-Type: application/octet-stream" \
  -H "$ACCEPT" \
  --data-binary "@$PROFILE" \
  "$PROFILER_API/compressed-store") || { echo "Upload failed" >&2; exit 1; }

# Extract profileToken from JWT payload (header.payload.signature)
PAYLOAD=$(echo "$JWT" | cut -d. -f2)
case $(( ${#PAYLOAD} % 4 )) in
  2) PAYLOAD="${PAYLOAD}==" ;;
  3) PAYLOAD="${PAYLOAD}=" ;;
esac
PROFILE_TOKEN=$(echo "$PAYLOAD" | base64 -d 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['profileToken'])")
PROFILE_URL="https://profiler.firefox.com/public/${PROFILE_TOKEN}"

# Shorten the URL (fall back to long URL on failure)
SHORT_URL=$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -H "$ACCEPT" \
  -d "{\"longUrl\":\"$PROFILE_URL\"}" \
  "$PROFILER_API/shorten" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['shortUrl'])" 2>/dev/null) || SHORT_URL="$PROFILE_URL"

echo "$SHORT_URL"
