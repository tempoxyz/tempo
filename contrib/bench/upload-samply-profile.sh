#!/usr/bin/env bash
# Upload a samply profile (.json.gz) to Firefox Profiler.
# Prints the (shortened) profile URL to stdout; progress and errors go to stderr.
# Usage: upload-samply-profile.sh <profile.json.gz>
#
# Same upload flow as reth's .github/workflows/bench.yml, plus size handling:
# api.profiler.firefox.com rejects bodies above 150 MiB (MAX_BODY_LENGTH in
# profiler-server src/routes/publish.ts). Profiles recorded with --log.samply are
# several times that because of tracing-span markers, so anything above
# SAMPLY_UPLOAD_MAX_BYTES is first shrunk with shrink-samply-profile.py (short
# interval markers dropped, samples untouched, note added to meta.extra). The
# original file is never modified; the shrunk copy is removed after a successful
# upload unless SAMPLY_KEEP_SHRUNK=1.
#
# Environment:
#   SAMPLY_UPLOAD_MAX_BYTES  shrink profiles larger than this (default 140 MiB)
#   SAMPLY_KEEP_SHRUNK       set to 1 to keep the shrunk copy next to the original
#   PROFILER_API             API base URL (default https://api.profiler.firefox.com)

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <profile.json.gz>" >&2
  exit 2
fi

PROFILE="$1"
PROFILER_API="${PROFILER_API:-https://api.profiler.firefox.com}"
ACCEPT="Accept: application/vnd.firefox-profiler+json;version=1.0"
MAX_BYTES="${SAMPLY_UPLOAD_MAX_BYTES:-146800640}" # 140 MiB, headroom below the 150 MiB limit
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "$*" >&2; }
size_of() { wc -c <"$1" | tr -d ' '; }
mib() { awk -v b="$1" 'BEGIN { printf "%.1f MiB", b / 1048576 }'; }

if [ ! -f "$PROFILE" ]; then
  log "Error: profile not found: $PROFILE"
  exit 1
fi

UPLOAD="$PROFILE"
SHRUNK=""
SIZE=$(size_of "$PROFILE")
if [ "$SIZE" -gt "$MAX_BYTES" ]; then
  case "$PROFILE" in
    *.json.gz) SHRUNK="${PROFILE%.json.gz}.shrunk.json.gz" ;;
    *) SHRUNK="${PROFILE}.shrunk.json.gz" ;;
  esac
  log "Profile $(basename "$PROFILE") is $(mib "$SIZE"), above the $(mib "$MAX_BYTES") threshold (profiler.firefox.com rejects uploads over 150 MiB); shrinking to $(basename "$SHRUNK"), original kept"
  if ! python3 "$SCRIPT_DIR/shrink-samply-profile.py" --max-bytes "$MAX_BYTES" "$PROFILE" "$SHRUNK"; then
    log "Error: could not shrink $(basename "$PROFILE") to fit the upload limit; not uploading"
    exit 1
  fi
  UPLOAD="$SHRUNK"
  log "Uploading shrunk profile $(basename "$UPLOAD") ($(mib "$(size_of "$UPLOAD")")) instead of the original"
fi

RESPONSE=$(mktemp)
trap 'rm -f "$RESPONSE"' EXIT

# Upload compressed profile → get JWT. Capture the HTTP status so a rejected
# upload (e.g. 413 Payload Too Large) is reported instead of swallowed.
HTTP_STATUS=$(curl -sS -o "$RESPONSE" -w '%{http_code}' -X POST \
  -H "Content-Type: application/octet-stream" \
  -H "$ACCEPT" \
  --data-binary "@$UPLOAD" \
  "$PROFILER_API/compressed-store") || {
  log "Error: upload request to $PROFILER_API/compressed-store failed (curl exit $?)"
  exit 1
}
case "$HTTP_STATUS" in
  2??) ;;
  *)
    log "Error: Firefox Profiler rejected $(basename "$UPLOAD") ($(mib "$(size_of "$UPLOAD")")) with HTTP $HTTP_STATUS: $(head -c 300 "$RESPONSE" | tr -d '\n')"
    exit 1
    ;;
esac
JWT=$(cat "$RESPONSE")

# Extract profileToken from JWT payload (header.payload.signature); the payload
# is base64url, so map its alphabet back to standard base64 before decoding.
PAYLOAD=$(echo "$JWT" | cut -d. -f2 | tr '_-' '/+')
case $(( ${#PAYLOAD} % 4 )) in
  2) PAYLOAD="${PAYLOAD}==" ;;
  3) PAYLOAD="${PAYLOAD}=" ;;
esac
PROFILE_TOKEN=$(echo "$PAYLOAD" | base64 -d 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['profileToken'])") || {
  log "Error: could not extract profileToken from upload response: $(head -c 300 "$RESPONSE" | tr -d '\n')"
  exit 1
}
PROFILE_URL="https://profiler.firefox.com/public/${PROFILE_TOKEN}"

# Shorten the URL (fall back to long URL on failure)
SHORT_URL=$(curl -sf -X POST \
  -H "Content-Type: application/json" \
  -H "$ACCEPT" \
  -d "{\"longUrl\":\"$PROFILE_URL\"}" \
  "$PROFILER_API/shorten" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['shortUrl'])" 2>/dev/null) || SHORT_URL="$PROFILE_URL"

if [ -n "$SHRUNK" ] && [ "${SAMPLY_KEEP_SHRUNK:-0}" != "1" ]; then
  rm -f "$SHRUNK"
fi

echo "$SHORT_URL"
