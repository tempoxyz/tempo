#!/usr/bin/env bash
# Resolve only artifacts actually pushed by Bake, never metadata-action's planned tags.
set -euo pipefail

case "$TEMPO_TARGET" in
  tempo|tempo-nightly) ;;
  *) echo "Unexpected Tempo target: $TEMPO_TARGET" >&2; exit 1 ;;
esac

jq -er --arg tempo_target "$TEMPO_TARGET" '
  . as $metadata
  | [$tempo_target, "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
  | map(. as $target | $metadata[$target]
      | .["containerimage.digest"] as $digest
      | .["image.name"] as $names
      | if ($digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))
          and ($names | type == "string" and length > 0)
        then $names | split(",")[]
          | if test("^[^@,[:space:]]+:[^/:@,[:space:]]+$")
            then sub(":[^/:]+$"; "") + "@" + $digest
            else error("Invalid published image name for " + $target)
            end
        else error("Missing published image metadata for " + $target)
        end)
  | unique[]
' <<< "$BUILD_METADATA" > "${RUNNER_TEMP}/docker-signing-refs.txt"

jq -e --arg target "$TEMPO_TARGET" --arg commit "$GITHUB_SHA" \
  --arg run_id "$GITHUB_RUN_ID" --arg run_attempt "$GITHUB_RUN_ATTEMPT" '
  {digest: .[$target]["containerimage.digest"], target: $target,
   commit: $commit, run_id: $run_id, run_attempt: $run_attempt}
' <<< "$BUILD_METADATA" > "${RUNNER_TEMP}/tempo-image.json"

echo "digest=$(jq -er '.digest' "${RUNNER_TEMP}/tempo-image.json")" >> "$GITHUB_OUTPUT"
