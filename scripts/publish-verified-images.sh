#!/usr/bin/env bash
# Promote the archives that passed verification; never re-run the build.
set -euo pipefail
: "${IMAGE_DIR:?IMAGE_DIR is required}"
: "${GITHUB_RUN_ID:?GITHUB_RUN_ID is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
artifact_attempt="${ARTIFACT_RUN_ATTEMPT:-$GITHUB_RUN_ATTEMPT}"
cd "$IMAGE_DIR"
sha256sum --check verified.sha256
metadata='{}'
for image in tempo tempo-devnet tempo-localnet tempo-sidecar tempo-xtask; do
  variable="${image^^}_TAGS"
  variable="${variable//-/_}"
  tags="${!variable}"
  [[ -n "$tags" ]] || { echo "Missing tags for $image" >&2; exit 1; }
  # Push an architecture tag once per destination repository, then create its
  # final multi-platform tags from the exact pushed manifest digests.
  mapfile -t repositories < <(printf '%s\n' "$tags" | sed 's/:[^/:]*$//' | sort -u)
  for repository in "${repositories[@]}"; do
    sources=()
    for arch in amd64 arm64; do
      docker load --input "docker-candidate-$arch-$artifact_attempt/$image.tar"
      source="$repository:verified-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT-$arch"
      docker tag "$image:candidate-$arch" "$source"
      digest="$(docker push --quiet "$source" | tail -n 1)"
      [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "Invalid pushed digest" >&2; exit 1; }
      sources+=("$repository@$digest")
    done
    tag_args=()
    while IFS= read -r tag; do
      [[ "${tag%:*}" != "$repository" ]] || tag_args+=(--tag "$tag")
    done <<< "$tags"
    docker buildx imagetools create "${tag_args[@]}" "${sources[@]}"
  done
  first_tag="${tags%%$'\n'*}"
  digest="$(docker buildx imagetools inspect "$first_tag" --format '{{.Manifest.Digest}}')"
  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]
  metadata="$(jq --arg image "$image" --arg digest "$digest" '.[$image] = {"containerimage.digest": $digest}' <<< "$metadata")"
done
printf 'metadata=%s\n' "$(jq -c . <<< "$metadata")" >> "$GITHUB_OUTPUT"
