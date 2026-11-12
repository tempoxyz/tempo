#!/usr/bin/env bash
# Points held-back tags at digests that are already attested.
#
# Trusted runs publish each image under its per-commit sha- tag only, attest the
# digest, and only then move the tags deployments follow (edge, latest, nightly,
# stable, semver). DEFERRED_TAGS is a JSON array of
#   {"ref": "<registry>/tempoxyz/<name>@sha256:<digest>", "tags": ["<registry>/tempoxyz/<name>:<tag>", ...]}
# Each tag is a carbon copy of ref in the same repository, so it resolves to the
# attested digest; the script fails if any tag ends up anywhere else.
set -euo pipefail

: "${DEFERRED_TAGS:?DEFERRED_TAGS is required}"

count="$(jq -er 'if type == "array" then length else error("not an array") end' <<< "$DEFERRED_TAGS")"
if [[ "$count" -eq 0 ]]; then
  echo "No held tags to move"
  exit 0
fi

for ((i = 0; i < count; i++)); do
  ref="$(jq -er --argjson i "$i" '.[$i].ref' <<< "$DEFERRED_TAGS")"
  [[ "$ref" =~ ^(ghcr\.io|docker\.io)/tempoxyz/[a-z0-9-]+@sha256:[0-9a-f]{64}$ ]] || {
    echo "Invalid image reference: $ref" >&2
    exit 1
  }
  repository="${ref%@*}"
  digest="${ref#*@}"

  mapfile -t tags < <(jq -er --argjson i "$i" '.[$i].tags[]' <<< "$DEFERRED_TAGS")
  (( ${#tags[@]} > 0 )) || continue
  tag_args=()
  for tag in "${tags[@]}"; do
    [[ "$tag" == "$repository:"* && "${tag#"$repository:"}" =~ ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$ ]] || {
      echo "Tag $tag is not a tag of $repository" >&2
      exit 1
    }
    tag_args+=(--tag "$tag")
  done

  # --prefer-index=false copies the manifest as is, so the digest stays the attested one.
  docker buildx imagetools create --prefer-index=false "${tag_args[@]}" "$ref"

  for tag in "${tags[@]}"; do
    tag_digest=""
    for attempt in {1..12}; do
      tag_digest="$(docker buildx imagetools inspect "$tag" --format '{{.Manifest.Digest}}' 2>/dev/null || true)"
      [[ "$tag_digest" =~ ^sha256:[0-9a-f]{64}$ ]] && break
      echo "Waiting for $tag to become readable (attempt $attempt/12)"
      sleep 5
    done
    [[ "$tag_digest" == "$digest" ]] || {
      echo "Moving $tag left it on $tag_digest, not $digest" >&2
      exit 1
    }
    echo "Moved $tag to $digest"
  done
done
