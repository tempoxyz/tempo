#!/usr/bin/env bash
set -euo pipefail

# Print a short summary of the current Tempo codebase:
# - current branch
# - latest tag (if any)
# - short commit hash
# This is useful when attaching logs or metrics from dev or test environments.

if ! command -v git >/dev/null 2>&1; then
  echo "[tempo-release] git is not available on PATH" >&2
  exit 1
fi

branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")"
tag="$(git describe --tags --abbrev=0 2>/dev/null || echo "no-tag")"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")"

echo "Tempo release info:"
echo "  Branch: ${branch}"
echo "  Tag:    ${tag}"
echo "  Commit: ${commit}"
