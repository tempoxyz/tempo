#!/usr/bin/env bash
set -euo pipefail

WORKTREE_DIR="${1:?usage: bench-update-reth-ref.sh <worktree-dir> <reth-ref> [label]}"
RETH_REF="${2:-}"
LABEL="${3:-tempo}"
RETH_REPO="${RETH_REPO:-https://github.com/paradigmxyz/reth}"

if [ -z "$RETH_REF" ]; then
  exit 0
fi

if [ ! -f "$WORKTREE_DIR/Cargo.toml" ]; then
  echo "::error::Cargo.toml not found in $WORKTREE_DIR"
  exit 1
fi

resolve_reth_ref() {
  local ref="$1"
  local resolved=""

  if [[ "$ref" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    printf '%s' "$ref"
    return
  fi

  resolved="$(
    git ls-remote "$RETH_REPO" "$ref" "refs/heads/$ref" "refs/tags/$ref" "refs/tags/$ref^{}" |
      awk '
        BEGIN { first = ""; found = 0 }
        /\^\{\}$/ { print $1; found = 1; exit }
        first == "" { first = $1 }
        END { if (!found && first != "") print first }
      '
  )"

  if [ -z "$resolved" ]; then
    echo "::error::Unable to resolve reth ref '$ref' in $RETH_REPO"
    exit 1
  fi

  printf '%s' "$resolved"
}

NEW_RETH_REV="$(resolve_reth_ref "$RETH_REF")"
CURRENT_RETH_REV="$(
  grep -m1 'paradigmxyz/reth' "$WORKTREE_DIR/Cargo.toml" |
    sed -n 's/.*rev = "\([^"]*\)".*/\1/p' || true
)"

if [ -z "$CURRENT_RETH_REV" ]; then
  echo "::error::Unable to find current paradigmxyz/reth rev in $WORKTREE_DIR/Cargo.toml"
  exit 1
fi

if [ "$CURRENT_RETH_REV" = "$NEW_RETH_REV" ]; then
  echo "$LABEL reth rev already set to $NEW_RETH_REV"
  exit 0
fi

export CURRENT_RETH_REV NEW_RETH_REV
find "$WORKTREE_DIR" -name Cargo.toml -print0 |
  xargs -0 perl -0pi -e 's|paradigmxyz/reth", rev = "\Q$ENV{CURRENT_RETH_REV}\E"|paradigmxyz/reth", rev = "$ENV{NEW_RETH_REV}"|g'

echo "Updated $LABEL reth rev: $CURRENT_RETH_REV -> $NEW_RETH_REV"
