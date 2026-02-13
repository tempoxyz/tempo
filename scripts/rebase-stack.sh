#!/usr/bin/env bash
set -euo pipefail

# Rebase the abi-macro PR stack.
#
# Usage:
#   ./scripts/rebase-stack.sh                       # rebase all children of abi-macro
#   ./scripts/rebase-stack.sh migrate-tip20-factory  # "I changed tip20-factory, propagate downward"
#   ./scripts/rebase-stack.sh --push                 # rebase + force-push all rebased branches

STACK=(
  rus/abi-macro
  rus/migrate-tip20-factory
  rus/migrate-tip403-registry
  rus/migrate-nonce
  rus/migrate-tip-fee-manager
  rus/migrate-account-keychain
  rus/migrate-validator-config
  rus/migrate-stable-dex
  rus/migrate-tip20
)

push=false
start_from=""

for arg in "$@"; do
  if [[ "$arg" == "--push" ]]; then
    push=true
  else
    start_from="$arg"
  fi
done

# When the user specifies a branch, they mean "I modified THIS branch,
# propagate to everything after it." So we start rebasing at the NEXT index.
start_idx=1
if [[ -n "$start_from" ]]; then
  found=false
  for i in "${!STACK[@]}"; do
    if [[ "${STACK[$i]}" == *"$start_from"* ]]; then
      start_idx=$((i + 1))
      found=true
      break
    fi
  done
  if ! $found; then
    echo "error: no branch matching '$start_from' found in stack"
    exit 1
  fi
  if (( start_idx >= ${#STACK[@]} )); then
    echo "error: '$start_from' is the last branch in the stack, nothing to propagate"
    exit 1
  fi
fi

current_branch=$(git symbolic-ref --short HEAD 2>/dev/null || true)

# Save the CURRENT tip of each branch's PARENT before any rebasing.
# The parent's old tip is the exclusion point: commits in child NOT
# reachable from parent's old tip = child's own commits.
declare -a parent_old_tips
for i in "${!STACK[@]}"; do
  parent_old_tips[$i]=$(git rev-parse "${STACK[$i]}")
done

rebased=()

for (( i=start_idx; i<${#STACK[@]}; i++ )); do
  parent="${STACK[$((i-1))]}"
  child="${STACK[$i]}"
  # Use the PARENT's old tip as exclusion point, not the child's
  old_parent_tip="${parent_old_tips[$((i-1))]}"

  echo "=== Rebasing $child onto $parent ==="
  echo "    (replaying commits after ${old_parent_tip:0:8})"
  git rebase --onto "$parent" "$old_parent_tip" "$child"
  echo "  ✅ done"

  rebased+=("$child")
done

# Restore original branch
if [[ -n "$current_branch" ]]; then
  git checkout "$current_branch" --quiet 2>/dev/null || true
fi

echo ""
echo "Rebased ${#rebased[@]} branches."

if $push; then
  echo ""
  for branch in "${rebased[@]}"; do
    echo "=== Pushing $branch ==="
    git push --force-with-lease origin "$branch"
  done
  echo ""
  echo "Pushed ${#rebased[@]} branches."
fi
