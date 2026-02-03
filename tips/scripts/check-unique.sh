#!/bin/sh
#
# Check if TIP number is unique.
#
# Usage: check-unique.sh <file> <pr_number>
# Exit:  0 if unique, 1 with error message on stdout if taken
#
# Checks:
#   - Not already on main branch
#   - Not used in another open PR
#

file="$1"
pr="$2"
num=$(echo "$file" | grep -oE '[0-9]+')

# Check main branch
if git ls-tree origin/main "$file" 2>/dev/null | grep -q .; then
  echo "TIP-$num exists on main"
  exit 1
fi

# Check other open PRs
other_prs=$(
  gh pr list --state open --json number,files \
    --jq ".[] | select(.number != $pr) | .files[].path" 2>/dev/null
)

if echo "$other_prs" | grep -q "^$file$"; then
  echo "TIP-$num used in another PR"
  exit 1
fi
