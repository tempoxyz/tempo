#!/bin/sh
#
# Get next available TIP number.
#
# Usage: next-number.sh
# Output: Next sequential TIP number on stdout
#
# Scans both main branch and open PRs to find highest existing number.
#

# Collect all TIP numbers from main and open PRs
all_tips=$(
  git ls-tree origin/main tips/
  gh pr list --state open --json files --jq '.[].files[].path' 2>/dev/null
)

# Extract highest number
max=$(
  echo "$all_tips" \
    | grep -oE 'tip-[0-9]+' \
    | sed 's/tip-//' \
    | sort -n \
    | tail -1
)

# Output next (default to 1011 if none exist)
echo $(( ${max:-1010} + 1 ))
