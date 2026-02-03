#!/bin/sh
#
# Validate TIP title against standards.
#
# Usage: validate.sh <file>
# Exit:  0 if valid, 1 with error message on stdout if invalid
#
# Rules:
#   - Title required in frontmatter
#   - Max 44 characters
#   - No word "standard"
#   - No TIP-N references (except TIP-20, TIP-403)
#
set -e

file="$1"
title=$(sed -n 's/^title: *//p' "$file" | head -1 | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')

# Title required
if [ -z "$title" ]; then
  echo "missing title"
  exit 1
fi

# Max length
if [ ${#title} -gt 44 ]; then
  echo "title too long (${#title}/44)"
  exit 1
fi

# No "standard"
if echo "$title" | grep -qi standard; then
  echo "contains 'standard'"
  exit 1
fi

# No TIP-N (except allowed)
if echo "$title" | grep -oE 'TIP-[0-9]+' | grep -qvE '^(TIP-20|TIP-403)$'; then
  echo "contains TIP number"
  exit 1
fi
