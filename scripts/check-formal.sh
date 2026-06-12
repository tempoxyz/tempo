#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/../formal/lean"
if command -v lake >/dev/null 2>&1; then
  lake --wfail build
else
  "$HOME/.elan/bin/lake" --wfail build
fi
