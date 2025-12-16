#!/usr/bin/env bash
set -euo pipefail

# Quick check that the main tools required by Tempo are available.

TOOLS=(
  "rustc"
  "cargo"
  "just"
)

echo "Checking required tools for Tempo..."

missing=()

for tool in "${TOOLS[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    version="$("$tool" --version 2>/dev/null || echo "")"
    echo "✅ ${tool} found ${version:+(${version})}"
  else
    echo "⚠️  ${tool} is not installed or not on PATH"
    missing+=("$tool")
  fi
done

if [ "${#missing[@]}" -gt 0 ]; then
  echo
  echo "The following tools are missing:"
  for tool in "${missing[@]}"; do
    echo "  - ${tool}"
  done
  echo
  echo "Please install them before running Tempo locally."
  exit 1
fi

echo
echo "All required tools appear to be installed."
