#!/usr/bin/env bash
set -euo pipefail

echo "Tempo developer helper"
echo "----------------------"
echo

if ! command -v cargo >/dev/null 2>&1; then
  echo "Warning: cargo is not installed or not on PATH."
  echo "Install Rust from https://rustup.rs before working on Tempo."
  echo
fi

if ! command -v just >/dev/null 2>&1; then
  echo "Note: 'just' is not installed. Some developer workflows use the Justfile."
  echo "See https://github.com/casey/just for installation instructions."
  echo
fi

cat <<'EOF'
Suggested local workflows:

  Build all Rust crates:
    cargo build

  Run the main test suite:
    cargo test

  Run only fast checks (if you use just):
    just check

  Format Rust code:
    cargo fmt

  Run clippy lints:
    cargo clippy --all-targets --all-features

Run this script from the repository root:

  ./bin/dev_help.sh
EOF
