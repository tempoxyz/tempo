#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec cargo run --manifest-path "$repo_root/Cargo.toml" -p tempo-tip1092-migration --bin tip1092-migrate -- "$@"
