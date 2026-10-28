#!/usr/bin/env bash
# Installs an Earn checkout's public Solidity dependencies and prints its Foundry project root.
#
# tempoxyz/earn holds Earn either at the repository root, with lib/ submodules, or as the earn/
# project beside others, with dependencies pinned in earn/foundry.lock and installed by
# scripts/solidity-deps.sh. Workflows pass the printed path to `forge build --root`.
#
# Usage: .github/scripts/prepare-earn-checkout.sh <earn checkout>
set -euo pipefail

checkout="$(cd "${1:?usage: $0 <earn checkout>}" && pwd)"

if [[ -f "$checkout/earn/foundry.toml" ]]; then
  # Also builds Earn's pinned solar with cargo when earn/solar.lock exists. Build it with none of the
  # job's Rust settings: RUSTC_WRAPPER may name an sccache that is not installed yet, linker flags
  # may name a mold that is not installed, and RUSTFLAGS such as target-cpu=native would make the
  # shared solar cache non-portable across runners.
  (
    cd "$checkout"
    for name in $(compgen -e); do
      case "$name" in
        RUSTC_WRAPPER | RUSTC_WORKSPACE_WRAPPER | RUSTFLAGS | RUSTDOCFLAGS | CARGO_ENCODED_RUSTFLAGS | \
          CARGO_BUILD_RUSTFLAGS | CARGO_BUILD_RUSTC_WRAPPER | CARGO_TARGET_*_RUSTFLAGS | CARGO_TARGET_*_LINKER)
          unset "$name"
          ;;
      esac
    done
    bash scripts/solidity-deps.sh earn
  ) >&2
  echo "$checkout/earn"
else
  # PropAMM is private and only needed by Earn's integration tests.
  git -C "$checkout" submodule update --init lib/forge-std lib/openzeppelin-contracts >&2
  echo "$checkout"
fi
