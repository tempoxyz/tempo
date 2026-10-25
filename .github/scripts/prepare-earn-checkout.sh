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
  (cd "$checkout" && bash scripts/solidity-deps.sh earn) >&2
  echo "$checkout/earn"
else
  # PropAMM is private and only needed by Earn's integration tests.
  git -C "$checkout" submodule update --init lib/forge-std lib/openzeppelin-contracts >&2
  echo "$checkout"
fi
