#!/usr/bin/env bash
# Compiles TopOfBlockRegistry.sol into crates/contracts/abi/TopOfBlockRegistry.json.
# Requires solc 0.8.30 (set SOLC to its path if it is not on PATH) and jq.
set -euo pipefail

dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
solc="${SOLC:-solc}"

"$solc" --version | grep -q '0\.8\.30' || {
  echo "expected solc 0.8.30, got: $("$solc" --version | tail -1)" >&2
  exit 1
}

cd "$dir"
"$solc" --optimize --optimize-runs 200 --evm-version cancun --metadata-hash none \
  --combined-json abi,bin,bin-runtime TopOfBlockRegistry.sol |
  jq '.contracts["TopOfBlockRegistry.sol:TopOfBlockRegistry"] | {
    abi: .abi,
    bytecode: { object: ("0x" + .bin) },
    deployedBytecode: { object: ("0x" + .["bin-runtime"]) }
  }' >../abi/TopOfBlockRegistry.json
