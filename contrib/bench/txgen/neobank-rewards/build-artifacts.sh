#!/usr/bin/env bash
set -euo pipefail

readonly ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly OUT="$ROOT/artifacts"
readonly EXPLORER="https://explore.tempo.xyz/api/code"
readonly CHAIN_ID=4217
readonly SOLC_URL="https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-v0.8.25+commit.b61c2a91"
readonly SOLC_SHA256="c42aada7a52057ddbed93ec011235e256c564c440b68dbaac5ae482babbb3d6d"
readonly DISTRIBUTOR=0x918261fa5dd9c3b1358cA911792E9bDF3c5CCa35
readonly PROXY=0x3Ef3D8bA38EBe18DB133cEc108f4D14CE00Dd9Ae
readonly WRAPPER=0x5f5dE6338Bc78CB528E08ef6A8328956E5a68C5C

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$OUT"
curl -fsSL "$SOLC_URL" -o "$tmp/solc"
printf '%s  %s\n' "$SOLC_SHA256" "$tmp/solc" | sha256sum --check --status
chmod +x "$tmp/solc"

compile_standard_json() {
  local input=$1
  local output=$2

  "$tmp/solc" --standard-json <"$input" >"$output"

  if jq -e '.errors[]? | select(.severity == "error")' "$output" >/dev/null; then
    jq -r '.errors[] | select(.severity == "error") | .formattedMessage' "$output" >&2
    return 1
  fi
}

write_artifact() {
  local output=$1
  local source=$2
  local contract=$3
  local destination=$4

  jq --arg source "$source" --arg contract "$contract" \
    '.contracts[$source][$contract]
      | {
          abi,
          bytecode: { object: ("0x" + .evm.bytecode.object) },
          deployedBytecode: {
            object: ("0x" + .evm.deployedBytecode.object),
            immutableReferences: .evm.deployedBytecode.immutableReferences
          }
        }' "$output" >"$destination"
}

compile_verified() {
  local address=$1
  local source=$2
  local contract=$3
  local destination=$4
  local slug=$5

  curl -fsSL "$EXPLORER?address=${address,,}&chainId=$CHAIN_ID&highlight=false" >"$tmp/$slug.json"
  jq '.stdJsonInput | .sources |= with_entries(.value = {content: .value.content})' \
    "$tmp/$slug.json" >"$tmp/$slug-input.json"
  compile_standard_json "$tmp/$slug-input.json" "$tmp/$slug-output.json"
  write_artifact "$tmp/$slug-output.json" "$source" "$contract" "$OUT/$destination"
}

compile_verified \
  "$DISTRIBUTOR" \
  contracts/Distributor.sol \
  Distributor \
  distributor.json \
  distributor

# Derive the benchmark-only implementation from the exact verified production
# compiler input. The transformer asserts every source fragment it changes so
# an upstream source change cannot silently alter the benchmark contract.
node "$ROOT/transform-benchmark-distributor.mjs" \
  "$tmp/distributor-input.json" \
  "$tmp/benchmark-distributor-input.json"
compile_standard_json \
  "$tmp/benchmark-distributor-input.json" \
  "$tmp/benchmark-distributor-output.json"
write_artifact \
  "$tmp/benchmark-distributor-output.json" \
  contracts/Distributor.sol \
  BenchmarkDistributor \
  "$OUT/benchmark-distributor.json"

compile_verified \
  "$PROXY" \
  contracts/vendor/OZProxyImports.sol \
  ERC1967ProxyImport \
  erc1967-proxy.json \
  proxy

compile_verified \
  "$WRAPPER" \
  contracts/partners/tokenWrappers/PullTokenWrapperAllowImmutable.sol \
  PullTokenWrapperAllowImmutable \
  pull-token-wrapper.json \
  wrapper

jq -n --rawfile source "$ROOT/src/RewardsSetup.sol" \
  '{
    language: "Solidity",
    sources: {"src/RewardsSetup.sol": {content: $source}},
    settings: {
      optimizer: {enabled: true, runs: 100},
      evmVersion: "cancun",
      outputSelection: {"*": {"*": ["abi", "evm.bytecode", "evm.deployedBytecode"]}}
    }
  }' >"$tmp/setup-input.json"
compile_standard_json "$tmp/setup-input.json" "$tmp/setup-output.json"
write_artifact \
  "$tmp/setup-output.json" \
  src/RewardsSetup.sol \
  BenchmarkAccessControlManager \
  "$OUT/access-control-manager.json"
write_artifact \
  "$tmp/setup-output.json" \
  src/RewardsSetup.sol \
  BenchmarkDistributionCreator \
  "$OUT/distribution-creator.json"

chmod 644 "$OUT"/*.json
node "$ROOT/verify-runtime.mjs" "$OUT/distributor.json" "$DISTRIBUTOR"
node "$ROOT/verify-runtime.mjs" "$OUT/erc1967-proxy.json" "$PROXY"
node "$ROOT/verify-runtime.mjs" "$OUT/pull-token-wrapper.json" "$WRAPPER"

if ! diff -q \
  <(jq -S '.abi' "$OUT/distributor.json") \
  <(jq -S '.abi' "$OUT/benchmark-distributor.json") >/dev/null; then
  printf 'BenchmarkDistributor ABI differs from production Distributor\n' >&2
  exit 1
fi
if [[ $(jq -r '.deployedBytecode.object' "$OUT/distributor.json") == \
      $(jq -r '.deployedBytecode.object' "$OUT/benchmark-distributor.json") ]]; then
  printf 'BenchmarkDistributor runtime unexpectedly matches production Distributor\n' >&2
  exit 1
fi

printf 'Wrote rewards artifacts to %s\n' "$OUT"
