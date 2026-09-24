#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
forge=${FORGE_BIN:-$HOME/.foundry/bin/forge}
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
if [[ ${1:-} == --test ]]; then
    cp StateAccessBenchmark.sol HistoryStatePaths.sol HistoryStatePaths.t.sol "$build/"
    "$forge" test --root "$build" --contracts "$build" --use 0.8.28 \
        --optimizer-runs 200 --optimize --evm-version cancun -vv
    exit
fi
"$forge" build HistoryStatePaths.sol --root "$PWD" --contracts . --use 0.8.28 \
    --optimizer-runs 200 --optimize --evm-version cancun --out "$build/out" --cache-path "$build/cache"
node - "$build/out/HistoryStatePaths.sol/HistoryStatePaths.json" <<'JS'
const fs = require('node:fs');
const artifact = JSON.parse(fs.readFileSync(process.argv[2]));
fs.writeFileSync('history-state-paths.json', JSON.stringify({abi:artifact.abi,
  bytecode:artifact.bytecode, deployedBytecode:artifact.deployedBytecode,
  compiler:{version:'0.8.28',optimizer_runs:200,evm_version:'cancun'}},null,2)+'\n');
JS
