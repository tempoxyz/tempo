# State reader fixture

`StateReader` backs the `state-read-cold`, `state-read-hot` and `state-read-dependent` presets. Each
transaction spends its gas on TIP20 `balanceOf` reads of state-bloat accounts,
so a block filled with them is a worst case for state reads. It is a local
execution fixture: chain 1337 only, no real funds.

## Rebuild

The artifact uses solc 0.8.30, optimizer 200 runs, Cancun EVM:

```sh
forge build --root contrib/bench/txgen/state-read --contracts . \
  --out "$PWD/.bench-tmp/state-read-out" --cache-path "$PWD/.bench-tmp/state-read-cache" \
  --use 0.8.30 --evm-version cancun --optimize --optimizer-runs 200
jq '{abi, bytecode: {object: .bytecode.object}}' \
  .bench-tmp/state-read-out/StateReader.sol/StateReader.json \
  > contrib/bench/txgen/state-read/StateReader.json
```
