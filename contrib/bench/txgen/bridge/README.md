# Bridge fixture

`BridgeFixture` is a minimal bridge for the `bridge-mix` preset. Operators pay
out with `withdrawV2(address,address,uint256)` and users bridge in with
`depositWithId`. It is a local execution fixture: chain 1337 only, no real funds.

## Rebuild

The artifact uses solc 0.8.30, optimizer 200 runs, Cancun EVM:

```sh
forge build --root contrib/bench/txgen/bridge --contracts . \
  --out "$PWD/.bench-tmp/bridge-out" --cache-path "$PWD/.bench-tmp/bridge-cache" \
  --use 0.8.30 --evm-version cancun --optimize --optimizer-runs 200
jq '{abi, bytecode: {object: .bytecode.object}}' \
  .bench-tmp/bridge-out/BridgeFixture.sol/BridgeFixture.json \
  > contrib/bench/txgen/bridge/BridgeFixture.json
```
