# State caller fixture

`StateCaller` backs the `state-call-*` presets. Each transaction spends its gas on
cold calls to the state bloat's synthetic contracts, so every call reads a cold account
and loads its bytecode. Blocks filled with them measure how fast validators execute
undeclared cold contract calls. It is a local execution fixture: chain 1337 only, no
real funds.

The contracts come from `tempo-xtask generate-state-bloat --contracts N`: contract `i`
lives at the last 20 bytes of `keccak256(seed || uint64_be(i))` (seed defaults to
`keccak256("tempo-state-bloat-contracts")`) and its code returns that hash as one word,
padded with distinct filler to `--contract-size` bytes (default 24,576, the EIP-170
maximum). The presets call indices `[0, 2000000)`, so the bloat needs 2,000,000
contracts.

| Preset | Calls | Notes |
|---|---|---|
| `state-call-cold-disk` | random contracts across the bloat | tempo-node capped at 16 GB |
| `state-call-dependent-disk` | each target from the word the previous contract returned, chained across transactions | nothing can be prefetched |

At today's 2,600-gas cold call a 10M-gas transaction makes about 2,840 random or
2,750 dependent calls. `../state-read/gate.py` reads the results the same way as for
the state-read presets.

## Rebuild

The artifact uses solc 0.8.30, optimizer 200 runs, Cancun EVM:

```sh
forge build --root contrib/bench/txgen/state-call --contracts . \
  --out "$PWD/.bench-tmp/state-call-out" --cache-path "$PWD/.bench-tmp/state-call-cache" \
  --use 0.8.30 --evm-version cancun --optimize --optimizer-runs 200
jq '{abi, bytecode: {object: .bytecode.object}}' \
  .bench-tmp/state-call-out/StateCaller.sol/StateCaller.json \
  > contrib/bench/txgen/state-call/StateCaller.json
```
