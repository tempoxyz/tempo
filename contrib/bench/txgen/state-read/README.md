# State reader fixture

`StateReader` backs the `state-read-*` presets. Each transaction spends its gas on
TIP20 `balanceOf` reads of state-bloat accounts, so blocks filled with them measure
how fast validators execute cold storage reads. It is a local execution fixture:
chain 1337 only, no real funds.

| Preset | Reads | Notes |
|---|---|---|
| `state-read-cold` | random accounts across the bloat | |
| `state-read-hot` | random accounts among 100K | stays in page cache |
| `state-read-dependent` | each account from the previous balance, chained across transactions | nothing can be prefetched |
| `*-lowmem` / `*-disk` | as above | tempo-node capped at 45 GB / 16 GB |

## Running

Use `bloat=100`, `gas-limit=general-gas-limit=500000000` and a send rate the chain
can include, or the pre-measurement pool reset times out:

| Preset | `tps` | `max-concurrent-requests` |
|---|---|---|
| `state-read-cold`, `-hot`, `-lowmem` | 20 | 20 |
| `state-read-dependent` | 1 | 4 |
| `state-read-cold-disk` | 40 | 40 |

`bench-state-read-gate` (manual dispatch) runs `state-read-cold` and `state-read-dependent`
on the chosen ref after a gas pricing change, then `gate.py` reports the p99
worst-case block execution time for the feature phase against a 500 ms threshold (about
one block time). Validators run blocks of up to 4 transactions serially, so smaller blocks
are projected to 4 serial transactions; runs with fewer than 30 loaded blocks are inconclusive.

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
