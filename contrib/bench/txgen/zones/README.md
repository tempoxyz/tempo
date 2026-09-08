# Zone portal execution preset

Use the existing `bench-txgen.nu run` command with `--preset zones --accounts 1`.
It renders exactly `tps * duration` operations, alternating encrypted deposits and
single-item `processWithdrawals` calls. Set `TXGEN_ZONE_MODE=deposit` or
`TXGEN_ZONE_MODE=withdraw` for either workload alone (default: `mixed`). Requires
`uv`, chain ID 1337, and a T10-or-later genesis containing the shared zone runtimes.
The helper checks the runtime before rendering and gives every run its own output
directory, so rendering another run cannot overwrite an in-flight workload.

Setup deploys **local-only fixtures**, funds their withdrawal escrow, and approves
their deposit allowances. Each constructor seeds portal storage and returns the exact
production ERC-1167 proxy bytecode. Workload transactions execute the node's real
portal implementation, with no extra wrapper calls. Setup is classified as setup
by txgen and excluded from workload measurements by `bench send`.

This measures portal execution, not zone sequencing, proof verification, settlement,
or cross-chain latency. The fixture is not registered with ZoneFactory and supports
plain withdrawals only; it does not exercise gateway callbacks. Its constructor
rejects other chain IDs. It has no deployed fixture methods or queue-reset hook.
Do not use it for custody. All key material is deterministic public test material.

Each operation transfers one pathUSD base unit. Deposit fees and bounce-back
reserves are zero in the fixture. Deposits contain a valid encrypted recipient and
memo bound to the predicted portal address and depositor. The fixture has one
sequencer, open access, and one precommitted withdrawal batch. The renderer hashes
the batch backwards and supplies the correct suffix for each one-item withdrawal.
Each portal receives at most 210 deposits, respecting TIP-1096's outstanding
deposit limit without settlement. Larger deposit or mixed runs deploy additional
portals during setup. Withdrawal-only runs need one portal. All transactions use
one account's protocol nonce lane to preserve FIFO ordering.
The final withdrawal clears the batch; subsequent deposits may remain unprocessed.
Check `WithdrawalProcessed(success=true)`, not just transaction receipt status.

The sequence is finite: use exactly the rendered `--count`, and regenerate for each
fresh setup. Fewer transactions than the sequence length cause txgen to emit no
workload; a larger count can replay the exhausted queue. The built-in benchmark
helper supplies the matching count automatically. Rendering takes O(count) memory.
The configured duration controls when sequences start, not a deadline inside this
single sequence. The sender TPS and count bound the run. The portal's per-block
deposit cap still applies; begin with a low rate (for example 100 TPS).

For manual generation (before any transaction consumes the deployer's current nonce):

```sh
uv run contrib/bench/txgen/zones/render.py --count 100 --nonce 0 \
  --output .bench-tmp/txgen-specs/zones.yml
txgen-tempo generate -s .bench-tmp/txgen-specs/zones.yml -n 100 \
  --rpc http://127.0.0.1:8545 | bench send --rpc-url http://127.0.0.1:8545 --tps 100
```

## Rebuild and check

The checked-in artifact uses solc 0.8.30, optimizer 200 runs, Cancun EVM. Rebuild:

```sh
zone_tools=$(mktemp -d)
npm install --prefix "$zone_tools" solc@0.8.30
NODE_PATH="$zone_tools/node_modules" node contrib/bench/txgen/zones/build.cjs
```

Start a disposable local Tempo node using `crates/chainspec/src/genesis/dev.json`,
`--dev`, and `--http.api eth,net,web3,txpool,tempo`, then run:

```sh
uv run contrib/bench/txgen/zones/check.py --rpc http://127.0.0.1:18545 \
  --txgen-bin /path/to/txgen-tempo --bench-bin /path/to/bench
```

The check executes setup and six operations in each mode, verifies the production
proxy bytes, rejects an incorrect withdrawal suffix, counts deposit and successful
withdrawal events, and checks that the queue is exhausted. Keep the fixture storage
layout aligned with `crates/precompiles/src/zone_factory/portal.rs` when it changes.
Use `--count 421` to cross the portal-capacity boundary in both deposit and mixed
modes. The helper treats failed or reverted transactions in the report as a failed run.
