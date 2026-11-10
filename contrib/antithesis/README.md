# Antithesis targets

Each directory is one Antithesis target with its own workload image, config image
(`docker-compose.yaml` and `Dockerfile.config`) and publishing workflow.

| Target | What it tests | Workflow |
|---|---|---|
| [`reth-proofs`](reth-proofs) | `eth_getMultiProof`-style account and storage proofs against the state root | [`antithesis-reth-proofs.yml`](../../.github/workflows/antithesis-reth-proofs.yml) |
| [`reth-state-root`](reth-state-root) | Sparse-trie state root computation, persistence and restart recovery | [`antithesis-reth-state-root.yml`](../../.github/workflows/antithesis-reth-state-root.yml) |
| [`zones`](zones) | A Tempo L1 and zones network running deposits, withdrawals and transfers | [`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) |

[`trie-shapes`](trie-shapes) is a library both reth targets use: it generates writes in trie shape templates
(spikes, fans, nested groups, a dense storage trie) and reports the shapes each block reaches.

Both reth targets run a `serve` process that owns the database and the model and builds blocks only
when a test template command asks over a Unix socket (`trie-shapes/src/harness.rs`). The commands, in
`test/v1/<template>/`, are subcommands of a separate binary (`trie-shapes/src/bin/<target>-commands.rs`)
built without coverage instrumentation, so only the server reports coverage and has its threads paused:

| Command | What it does |
|---|---|
| `first_genesis` | Waits for the server and builds the first block |
| `parallel_driver_writes` | Draws one trie-shapes step against the tip state and queues its writes |
| `parallel_driver_blocks` | Builds 1 to 4 blocks from queued writes, padded with random ones |
| `parallel_driver_proofs` | reth-proofs: proofs at random blocks, verified against the model's root |
| `anytime_root` | reth-state-root: the root the overlay serves at the tip equals the model's |
| `eventually_persisted` | Flushes to the head; the persisted state must match the model |
| `finally_recovered` | The same once the server is back after the last fault |

Launch both reth targets with `--fault-tolerance legacy` (network faults and thread pauses, no container
kills), which leaves restart recovery unexercised: "Restart recovers persisted blocks" stays unreached. A command that finds the server down exits successfully, so a restart is not a failure. Run one
locally with `ANTITHESIS_TRIE_SOCKET=/tmp/trie.sock` set for both the server and the commands.

The zones workload drivers live in `xtask/zones-antithesis`, also built uninstrumented; see [`zones/README.md`](zones/README.md).
