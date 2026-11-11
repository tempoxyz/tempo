# Antithesis targets

Each directory is one Antithesis target with its own workload image, config image
(`docker-compose.yaml` and `Dockerfile.config`) and publishing workflow.

| Target | What it tests | Workflow |
|---|---|---|
| [`reth-state-root`](reth-state-root) | Sparse-trie state root computation, `eth_getMultiProof`-style account and storage proofs (and the same proofs rebuilt from an execution witness) over the same blocks, persistence and restart recovery | [`antithesis-reth-state-root.yml`](../../.github/workflows/antithesis-reth-state-root.yml) |
| [`zones`](zones) | A Tempo L1 and zones network running deposits, withdrawals and transfers | [`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) |

[`trie-shapes`](trie-shapes) is the library the reth target uses: it generates writes in trie shape templates
(spikes, fans, nested groups, a dense storage trie) and reports the shapes each block reaches.

The reth target runs a `serve` process that owns the database and the model and builds blocks only
when a test template command asks over a Unix socket (`trie-shapes/src/harness.rs`). The commands, in
`test/v1/<template>/`, are subcommands of a separate binary (`<target>-commands` in `trie-shapes/src/bin`)
built without coverage instrumentation, so only the server reports coverage and has its threads paused:

| Command | What it does |
|---|---|
| `first_genesis` | Waits for the server and builds the first block |
| `parallel_driver_writes` | Draws one trie-shapes step against the tip state and queues its writes |
| `parallel_driver_blocks` | Builds 1 to 4 blocks from queued writes, padded with random ones |
| `parallel_driver_proofs` | Proofs and the execution witness at random blocks, verified against the model's root |
| `anytime_root` | The root the overlay serves at the tip equals the model's |
| `eventually_persisted` | Flushes to the head; the persisted state, the tip root and proofs must match the model |
| `finally_recovered` | The same once the server is back after the last fault |

Launch the reth target with `--fault-tolerance legacy` (network faults and thread pauses, no container
kills), which leaves restart recovery unexercised: "Restart recovers persisted blocks" stays unreached. A command that finds the server down exits successfully, so a restart is not a failure. Run one
locally with `ANTITHESIS_TRIE_SOCKET=/tmp/trie.sock` set for both the server and the commands.

The zones workload drivers live in `xtask/zones-antithesis`, also built uninstrumented; see [`zones/README.md`](zones/README.md).

## Experimental shape exploration

The local `sometimes_each!` macro emits JSON exploration guidance through the Rust SDK's
internal guidance API. A stable message identifies the exploration site; the serialized shape
is guidance data, not a dynamically named assertion. This is experimental: local JSON tests
check the wire format, not whether Antithesis schedules different shapes as distinct goals.
Keep the explicit `assert_sometimes!` shape checks as independent coverage properties.

The tracker observes complete tries reconstructed from model leaves. It can report structural
branch shapes, but cannot measure a sparse trie's runtime revealed mask. Do not interpret these
observations as coverage of partially revealed sparse nodes.

Validate in short, budget-capped Antithesis runs before relying on this guidance. First check
startup, SDK errors and multiple shape payloads under one stable identity. Compare guidance-on
and guidance-off exploration separately: seeing the payloads accepted is not proof that novelty
scheduling uses them. Record immutable image digests, run IDs and actual compute usage; a small
comparison is a smoke test, not evidence of a statistically significant coverage improvement.
