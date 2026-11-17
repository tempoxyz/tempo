# Antithesis targets

Each directory is one Antithesis target with its own workload image, config image
(`docker-compose.yaml` and `Dockerfile.config`) and publishing workflow.

| Target | What it tests | Workflow |
|---|---|---|
| [`reth-state-root`](reth-state-root) | Sparse-trie state root computation, `eth_getMultiProof`-style account and storage proofs (and the same proofs rebuilt from an execution witness) over the same blocks, persistence and restart recovery | [`antithesis-reth-state-root.yml`](../../.github/workflows/antithesis-reth-state-root.yml) |
| [`zones`](zones) | A Tempo L1 and zones network running deposits, withdrawals and transfers | [`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) |

[`trie-shapes`](trie-shapes) is the library the reth target uses: it generates writes in trie shape templates
(spikes, fans, nested groups, a dense storage trie) and reports the shapes each block reaches.

The reth target runs a `serve` process that owns the database and a reference model of the expected
state, and builds blocks only when a test template command asks over a Unix socket (`trie-shapes/src/harness.rs`). The commands, in
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

The state overlay combines persisted state with newer in-memory blocks. A proof provider can lose
the chain of blocks connecting its overlay to persisted state while persistence advances.
Proof requests that hit this known overlay anchor gap (`state trie overlay for tip … cannot be
anchored to … with current blocks`) are temporarily rejected and logged as `proof_overlay_gap`
events, not assertion failures. A run does not need to encounter the gap to pass. The server stays
up; all other proof errors and returned-proof checks still fail normally. Remove this exception once
reth pins the Finish chain for a provider's lifetime.

Launch the reth target with snouty's `--fault-tolerance high_availability`, which includes container
kills and stops as well as thread pauses and network faults. The launch helper selects this
profile explicitly (the Antithesis launch default, `legacy`, does not kill containers):

```sh
# Use an immutable config image from the image-publishing workflow and an approved duration and compute tier.
contrib/antithesis/reth-state-root/launch.sh "$CONFIG_IMAGE" 12h --performance-tier turbo
```

The helper sends an explicit fuzzing duration: a compute-hour budget alone was not honored by
the `basic_test` launcher. Check the recorded duration and tier after launch.

Antithesis restarts the container on the same `trie-state` volume mounted at `/state`; do not add a
Docker restart policy. The server reopens the database through reth's recovery path, replays its synced operation
journal into the reference model, and checks recovered roots and persisted state. A command that
finds the server down exits successfully to tolerate injected downtime; `finally_recovered` must
finish its root and proof checks after faults stop. Run the server and commands locally with
`ANTITHESIS_TRIE_SOCKET=/tmp/trie.sock` set for both.

To smoke-test container recovery locally, set `RETH_STATE_ROOT_IMAGE` to the
workload image (not the config image) recorded by the image-publishing workflow:

```sh
python3 contrib/antithesis/reth-state-root/smoke-test.py --image "$RETH_STATE_ROOT_IMAGE"
```

For local source testing without a published image, build the two binaries with
`cargo build -p reth-state-root-antithesis -p antithesis-trie-shapes --bin reth-state-root-antithesis --bin reth-state-root-commands`,
then pass `--image ubuntu:24.04 --binary-dir target/debug` instead. This mounts the local binaries
and test commands into the runtime image; it does not test the published image's instrumentation.
The runtime image must already be present locally.

The test uses an isolated Compose project and volume, flushes nonempty state, kills the container
with SIGKILL, starts it on the same volume, and checks the recovered height and roots.
It also runs the root, proof/witness and final-recovery commands and checks that block production
continues. This is a happy-path process-crash check after a completed flush, not a power-loss or
in-flight persistence test; it does not establish correctness at every crash boundary.

To exercise an in-flight state-root calculation across a container pause longer than the old
60-second deadline, run `pause-smoke-test.py` with the same `--image` and `--binary-dir` options.
It then checks roots and proofs, kills the container and verifies restart recovery. The workload
allows 600 seconds for state-root and persistence acknowledgements, including fault-induced pauses;
this is a bounded allowance, not a guarantee against arbitrarily long fault schedules.

The zones workload drivers live in `xtask/zones-antithesis`, also built uninstrumented; see [`zones/README.md`](zones/README.md).
