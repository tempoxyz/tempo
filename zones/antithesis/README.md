# Zone test environment

A multi-sequencer zone in Docker Compose, for fault-injection testing of the L1 and zone nodes built with
`--features fuzz` (SDK assertions enabled). The L1 is the parent Tempo chain; a Zone is its
layer-2 payment chain. Four L1 validators run real Tempo consensus, with a certified RPC follower. Three Zone
sequencers produce Zone blocks and a fourth Zone node follows them.
The portal is the L1 bridge contract that holds deposited tokens, and funders are prefunded
L1 accounts used to deposit. A settled Zone block is one whose hash has been recorded on L1.
`docker-compose.yaml` describes this topology.

The Dockerfile builds every binary with Antithesis [coverage instrumentation](https://antithesis.com/docs/reference/sdk/rust/instrumentation/)
(`--features antithesis-coverage` and its sancov `RUSTFLAGS`, in the `antithesis` profile: no LTO, one codegen unit)
and links them into `/symbols`. Coverage guides the exploration, and Antithesis only pauses threads in
instrumented processes. Outside Antithesis the shim finds no `libvoidstar` and does nothing.

Build the images from the repository root, with the contract submodules checked out:

```bash
docker build -f zones/antithesis/Dockerfile -t tempo-zones-antithesis:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f zones/antithesis/Dockerfile --target workload -t tempo-zones-antithesis-workload:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f zones/antithesis/Dockerfile.config -t tempo-zones-antithesis-config:latest zones/antithesis
```

Run it locally:

```bash
docker compose -f zones/antithesis/docker-compose.yaml up
```

`ZONES_IMAGE` overrides the image the L1, provisioner and zone nodes run, and `WORKLOAD_IMAGE` the
`workload` container's.

## Antithesis registry

[`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) builds the node, workload and config images on every push to `main`
that touches the node or this directory, and on a manual dispatch of any branch, and pushes them to
`us-central1-docker.pkg.dev/molten-verve-216720/tempo-repository` as `<branch>-<sha>` and `<branch>`. The
config image adds an `.env` that pins `ZONES_IMAGE` and `WORKLOAD_IMAGE` to the digests just built. It needs the registry's JSON
key in the `ANTITHESIS_REGISTRY_KEY` repository secret.

## Test template

`test/v1/zone_payments` ships at `/opt/antithesis/test/v1` in the workload image only (the Dockerfile's
`workload` target), so only the `workload` container offers it. The test platform finds templates in the
images it is given, so they must be in the image rather than copied in when a container starts.
All payment, ledger, and proof commands use `tempo-zone-xtask antithesis`. The
`check-proofs` subcommand verifies account/storage proofs against finalized block state roots.
The shell commands in the table below invoke these subcommands; Antithesis schedules
`anytime_*` during faults and `eventually_*` after faults stop.
Each Zone node and L1 validator has a different execution profile (state-root computation and cache settings):
optimized, sequential fallback, cache-disabled comparison, or fast fallback. The checks compare
the proven state within each chain while the same payment drivers continue running.

A separate node-side solvency checker verifies that token supply and balances match bridge
accounting and that the L1 portal holds enough tokens to cover liabilities. It remains in
observe mode, recording findings without enforcement actions; SDK assertions are still enabled
in the fuzz build.

| Command | What it does |
|---|---|
| `first_seed` | Approves the portal for the L1 funders and funds the first zone accounts |
| `parallel_driver_deposit` | Deposits from a funder or a new L1 account to a new or existing zone account |
| `parallel_driver_transfer` | TIP-20 transfer inside the zone to a new or existing account |
| `parallel_driver_withdraw` | Withdraws to a new or existing L1 address |
| `parallel_driver_fanout` | Funds 5 to 20 new zone accounts from one sender |
| `anytime_consistency` | Nodes that imported the Zone block recorded on L1 agree on its hash and on balances there, and settled workload transactions stay final |
| `anytime_proofs` | Independently verifies account/storage proofs and compares finalized state across execution profiles; skips unavailable samples during faults |
| `eventually_proofs` | After faults stop, requires every profile to serve matching, valid proofs within the same 300-second recovery budget as `eventually_settled` |
| `eventually_settled` | After faults stop, every confirmed deposit is credited and every confirmed withdrawal is paid, and all nodes converge |
| `finally_ledger` | The same, then every workload account's zone balance equals what the zone's Transfer logs add up to |

Half of all recipients are accounts nobody has used before, so the L1 and zone state tries keep
growing during a run. Account keys are hashes of their index, counting from 1000, and are
recorded in an append-only ledger in `/state`, which also holds a lock file per account so
only one command sends from an account at a time. Drivers record a deposit, withdrawal or
transfer only once its receipt confirms it; the checks compare those records with both chains.

Run a command against the local stack the way the platform does:

```bash
docker compose -f zones/antithesis/docker-compose.yaml exec workload \
    /opt/antithesis/test/v1/zone_payments/first_seed
```

## Execution differential

The same payment workload checks execution agreement as well as payment accounting. Four real
L1 validators and a certified follower replace the former single dev-mode L1 node. The follower
keeps the existing L1 endpoint, so provisioning, deposit/withdrawal drivers, and Zone nodes use
the same interface. The existing four Zone nodes remain in place. There is one Compose topology,
one workload image, and one launch configuration.

The node scripts print their execution and persistence flags. The persistence threshold is
the number of in-memory canonical blocks ahead of disk that triggers another flush. Masking
defers state/trie writes for a configured number of blocks in that flush; the buffer is the
target number of blocks retained in memory. All three settings are measured in blocks.

L1 validators mix threshold/masking/buffer profiles of `2/0/0` (sequential fallback), `3/1/0` (optimized comparison),
`5/2/0` (fast fallback), and `8/3/0` (cache-disabled comparison); the certified follower uses
`3/1/0`. Each satisfies `masking + buffer < threshold`. This reuses the L1 setup from
[Bedrock](https://github.com/tempoxyz/bedrock), Tempo's deterministic fault-testing harness.
Antithesis, rather than Bedrock, supplies faults here.
Zone nodes retain their execution-profile mix but force immediate persistence for settlement
and replication; setting delayed-persistence arguments on them would be overridden.

`CheckProofs` (`check-proofs` on the CLI) samples the test payment token, pathUSD:
its total supply and up to 63 recent workload-account balance slots, derived from the TIP-20
storage bindings. It uses the existing
ledger and RPC connections directly, without a separate executable or generated config:

```sh
tempo-zone-xtask antithesis check-proofs
tempo-zone-xtask antithesis check-proofs --eventually
```

The command checks two independent node groups concurrently: the five L1 nodes and the four
Zone nodes. For each chain it pins the first reachable node's finalized block, waits for the
other nodes to finalize through that height, and requests proofs by canonical block hash. It independently
verifies the full account leaf (including Tempo account extensions) and requested storage
values before comparing the proven fields across profiles. Proof-node ordering is not compared.
The node launchers permit bounded historical proofs, including when the sampled finalized
block trails the tip.

During faults, unavailable samples produce incomplete coverage rather than a correctness
failure. With `--eventually`, completed nodes are retained and unfinished samples are retried
within the shared 300-second settlement recovery budget. Deadline expiry fails a separate
availability assertion; invalid proofs and state disagreements fail immediately. Antithesis SDK Sometimes
properties, which must hold at least once in a run, require successful cross-profile comparisons
beyond genesis separately for L1 and Zone state; one chain cannot satisfy the other's coverage.

The node-side solvency assertions and existing payment drivers are unchanged. Payment drivers
do not stop nodes; the nonvoting Zone RPC follower accepts the node-local maintenance operations
described below.
With four L1 validators, one unavailable validator is within the Simplex fault budget; overlapping
faults can still prevent a quorum. Safety checks run during faults, while recovery/liveness
checks run after faults stop.

## Fault injection

Antithesis owns node pauses, termination, and recovery, as well as network faults and
instrumented thread pauses. The Compose services deliberately have no restart policy:
Docker restarting a stopped container immediately can cancel the intended fault duration.
The Antithesis launch settings control the fault-tolerance level; the `high_availability`
level enables node termination, whereas `resilient` includes pauses but not termination.
These settings are not specified by this repository's image-build workflow.

See [Antithesis fault types](https://antithesis.com/docs/product/writing_tests/controlling_faults/fault_types/).
A generic node crash is not a stage-boundary crash or an operator-maintenance action.
Commands such as `db repair-trie` need a custom fault running in the affected node, with
exclusive access to its stopped database. Antithesis supports custom faults; coordinate their
registration and data-directory durability behavior with the Antithesis team.


### Offline repair and unwind

Only `zone-rpc`, the nonvoting Zone RPC follower, runs the maintenance supervisor, a process
that owns the node child and serializes these offline operations. Register these
commands as custom faults **inside that container**, not as payment-workload commands:

```sh
python3 /opt/zones/node-control.py repair-trie
python3 /opt/zones/node-control.py unwind --blocks 1
```

`repair-trie` always uses `--dry-run`: it checks for the completed zero-inconsistency report,
not just exit status, and never repairs evidence away. `unwind` removes 1–32 recent blocks,
never genesis, and requires the CLI to report an actual unwind. Both stop and reap the node
before opening its database, use the same binary, genesis and datadir, and then restart it.
Offline Zone execution uses `L1_OFFLINE=true`, which skips L1 deposit/token validation; this
is an operator-recovery drill, not an independent execution oracle.

The supervisor reports armed, fired, recovered and failed separately. Requests rejected before
arming and normal shutdown interruptions do not fail safety assertions. Recovery must restore
the pre-operation finalized height and hash within 120 seconds. Arming declares the operation's
Always (every result must pass) and Sometimes (at least one must complete) SDK assertions
through the node-local `report-maintenance` xtask command. Unregistered, unused drills do not
add missing-coverage properties to ordinary payments campaigns; existing eventual
`CheckProofs` and settlement checks still verify cross-node recovery after faults stop.
A concurrent partition can prevent this node-local recovery check from completing; register
these drills in a fault-free recovery window rather than scheduling overlapping faults.
The supervisor does not automatically restart an unexpectedly exited node: Antithesis still
controls ordinary node failures and their duration. Its control socket is local-only and
accepts no arbitrary commands. Register custom faults with the Antithesis team before
claiming campaign coverage; building this image alone does not schedule them.
