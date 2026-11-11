# Zone test environment

A multi-sequencer zone in Docker Compose, for fault-injection testing of the L1 and zone nodes built with
`--features fuzz` (SDK assertions enabled). `docker-compose.yaml` describes the topology.

The Dockerfile builds every binary with Antithesis [coverage instrumentation](https://antithesis.com/docs/reference/sdk/rust/instrumentation/)
(`--features antithesis-coverage` and its sancov `RUSTFLAGS`, in the `antithesis` profile: no LTO, one codegen unit)
and links them into `/symbols`. Coverage guides the exploration, and Antithesis only pauses threads in
instrumented processes. Outside Antithesis the shim finds no `libvoidstar` and does nothing.

Build the images from the repository root, with the contract submodules checked out:

```bash
docker build -f contrib/antithesis/zones/Dockerfile -t tempo-zones-antithesis:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f contrib/antithesis/zones/Dockerfile --target workload -t tempo-zones-antithesis-workload:latest \
    --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" .
docker build -f contrib/antithesis/zones/Dockerfile.config -t tempo-zones-antithesis-config:latest contrib/antithesis/zones
```

Run it locally:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml up
```

`ZONES_IMAGE` overrides the image the L1, provisioner and zone nodes run, and `WORKLOAD_IMAGE` the
`workload` container's.

## Antithesis registry

[`antithesis-zones.yml`](../../.github/workflows/antithesis-zones.yml) builds the node, workload and config images on every push to `main`
that touches the node or this directory, and on a manual dispatch of any branch, and pushes them to
`us-central1-docker.pkg.dev/molten-verve-216720/tempo-repository` as `<branch>-<sha>` and `<branch>`. The
config image adds an `.env` that pins `ZONES_IMAGE` and `WORKLOAD_IMAGE` to the digests just built. It needs the registry's JSON
key in the `ANTITHESIS_REGISTRY_KEY` repository secret.

To check an already-published config without rebuilding, manually dispatch the same workflow with
`validate_config_digest` set to its `sha256:...` digest. It pulls the config and its pinned images
using the existing registry secret, then runs `snouty validate` to check startup and the test template.
This does not launch a paid Antithesis run.

## Test template

`test/v1/zone_payments` ships at `/opt/antithesis/test/v1` in the workload image only (the Dockerfile's
`workload` target), so only the `workload` container offers it. The test platform finds templates in the
images it is given, so they must be in the image rather than copied in when a container starts. Each command is a subcommand of `tempo-zones-antithesis` ([`xtask/zones-antithesis`](../../../xtask/zones-antithesis)), built without coverage instrumentation so only the nodes report coverage:

| Command | What it does |
|---|---|
| `first_seed` | Approves the portal for the L1 funders and funds the first zone accounts |
| `parallel_driver_deposit` | Deposits from a funder or a new L1 account to a new or existing zone account |
| `parallel_driver_transfer` | TIP-20 transfer inside the zone to a new or existing account |
| `parallel_driver_withdraw` | Withdraws to a new or existing L1 address |
| `parallel_driver_fanout` | Funds 5 to 20 new zone accounts from one sender |
| `parallel_driver_rotate_leader` | Hands leadership to another sequencer, through the admin or a zone node's `zone_setLeader` relay, then observes production and settlement if its term is not superseded |
| `serial_driver_recovery` | Pauses faults for 360 seconds, then proves a fresh canary settles on finalized L1 and all nodes preserve its receipt and the prior settled prefix within 300 seconds |
| `anytime_consistency` | Nodes that reached the height L1 settled agree on its hash and on balances there, settled workload transactions stay final, and every zone block comes from the leader the portal names at its Tempo anchor; reconciles persistent handoff history |
| `eventually_settled` | After faults stop, resolves every durable signed intent first, then every confirmed deposit is credited or refunded and every confirmed withdrawal is paid, and all nodes converge |
| `finally_ledger` | The same, then every workload account's zone balance equals what the zone's Transfer logs add up to |

Half of all recipients are accounts nobody has used before, so the L1 and zone state tries keep
growing during a run. Account keys are hashes of their index, counting from 1000, and are
recorded in an append-only ledger in `/state`, which also holds a lock file per account so
only one command sends from an account at a time. Drivers durably journal signed transaction
bytes before broadcasting, then record their exact
receipt outcome and confirmed deposit, withdrawal or transfer obligations. A killed driver or
ambiguous RPC error leaves a pending intent: reconciliation rebroadcasts the identical bytes and
never replaces the nonce or creates a second payment. Unknown intents cannot be omitted from
`eventually_settled`, which checks a reconciled obligation snapshot rather than requiring
parallel drivers to stop writing. Leadership requests and observed updates also survive driver cancellation;
consistency and recovery check their history and activation boundaries.

### Mid-run recovery

`serial_driver_recovery` invokes the binary at `ANTITHESIS_STOP_FAULTS`, if nonempty, with `360`
seconds. The platform restores killed containers and network connectivity and resumes faults
automatically when the window expires. Locally, with the variable unset, the same check runs
without requesting a pause. There is no external-faults toggle.

The probe has one 300-second async deadline covering startup, reconciliation, sends and reads;
individual HTTP requests are also bounded. It first requires every configured node, including
the RPC-only follower, to answer and agree with a baseline portal settlement read at a single
**finalized L1 block hash**. After resolving old signed intents it journals a new canary before sending it. A lost send
reply is reconciled by that exact transaction ID and bytes, never a replacement canary.
Success requires a newer finalized portal settlement at or beyond that canary, the portal's
exact block hash on every node at that same checkpoint, the unchanged baseline prefix, and the
canary's unchanged successful receipt/block hash everywhere. The producer must be the eligible
leader at the zone block's L1 anchor. The settled checkpoint must also anchor at or beyond
the baseline L1 height: old-leader catch-up below that anchor is not recovery progress. The
canary itself may precede that anchor; a superseded intermediate leader need not produce.
Agreement on an old tip, an unfinalized settlement, a missing follower, an error or a timeout
cannot pass. Cancellation of the probe leaves its signed canary in the journal for the next
reconciliation; the platform quiet window still expires automatically.

Run a command against the local stack the way the platform does:

```bash
docker compose -f contrib/antithesis/zones/docker-compose.yaml exec workload \
    /opt/antithesis/test/v1/zone_payments/first_seed
```
