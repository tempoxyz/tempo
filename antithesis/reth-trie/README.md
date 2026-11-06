# Reth trie workload for Antithesis

Antithesis is a deterministic fault-injection testing platform. This workload
exercises Reth's sparse-trie task, proof workers, in-memory state overlays and
concurrent database persistence without running a node or executing EVM transactions.
It is adapted from [Bedrock's reth-trie-dst workload](https://github.com/tempoxyz/bedrock/tree/80a02573bdb7c21127064bc3e26121f40d6fb90e/workloads/reth-trie-dst).
Bedrock is not a build or runtime dependency and its repository is unchanged.

The workload checks each computed root against an independent reference model that rebuilds the trie root from account and storage maps.
After persistence it checks overlay-backed accounts and storage, including deleted
slots; after a full flush it also compares the raw hashed tables and database root.
The chain is linear: reorgs, EVM execution, account destruction and storage wipes
are outside its scope.

## Build and publish

The Cargo workspace in this directory is separate from Tempo's root workspace.
It preserves the source workload's Reth revision
`b26d8264effaa9f6478fb91074b169e1f0f04c48` and
its dependency graph, rather than silently changing the system under test to
Tempo's Reth pin. Its own lockfile is used for image builds.

The [image workflow](../../.github/workflows/antithesis-reth-trie.yml) follows
[Alexey's Zones registry integration](https://github.com/tempoxyz/tempo/pull/9016):
it builds Linux amd64 workload image (the executable and its libraries) and config image (the compose
configuration) and pushes them to
`us-central1-docker.pkg.dev/molten-verve-216720/tempo-repository`.
Registry authentication uses the repository secret `ANTITHESIS_REGISTRY_KEY` as the JSON service-account key, with username `_json_key`.
No credentials belong in the images or compose file.

The workflow writes the built workload digest into the config image.
The config image contains `docker-compose.yaml` and an `.env` that pins the
workload image by digest. Use the matching config image to launch a run, not a
moving workload tag combined with an older config. Image builds and uploads do
not themselves launch paid Antithesis runs.

Antithesis runs without internet access; all code, native libraries and test
commands must already be in the workload image. Coverage instrumentation follows
[the Rust instrumentation guide](https://antithesis.com/docs/reference/sdk/rust/instrumentation/),
with debug symbols exposed under `/symbols`. SDK assertions and coverage are
separate mechanisms; an ordinary local build is not evidence of platform coverage.

See [Antithesis's Compose setup guide](https://antithesis.com/docs/setup/docker_compose/)
for registry authentication and launching the matching config image in setup mode, which validates startup before a fault-injection run. Local success does not verify an upload or execution
inside the Antithesis tenant.

## Run locally

From the Tempo repository root:

```sh
cargo build --locked --manifest-path antithesis/reth-trie/Cargo.toml --features fuzz
ANTITHESIS_SDK_LOCAL_OUTPUT=/tmp/trie-assertions.jsonl \
  antithesis/reth-trie/target/debug/reth-trie-antithesis \
  '{"datadir":"/tmp/reth-trie-smoke","rounds":1}'
docker build -f antithesis/reth-trie/Dockerfile -t tempo-reth-trie-antithesis:latest .
docker compose -f antithesis/reth-trie/docker-compose.yaml up
```

`--features fuzz` enables assertions in the upstream database and trie crates.
The binary accepts one JSON configuration argument. Without `rounds`, it runs
continuous bounded rounds, each with a fresh database after successful verification.
Defaults are 64 blocks, 64 updates per block, two proof workers, a 60-second
result timeout, persistence threshold 50 and 30 masked state blocks. Persistence
starts when retained blocks exceed the threshold; masking delays the newest
persisted blocks' state/trie writes while their block data is already durable.
The memory buffer defaults to five blocks retained above the database tip. Use
`blocks`, `updates`, `proof_workers`, `timeout_secs`, `persistence_threshold`,
`num_state_masking_blocks` and `memory_block_buffer_target` to override them.
The buffer plus masking window must be smaller than the persistence threshold
when masking is enabled.

Random choices come directly from the Antithesis SDK, not a locally seeded RNG.
The realized operation stream and append-only block journal are kept in the
active round's directory under `datadir`. Restarts must use the same configuration
and state volume; production startup recovery determines the durable database head
and the journal reconstructs the reference state. A successful round retires its
database before starting another. There is no shell restart loop or Docker restart
policy: Antithesis controls injected crashes and restart timing.

No prefix dataset is required. Without one, keys use direct preimages with random
hash distribution, not the source workload's precomputed shared-prefix table.
To use a table, make the same immutable file available across restarts and set
`RETH_TRIE_PREFIX_DATASET` to its path. No table is generated or downloaded at runtime.

The workload emits SDK properties for root/storage consistency, errors and panics,
and reachability properties for completed rounds, masked persistence, prewarming,
inter-batch sleeps and recovery of persisted blocks. Inspect actual property
observations rather than treating image startup as proof those paths ran. SDK
local JSON output is useful for smoke checks but does not validate Antithesis's
platform instrumentation or fault scheduling.

## Known dependency-scan failures

The imported Reth graph still triggers six unsuppressed advisories:
`RUSTSEC-2026-0387` for crypto-bigint 0.5.5 (constant-time variability; the fix
requires 0.7.6, outside elliptic-curve 0.13's compatible dependency range), and
unmaintained-package notices for bincode, derivative, paste, pin-utils and
proc-macro-error2. These are not evidence that this workload is exploitable, but
they are unresolved findings, not passing security checks. Updating that
cryptography graph requires an upstream-compatible dependency migration.
The lockfile updates libz-sys to 1.1.31, which fixes `RUSTSEC-2026-0418`.
