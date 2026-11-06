# Cross-engine execution checks

This opt-in Antithesis workload runs the [Zones payment drivers](../../../zones/antithesis/README.md) against four full nodes. Zones is Tempo’s layer-2 payment system; its drivers deposit, transfer, withdraw, and fund new accounts. The nodes use optimized, sequential-fallback, cache-disabled comparison, and fast-fallback configurations. A separate Rust checker authenticates `eth_getProof` responses and compares their proven account and storage state. It does not execute transactions itself or replace the Zones solvency checker, which checks token balances and bridge liabilities.

## Build and run

From the Tempo repository root, with the Zones contract submodules checked out:

```sh
docker build -f zones/antithesis/Dockerfile -t tempo-zones-antithesis:latest .
docker build -f zones/antithesis/Dockerfile --target execdiff-workload \
  -t tempo-zones-antithesis-execdiff-workload:latest .
docker compose -f zones/antithesis/docker-compose.exec-diff.yaml up -d
```

For a local smoke run, execute the seed command (which funds eight payment accounts), a transfer, and the differential check in order:

```sh
docker compose -f zones/antithesis/docker-compose.exec-diff.yaml exec workload \
  /opt/antithesis/test/v1/zone_payments/first_seed
docker compose -f zones/antithesis/docker-compose.exec-diff.yaml exec workload \
  /opt/antithesis/test/v1/zone_payments/parallel_driver_transfer
docker compose -f zones/antithesis/docker-compose.exec-diff.yaml exec workload \
  /opt/antithesis/test/v1/zone_payments/eventually_exec_diff
```

Compose only starts the environment locally; it does not schedule the test commands. In Antithesis, the existing `zone_payments` template retains the deposit, transfer, withdrawal, and fan-out drivers. It adds `anytime_exec_diff` during faults and `eventually_exec_diff` after faults stop. Only the `execdiff-workload` image target offers these commands; the original Zones template and topology are unchanged.

[The image workflow](../../../.github/workflows/antithesis-zones.yml) publishes `tempo-zones-antithesis-execdiff-config` to `us-central1-docker.pkg.dev/molten-verve-216720/tempo-repository`. Its full Compose topology pins the node and alternative workload images by digest. In the Antithesis launch configuration, use that registry-qualified config image instead of the normal Zones config image. The Compose commands above are the local alternative.

## Checks and coverage

The seed and checker wrapper scripts call `tempo-zone-xtask antithesis exec-diff-config`, which writes `/state/exec-diff.json` atomically. It derives pathUSD (the test payment token) total-supply and up to 63 recent workload-account balance slots from the TIP-20 token contract’s generated storage bindings, not hardcoded offsets. The four full operator RPC endpoints use port 8545; the privacy-redacted RPC does not offer proofs.

The checker accepts `exec-diff-antithesis CONFIG.json anytime|eventually`. Each invocation pins the first reachable node’s finalized block, waits for the other nodes to finalize through its height, and requests canonical hash-pinned proofs. The opt-in launcher allows historical proofs within 10,000 blocks of the tip so finalized samples remain queryable. It independently authenticates complete account leaves, including Tempo account extensions, and all requested storage values. Proven fields and finalized block identities must agree. Proof-node byte ordering is not compared.

RPC outages and lag are not correctness failures. `anytime` reports incomplete coverage and exits successfully when a sample is unavailable. `eventually` retains completed samples and retries unfinished work until its configured deadline; expiry fails a separate availability property. Invalid proofs and disagreements fail immediately in either mode. Antithesis Sometimes properties—requiring a condition to occur at least once—record successful cross-profile proof comparisons and comparisons beyond genesis, not merely RPC attempts.

The launcher prints exact profile flags. Fast fallback sets `--engine.state-root-task-timeout 1ms`; sequential fallback uses `--engine.state-root-fallback`. The other profiles enable root-task comparison, with or without the state cache. These are different configurations of the same Tempo build, not independent client implementations. Zones disables delayed state writes (state masking) when using the provisioned sequencer manifest. This workload therefore does not cover the L1 node’s persistence cadence or masking. Checks sample finalized state; they do not exhaustively replay every block.
