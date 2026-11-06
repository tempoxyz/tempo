# Cross-engine execution checks

`exec-diff-antithesis` is the independent proof checker in the existing
[Zones payment workload](../../../zones/antithesis/README.md). Zones is Tempo's layer-2
payment system. Its deposit, transfer, withdrawal, and account-funding drivers exercise four
full Zone nodes with different execution profiles: optimized, sequential fallback,
cache-disabled comparison, and fast fallback. Profiles vary state-root computation and cache
settings while processing the same chain. The checker authenticates
`eth_getProof` responses against the selected finalized header's state root and compares
their proven account and storage state; it does not
execute transactions itself.

## Run with the payment workload

Build and start the ordinary node and workload images using the Zones README. The existing
`tempo-zones-antithesis-workload` image includes both payment drivers and proof checks, and
`tempo-zones-antithesis-config` launches them together. There is no separate differential
workload image, Compose file, or Antithesis launch configuration.

For a local smoke run, execute these commands from the repository root after starting Compose:

```sh
docker compose -f zones/antithesis/docker-compose.yaml exec workload \
  /opt/antithesis/test/v1/zone_payments/first_seed
docker compose -f zones/antithesis/docker-compose.yaml exec workload \
  /opt/antithesis/test/v1/zone_payments/parallel_driver_transfer
docker compose -f zones/antithesis/docker-compose.yaml exec workload \
  /opt/antithesis/test/v1/zone_payments/eventually_exec_diff
```

Compose only starts the environment locally; it does not schedule test commands.
Antithesis schedules `anytime_exec_diff` during faults and `eventually_exec_diff` after
faults stop, alongside the existing payment and ledger checks. The existing solvency
checker remains in observe mode: it records findings without enforcement actions, but
its SDK assertions still check token accounting and portal custody in fuzz builds.

## What is checked

The seed and proof-check wrappers run `tempo-zone-xtask antithesis exec-diff-config`, which
atomically writes `/state/exec-diff.json`. It derives pathUSD (the test payment token)
total-supply and up to 63 recent workload-account balance slots from the TIP-20 contract's
generated storage bindings. The four full operator RPC endpoints use port 8545; the
privacy-redacted RPC does not offer proofs.

The checker accepts `exec-diff-antithesis CONFIG.json anytime|eventually`. Each invocation
pins the first reachable node's finalized block, waits for the other nodes to finalize
through its height, and requests canonical hash-pinned proofs. The launcher allows
historical proofs within 10,000 blocks of the tip. Complete account leaves, including
Tempo account extensions, and requested storage values are authenticated independently.
Finalized block identities and proven fields must agree; proof-node byte ordering is not
compared.

RPC outages and lag are not correctness failures. `anytime` reports incomplete coverage
and succeeds when a sample is unavailable. `eventually` retains completed samples and
retries unfinished work within the same recovery budget as `eventually_settled` (currently
300 seconds); expiry fails a separate availability assertion. Invalid proofs and
disagreements fail immediately. SDK Sometimes properties, which must hold at least once in a run, require successful cross-profile
comparisons and comparisons beyond genesis, not merely RPC attempts.

## Execution profiles and limits

The launcher prints each node's flags. Root-task comparison checks trie updates produced by
the background state-root task against those from regular state-root calculation.
Zone node 0 enables this comparison; node 1
uses sequential fallback and disables prewarming and caches; node 2 enables comparison
without the state cache; the RPC follower uses a 1 ms root-task timeout to exercise fast
fallback. These are configurations of the same Tempo build, not independent client
implementations.

The topology still uses dev consensus on L1. Zones immediately persists every block, so
these checks do not cover delayed L1 persistence or state masking. They sample finalized
state, rather than replaying every block. No new driver stops nodes or runs maintenance
commands such as `db repair-trie` or stage unwind.
