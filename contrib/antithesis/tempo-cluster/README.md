# Tempo consensus cluster on Antithesis

Four independent real-consensus validators (3-of-4 quorum), fixed IPs/keys and
persistent execution/consensus datadirs. No `--dev`, fake finality, process restart
loops or Compose restart policies. A 100-block epoch exercises DKG transitions.

The `public-mix` preset combines token transfers, memos, MPP payments, vault
deposits/withdrawals and synthetic zone settlement transactions.
The Python driver uses Hegel, a state-machine testing library, to choose actions.
It is excluded from container/network fault injection and waits for all validators to finalize,
funds accounts and confirms the `public-mix` preset setup before
reporting setup complete. Its sole `first_` command activates workload generation.
Hegel chooses each burst's seed and RPC endpoint; the pinned real `txgen-tempo`
and `bench` tools generate/sign/send 32 transactions with eight concurrent sends.
Failed/time-out bursts have unknown outcomes and are not safety violations.

Properties: finalized heights never regress; validators agree on block/state,
transaction and receipt roots at the same finalized height; retained checkpoints
stay immutable; sampled finalized receipts match their block; successful workload
transactions and new finality are reached. A recovery action pauses faults through Hegel, requires
all four validators to advance and a **new** successful transaction, then exits.
The model retains 64 checkpoints and 256 receipt IDs. RPC reads time out in 2s;
recovery has a 180s bound. No liveness assertion assumes quorum during faults.

## Build and local smoke

From the repository root, using the pinned `tempoxyz/txgen` transaction generator:

```sh
gh repo clone tempoxyz/txgen ../txgen
git -C ../txgen checkout ca437320c94baf64b05b1e31fde576e6e493479d
docker build -f contrib/antithesis/tempo-cluster/Dockerfile \
  --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" \
  -t tempo-cluster-antithesis:latest .
docker build -f contrib/antithesis/tempo-cluster/Dockerfile.workload \
  --build-context txgen-src=../txgen \
  --build-arg NODE_IMAGE=tempo-cluster-antithesis:latest \
  -t tempo-cluster-antithesis-workload:latest .
contrib/antithesis/tempo-cluster/scripts/smoke.sh
```

Smoke uses prebuilt images (`TEMPO_IMAGE`/`WORKLOAD_IMAGE` override them), fresh
volumes, activates the test command, kills/restarts one validator and forces
recovery after 60s of workload.
It checks SDK safety/progress and copies evidence to `.bench-tmp/tempo-cluster-smoke`,
then removes the local cluster. Do not run alongside another copy with the same
container names/subnet. Unit tests need `antithesis==0.4.1 hegeltest==0.4.7`:
`python3 -m unittest discover -s contrib/antithesis/tempo-cluster/tests -v`.

CI builds the config image from this directory with a generated `.env` pairing
immutable node/workload image digests. `Dockerfile.config` copies `docker-compose.yaml` and `.env`.
Validate locally with `snouty validate contrib/antithesis/tempo-cluster` once the
images exist. **No paid launch is authorized by these build/smoke commands.**
A separately approved launch must use `basic_test`, `high_availability` fault
tolerance and fault exclusion `^driver$`, with an explicit compute-hour budget.

## Differences from the benchmark

The end-to-end benchmark (`.github/workflows/bench-e2e.yml`) runs the same
public-mix transaction preset to measure throughput. This target instead tests
consensus safety and recovery:

- Reuses `contrib/bench/txgen/helpers.nu` and the complete public-mix templates,
  including MPP, vaults and synthetic zone settlement, not real zone sequencers.
- Uses a shared 64-account genesis instead of a large state-bloat dump: 16 senders
  and existing BIP39 recipients 16–63 (replacing state-bloat fast derivation). This tests consensus under mixed transactions,
  not large-state performance. All four standard TIP20 tokens are retained.
- Fixed-count bursts preserve the preset's transaction weights; no ten-second
  gas-weight resampling or benchmark duration cutoffs. Hegel controls the seed,
  while Antithesis replay controls time/network; independently generated runs
  need not have byte-identical signatures or timestamps.
- Reuses the zones Dockerfile's pinned Rust/base images, profile and sancov shim,
  but enables full `tempo/fuzz`, including consensus assertions. Python and the
  external generator/sender are uninstrumented; node branches guide coverage.
  No extra log-forwarding/stateful-client pattern is introduced.
- Partial fixed-nonce fixture setup fails explicitly; existing setup files alone
  never prove confirmation. Recreate **local** volumes to retry failed setup;
  ordinary validator restarts retain their entire datadir and fixture identities.
