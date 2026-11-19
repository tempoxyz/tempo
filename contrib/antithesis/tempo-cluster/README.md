# Tempo consensus cluster on Antithesis

Four independent real-consensus validators (3-of-4 quorum) and one non-signing,
certified follower, with fixed IPs/keys and persistent execution/consensus datadirs.
No `--dev`, fake finality or process restart loops. Validators and the follower use
`restart: unless-stopped` so disk crash faults bring them back; each validator's consensus
journal (/data/consensus) is a separate volume labelled for disk faults; the MDBX
execution DB is not, since its mmap gets SIGBUS there. A 20-block epoch exercises DKG transitions often. The follower uses
`--follow ws://validator-0:8546` (certification stays enabled), has its own execution peer
identity and datadir, and has no validator signing key or share. It remains subject
to the same injected faults as the validators.

Signing-key fixtures are plaintext hex, generated with `--unencrypted-signing-keys`.
These disposable keys are not secrets; skipping passphrase encryption keeps
restart testing independent of age/scrypt timing calibration under injected faults.
Normal localnet generation remains encrypted by default.

The workload sends BetaUSD (`0x20c0…0002`) transfers between genesis accounts 1–16 and
mints from the issuer (account 0) to them. Genesis sets AlphaUSD as every account's fee
token, so BetaUSD moves only through these transactions and its ledger is exact.
The Python driver uses Hegel, a state-machine testing library, to choose actions:
`transfers` (weight 6) and `mints` (weight 2) each send 1–8 signed transactions to a
random validator. It is excluded from container/network fault injection, waits for all
validators and the follower to finalize, takes a ledger baseline and reports setup
complete; there are no setup transactions. Its sole `first_` command activates the workload.
No transaction traffic is submitted directly to the follower. Every signed transaction is
tracked before it is sent, since a failed send can still land; send errors are unknown
outcomes, not safety violations.

Ledger: at each common finalized height the driver applies exactly the tracked transactions
whose receipts are at or below it (a transaction whose nonce was consumed by another one is
dropped), then requires every tracked balance and `totalSupply` to equal the model and no
balance to be negative.

Properties: finalized RPC markers may temporarily lag after restart. Validators and the follower
agree on block/state, transaction and receipt roots at the same finalized height.
Retained checkpoints stay immutable, including readable checkpoints above a
lagging marker on a node that previously finalized them. Sampled finalized receipts
match their block; successful workload transactions and new finality are reached. A recovery action requests a bounded
quiet period through the platform's `ANTITHESIS_STOP_FAULTS` helper, requires all
four validators' and the follower's current finalized markers to advance beyond the pre-recovery
high-water mark and observes another successful finalized transaction,
then exits. This does not prove admission of the specific recovery transfer.
The model retains 64 checkpoints and 256 receipt IDs. RPC reads time out in 2s;
recovery polls for 180s inside a one-hour quiet lease; a final bounded RPC batch
can overrun that polling deadline. Local SDK-output mode skips the helper only
outside Antithesis. Existing clock skips are not reversed by the pause. No liveness assertion assumes quorum during active faults.

## Build and local smoke

From the repository root:

```sh
docker build -f contrib/antithesis/tempo-cluster/Dockerfile \
  --build-arg VERGEN_GIT_SHA="$(git rev-parse HEAD)" \
  -t tempo-cluster-antithesis:latest .
docker build -f contrib/antithesis/tempo-cluster/Dockerfile.workload \
  --build-arg NODE_IMAGE=tempo-cluster-antithesis:latest \
  -t tempo-cluster-antithesis-workload:latest .
contrib/antithesis/tempo-cluster/scripts/smoke.sh
```

Smoke uses prebuilt images (`TEMPO_IMAGE`/`WORKLOAD_IMAGE` override them), fresh
volumes, activates the test command, kills/restarts one validator and the follower, then forces
recovery after 60s of workload.
It requires five-node recovery and both certified-follower execution/forkchoice
assertions to have run successfully. It checks SDK safety/progress and copies evidence to `.bench-tmp/tempo-cluster-smoke`,
then removes the local cluster. Do not run alongside another copy with the same
container names/subnet. Unit tests need `antithesis==0.4.1 hegeltest==0.4.7 eth-account==0.13.7`:
`python3 -m unittest discover -s contrib/antithesis/tempo-cluster/tests -v`.

CI builds the config image from this directory with a generated `.env` pairing
immutable node/workload image digests. `Dockerfile.config` copies `docker-compose.yaml` and `.env`.
Validate locally with `snouty validate contrib/antithesis/tempo-cluster` once the
images exist. **No paid launch is authorized by these build/smoke commands.**
A separately approved launch must use `basic_test`, `high_availability` fault
tolerance and fault exclusion `^driver$`, with an explicit compute-hour budget.
