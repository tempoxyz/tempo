# Zones lifecycle model and implementation trace experiment

This pilot model-checks the deposit/withdrawal lifecycle in [the spec](../specs/spec.md)
and checks selected observations from the Solidity portal and native Rust precompiles
against the same TLA+ actions. It is bounded safety checking plus trace conformance,
not a proof that all implementation executions refine the specification.

## Run

Requirements: the repository's Rust toolchain, `uv`, Java 11 or later, an official
[`tla2tools.jar`](https://github.com/tlaplus/tlaplus/releases), and a Tempo-capable
Forge that supports this checkout's `tempo:T8` configuration (tested with Foundry
1.8.5; 1.6.0 does not). Initialize the contract submodules first:

```sh
git submodule update --init --depth 1 \
  crates/zones/contracts/lib/forge-std crates/zones/contracts/lib/tempo-std
export TLA2TOOLS_JAR=/absolute/path/to/tla2tools.jar
# Optional: export JAVA=/absolute/path/to/java FORGE=/absolute/path/to/forge
zones/formal/run.sh
```

The script executes both implementations, captures their `ZONES_TLA` observations,
runs the bounded model, replays every scenario, and verifies that corrupting the
last observation of each scenario causes TLC to reject it. It uses temporary files
and does not download or execute a prover or contact a chain.

For just the bounded model:

```sh
uv run python zones/formal/check.py --jar "$TLA2TOOLS_JAR"
```

For previously captured logs:

```sh
uv run python zones/formal/check.py --jar "$TLA2TOOLS_JAR" \
  --trace native.log --trace portal.log --negative-control
```

## What the model checks

`Zones.tla` tracks escrow, zone supply, funds released on Tempo, both refund
balances, the deposit log, pending withdrawals, finalized batches awaiting proof
acceptance, accepted FIFO batches, deposit cursors, and fallback nonces.
`Zones.cfg` bounds external funding and withdrawal requests to two each and
finalizations to three. Operations move one unit of a single token; fees are zero.
Deposit capacity is scaled to three with one reserved slot, versus 230/20 in the
implementation. `Advance` imports the complete outstanding suffix atomically,
with independently successful or failed credits.

| Spec section | Model actions / checks |
| --- | --- |
| Deposit Queue, Deposits | `Fund`, `Advance`; capacity, cursor ordering |
| Deposit Failures and Bounce-Back | Failed import queues a nonce-zero refund withdrawal |
| Withdrawal Request | `Request` burns supply and assigns a fresh fallback nonce |
| Withdrawal Batching | `Finalize` captures the complete pending queue, including empty batches |
| Withdrawal Queue, Withdrawal Processing | `Submit`, `Deliver`; ordered batches and partial dequeue |
| Withdrawal Failures and Bounce-Back | Failed user withdrawal appends a bounce deposit; its import consumes the nonce |
| Refund claims | `ClaimPortal`, `ClaimZone`; terminal refunds, no repeated bounce |

TLC checks `TypeOK`, `Conservation`, `EscrowBacking`, `DepositCapacity`,
`QueueIndices`, and `FallbackAvailable` in every reachable bounded state. The
conservation equation includes in-flight deposits, withdrawals, and finalized
batches, so funds are accounted for between chains as well as at rest.
Successful Tempo delivery leaves the zone-local fallback mapping intact; only
bounce-back import consumes it. Modeling successful delivery as deleting that
mapping would add a cross-chain operation that the spec does not define.

FIFO order and fresh nonces are encoded in the transition relation. The six
invariants do not independently establish every ordering or uniqueness property.
No fairness or liveness property is checked.

## What executes

The native test in `crates/zones/precompiles/src/inbox/tests/tla.rs` runs the real
Inbox/Outbox ABI dispatch, ECIES deposit verification, TIP-20 mint/burn, batch
finalization, nonce consumption, receive-policy failure, and zone refund claims.
It observes total supply, processed deposit count, pending count, finalization
index, last nonce, live fallback mappings, and zone refunds through the real state
APIs. Its L1 headers, portal storage, and settlement steps are fixtures.

The Foundry test in
`crates/zones/contracts/test/tempo/ZonesTlaTrace.t.sol` runs the real portal
deposit, batch acceptance, queue processing, failure routing, and refund paths
with Tempo-native token precompiles. It observes escrow, portal refunds, deposit
count, accepted cursor, batch index, and queue indices. It inherits the existing
test setup: certificate recovery is mocked and the configured test verifier
accepts fixture proofs. Zone execution is a fixture in these traces.

Eight scenarios cover successful delivery, failed deposit refunds, failed
withdrawal bounce-back minting, parked zone refunds and claims, empty batches,
FIFO rejection, split processing of a two-item batch, and reverted/empty retries.

`Replay.tla` uses the exact transition operators in `Zones.tla`; the Python runner
only parses observations and renders TLA+ data. Each action label fixes its outcome,
leaving at most one model successor. A measured field that disagrees with that
successor makes the replay deadlock. Only fields actually observed in the source
process are compared; missing fields are not evidence about that implementation.
An explicit `complete` observation is required to reject truncated scenario logs.

The chains run separately and do not exchange their actual message bytes. These
are complementary implementation slices through an end-to-end abstract lifecycle,
not a connected two-chain end-to-end execution. In particular this experiment
does not validate proof soundness, certificates, cryptographic commitments against
each other, real networking, reorgs, leader rotation, callbacks, multi-token policy
changes, fees, or the production 230/20 boundary. Passing traces say nothing about
unrecorded executions or unobserved fields.

## Experiment result

See [RESULTS.md](RESULTS.md) for the tested snapshot, observed counts, and an
implementation mutation that the replay rejects. The next extension should pass
actual deposit, withdrawal, and bounce-back messages between the two harnesses,
then generate bounded action schedules and faults against those connected
implementations. Add proof/certificate checks and fairness assumptions separately
before making stronger verification claims.

This follows the basic idea of
[TLC trace validation](https://docs.tlapl.us/using:tlc:trace_validation): check
recorded implementation behavior against a specification, with explicit limits
on what the recordings establish.
