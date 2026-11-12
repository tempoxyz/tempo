# Zone E2E Test Harness

End-to-end test infrastructure for the Tempo Zone node, supporting both fast
synthetic injection and real in-process L1 integration.

## Architecture

The harness provides two independent testing paths:

```
┌─────────────────────────────┐     ┌──────────────────────────────┐
│  Injection Path (e2e.rs)    │     │  Real L1 Path (l1_e2e.rs)    │
│                             │     │                              │
│  L1Fixture builds synthetic │     │  L1TestNode (Tempo dev mode) │
│  TempoHeaders + Deposits    │     │  produces real blocks @500ms │
│           │                 │     │           │                  │
│           ▼                 │     │           ▼                  │
│  DepositQueue.enqueue()     │     │  L1Subscriber (WS + HTTP)    │
│  + seed_l1_cache()          │     │  parses encrypted deposits   │
│                             │     │           │                  │
└───────────┬─────────────────┘     └───────────┬──────────────────┘
            │                                   │
            └───────────────┬───────────────────┘
                            ▼
                    ┌───────────────┐
                    │ DepositQueue  │
                    └───────┬───────┘
                            ▼
                    ┌───────────────┐
                    │  ZoneEngine   │  (pops L1 blocks, builds L2 blocks)
                    └───────┬───────┘
                            ▼
              ┌─────────────────────────┐
              │  Zone L2 Predeploys     │
              │  TempoState  (0x1c..00) │  slot 0=blockHash, slot 7=packed fields
              │  ZoneInbox   (0x1c..01) │  advanceTempo → mint pathUSD
              │  ZoneOutbox  (0x1c..02) │  finalizeWithdrawalBatch
              │  StateReader (0x1c..04) │  reads L1 storage via cache
              └─────────────────────────┘
```

### Injection Path (`e2e.rs`)

Uses `L1Fixture` to manually construct `TempoHeader` and `Deposit` objects,
push them into the `DepositQueue`, and seed the `L1StateCache` for
`TempoState` storage reads. Fast (~1s per test) and deterministic.

```rust
let (zone, mut fixture) = start_local_zone_with_fixture(10).await?;
let deposit = fixture.make_deposit(sender, recipient, amount);
fixture.inject_deposits(&zone.deposit_queue, vec![deposit]);
// poll for balance change...
```

**L1Fixture internals:**
- Chains `parent_hash = keccak256(rlp(prev_header))` to match `TempoState` verification
- Monotonic block numbers starting from 1, timestamps from 1,000,000
- `seed_l1_cache()` populates portal storage slots (sequencer membership and deposit queue hash=3)
  so `TempoState` storage reads succeed without a real L1

**Multi-zone support:** Use `next_block()` + `enqueue()` to broadcast the same
`FixtureBlock` to multiple zone deposit queues:

```rust
let b1 = fixture.next_block();
fixture.enqueue(&b1, &zone1.deposit_queue, vec![deposit_for_zone1]);
fixture.enqueue(&b1, &zone2.deposit_queue, vec![]);
```

### Real L1 Path (`l1_e2e.rs`)

Starts an in-process Tempo L1 dev node via `L1TestNode::start()`, then connects
a zone node via `ZoneTestNode::start_from_l1()`. The `L1Subscriber` receives
real blocks over WebSocket.

The default L1 starts at T13. Its genesis copies the bundled Solidity verifier
stub to `0xBEEF` and patches the shared portal bytecode's proof-call target to use
that address. The patch preserves code length and requires a unique matching
instruction sequence. Portal state, certificate domains, native precompiles, and
prewarming retain their normal behavior.

The T12-to-T13 migration-and-settlement test instead creates its portal in genesis
using the native factory under T12, then points its verifier storage and factory
metadata at `0xBEEF`, with a handwritten runtime returning ABI-encoded `true` for
any calldata so both verifier ABIs work. It uses the canonical shared runtimes: the
T13 upgrade replaces the runtime but preserves the mock verifier in storage.
Other tests continue creating their zones through real factory transactions.

**Genesis patching in `start_from_l1()`:**

The zone's `TempoState` genesis must be anchored to the L1's current state.
`start_from_l1()` fetches the L1's latest header and patches the bundled genesis
template (`crates/node/assets/zone-dev-genesis.json`, via `zone_node::genesis`):

1. **Slot 0** (`tempoBlockHash`): Set to `keccak256(rlp(l1_header))`
2. **Slot 7** (packed `uint64` fields): Low 64 bits set to `l1_header.number`
   - Layout: `(tempoBlockNumber:u64, tempoGasLimit:u64, tempoGasUsed:u64, tempoTimestamp:u64)`
   - Only `tempoBlockNumber` is currently patched; other fields retain genesis defaults

## Test Inventory

### `e2e.rs` — Injection-Based Tests

| Test | What it exercises |
|------|-------------------|
| `test_deposit_via_queue_injection` | Single deposit → pathUSD mint on L2 |
| `test_multiple_deposits_across_blocks` | Multi-block, multi-recipient deposits |
| `test_empty_l1_blocks_advance_zone` | Chain continuity without deposits |
| `test_two_zones_independent_deposits` | Cross-zone isolation (shared L1 timeline, independent queues) |
| `test_tempo_state_advances_with_l1_blocks` | `tempoBlockNumber` and `tempoBlockHash` tracking |
| `test_zone_inbox_events_on_deposit` | `TempoAdvanced` + `DepositProcessed` event emission |
| `test_withdrawal_batch_finalization` | `ZoneOutbox.withdrawalBatchIndex` advancement |
| `test_large_deposit_batch` | 10 deposits in one L1 block |

### `l1_e2e.rs` — Real L1 Integration Tests

| Test | What it exercises |
|------|-------------------|
| `test_zone_advances_with_real_l1` | Full L1Subscriber → DepositQueue → ZoneEngine pipeline |
| `test_deposit_via_real_l1` | Zone startup from real L1 + initial state verification |

### `deposit.rs` — Testnet Integration Tests (ignored by default)

| Test | What it exercises |
|------|-------------------|
| `test_l1_deposit_mints_on_zone` | Real deposit on testnet portal → mint on local zone |

## Key Types

- **`ZoneTestNode`** — In-process zone L2 node with RPC endpoint. Fields are
  private; use `http_url()`, `deposit_queue()`, `l1_state_cache()` getters.
  Constructed via `start_local()`, `start_from_l1()`, or `start()`.
- **`L1TestNode`** — In-process Tempo L1 dev node. Fields are private; use
  `http_url()` and `ws_url()` getters. Constructed via `start()`.
- **`L1Fixture`** — Synthetic L1 block builder maintaining hash chain continuity.
- **`FixtureBlock`** — Clonable L1 block for multi-zone broadcast.
- **`poll_until`** — Generic async condition poller with timeout.

## Known Issues / Improvements

- **Chain ID collisions:** `start_local()` hardcodes `chain_id = 1337`. Tests
  running in parallel can collide. Use `start_local_with_chain_id()` with unique
  IDs, or switch `start_local()` to pick random chain IDs.
- **Slot 7 partial patch:** `start_from_l1()` only patches `tempoBlockNumber` in
  the packed slot 7. Should also patch `tempoGasLimit`, `tempoGasUsed`, and
  `tempoTimestamp` from the anchor header for full consistency.
- **Event assertions:** Some tests query events from block 0 and assume ordering.
  Filter by sender/recipient/amount for robustness.
