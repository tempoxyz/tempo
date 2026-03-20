# StablecoinDEX Invariant Testing Framework

State machine testing for the StablecoinDEX orderbook using [proptest-state-machine](https://github.com/proptest-rs/proptest).

## Quick Start

```bash
# Run with default 500 cases
cargo test --test invariants --features test-utils

# Run with custom case count
PROPTEST_CASES=5000 cargo test --test invariants --features test-utils

# Verbose mode: see each transition applied
PROPTEST_CASES=10 PROPTEST_VERBOSE=1 cargo test --test invariants --features test-utils -- --nocapture

# Coverage report
./scripts/run-invariant-coverage.sh 200
```

## How It Works

The framework generates random sequences of DEX operations and verifies 8 invariants after **every** operation. Uses `proptest-state-machine` for state-aware generation — operations are only generated when they're valid for the current state.

```
proptest-state-machine generates 500 test cases
  => Each case: 1-50 transitions (state-aware)
    => Each transition: execute on real DEX + verify 8 invariants
      => If violated: shrink to minimal counterexample
```

### Two Parallel Worlds

1. **Reference model** (`DexRefState`) — lightweight abstract state that drives generation
2. **Real DEX** (`StablecoinDEX` in `HashMapStorageProvider`) — the actual code being tested

### 8 Operations

| Operation | Weight | What it tests |
|-----------|--------|---------------|
| PlaceBid | 20 | Order creation, escrow, linked list insertion |
| PlaceAsk | 20 | Same, ask side |
| PlaceFlipBid | 8 | Checkpoint atomicity, flip tick constraints |
| PlaceFlipAsk | 7 | Same, ask side |
| Cancel | 10-18 | Linked list removal, bitmap cleanup, refund rounding |
| SwapExactIn | 12-20 | Matching engine, partial/full fills, flip creation |
| SwapExactOut | 5 | Reverse path matching |
| Withdraw | 5 | Balance withdrawal |

Weights adjust dynamically: Cancel gets +8 when partially filled orders exist (rounding edge cases), SwapExactIn gets +8 when flip orders exist (trigger flip creation path).

### 8 Invariants

| Invariant | TEMPO-DEX | What it checks |
|-----------|-----------|----------------|
| linked_list | DEX14/16 | 10 checks per tick: pointers, bitmap, side, tick, remaining, cycles |
| liquidity | DEX11 | total_liquidity == sum(order.remaining()) per tick |
| balance | DEX10/8 | DEX solvency: external TIP20 balance >= internal + escrow (with dust tolerance) |
| best_tick | DEX12/13 | best_bid/ask is the actual best tick with liquidity |
| bitmap | DEX15 | Bitmap bit set ⟺ tick has liquidity > 0 |
| rounding | DEX19 | round_up >= round_down, difference <= 1, escrow monotonic |
| flip_order | (new — not in Solidity suite) | Flip tick constraints, remaining <= amount |
| cross_pair | (new — not in Solidity suite) | Control pair (CTRL/PathUSD) untouched by active pair operations |

## Extending the Framework

There are two independent ways to extend:
- **Add an invariant** — a new CHECK that runs after every operation (doesn't require new operations)
- **Add an operation** — a new ACTION the fuzzer can execute (doesn't require new invariants)

## Adding a New Invariant

### Step 1: Create the check function

```rust
// invariants/my_check.rs
use crate::invariant_tests::framework::{
    context::InvariantContext,
    result::InvariantResult,
};

pub(crate) fn check_my_invariant(ctx: &InvariantContext<'_>) -> eyre::Result<InvariantResult> {
    // Access DEX state via ctx.exchange
    // Access orderbook via ctx.exchange.books[ctx.book_key]
    // Access orders via ctx.exchange.orders[order_id].read()?
    // Access user balances via ctx.exchange.balance_of(user, token)?

    // Return Passed or Violated
    Ok(InvariantResult::Passed)
}
```

### Step 2: Register it

Add to `invariants/mod.rs`:
```rust
pub(crate) mod my_check;
```

Add to `framework/registry.rs` in `all_invariants()`:
```rust
Invariant {
    name: "my_invariant",
    description: "What it checks",
    check: my_check::check_my_invariant,
},
```

### Step 3: Run

```bash
cargo test --test invariants --features test-utils
```

## Adding a New Operation (independent from invariants)

### Step 1: Add variant to `DexTransition`

In `strategies/operations.rs`:
```rust
pub(crate) enum DexTransition {
    // ... existing variants ...
    MyNewOp { user_idx: usize, amount: u128 },
}
```

### Step 2: Generate it in `transitions()`

In `strategies/operations.rs`, inside `ReferenceStateMachine::transitions()`:
```rust
if /* condition when this op is valid */ {
    let my_op = (arb_user.clone(), arb_amount.clone())
        .prop_map(|(u, a)| DexTransition::MyNewOp { user_idx: u, amount: a })
        .boxed();
    options.push((weight, my_op));
}
```

### Step 3: Update model in `apply()`

In `strategies/operations.rs`, inside `ReferenceStateMachine::apply()`:
```rust
DexTransition::MyNewOp { .. } => {
    // Update abstract model state
}
```

### Step 4: Execute in `executor.rs`

In `strategies/executor.rs`, inside `StateMachineTest::apply()`:
```rust
DexTransition::MyNewOp { user_idx, amount } => {
    let user = users[user_idx % NUM_USERS];
    if exchange.my_new_function(user, amount).is_err() {
        return TransitionResult::None;
    }
    TransitionResult::None
}
```

## Architecture

```
tests/invariants.rs                    # Entry point
tests/invariant_tests/
├── mod.rs                             # prop_state_machine! macro
├── framework/
│   ├── context.rs                     # InvariantContext shared by all checks
│   ├── registry.rs                    # all_invariants() list
│   └── result.rs                      # Passed / Violated enum
├── strategies/
│   ├── operations.rs                  # DexTransition + DexRefState + ReferenceStateMachine
│   └── executor.rs                    # StateMachineTest + checkpoint atomicity
└── invariants/
    ├── linked_list.rs                 # 10 structural checks per tick
    ├── liquidity.rs                   # Sum verification
    ├── balance.rs                     # Solvency (TEMPO-DEX10)
    ├── best_tick.rs                   # Price discovery accuracy
    ├── bitmap.rs                      # Bitmap consistency
    ├── rounding.rs                    # Protocol-favoring rounding
    ├── flip_order.rs                  # Flip constraints
    └── cross_pair.rs                  # Isolation verification
```

## Key Implementation Details

- Uses `HashMapStorageProvider::new_with_spec(1, TempoHardfork::T2)` for production-accurate checkpoint behavior
- Each operation wrapped in explicit checkpoint to simulate EVM transaction atomicity
- `RefCell<HashMapStorageProvider>` for interior mutability in `check_invariants(&self)`
- Balance check uses dust tolerance (`swap_count * 50`) per TEMPO-DEX8
- Swap direction randomized (`buy_base: bool`) to test both bid-fill and ask-fill rounding paths
