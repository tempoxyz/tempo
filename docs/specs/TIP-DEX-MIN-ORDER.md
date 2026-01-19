# DEX Minimum Order Enforcement on Partial Fills

This document specifies a protocol change to prevent DoS attacks on the Stablecoin DEX by enforcing minimum order size after partial fills.

- **Spec ID**: TIP-DEX-MIN-ORDER
- **Authors/Owners**: @georgios, @dan
- **Status**: Draft
- **Related Specs**: Stablecoin DEX Specification

---

# Overview

## Abstract

When a partial fill on the Stablecoin DEX leaves an order with remaining amount below `MIN_ORDER_AMOUNT` ($100), the order is treated as **early completed**:

- Dust (remaining tokens) is refunded to maker's internal balance
- Order is marked as fully executed (not cancelled)
- For flip orders, the flip is created in a "partially filled" state

This prevents DoS attacks where malicious users create arbitrarily small orders by self-matching, while preserving flip order functionality and providing a cleaner UX (no cancellation events).

## Motivation

### Problem

The current DEX enforces a $100 minimum order size at placement time, but not after partial fills. This creates a vulnerability:

1. User places a $100+ order (e.g., $150)
2. User trades against their own order to partially fill it (e.g., buy $60)
3. Order now has $90 remaining, below the minimum
4. Repeat to create arbitrarily small orders (e.g., $0.000001)

By stacking many tiny orders on the orderbook, an attacker can:
- Increase gas costs for legitimate swaps (more orders to iterate)
- Bloat storage with dust orders
- Degrade orderbook performance

### Solution

Extend the minimum order size enforcement to partial fills via **early completion**:

1. When `remaining < MIN_ORDER_AMOUNT` after a fill, treat the order as completed
2. Refund dust to maker's internal balance
3. Emit `OrderFilled` with `partialFill = false` (order is complete, not cancelled)
4. For flip orders, create the flip in a "partially filled" state preserving chain semantics

---

# Specification

## Constants

No new constants. Uses existing:

```solidity
uint128 public constant MIN_ORDER_AMOUNT = 100_000_000; // $100 with 6 decimals
```

## Key Insight: Flip as Partially-Filled State

For flip orders, we can compute the filled amount without additional storage:

```
filled = order.amount - order.remaining
```

When a flip order is force-completed, the flip order is created in a "partially filled" state:
- `remaining` = filled (tradeable liquidity matches what was actually filled)
- `amount` = original amount (preserves flip chain semantics)

This ensures:
- The flip has correct tradeable liquidity
- When this flip is fully filled, the next flip uses the original amount
- The flip chain eventually "heals" back to original size
- No new storage fields needed

## Behavior Change

### Current Behavior

`partial_fill_order` updates `order.remaining` and leaves the order active regardless of the new remaining amount.

### New Behavior

After computing `new_remaining = order.remaining - fill_amount`:

1. If `new_remaining >= MIN_ORDER_AMOUNT` OR `new_remaining == 0`:
   - Continue with normal partial/full fill logic (no change)

2. If `0 < new_remaining < MIN_ORDER_AMOUNT` (dust remaining):
   - Credit the filled amount to maker (normal settlement)
   - Refund dust to maker's internal balance
   - Remove order from orderbook, delete from storage
   - For flip orders with `total_filled >= MIN_ORDER_AMOUNT`:
     - Create flip order in "partially filled" state:
       - `remaining = total_filled` (tradeable liquidity)
       - `amount = original amount` (preserves flip chain)
     - Flip order placed at `flip_tick`, with `is_flip = true`
   - For flip orders with `total_filled < MIN_ORDER_AMOUNT`:
     - No flip order created (filled amount too small)
   - Emit `OrderFilled` with `partialFill = false` (order is complete)
   - Emit `OrderPlaced` if flip was created

## Interface Changes

No interface changes. Existing events are reused:

```solidity
event OrderFilled(
    uint128 indexed orderId,
    address indexed maker,
    address indexed taker,
    uint128 fillAmount,
    bool partialFill  // false when order is early-completed due to dust
);

event OrderPlaced(
    uint128 indexed orderId,
    address indexed maker,
    address indexed base,
    uint128 amount,
    bool isBid,
    int16 tick,
    bool isFlip
);
```

Note: `OrderCancelled` is NOT emitted for early completion. The order is considered fully executed.

## Affected Functions

- `partial_fill_order` (internal) - Primary change location
- `fill_orders_exact_in` - Calls `partial_fill_order`
- `fill_orders_exact_out` - Calls `partial_fill_order`

## Pseudocode

```rust
fn partial_fill_order(&mut self, order: &mut Order, level: &mut TickLevel, fill_amount: u128, taker: Address) -> Result<u128> {
    let new_remaining = order.remaining() - fill_amount;
    
    // Normal maker settlement for filled portion
    settle_maker(order, fill_amount);
    
    if new_remaining > 0 && new_remaining < MIN_ORDER_AMOUNT {
        // Refund remaining to maker
        refund_remaining_to_maker(order, new_remaining);
        
        // Remove from orderbook
        remove_from_linked_list(order, level);
        update_tick_level_liquidity(level, order.remaining());
        
        if level.head == 0 {
            clear_tick_bitmap(order);
            update_best_tick_if_needed(order);
        }
        
        delete_order(order);
        
        // Handle flip orders: create flip in "partially filled" state
        if order.is_flip() {
            let total_filled = order.amount() - new_remaining;
            if total_filled >= MIN_ORDER_AMOUNT {
                // Create flip order with total_filled as initial amount (correct escrow)
                let flip_order_id = place_flip(
                    order.maker(),
                    orderbook.base,
                    total_filled,        // Use filled amount for correct escrow
                    !order.is_bid(),     // Flip side
                    order.flip_tick(),   // New tick
                    order.tick(),        // New flip_tick
                    true,                // is_flip
                );
                // Update amount to original value to preserve flip chain semantics
                // Now: remaining = total_filled, amount = original
                orders[flip_order_id].amount = order.amount();
            }
            // If total_filled < MIN_ORDER_AMOUNT, no flip (too small)
        }
        
        // Emit as complete fill (not partial, not cancelled)
        emit_order_filled(order, fill_amount, partial_fill: false);
    } else {
        // Normal partial fill
        order.remaining = new_remaining;
        update_tick_level_liquidity(level, fill_amount);
        emit_order_filled(order, fill_amount, partial_fill: true);
    }
    
    Ok(amount_out)
}
```

---

# Invariants

1. **No orders below minimum**: After any swap, no active order has `0 < remaining < MIN_ORDER_AMOUNT`

2. **Maker made whole**: When force-completed, maker receives:
   - Settlement for filled portion (normal)
   - Full refund of remaining escrowed tokens
   - Flip order in "partially filled" state (for flip orders with sufficient filled amount)

3. **Flip state preservation**: Flip orders created on force-complete have:
   - `remaining = total_filled` (tradeable liquidity)
   - `amount = original` (flip chain semantics preserved)

4. **Accounting consistency**: Total liquidity at tick level equals sum of remaining amounts of all orders at that tick

5. **Event ordering**: `OrderFilled` (with `partialFill = false`) → `OrderPlaced` (if flip created)

## Test Cases

### Non-Flip Orders
1. **Early completion triggers**: Place $150 order, swap $60 → order completed, $90 refunded as dust
2. **Boundary - at minimum**: Place $200 order, swap $100 → order remains with $100
3. **Boundary - just below**: Place $199 order, swap $100 → order completed, $99 refunded as dust
4. **Full fill unaffected**: Place $100 order, swap $100 → normal full fill

### Flip Orders
5. **Flip with sufficient filled**: Place $200 flip order, swap $110 → completed, $90 refunded, flip created (remaining=$110, amount=$200)
6. **Flip with insufficient filled**: Place $150 flip order, swap $60 → completed, $90 refunded, NO flip (filled < $100)
7. **Flip at exact minimum filled**: Place $190 flip order, swap $100 → completed, $90 refunded, flip created (remaining=$100, amount=$190)
8. **Flip chain healing**: Flip order early-completed → flip with reduced remaining → fully filled → next flip restores original amount

### Edge Cases
9. **Bid order refund**: Verify quote tokens refunded with correct rounding
10. **Ask order refund**: Verify base tokens refunded exactly
11. **Linked list integrity**: Multiple orders at tick, middle order force-completed
12. **Best tick updates**: Force-complete last order at best tick

---

# Examples

## Example 1: Non-Flip Order Early Completion

```
1. Alice places $150 ask order at tick 0
2. Bob swaps $60 quote for base (fills $60 of Alice's order)
3. Remaining = $90 < $100 minimum (dust)
4. Order early-completed:
   - Alice receives $60 quote settlement (from fill)
   - Alice receives $90 base refund (dust)
   - OrderFilled emitted with partialFill = false
```

## Example 2: Flip Order Early Completion

```
1. Alice places $200 flip bid at tick 0, flip_tick 100
2. Bob swaps $110 base for quote (fills $110 of Alice's bid)
3. Remaining = $90 < $100 minimum (dust)
4. Order early-completed:
   - Alice receives $110 base settlement
   - Alice receives $90 quote refund (dust)
   - Flip order created: ask at tick 100 with:
     - remaining = $110 (tradeable liquidity)
     - amount = $200 (original, for future flip chain)
   - OrderFilled (partialFill=false) + OrderPlaced emitted
5. Later: Flip order fully filled ($110)
   - Next flip created with amount = $200 (chain healed to original size)
```

## Example 3: Flip Order with Insufficient Filled Amount

```
1. Alice places $150 flip bid at tick 0, flip_tick 100
2. Bob swaps $60 base for quote (fills $60)
3. Remaining = $90 < $100 minimum (dust)
4. Order early-completed:
   - Alice receives $60 base settlement
   - Alice receives $90 quote refund (dust)
   - NO flip order created ($60 < $100 minimum)
   - OrderFilled emitted with partialFill = false
```

---

# Maker Considerations

Makers should understand that orders can be early-completed when remaining falls below `MIN_ORDER_AMOUNT` ($100). This affects smaller orders more significantly:

| Order Size | Min Fill Before Early Completion | % That Must Fill |
|------------|----------------------------------|------------------|
| $200 | $100 | 50% |
| $500 | $400 | 80% |
| $1,000 | $900 | 90% |
| $10,000 | $9,900 | 99% |

**Recommendation:** Makers who want full order execution should place orders significantly larger than `MIN_ORDER_AMOUNT`. For market making strategies, this behavior is generally acceptable since the filled portion is settled normally and the dust is refunded.

---

# Migration

This change requires a **hard fork** as it modifies consensus-critical behavior:

- Existing orders below minimum (if any exist from edge cases) will be early-completed on next interaction
- No state migration needed - change is forward-only
- Clients should handle:
  - Orders completing with dust refunded (no `OrderCancelled` event)
  - Flip orders in "partially filled" state (remaining < amount)
