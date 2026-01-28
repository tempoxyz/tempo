---
id: TIP-XXXX
title: Brick as a new form of metering for Storage Creation
description: Introduces a separate type of gas called "brick" for storage creation operations, decoupling storage costs from compute costs and increasing contract creation pricing to 2500 brick per byte.
authors: Dankrad Feist @dankrad
status: Draft
related: TIP-1000, TIP-1010
protocolVersion: TBD
---

# TIP-XXXX: Brick as a new form of metering for Storage Creation

## Abstract

This TIP introduces a dual metering mechanism that separates the pricing of storage creation operations from compute operations. Currently, all gas costs are charged using a single basefee. This proposal introduces a second type of metering called "brick" specifically for storage creation operations, while compute, calldata, and storage read/update operations continue to use the existing gas. Additionally, contract creation pricing is increased from 1,000 gas per byte to 2,500 brick per byte to better reflect the long-term cost of storing contract code.

## Motivation

Under the current gas model (TIP-1000, TIP-1010), all operations—whether compute-intensive (e.g., cryptographic operations, loops) or storage-intensive (e.g., creating new state elements, deploying contracts)—are metered using the same mechanism. This creates several issues:

1. **Economic Misalignment**: Storage creation has a permanent cost to the network (disk space, state size, database performance), while compute is ephemeral. Storage is expensive because it has a long term effect on the network, while compute is expensive because the time to execute each single block has to be capped.

2. **No per-block cap on storage creation pricing**: The new metering unit brick does not have a per block cap. The current 1,000 gas per byte for contract code introduced by TIP-1000 undervalues the permanent storage burden, but we could not increase it further or it would be impossible to create 24 kB contracts.

3. **Limited Economic Policy Flexibility**: A single basefee prevents independent adjustment of storage vs. compute pricing in response to different economic or technical constraints.

The name brick is introduced to suggest a unit similar to gas but creating something permanent.

### Design Goals

1. **Separate Pricing Domains**: Compute operations and storage creation should have independent pricing
2. **Simplicity**: Use the same units for both basefees to minimize implementation complexity
3. **Fixed Brick Basefee**: The brick basefee should be constant. No priority fees are required since there is no per block cap
4. **Economic Sustainability**: Storage should be priced to reflect its permanent burden on the network

---

# Specification

## New "brick"

### Basefee Types

There are now two independent metering units "gas" and "brick", introducing two independent basefees:

1. **Gas Basefee** (`base_fee_per_gas`): Applies to gas operations
   - **Fixed**: `2 × 10^10` (in the smallest denomination, where 10^12 smallest units = 1 token unit, and 1 token unit = 10^-6 USD)
   - Per-block cap: 500,000,000 gas
   - Charges: CPU operations, memory expansion, precompile execution, storage loading, storage updates (non-zero → non-zero), calldata

2. **Brick Basefee** (`base_fee_per_brick`): Applies to brick operations
   - **Fixed**: `2 × 10^10` (in the smallest denomination)
   - No per-block cap
   - Charges: New state element creation (SSTORE zero → non-zero), account creation, contract code storage

### Metering and Accounting

Each transaction's total cost is now calculated as:

```
total_cost = gas × (base_fee_per_gas + priority_fee) + brick × base_fee_per_brick
```

Where:
- `gas`: Gas consumed by compute, memory, storage reads/updates
- `brick`: Brick consumed by storage creation operations (from TIP-1000)
- `base_fee_per_gas`: Fixed gas basefee (2 × 10^10 smallest units)
- `base_fee_per_brick`: Fixed brick basefee (2 × 10^10 smallest units)
- `priority_fee`: Optional tip to validators (applies to gas only)

## Brick Operations

The following operations consume **brick** (charged at `base_fee_per_brick`):

| Operation | Brick Cost | Description |
|-----------|----------|-------------|
| New state element (SSTORE zero → non-zero) | 250,000 | Creating a new storage slot |
| Account creation (nonce 0 → 1) | 250,000 | First transaction from an account |
| Contract code storage (per byte) | 2,500 | Each byte of deployed contract code |
| Contract metadata (keccak + nonce) | 500,000 | Contract codehash and account |

**Important**: The per-byte contract storage cost increases from 1,000 gas (TIP-1000) to **2,500 brick** under this TIP.

## Transaction Validation

### Intrinsic Gas Requirements

Transactions must have sufficient gas limit to cover compute operations. The transaction must also be able to pay for brick consumption. The minimum gas limit is calculated based on compute operations only:

```
min_gas_limit = compute_gas_required
```

For example:
- Transaction with `nonce == 0`: Requires at least 21,000 gas (for compute) plus sufficient balance to pay for 250,000 brick
- CREATE transaction: Requires at least 21,000 gas (for compute) plus sufficient balance to pay for brick costs

### Maximum Fee Calculation

Users specify a single `max_fee_per_gas` (or `gasPrice` in legacy transactions) that applies to both basefees. The transaction is valid only if:

```
max_fee_per_gas >= max(base_fee_per_gas, base_fee_per_brick)
```

Since both basefees are fixed at 2 × 10^10 smallest units in this TIP, the transaction is valid if `max_fee_per_gas >= 2 × 10^10`. This simplifies the user experience: users don't need to reason about two separate fee markets.

### Gas Limit and Refunds

- The gas limit specified in the transaction applies to **gas consumption only** (not brick)
- Brick consumption is unlimited per transaction (no per-block cap on brick)
- Gas refunds (e.g., from storage clearing) are applied to gas only (clearing storage is a compute operation)
- Unused gas is refunded at the rate paid (`base_fee_per_gas` + `priority_fee`)

## Contract Creation Pricing Example

Under TIP-1000:
- 1,000 byte contract: `(1,000 × 1,000) + 500,000 = 1,500,000` gas for code storage
- Account creation: `250,000` gas
- Total: `1,750,000` gas
- At 2 × 10^10 per gas: `1,750,000 × 2 × 10^10 = 3.5 × 10^16` smallest units = 0.035 token units = 0.000035 USD (3.5 cents)

Under TIP-XXXX:
- 1,000 byte contract: `(1,000 × 2,500) + 500,000 = 3,000,000` brick for code storage
- Account creation: `250,000` brick
- Total: `3,250,000` brick
- At 2 × 10^10 per brick: `3,250,000 × 2 × 10^10 = 6.5 × 10^16` smallest units = 0.065 token units = 0.000065 USD (6.5 cents)

**Impact**: Contract deployment costs increase by ~85% for the storage component.

## Block Validation

Blocks must track gas and brick consumption separately:

1. **Payment lane gas limit**: 500,000,000 gas (unchanged from TIP-1010), **general gas limit**: 30,000,000 gas (unchanged from TIP-1010)
2. **Gas accounting**: Sum of all gas consumed by transactions
3. **Brick accounting**: Sum of all brick consumed by transactions
4. **Validation**: `gas_used <= block_gas_limit` (brick has no per-block limit)

The block header includes two new fields:
- `gas_used`: Total gas consumed in the block (unchanged semantically, but now excludes brick)
- `brick_used`: Total brick consumed in the block (new field)

## Fee Distribution

The base fees from both gas and brick are burned. Priority fees (which apply only to gas) go to validators.

Total burned per block:
```
burned = (gas_used × base_fee_per_gas) + (brick_used × base_fee_per_brick)
```

Total to validators per block:
```
validator_fees = gas_used × average_priority_fee
```

---

# Invariants

1. **Dual Metering Invariant**: Every transaction MUST be metered using two independent units: `gas` for compute operations and `brick` for storage creation operations, each charged at their respective basefees.

2. **Brick Basefee Fixed Invariant**: The `base_fee_per_brick` MUST remain constant at `2 × 10^10` smallest units.

3. **Gas Basefee Fixed Invariant**: The `base_fee_per_gas` MUST remain constant at `2 × 10^10` smallest units.

4. **Metering Separation Invariant**: Operations MUST be correctly categorized as either gas operations or brick operations, with no operation counted in both categories.

5. **Brick Operations Invariant**: Storage creation operations (new state elements, account creation, contract code storage) MUST consume brick and MUST NOT consume gas.

6. **Gas Operations Invariant**: Compute operations (including storage reads and updates to existing slots) MUST consume gas and MUST NOT consume brick.

7. **Contract Code Pricing Invariant**: Contract code storage MUST cost exactly 2,500 brick per byte (increased from 1,000 gas in TIP-1000).

8. **Total Cost Invariant**: The total cost of a transaction MUST equal:
   ```
   (gas × (base_fee_per_gas + priority_fee)) + (brick × base_fee_per_brick)
   ```

9. **Block Gas Limit Invariant**: The gas consumed in a block MUST NOT exceed the block gas limit (500,000,000). Brick has no per-block limit.

10. **User Simplicity Invariant**: Users MUST be able to specify a single `max_fee_per_gas` that is compared against both basefees, ensuring the transaction is valid only if `max_fee_per_gas >= max(base_fee_per_gas, base_fee_per_brick)`.

11. **Refund Invariant**: Gas refunds (e.g., from storage clearing) MUST be applied to gas only, since storage clearing is a compute operation that does not consume brick.

---

# Implementation Notes

## High-Level Changes

1. **Dual Metering**: EVM must track gas and brick consumption separately
2. **Fixed Basefees**: Both `base_fee_per_gas` and `base_fee_per_brick` set to `2 × 10^10` smallest units
3. **Operation Classification**: Each EVM operation categorized as either gas or brick
4. **Block Headers**: Add `brick_used` field alongside existing `gas_used`
5. **Transaction Receipts**: Include both `gas_used` and `brick_used`

## Economic Impact

For typical operations at 2 × 10^10 basefee for both types:

| Operation | TIP-1000 Cost | TIP-XXXX Cost | Change |
|-----------|---------------|---------------|--------|
| TIP-20 transfer (existing) | 0.1 cent | 0.1 cent | No change |
| TIP-20 transfer (new address) | 0.6 cent | 0.6 cent | No change |
| First transaction (new account) | 0.6 cent | 0.6 cent | No change |
| 1KB contract deployment | 3.5 cents | 6.5 cents | +85% |
| 10KB contract deployment | 25 cents | 56 cents | +124% |
| 24KB contract deployment | 60 cents | 130 cents | +117% |

The primary impact is on contract deployment costs, which increase significantly to better reflect the permanent storage burden.

---

# Key Benefits

1. **No Per-Block Cap on Storage**: Brick has no per-block limit, allowing large contracts to deploy without hitting gas limits
2. **Economic Sustainability**: Increased contract code pricing (2,500 brick/byte vs 1,000 gas/byte) provides stronger protection against state growth attacks
3. **Separation of Concerns**: Gas meters ephemeral compute; brick meters permanent storage creation
4. **Future Flexibility**: Foundation for potential dynamic pricing, storage rent, or state expiry mechanisms

## State Growth Protection

At 2,500 brick/byte and 2 × 10^10 per brick:
- **Cost to create 1 TB via contract code**: $50,000,000 (vs $20M in TIP-1000)
- **24 KB contract deployment**: ~130 cents (vs 60 cents in TIP-1000)

The increased cost provides economic deterrent against state bloat while keeping deployment costs reasonable for legitimate use cases.
