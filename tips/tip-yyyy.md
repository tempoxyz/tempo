---
id: TIP-YYYY
title: Exempt Storage Creation from Gas Limits
description: Storage creation gas costs are charged but don't count against transaction or block gas limits, enabling higher contract code pricing and better throughput for new account operations.
authors: Dankrad Feist @dankrad
status: Draft
related: TIP-1000, TIP-1010
protocolVersion: TBD
---

# TIP-YYYY: Exempt Storage Creation from Gas Limits

## Abstract

Storage creation operations (new state elements, account creation, contract code storage) continue to consume and be charged for gas, but this gas does not count against transaction or block gas limits. This allows increasing contract code pricing to 2,500 gas/byte without preventing large contract deployments, and prevents new account creation from reducing effective throughput.

## Motivation

TIP-1000 increased storage creation costs to 250,000 gas per operation and 1,000 gas/byte for contract code. This created two problems:

1. **Contract deployment constraints**: 24KB contracts require ~26M gas, forcing us to:
   - Keep transaction gas cap at 30M (would prefer 16M)
   - Keep general gas limit at 30M (would prefer lower)
   - Limit contract code to 1,000 gas/byte (would prefer 2,500)

2. **New account throughput penalty**: TIP-20 transfer to new address costs 300,000 gas (vs 50,000 to existing). At 500M gas/block:
   - Existing accounts: 10,000 transfers/block = 20,000 TPS
   - New accounts: 1,667 transfers/block = 3,334 TPS
   - 6x throughput reduction despite execution stack handling it fine

The root cause: storage creation gas counts against limits designed for execution time constraints. Storage creation is permanent (disk) not ephemeral (CPU), and shouldn't be bounded by per-block execution limits.

---

# Specification

## Gas Accounting

All operations continue to consume gas as specified in TIP-1000. Gas is now categorized into two types for accounting purposes:

- **Execution gas**: Compute, memory, storage reads/updates, calldata
- **Storage gas**: New state elements, account creation, contract code storage

## Gas Limits

Storage gas counts against the user's transaction gas limit (to prevent surprise costs) but NOT against protocol limits:

```
User Authorization:
  execution_gas + storage_gas <= transaction.gas_limit

Protocol Limits:
  execution_gas <= max_transaction_gas_limit (EIP-7825, e.g. 16M)
  block_execution_gas <= block_gas_limit (e.g. 500M)

Cost:
  total_gas = execution_gas + storage_gas
  cost = total_gas × (base_fee_per_gas + priority_fee)
```

**Rationale**:
- User's `gas_limit` bounds total cost (no surprise charges)
- Protocol limits bound only execution gas (block time constraint)
- Storage doesn't reduce block execution capacity or prevent large contracts

## Storage Gas Operations

The following operations consume storage gas (not counted against limits):

| Operation | Gas Cost | Counted Against Limits |
|-----------|----------|------------------------|
| New state element (SSTORE zero → non-zero) | 250,000 | No |
| Account creation (nonce 0 → 1) | 250,000 | No |
| Contract code storage (per byte) | 2,500 | No |
| Contract metadata (keccak + nonce) | 500,000 | No |

All other operations consume execution gas (counted against limits).

## Contract Creation Pricing

Contract code storage cost increases from 1,000 to **2,500 gas/byte**.

Example for 24KB contract:
- Contract code: `24,576 × 2,500 = 61,440,000` storage gas
- Contract metadata: `500,000` storage gas
- Account creation: `250,000` storage gas
- Execution gas for deployment: ~2M
- Total gas: ~64M
- User must set `transaction.gas_limit >= 64M` (authorizes cost)
- But only ~2M execution gas counts against protocol's max_transaction_gas_limit (e.g. 16M)
- **Can deploy even with protocol max_transaction_gas_limit = 16M**

## Examples

### TIP-20 Transfer to New Address
- Execution gas: ~50,000 (transfer logic)
- Storage gas: ~250,000 (new balance slot)
- User must authorize: `gas_limit >= 300,000`
- Counts toward block limit: ~50,000 execution gas
- Total cost: 300,000 gas

### TIP-20 Transfer to Existing Address
- Execution gas: ~50,000 (transfer logic)
- Storage gas: 0
- User must authorize: `gas_limit >= 50,000`
- Counts toward block limit: ~50,000 execution gas
- Total cost: 50,000 gas

### Block Throughput
At 500M execution gas block limit:
- Each transfer (new or existing) consumes ~50k execution gas
- 10,000 transfers per block (regardless of new vs existing accounts)
- Storage gas doesn't reduce block capacity

---

# Invariants

1. **User Authorization**: `execution_gas + storage_gas` MUST NOT exceed `transaction.gas_limit` (prevents surprise costs)
2. **Protocol Transaction Limit**: `execution_gas` MUST NOT exceed `max_transaction_gas_limit` (EIP-7825 limit, e.g. 16M)
3. **Protocol Block Limit**: Block `execution_gas` MUST NOT exceed `block_gas_limit` (e.g. 500M)
4. **Storage Gas Exemption**: Storage gas MUST NOT count toward protocol limits (transaction and block)
5. **Total Cost**: Transaction cost MUST equal `(execution_gas + storage_gas) × (base_fee_per_gas + priority_fee)`
6. **Classification**: Every operation MUST be classified as either execution gas or storage gas, not both
7. **Storage Gas Operations**: Storage creation MUST consume storage gas; compute/memory/reads MUST consume execution gas

---

# Changes from TIP-1000

| Parameter | TIP-1000 | TIP-YYYY |
|-----------|----------|----------|
| Contract code pricing | 1,000 gas/byte | 2,500 gas/byte |
| Storage gas counts toward user's gas_limit | Yes | Yes (no change) |
| Storage gas counts toward protocol limits | Yes | No (exempted) |
| Max transaction gas limit (EIP-7825) | 30M | Can reduce to 16M |
| Block gas limit for execution | 500M | 500M (unchanged) |
| Block gas limit for storage | 500M (shared) | Unlimited (exempted) |

---

# Key Benefits

1. **Higher contract code pricing**: 2,500 gas/byte provides better state growth protection ($50M for 1TB vs $20M)
2. **Lower protocol transaction limit**: Can use 16M max_transaction_gas_limit (better for execution safety) while still deploying 24KB contracts
3. **Full throughput for new accounts**: 20,000 TPS regardless of new vs existing accounts (storage doesn't consume block capacity)
4. **No surprise costs**: User's `gas_limit` still bounds total cost (no griefing)
5. **No complexity**: Single gas unit, one basefee, existing transaction format works

## Economic Impact

| Operation | TIP-1000 Cost | TIP-YYYY Cost |
|-----------|---------------|---------------|
| TIP-20 transfer (existing) | 0.1 cent | 0.1 cent |
| TIP-20 transfer (new) | 0.6 cent | 0.6 cent |
| 1KB contract | 3.5 cents | 6.5 cents |
| 24KB contract | 60 cents | 130 cents |

Cost calculations assume base_fee = 2 × 10^10 smallest units (1 token unit = 10^-6 USD).
