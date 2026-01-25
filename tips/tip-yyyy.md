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

Transaction and block gas limits apply only to execution gas:

```
Validation:
  execution_gas_consumed <= transaction_gas_limit
  block_execution_gas_consumed <= block_gas_limit

Cost:
  total_gas = execution_gas + storage_gas
  cost = total_gas × (base_fee_per_gas + priority_fee)
```

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
- Total storage gas: `62,190,000` (not counted against transaction limit)
- Execution gas for deployment: ~1-2M (counted against transaction limit)
- **Can deploy with transaction_gas_limit = 16M**

## Examples

### TIP-20 Transfer to New Address
- Execution gas: ~50,000 (transfer logic)
- Storage gas: ~250,000 (new balance slot)
- Transaction gas limit: 50,000 required
- Total cost: 300,000 gas

### TIP-20 Transfer to Existing Address
- Execution gas: ~50,000 (transfer logic)
- Storage gas: 0
- Transaction gas limit: 50,000 required
- Total cost: 50,000 gas

### Block Throughput
At 500M block gas limit:
- New accounts: ~10,000 transfers/block (same as existing accounts)
- Not penalized by storage creation costs

---

# Invariants

1. **Execution Gas Limit**: Transaction execution gas MUST NOT exceed transaction gas limit
2. **Block Execution Gas Limit**: Block execution gas MUST NOT exceed block gas limit
3. **Storage Gas Unrestricted**: Storage gas consumption has no per-transaction or per-block limit
4. **Total Cost**: Transaction cost MUST equal `(execution_gas + storage_gas) × (base_fee_per_gas + priority_fee)`
5. **Classification**: Every operation MUST be classified as either execution gas or storage gas, not both
6. **Storage Gas Operations**: Storage creation MUST consume storage gas; compute/memory/reads MUST consume execution gas

---

# Changes from TIP-1000

| Parameter | TIP-1000 | TIP-YYYY |
|-----------|----------|----------|
| Contract code pricing | 1,000 gas/byte | 2,500 gas/byte |
| Contract code counted against limits | Yes | No |
| Account creation counted against limits | Yes | No |
| Storage creation counted against limits | Yes | No |
| Transaction gas cap | 30M | Can reduce to 16M |
| General gas limit | 30M | Can reduce to lower value |

---

# Key Benefits

1. **Higher contract code pricing**: 2,500 gas/byte provides better state growth protection ($50M for 1TB vs $20M)
2. **Lower transaction cap**: Can use 16M transaction gas limit (better for execution safety)
3. **Full throughput for new accounts**: 20,000 TPS regardless of new vs existing accounts
4. **No complexity**: Single gas unit, one basefee, existing transaction format works
5. **No griefing**: Transaction gas limit still bounds execution gas (CPU/memory)

## Economic Impact

| Operation | TIP-1000 Cost | TIP-YYYY Cost |
|-----------|---------------|---------------|
| TIP-20 transfer (existing) | 0.1 cent | 0.1 cent |
| TIP-20 transfer (new) | 0.6 cent | 0.6 cent |
| 1KB contract | 3.5 cents | 6.5 cents |
| 24KB contract | 60 cents | 130 cents |

Cost calculations assume base_fee = 2 × 10^10 smallest units (1 token unit = 10^-6 USD).
