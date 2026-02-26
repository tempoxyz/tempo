---
id: TIP-YYYY
title: Cached Policy Type for TIP-20 Transfer Policy
description: Cache the TIP-403 policy type in TIP-20 storage to eliminate one SLOAD per transfer authorization check.
author: Mallesh Pai
status: Draft
related: TIP-403
---

# TIP-YYYY: Cached Policy Type for TIP-20 Transfer Policy

## Abstract

This TIP proposes caching the TIP-403 policy type alongside the `transferPolicyId` in TIP-20 token storage. Since TIP-403 policy types are immutable after creation, caching the type eliminates the cold SLOAD of `policyData[policyId]` during transfer authorization, saving ~2,200 gas per transfer.

## Motivation

Currently, the TIP-403 `isAuthorized(policyId, user)` function reads `_policyData[policyId]` to determine the policy type (whitelist vs blacklist) before checking membership. This SLOAD is redundant because:

1. TIP-403 policy types are **immutable** — set at creation and never changed
2. The TIP-20 already stores the `transferPolicyId` and reads it on every transfer
3. The policy type can be cached when `changeTransferPolicyId` is called

By packing the policy type into the same storage slot as `transferPolicyId` and providing a new `isAuthorizedWithType` function, we eliminate one SLOAD per authorization check.

---

# Specification

## Current Storage Layout

TIP-20 slot 7 is currently packed as follows:

| Byte Offset | Field | Type | Size |
|-------------|-------|------|------|
| 0–19 | `nextQuoteToken` | address | 20 bytes |
| 20–27 | `transferPolicyId` | uint64 | 8 bytes |
| 28–31 | (unused) | — | 4 bytes |

## New Storage Layout

The unused 4 bytes in slot 7 are repurposed:

| Byte Offset | Field | Type | Size |
|-------------|-------|------|------|
| 0–19 | `nextQuoteToken` | address | 20 bytes |
| 20–27 | `transferPolicyId` | uint64 | 8 bytes |
| 28 | `transferPolicyType` | uint8 | 1 byte |
| 29 | `isPolicyCached` | uint8 | 1 byte (0 = not cached, 1 = cached) |
| 30–31 | (reserved) | — | 2 bytes |

In terms of bit positions within the 256-bit slot:

| Bits | Field |
|------|-------|
| 0–159 | `nextQuoteToken` (address) |
| 160–223 | `transferPolicyId` (uint64) |
| 224–231 | `transferPolicyType` (uint8) |
| 232–239 | `isPolicyCached` (uint8) |
| 240–255 | Reserved |

For backward compatibility, the `transferPolicyId()` view function continues to return just the policy ID.

## Interface Changes

### TIP-403 Registry Addition

```solidity
/// @notice Checks authorization using a provided policy type (avoids policyData SLOAD)
/// @param policyId The policy to check
/// @param policyType The cached policy type (must match the actual policy type)
/// @param user The address to check
/// @return True if the user is authorized under the policy
/// @dev Caller is responsible for ensuring policyType matches the policy's actual type.
///      If policyType is incorrect, authorization result will be wrong.
function isAuthorizedWithType(
    uint64 policyId, 
    PolicyType policyType, 
    address user
) external view returns (bool);
```

Implementation:

```solidity
function isAuthorizedWithType(
    uint64 policyId, 
    PolicyType policyType, 
    address user
) public view returns (bool) {
    // Special case for the "always-allow" and "always-reject" policies.
    if (policyId < 2) {
        return policyId == 1;
    }

    // Skip policyData read — caller provides the type
    return policyType == PolicyType.WHITELIST
        ? policySet[policyId][user]
        : !policySet[policyId][user];
}
```

### TIP-20 Changes

#### changeTransferPolicyId

The `changeTransferPolicyId` function caches the policy type and sets `isPolicyCached`:

```solidity
function changeTransferPolicyId(uint64 newPolicyId) external onlyRole(DEFAULT_ADMIN_ROLE) {
    if (!TIP403_REGISTRY.policyExists(newPolicyId)) {
        revert InvalidTransferPolicyId();
    }
    
    // Cache the policy type (immutable, so always valid)
    uint8 policyType = 0;
    if (newPolicyId >= 2) {
        (PolicyType pt, ) = TIP403_REGISTRY.policyData(newPolicyId);
        policyType = uint8(pt);
    }
    
    // Read current slot to preserve nextQuoteToken
    uint256 slot7 = _loadSlot7();
    address nextQuote = address(uint160(slot7));
    
    // Pack: nextQuoteToken | (policyId << 160) | (policyType << 224) | (isPolicyCached << 232)
    uint256 packed = uint256(uint160(nextQuote))
        | (uint256(newPolicyId) << 160)
        | (uint256(policyType) << 224)
        | (uint256(1) << 232);  // Mark as cached
    
    _storeSlot7(packed);
    
    emit TransferPolicyUpdate(msg.sender, newPolicyId);
}
```

#### Transfer Authorization

The transfer authorization logic checks `isPolicyCached` and lazily caches on first use:

```solidity
function _ensureTransferAuthorized(address from, address to) internal {
    uint256 slot7 = _loadSlot7();
    
    uint64 policyId = uint64(slot7 >> 160);
    uint8 policyType = uint8(slot7 >> 224);
    bool isCached = uint8(slot7 >> 232) == 1;
    
    // Lazy migration: cache policy type on first transfer post-hardfork
    if (!isCached) {
        if (policyId >= 2) {
            (PolicyType pt, ) = TIP403_REGISTRY.policyData(policyId);
            policyType = uint8(pt);
        }
        // Update storage with cached type and set isPolicyCached = 1
        // Preserve nextQuoteToken (low 160 bits)
        uint256 packed = (slot7 & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF)  // keep nextQuoteToken
            | (uint256(policyId) << 160)
            | (uint256(policyType) << 224)
            | (uint256(1) << 232);
        _storeSlot7(packed);
    }
    
    if (
        !TIP403_REGISTRY.isAuthorizedWithType(policyId, PolicyType(policyType), from)
            || !TIP403_REGISTRY.isAuthorizedWithType(policyId, PolicyType(policyType), to)
    ) revert PolicyForbids();
}
```

## Migration Strategy

Existing TIP-20 tokens on testnet/mainnet have `transferPolicyId` set but no cached policy type. The `isPolicyCached` byte (offset 29) is 0 for all existing tokens because those bytes are currently unused.

**Lazy migration**: On the first transfer of each token after the hardfork:

1. Read slot 7 and check `isPolicyCached` (byte 29)
2. If not cached (`isPolicyCached == 0`):
   - Read `policyData[policyId]` to get the policy type (one-time SLOAD)
   - Write slot 7 with cached type and `isPolicyCached = 1` (one-time SSTORE)
3. All subsequent transfers use the cached type (no extra reads)

**One-time cost per token**: The first transfer post-hardfork pays ~20,000 gas extra (SSTORE to update slot 7). All subsequent transfers save ~2,200 gas each.

**Special cases**:
- Policy ID 0 (always-reject) and 1 (always-allow): No type lookup needed, but `isPolicyCached` is still set to 1 to avoid repeated checks.
- Newly created tokens post-hardfork: `changeTransferPolicyId` sets `isPolicyCached = 1` immediately.
- Token creation: The factory/create flow must initialize with `isPolicyCached = 1` and the correct type for the default policy (ID 1).

**Revert safety**: If a transfer fails after the migration SSTORE, the entire transaction reverts, including the storage update. This is guaranteed by EVM semantics and the precompile's use of the state journal.

## Gas Impact

**Current flow (per transfer):**

| Step | Gas |
|------|-----|
| `isAuthorized(policyId, from)`: cold SLOAD `policyData` + cold SLOAD `policySet[from]` | ~4,200 |
| `isAuthorized(policyId, to)`: warm SLOAD `policyData` + cold SLOAD `policySet[to]` | ~2,200 |
| **Total** | **~6,400** |

**With caching (per transfer):**

| Step | Gas |
|------|-----|
| `isAuthorizedWithType(policyId, type, from)`: cold SLOAD `policySet[from]` | ~2,100 |
| `isAuthorizedWithType(policyId, type, to)`: cold SLOAD `policySet[to]` | ~2,100 |
| **Total** | **~4,200** |

**Summary:**

| Scenario | Gas Cost |
|----------|----------|
| First transfer post-hardfork (migration) | +~20,000 gas (one-time SSTORE) |
| Subsequent transfers | −~2,200 gas (permanent savings) |

Break-even after ~10 transfers per token.

---

# Invariants

1. **Cached Type Validity**: When `isPolicyCached == 1`, the cached `transferPolicyType` MUST match `policyData[transferPolicyId].policyType`. This is guaranteed because TIP-403 policy types are immutable after creation.

2. **Atomic Cache Update on Policy Change**: Any call to `changeTransferPolicyId` MUST atomically update `transferPolicyId`, `transferPolicyType`, and set `isPolicyCached = 1`.

3. **Lazy Migration Completeness**: After any successful transfer, `isPolicyCached` MUST be 1.

4. **Backward Compatibility**: The `transferPolicyId()` view function MUST continue to return only the policy ID (extracted from bits 160–223).

5. **Special Policy Handling**: Policy IDs 0 (always-reject) and 1 (always-allow) do not require type lookup but MUST still set `isPolicyCached = 1` after first use.

6. **Slot Preservation**: Updates to the policy cache MUST preserve the `nextQuoteToken` value in the low 160 bits of slot 7.

7. **Revert Safety**: If a transfer reverts after the lazy migration SSTORE, the storage update MUST also revert (standard EVM journaling).

8. **Token Creation**: New tokens created post-hardfork MUST be initialized with `isPolicyCached = 1` and the correct `transferPolicyType` for their initial policy.
