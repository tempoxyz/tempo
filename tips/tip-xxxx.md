---
id: TIP-XXXX
title: Linked Accounts
description: Extends Key Authorizations with an `isolate` flag that enables msg.sender isolation, on-demand fund pulling from the parent account, and post-execution sweeping.
authors: Jake Moxey
status: Draft
related: TIP-1011, TIP-1022
protocolVersion: TBD (requires hardfork)
---

# TIP-XXXX: Linked Accounts

## Abstract

This TIP introduces an `isolate` flag on Key Authorizations. When `isolate` is enabled, the access key's address becomes `msg.sender` (instead of the root account), essentially creating a "linked account". Linked accounts can pull funds from its parent account on-demand, bounded by spending limits. After execution, remaining balances are swept back to the parent. This enables per-application identity isolation, scoped blast radius, and simplified permission management.

## Motivation

### msg.sender Isolation

In the current delegate model, all access keys share the root account's `msg.sender`. This means:

- Any contract that uses `msg.sender` for access control (e.g., `grantRole`, `approve`, vault rights) grants privileges to the root account, not the individual key.
- A compromised access key acting as `msg.sender = root` has blast radius across all `msg.sender`-gated state, not just the permissions it was granted.
- Revoking an access key does not revoke `msg.sender`-based approvals it created, since those approvals belong to the root.

Linked accounts solve this by giving each authorized account its own `msg.sender`. A compromised linked account's blast radius is limited to state it directly owns.

### Keychain Mental Model

The mental model stays rooted in **Accounts**:

- An **Account** is an address with a balance and state.
- An **Access Key** authorizes an additional account on a parent account. The access key operates in one of two modes:
  - **Delegate**: the child acts as the parent (msg.sender = parent address).
  - **Linked**: the child acts as itself (msg.sender = child address), pulling funds from the parent.

```
                ┌─────────────────────┐
                │   Parent Account    │
                │   0xdeadbeef        │
                └────────┬────────────┘
                         │
          ┌──────────────┴──────────────┐
          │                             │
  authorizeKey(                 authorizeKey(
    ..., isolate: false)           ..., isolate: true)
          │                             │
          ▼                             ▼
 ┌─────────────────┐         ┌─────────────────┐
 │ Delegate Account│         │ Linked Account  │
 │                 │         │                 │
 │ msg.sender =    │         │ msg.sender =    │
 │   0xdeadbeef    │         │   0xcafebabe    │
 │                 │         │                 │
 │ Spends parent's │         │ Pulls funds     │
 │ balance directly│         │ from parent     │
 └─────────────────┘         └─────────────────┘
```

### Delegate vs. Linked

When to use Delegate vs. Linked accounts:

| | Delegate (`isolate: false`) | Linked (`isolate: true`) |
|---|---|---|
| **Applicability** | You have full control of the key | Someone else may control the key |
| **Examples** | Additional signing devices, recovery keys, export keys | External apps, AI agents, automated services |

---

# Specification

## Terminology

| Term | Description |
|------|-------------|
| Parent Account | The canonical account (EOA) that owns the keychain. |
| Parent Key | The private key of the Parent Account (`transactionKey == 0`). |
| Delegate Account | An account authorized via Key Authorization with `isolate: false` (default, existing behavior). `msg.sender` = Parent Account. |
| Linked Account | An account authorized via Key Authorization with `isolate: true`. `msg.sender` = the account's own address. |
| Pull | On-demand transfer of funds from Parent to Linked Account during execution. |
| Sweep | Post-execution transfer of remaining funds from Linked Account back to Parent. |

## Extended Data Structures

### AuthorizedKey (Precompile Storage)

**Current:**
```
AuthorizedKey (packed into single slot):
  - byte 0:  signature_type (u8)
  - bytes 1-8: expiry (u64)
  - byte 9:  enforce_limits (bool)
  - byte 10: is_revoked (bool)
```

**Proposed:**
```
AuthorizedKey (packed into single slot):
  - byte 0:  signature_type (u8)
  - bytes 1-8: expiry (u64)
  - byte 9:  enforce_limits (bool)
  - byte 10: is_revoked (bool)
  - byte 11: isolate (bool)          // NEW
```

### KeyAuthorization (Transaction Payload)

**Current fields retained:**
- `chain_id`, `key_type`, `key_id`, `expiry`, `limits`

**New field:**
```rust
pub struct KeyAuthorization {
    pub chain_id: u64,
    pub key_type: SignatureType,
    pub key_id: Address,
    pub expiry: Option<u64>,
    pub limits: Option<Vec<TokenLimit>>,
    pub allowed_calls: Option<Vec<CallScope>>,
    pub isolate: bool,               // NEW: trailing field
}
```

## Interface Changes

### IAccountKeychain.sol

```solidity
/// @notice Key information structure (updated)
struct KeyInfo {
    SignatureType signatureType;
    address keyId;
    uint64 expiry;
    bool enforceLimits;
    bool isRevoked;
    bool isolate;                    // NEW
}

/// @notice Authorize a new key (updated)
function authorizeKey(
    address keyId,
    SignatureType signatureType,
    uint64 expiry,
    bool enforceLimits,
    TokenLimit[] calldata limits,
    bool isolate                     // NEW
) external;

/// @notice Allows a linked account to revoke itself from its parent's keychain
/// @dev Can only be called by a linked account (isolate == true) in a transaction
///      where msg.sender == keyId
function selfRevoke() external;

/// @notice Get the parent account for a linked account
/// @param keyId The linked account address
/// @return parent The parent account address (address(0) if not linked)
function getLinkedParent(address keyId) external view returns (address parent);

```

### New Events

```solidity
/// @notice Emitted when a linked account self-revokes
event KeySelfRevoked(address indexed account, address indexed keyId);

```

### New Errors

```solidity
/// @notice The key is already linked to another account
error KeyAlreadyLinked();

/// @notice The caller is not a linked account
error NotLinkedKey();
```

## Semantic Behavior

### Authorization

When `authorizeKey` is called with `isolate: true`:

1. All existing validation applies (key not exists, not revoked, valid expiry, etc.).
2. **Single-parent constraint**: If `keyId` is already authorized as a linked account on any other account, revert with `KeyAlreadyLinked`.
3. Store the `isolate` flag in the `AuthorizedKey` packed slot.
4. Store a reverse mapping: `parent[keyId] → account` for parent lookups.

### Transaction Execution

When a transaction is signed by a linked account (`isolate: true`):

```
1. VALIDATE
   - Recover signer → linked account address
   - Look up linked account in parent's keychain
   - Verify not revoked, not expired
   - Nonce: use linked account's own nonce (not parent's)
   - Gas: deduct from parent account's balance

2. SET EXECUTION CONTEXT
   - msg.sender = linked account address (NOT parent)
   - tx.origin = linked account address
   - Store parent address in transient storage for pull lookups
   - Track TIP-20 tokens touched during execution (transient)

3. EXECUTE
   - EVM executes with msg.sender = linked account address
   - On-demand pulls happen transparently (see below)

4. POST-EXECUTION SWEEP
   - For each TIP-20 token touched during execution:
     - If linked account has nonzero balance, transfer to parent
   - If linked account has nonzero native balance, transfer to parent
```

### On-Demand Pull

When a TIP-20 transfer is initiated where the sender is a linked account and the linked account has insufficient balance, the TIP-20 precompile:

```
function transfer(from, to, amount):
    balance = balanceOf(from)
    
    if from is a linked account AND balance < amount:
        deficit = amount - balance
        parent = getLinkedParent(from)
        
        // Check spending limit
        remaining = getRemainingLimit(parent, from, token)
        if deficit > remaining:
            revert SpendingLimitExceeded()
        
        // Pull from parent
        parentBalance = balanceOf(parent)
        if deficit > parentBalance:
            revert InsufficientBalance()
        
        deductBalance(parent, deficit)
        addBalance(from, deficit)
        deductSpendingLimit(parent, from, token, deficit)
    
    // Proceed with normal transfer
    ...
```

This is transparent to the calling contract — `balanceOf(linkedAccount)` reflects the pulled amount during execution.

### Inbound Transfer Redirect (TIP-1022 Extension)

TIP-1022 introduced `resolveRecipient` in the TIP-20 transfer path to redirect transfers to virtual addresses to their registered master. This TIP extends that same resolution logic to handle isolated access keys:

```
function resolveRecipient(to: address) -> address:
    // TIP-1022: virtual address redirect
    if to matches VIRTUAL_MAGIC format:
        return lookupMaster(masterId)
    
    // TIP-XXXX: parent account redirect
    parent = getLinkedParent(to)
    if parent != address(0) AND currentExecutor != to:
        return parent
    
    return to  // no redirect
```

### Post-Execution Sweep

After EVM execution completes successfully (non-revert), the protocol handler:

1. Reads the set of TIP-20 tokens touched during execution (tracked via precompile hooks).
2. For each token with a nonzero balance at the linked account address, performs an implicit transfer to the parent.
3. Transfers any remaining native balance to the parent.

This catches mid-execution receipts that bypassed the inbound redirect (because the linked account was the executor).

On revert, no sweep is needed — EVM state changes (including pulls) are rolled back.

### Self-Revoke

The `selfRevoke()` function allows a linked account to remove itself:

1. Caller must be a linked account (`isolate: true`) executing in linked mode (`msg.sender == keyId`).
2. Marks the key as revoked on the parent's keychain (same as `revokeKey`).
3. Does NOT auto-sweep — the linked account holder retains any funds at their address and can move them independently.
4. After self-revoke, the address functions as a normal EOA.

## Precompile Storage Changes

### New Storage

| Mapping | Type | Description |
|---------|------|-------------|
| `parent[keyId]` | `Address` | Reverse mapping from linked account to parent account |
| `tokens_touched` (transient) | `Set<Address>` | TIP-20 tokens accessed during current tx execution |

### Modified Storage

The `AuthorizedKey` packed slot adds one byte for `isolate` (byte 11). Existing keys have `isolate = false` by default (zero byte), maintaining backward compatibility.

## Gas Costs

TBD

## Encoding

### KeyAuthorization RLP

`isolate` is added as a trailing field using `#[rlp(trailing)]`:

```
KeyAuthorization := RLP([
    chain_id: u64,
    key_type: u8,
    key_id: address,
    expiry?: uint64,
    limits?: [TokenLimit, ...],
    allowed_calls?: [CallScope, ...],
    isolate?: bool                       // NEW, trailing
])
```

Old encodings (without `isolate`) decode as `isolate = false` (delegate mode).

---

# Backward Compatibility

This TIP requires a **hardfork** due to changes in transaction execution semantics and precompile behavior.

## RLP Encoding

`isolate` is added as a trailing field to `KeyAuthorization`. Old encodings without this field decode as `isolate = false`, preserving delegate behavior. New encodings with `isolate` will be rejected by old nodes.

## Compact/Database Encoding

Same pattern as TIP-1011: `SignedKeyAuthorization` uses a custom `Compact` impl that wraps RLP encoding internally. Version-tolerant RLP decoding handles the new trailing field. **No DB rebuild required.**

## Precompile Storage

The `AuthorizedKey` packed slot has unused bytes available (bytes 11-31). Adding `isolate` at byte 11 is additive — existing keys read `isolate = false` from the zero byte. The new `parent` mapping is a new storage slot with no migration needed.

---

# Invariants

1. **Single parent**: A linked account (`isolate: true`) MUST have at most one parent account at any time. `authorizeKey` MUST revert if the `keyId` is already linked to a different account.

2. **Spending limit enforcement**: On-demand pulls MUST respect the spending limits set on the linked account. A pull MUST NOT exceed the remaining spending limit for the token.

3. **Inbound redirect**: TIP-20 transfers to a linked account from external transactions MUST be redirected to the parent. Transfers during the linked account's own execution MUST land normally.

4. **Post-execution sweep**: After successful execution, all nonzero TIP-20 and native balances at the linked account MUST be transferred to the parent. Sweep MUST NOT execute on reverted transactions.

5. **Self-revoke restriction**: `selfRevoke()` MUST only succeed when called by a linked account in linked execution mode. Delegate keys MUST NOT self-revoke.

6. **Gas from parent**: Gas for linked account transactions MUST be deducted from the parent account's native balance, not the linked account's balance.

7. **Nonce isolation**: Linked accounts MUST maintain their own nonce, independent of the parent's nonce.

8. **Recursive pull chain**: When linked accounts are nested, pulls MUST chain through each level, with spending limits enforced at every level.

9. **Backward compatibility**: Keys authorized without `isolate` MUST behave as delegate keys (`isolate = false`). No behavioral change for existing keys.

10. **Pull atomicity**: If a pull from parent fails (insufficient balance or spending limit exceeded), the entire transaction MUST revert.

## Security Considerations

### Blast Radius Isolation

The primary security benefit: a compromised linked account's damage is bounded by its spending limits and its own `msg.sender`-gated state. It cannot affect the parent's `msg.sender`-gated state (approvals, roles, vault positions, etc.).

### Recursive Pull Depth

Deeply nested linked accounts could create long pull chains. Implementations SHOULD enforce a maximum nesting depth (e.g., 8 levels) to prevent excessive gas consumption during recursive pulls.

## References

- [IAccountKeychain.sol](tips/ref-impls/src/interfaces/IAccountKeychain.sol)
- [TIP-1011: Enhanced Access Key Permissions](tips/tip-1011.md)
- [AccountKeychain Precompile](crates/precompiles/src/account_keychain/mod.rs)
- [Porto RFC-2: Sub Accounts](https://laced-king-de5.notion.site/RFC-2-Sub-Accounts-20d32f2c34848037ab9fed2c145ac598)
