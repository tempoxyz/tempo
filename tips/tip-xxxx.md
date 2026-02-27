---
id: TIP-XXXX
title: Account-Level Transfer Policies
description: Extends TIP-403 to allow individual accounts to set their own send, receive, and token receive policies, enabling regulated entities to enforce account-level compliance controls.
author: Mallesh Pai 
status: Draft
related: TIP-403
---

# TIP-XXXX: Account-Level Transfer Policies

## Abstract

This TIP extends the TIP-403 transfer policy system to support account-level policies. Currently, TIP-403 policies are set at the token level—each TIP-20 token has a single `transferPolicyId` that governs all transfers. This proposal adds the ability for individual accounts to set their own policies across three dimensions:

1. **Send policy** (counterparty filter): Control who this account can send to
2. **Receive policy** (counterparty filter): Control who can send to this account
3. **Token receive policy** (token filter): Control which tokens this account can receive

This enables regulated entities (banks, exchanges, etc.) to enforce compliance controls at the account level, independent of and in addition to token-level policies.

## Motivation

Regulated entities operating on Tempo need the ability to control their transactions, regardless of what policies the token issuer has set. For example:

- A bank may want to only receive funds from KYC'd addresses (whitelist on receives)
- An exchange may need to block sends to sanctioned addresses (blacklist on sends)
- A custodian may require that all incoming and outgoing transfers pass through approved counterparties
- **A regulated entity may only want to hold approved stablecoins** (whitelist on tokens, e.g. a 'MiCA'-only list)
- **An institution may need to block specific tokens** known to be associated with illicit activity or memecoins (blacklist on tokens) 

The current TIP-403 system only supports token-level policies: the token issuer sets a policy, and all transfers of that token must satisfy it. This does not allow individual account holders to impose their own restrictions on counterparties or tokens.

### Design Goals

1. **Minimal changes**: Reuse the existing TIP-403 policy infrastructure (policy creation, membership management, isAuthorized logic)
2. **Composable**: Account-level policies AND token-level policies must both pass (neither can override the other)
3. **Opt-in**: Accounts without policies do not have to do anything
4. **Gas-efficient**: Minimize hot-path gas cost for transfers
5. **State-efficient**: Minimize storage overhead per opted-in account

---

# Specification

## Overview

The TIP-403 Registry is extended with a new mapping that allows any account to set its own policies:

- **Send policy**: Controls which addresses this account can send tokens to (counterparty filter)
- **Receive policy**: Controls which addresses can send tokens to this account (counterparty filter)  
- **Token receive policy**: Controls which tokens this account can receive (token filter)

These policies are checked on every TIP-20 transfer and mint in addition to the existing token-level policy check. Since TIP-20 is implemented as a precompile, a hardfork that adds this functionality will apply to all tokens automatically.

## Storage Layout

### New Storage

```solidity
mapping(address => uint256) public accountPolicies;
```

The `accountPolicies` mapping packs policy IDs and their types into a single 256-bit storage slot:

| Bits (inclusive) | Size | Field | Description |
|------------------|------|-------|-------------|
| 0–63 | 64 bits | `sendPolicyId` | Policy checked when this account is the sender (counterparty filter) |
| 64–71 | 8 bits | `sendPolicyType` | Type of send policy (0 = whitelist, 1 = blacklist) |
| 72–135 | 64 bits | `receivePolicyId` | Policy checked when this account is the receiver (counterparty filter) |
| 136–143 | 8 bits | `receivePolicyType` | Type of receive policy (0 = whitelist, 1 = blacklist) |
| 144–207 | 64 bits | `tokenReceivePolicyId` | Policy checked on tokens being received (token filter) |
| 208–215 | 8 bits | `tokenReceivePolicyType` | Type of token receive policy (0 = whitelist, 1 = blacklist) |
| 216–255 | 40 bits | Reserved | For future use (must be 0) |


A policy ID of `0` means "no policy" (always authorized). This differs from token-level TIP-403 semantics where policy ID 0 is "always-reject"; for account-level policies, ID 0 means "no account policy set" (defer to token policy only). When `policyId` is 0, the corresponding `policyType` field is ignored and SHOULD be set to 0. We use 8 bits for `policyType` even though there are currently only 2 policy types (whitelist and blacklist) for possible future expansions. 

### Why Embed Policy Type?

TIP-403 policy types are **immutable** — set at creation and never changed. By embedding the policy type in the account storage, we avoid an SLOAD to `policyData[policyId]` on every authorization check, saving ~2,100 gas per check.

When `setAccountPolicies` is called, the policy type is read from the registry once and cached in the account's storage. Since policy types cannot change, this cached value remains valid forever.

### Encoding

```solidity
function encodeAccountPolicies(
    uint64 sendPolicyId, 
    PolicyType sendPolicyType,
    uint64 receivePolicyId, 
    PolicyType receivePolicyType,
    uint64 tokenReceivePolicyId,
    PolicyType tokenReceivePolicyType
) internal pure returns (uint256) {
    return uint256(sendPolicyId) 
        | (uint256(uint8(sendPolicyType)) << 64)
        | (uint256(receivePolicyId) << 72)
        | (uint256(uint8(receivePolicyType)) << 136)
        | (uint256(tokenReceivePolicyId) << 144)
        | (uint256(uint8(tokenReceivePolicyType)) << 208);
}

function decodeAccountPolicies(uint256 packed) 
    internal pure returns (
        uint64 sendPolicyId, 
        PolicyType sendPolicyType,
        uint64 receivePolicyId, 
        PolicyType receivePolicyType,
        uint64 tokenReceivePolicyId,
        PolicyType tokenReceivePolicyType
    ) 
{
    sendPolicyId = uint64(packed);
    sendPolicyType = PolicyType(uint8(packed >> 64));
    receivePolicyId = uint64(packed >> 72);
    receivePolicyType = PolicyType(uint8(packed >> 136));
    tokenReceivePolicyId = uint64(packed >> 144);
    tokenReceivePolicyType = PolicyType(uint8(packed >> 208));
}
```

## Interface Extensions

The following functions are added to the TIP-403 Registry:

```solidity
/// @notice Sets the send, receive, and token receive policies for the caller's account
/// @param sendPolicyId Policy to check when caller sends (0 = no policy)
/// @param receivePolicyId Policy to check when caller receives (0 = no policy)
/// @param tokenReceivePolicyId Policy to check on tokens being received (0 = no policy)
/// @dev All policies must exist (or be 0). Caller can only set their own policies.
/// @dev Policy types are cached from the registry at set time (immutable, so always valid).
function setAccountPolicies(
    uint64 sendPolicyId, 
    uint64 receivePolicyId, 
    uint64 tokenReceivePolicyId
) external;

/// @notice Returns all policies for an account
/// @param account The account to query
/// @return sendPolicyId The policy checked when account sends (0 = no policy)
/// @return sendPolicyType The type of the send policy
/// @return receivePolicyId The policy checked when account receives (0 = no policy)
/// @return receivePolicyType The type of the receive policy
/// @return tokenReceivePolicyId The policy checked on tokens being received (0 = no policy)
/// @return tokenReceivePolicyType The type of the token receive policy
function getAccountPolicies(address account) 
    external view returns (
        uint64 sendPolicyId, 
        PolicyType sendPolicyType,
        uint64 receivePolicyId, 
        PolicyType receivePolicyType,
        uint64 tokenReceivePolicyId,
        PolicyType tokenReceivePolicyType
    );

/// @notice Checks if a transfer is authorized under account-level policies
/// @param from The sender address
/// @param to The receiver address
/// @param token The token contract address being transferred
/// @return True if the transfer is authorized under all account policies
/// @dev Returns true if all of the following are true:
///      - from's sendPolicy is 0 OR to is authorized under from's sendPolicy
///      - to's receivePolicy is 0 OR from is authorized under to's receivePolicy
///      - to's tokenReceivePolicy is 0 OR token is authorized under to's tokenReceivePolicy
function isTransferAuthorized(address from, address to, address token) external view returns (bool);

/// @notice Checks if a mint is authorized under the receiver's token receive policy
/// @param to The receiver address
/// @param token The token contract address being minted
/// @return True if the mint is authorized under the receiver's token receive policy
/// @dev Returns true if to's tokenReceivePolicy is 0 OR token is authorized under it.
///      This function does NOT check address-based receive policies, only the token filter.
///      Used by TIP-20 mint operations.
function isTokenReceiveAuthorized(address to, address token) external view returns (bool);
```

### Events

```solidity
/// @notice Emitted when an account updates its policies
/// @param account The account that updated its policies
/// @param sendPolicyId The new send policy (0 = no policy)
/// @param receivePolicyId The new receive policy (0 = no policy)
/// @param tokenReceivePolicyId The new token receive policy (0 = no policy)
event AccountPoliciesUpdated(
    address indexed account, 
    uint64 sendPolicyId, 
    uint64 receivePolicyId,
    uint64 tokenReceivePolicyId
);
```

### Errors

```solidity
/// @notice Error when setting a policy that does not exist
error PolicyNotFound();
```

## Authorization Logic

### setAccountPolicies

```solidity
function setAccountPolicies(
    uint64 sendPolicyId, 
    uint64 receivePolicyId,
    uint64 tokenReceivePolicyId
) external {
    PolicyType sendPolicyType;
    PolicyType receivePolicyType;
    PolicyType tokenReceivePolicyType;
    
    // Validate and cache send policy type
    if (sendPolicyId != 0) {
        if (!policyExists(sendPolicyId)) {
            revert PolicyNotFound();
        }
        (sendPolicyType, ) = policyData(sendPolicyId);
    }
    
    // Validate and cache receive policy type
    if (receivePolicyId != 0) {
        if (!policyExists(receivePolicyId)) {
            revert PolicyNotFound();
        }
        (receivePolicyType, ) = policyData(receivePolicyId);
    }
    
    // Validate and cache token receive policy type
    if (tokenReceivePolicyId != 0) {
        if (!policyExists(tokenReceivePolicyId)) {
            revert PolicyNotFound();
        }
        (tokenReceivePolicyType, ) = policyData(tokenReceivePolicyId);
    }
    
    // Store packed policy data (IDs + types)
    accountPolicies[msg.sender] = encodeAccountPolicies(
        sendPolicyId, 
        sendPolicyType,
        receivePolicyId, 
        receivePolicyType,
        tokenReceivePolicyId,
        tokenReceivePolicyType
    );
    
    emit AccountPoliciesUpdated(msg.sender, sendPolicyId, receivePolicyId, tokenReceivePolicyId);
}
```

### getAccountPolicies

```solidity
function getAccountPolicies(address account) 
    external view returns (
        uint64 sendPolicyId, 
        PolicyType sendPolicyType,
        uint64 receivePolicyId, 
        PolicyType receivePolicyType,
        uint64 tokenReceivePolicyId,
        PolicyType tokenReceivePolicyType
    ) 
{
    return decodeAccountPolicies(accountPolicies[account]);
}
```

### isTransferAuthorized

This function checks account-level policies **without** reading `policyData` — the policy type is embedded in the `accountPolicy`.

```solidity
// Pseudocode — tuple destructuring syntax simplified for clarity
function isTransferAuthorized(address from, address to, address token) external view returns (bool) {
    // Decode sender's policies (includes cached policy type)
    (
        uint64 fromSendPolicy, 
        PolicyType fromSendType,
        ,
        ,
        ,
    ) = decodeAccountPolicies(accountPolicies[from]);
    
    // Check sender's send policy: "who can I send to?"
    if (fromSendPolicy != 0) {
        bool inSet = policySet[fromSendPolicy][to];
        bool authorized = (fromSendType == PolicyType.WHITELIST) ? inSet : !inSet;
        if (!authorized) {
            return false;
        }
    }
    
    // Decode receiver's policies (includes cached policy type)
    (
        ,
        ,
        uint64 toReceivePolicy, 
        PolicyType toReceiveType,
        uint64 toTokenReceivePolicy,
        PolicyType toTokenReceiveType
    ) = decodeAccountPolicies(accountPolicies[to]);
    
    // Check receiver's receive policy: "who can send to me?"
    if (toReceivePolicy != 0) {
        bool inSet = policySet[toReceivePolicy][from];
        bool authorized = (toReceiveType == PolicyType.WHITELIST) ? inSet : !inSet;
        if (!authorized) {
            return false;
        }
    }
    
    // Check receiver's token receive policy: "which tokens can I receive?"
    if (toTokenReceivePolicy != 0) {
        bool inSet = policySet[toTokenReceivePolicy][token];
        bool authorized = (toTokenReceiveType == PolicyType.WHITELIST) ? inSet : !inSet;
        if (!authorized) {
            return false;
        }
    }
    
    return true;
}
```

### isTokenReceiveAuthorized

This function checks only the token receive policy for mint operations.

```solidity
// Pseudocode — tuple destructuring syntax simplified for clarity
function isTokenReceiveAuthorized(address to, address token) external view returns (bool) {
    // Decode receiver's policies (includes cached policy type)
    (
        ,
        ,
        ,
        ,
        uint64 toTokenReceivePolicy,
        PolicyType toTokenReceiveType
    ) = decodeAccountPolicies(accountPolicies[to]);
    
    // Check receiver's token receive policy: "which tokens can I receive?"
    if (toTokenReceivePolicy != 0) {
        bool inSet = policySet[toTokenReceivePolicy][token];
        bool authorized = (toTokenReceiveType == PolicyType.WHITELIST) ? inSet : !inSet;
        if (!authorized) {
            return false;
        }
    }
    
    return true;
}
```

## Integration with TIP-20

The `transferAuthorized` modifier in TIP-20 is updated to check both token-level and account-level policies:

```solidity
modifier transferAuthorized(address from, address to) {
    // Token-level policy check (existing behavior)
    if (
        !TIP403_REGISTRY.isAuthorized(transferPolicyId, from)
            || !TIP403_REGISTRY.isAuthorized(transferPolicyId, to)
    ) revert PolicyForbids();
    
    // Account-level policy check (new) - includes counterparty and token filtering
    if (!TIP403_REGISTRY.isTransferAuthorized(from, to, address(this))) {
        revert PolicyForbids();
    }
    _;
}
```

### Affected Functions

The following TIP-20 functions use the `transferAuthorized` modifier and will now also check account-level policies:

- `transfer(address to, uint256 amount)`
- `transferFrom(address from, address to, uint256 amount)`
- `transferWithMemo(address to, uint256 amount, bytes32 memo)`
- `transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo)`
- `systemTransferFrom(address from, address to, uint256 amount)`

### Mint Behavior

Minting checks both the token-level policy AND the recipient's **token receive policy** (but not the address-based receive policy). This is important because TIP-20 creation is permissionless — anyone can create a token and attempt to mint to any address. A regulated entity can block **unwanted tokens** via token receive policy (token filter).

```solidity
function _mint(address to, uint256 amount) internal {
    // Token-level policy check (existing, unchanged)
    if (!TIP403_REGISTRY.isAuthorized(transferPolicyId, to)) {
        revert PolicyForbids();
    }
    
    // Account-level token receive policy check (new)
    if (!TIP403_REGISTRY.isTokenReceiveAuthorized(to, address(this))) {
        revert PolicyForbids();
    }
    
    // ... rest of mint logic
}
```

**Rationale:** A regulated entity (e.g., bank) may only want to hold approved tokens like USDC/EURC (token receive policy). Without this check, anyone could spam regulated accounts with unwanted tokens from malicious TIP-20 contracts.

**Why not check receive policy (counterparty filter) on mint?** The receive policy is designed to filter counterparties in transfers — it answers "who can send to me?" For minting, the "sender" is conceptually the token issuer, but:
- Issuers are already permissioned via `ISSUER_ROLE` at the token level
- Blocking mints based on issuer address would require regulated entities to maintain issuer allowlists, which is redundant with token-level controls
- The primary concern for regulated entities is *which tokens* they hold, not *who minted* them

The token receive policy alone provides sufficient protection against unwanted token spam.

### Burn Behavior

Burning does not involve a counterparty, so account-level policies are not applicable. The existing behavior is unchanged.

### Self-Transfers

Self-transfers (`from == to`) are treated as normal transfers and are subject to both send and receive policy checks. If an account sets a whitelist receive policy, it SHOULD include itself if self-transfers are needed. Note that for self-transfers, the second `accountPolicies` SLOAD is warm (~100 gas instead of ~2,100 gas).

### Fee Transfers

Fee transfers via `transferFeePreTx` and `transferFeePostTx` bypass account-level policy checks since they are system operations. Similarly, any system-initiated transfers that do not go through the `transferAuthorized` modifier are exempt. 

## Gas Cost Analysis

### Per-Transfer Overhead (Incremental)

| Scenario | Additional Gas |
|----------|----------------|
| Neither account has policies set | ~4,200 gas (2 SLOADs for accountPolicies) |
| Sender has send policy | ~6,300 gas (+1 policySet SLOAD) |
| Receiver has receive policy | ~6,300 gas (+1 policySet SLOAD) |
| Receiver has token receive policy | ~6,300 gas (+1 policySet SLOAD) |
| Receiver has receive + token policy | ~8,400 gas (+2 policySet SLOADs) |
| Both parties, all policies | ~12,600 gas (+4 policySet SLOADs) |

### Breakdown

1. `accountPolicies[from]` SLOAD: ~2,100 gas
2. `accountPolicies[to]` SLOAD: ~2,100 gas
3. If `fromSendPolicy != 0`: `policySet[fromSendPolicy][to]` SLOAD: ~2,100 gas
4. If `toReceivePolicy != 0`: `policySet[toReceivePolicy][from]` SLOAD: ~2,100 gas
5. If `toTokenReceivePolicy != 0`: `policySet[toTokenReceivePolicy][token]` SLOAD: ~2,100 gas

**Note on optimization**: Because we embed the policy type in `accountPolicies`, we do NOT need to read `policyData[policyId]` during authorization. This saves ~2,100 gas per policy check compared to a naive implementation.

The baseline ~4,200 gas is incurred on ALL transfers, even when no accounts have policies set. This is the cost of reading the two `accountPolicies` slots to check if policies exist. Token receive policy adds no baseline cost (packed in same slot).

*Note: Gas costs above assume cold SLOADs. If storage slots were accessed earlier in the same transaction, warm SLOADs cost only ~100 gas. For example, if `accountPolicies[from]` is warm, the baseline overhead drops to ~2,200 gas (one cold + one warm SLOAD).*

### State Creation Costs

Per TIP-1000, Tempo charges 250,000 gas for new state element creation (SSTORE zero→non-zero).

| Operation | Gas Cost |
|-----------|----------|
| First call to `setAccountPolicies` (creates slot) | ~250,000 gas |
| Subsequent updates to account policies | ~5,000 gas |
| Adding address to policy membership | ~250,000 gas (first time) |
| Updating address in policy membership | ~5,000 gas |

## Shared Policy Semantics

An account can reference **any existing TIP-403 policy**, including policies administered by other accounts. This enables shared compliance lists, with the same tradeoffs as multiple TIP-20s sharing a policy. 


# Invariants

The following invariants must always hold:

1. **Account Sovereignty**: Only an account itself can set its own account-level policies via `setAccountPolicies`. No other account can modify another account's `policyId`.

2. **Policy Existence**: `setAccountPolicies` MUST revert with `PolicyNotFound()` if any of `sendPolicyId`, `receivePolicyId`, or `tokenReceivePolicyId` is non-zero and does not correspond to an existing policy.

3. **Zero Policy Semantics**: A policy ID of `0` in `accountPolicies` MUST be interpreted as "no account-level policy" (always authorized at the account level). This differs from the token-level semantics where policy ID 0 is "always-reject".

4. **Composable Authorization (Transfers)**: A transfer is authorized if and only if ALL of the following are true:
   - Token-level policy authorizes `from`: `isAuthorized(token.transferPolicyId, from)`
   - Token-level policy authorizes `to`: `isAuthorized(token.transferPolicyId, to)`
   - Account-level send policy authorizes `to`: `from.sendPolicyId == 0 OR isAuthorized(from.sendPolicyId, to)`
   - Account-level receive policy authorizes `from`: `to.receivePolicyId == 0 OR isAuthorized(to.receivePolicyId, from)`
   - Account-level token receive policy authorizes `token`: `to.tokenReceivePolicyId == 0 OR isAuthorized(to.tokenReceivePolicyId, token)`

4a. **Composable Authorization (Mints)**: A mint is authorized if and only if ALL of the following are true:
   - Token-level policy authorizes `to`: `isAuthorized(token.transferPolicyId, to)`
   - Account-level token receive policy authorizes `token`: `to.tokenReceivePolicyId == 0 OR isAuthorized(to.tokenReceivePolicyId, token)`
   - Note: Address-based receive policy is NOT checked for mints.

5. **Mint Policy Check**: Minting operations MUST check the recipient's account-level **token receive policy** only (not the address-based receive policy). This protects regulated accounts from unwanted tokens while avoiding redundant issuer filtering.

6. **Burn Exemption**: Burn operations MUST NOT check account-level policies.

7. **Fee Transfer Exemption**: Fee transfers (`transferFeePreTx`, `transferFeePostTx`) MUST NOT check account-level policies.

8. **Storage Efficiency**: Account policies MUST be stored in a single storage slot per account (packed policy IDs and types into 256 bits).

9. **Gas Consistency**: Reading `accountPolicies[address]` for a non-existent entry MUST return 0 (interpreted as no policies set), incurring only the cold SLOAD cost (~2,100 gas).

10. **Cached Policy Type Validity**: The policy type cached in `accountPolicies` MUST always match the policy type in `policyData[policyId]`. This is guaranteed because TIP-403 policy types are immutable after creation.

11. **Policy Immutability Assumption**: This TIP assumes TIP-403 policies are never deleted and policy types are immutable. If policies could be deleted or have their types changed, cached types would become invalid. Any future TIP that allows policy deletion or type modification MUST address cache invalidation.

12. **Self-Transfer Behavior**: Self-transfers (`from == to`) are subject to both the sender's send policy (checking self as recipient) and the receiver's receive policy (checking self as sender). Accounts using whitelist policies SHOULD include themselves if self-transfers are required.

13. **Ignored Policy Type**: When `policyId` is 0, the corresponding `policyType` field MUST be ignored during authorization checks. The authorization result is always "authorized" regardless of the policyType value.

