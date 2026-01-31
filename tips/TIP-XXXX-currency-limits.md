---
id: TIP-XXXX
title: Currency Spending Limits for Access Keys
description: Extends AccountKeychain to support per-currency spending limits that apply across multiple tokens sharing the same currency
authors: howydev
status: Draft
related: TIP-403
protocolVersion: TBD
searchable: false
---

# TIP-XXXX: Currency Spending Limits for Access Keys

## Abstract

This TIP extends the AccountKeychain precompile to support per-currency spending limits in addition to per-token limits. Currency limits allow a single spending cap (e.g., 1000 USD) to apply across all TIP-20 tokens that share the same currency code, enabling more flexible and intuitive access key permissions.

## Motivation

The current AccountKeychain implementation only supports per-token spending limits. This creates friction for users who want to limit total spending in a currency (e.g., "max $1000 USD per day") without having to enumerate every possible stablecoin.

For example, a user provisioning an access key for a mobile wallet may want to limit USD spending to $500, regardless of whether the app uses USDC, USDT, or any other USD-denominated token. Without currency limits, the user must set individual limits on each token, and the app must predict which USD tokens the user will hold—any tokens not explicitly listed would be unspendable by default.

Currency limits solve this by leveraging the TIP-20 `currency()` method to group tokens. When a transfer occurs, the system checks the token's currency and deducts from the corresponding currency limit.

**Design considerations:**
- Currency limits are checked *in addition to* token limits (both must pass if set)
- A key can have token limits only, currency limits only, or both
- Missing currency limits (zero value) are treated as unlimited for that currency

---

# Specification

## Data Structures

### CurrencyLimit

```solidity
/// @notice Currency spending limit structure
struct CurrencyLimit {
    uint256 amount;   // Spending limit amount
    string currency;  // Currency code (e.g., "USD", "EUR", "GBP")
}
```

### Updated KeyInfo

```solidity
/// @notice Key information structure
struct KeyInfo {
    SignatureType signatureType;  // Signature type of the key
    address keyId;                // The key identifier (address)
    uint64 expiry;                // Unix timestamp when key expires
    bool enforceLimits;           // Master switch for spending limits
    bool hasTokenLimits;          // Whether per-token limits exist
    bool hasCurrencyLimits;       // Whether per-currency limits exist
    bool isRevoked;               // Whether this key has been revoked
}
```

### Storage Layout

```solidity
contract AccountKeychain {
    // slot 0: existing keys mapping
    mapping(address => mapping(address => AuthorizedKey)) private keys;
    
    // slot 1: existing token spending limits
    mapping(bytes32 => mapping(address => uint256)) private _spendingLimits;
    
    // NEW - slot 2: currency spending limits
    // keccak256(account || keyId) -> keccak256(currency) -> remaining amount
    mapping(bytes32 => mapping(bytes32 => uint256)) private _currencyLimits;
}
```

The `AuthorizedKey` struct is updated to include two additional flags:
- `enforce_token_limits` (bool): Whether per-token limits exist for this key
- `enforce_currency_limits` (bool): Whether per-currency limits exist for this key

## Interface

### authorizeKey (Updated)

```solidity
/// @notice Authorize a new key for the caller's account
/// @param keyId The key identifier (address derived from public key)
/// @param signatureType 0: secp256k1, 1: P256, 2: WebAuthn
/// @param expiry Block timestamp when the key expires (u64::MAX for never expires)
/// @param enforceLimits Whether to enforce spending limits for this key
/// @param tokenLimits Initial token spending limits (only used if enforceLimits is true)
/// @param currencyLimits Initial currency spending limits (only used if enforceLimits is true)
function authorizeKey(
    address keyId,
    SignatureType signatureType,
    uint64 expiry,
    bool enforceLimits,
    TokenLimit[] calldata tokenLimits,
    CurrencyLimit[] calldata currencyLimits
) external;
```

**Breaking change:** The `limits` parameter is renamed to `tokenLimits` and a new `currencyLimits` parameter is added.

### updateCurrencyLimit (New)

```solidity
/// @notice Update spending limit for a specific currency on an authorized key
/// @dev MUST only be called in transactions signed by the Root Key
/// @param keyId The key ID to update
/// @param currency The currency code (e.g., "USD", "EUR")
/// @param newLimit The new spending limit
function updateCurrencyLimit(
    address keyId,
    string calldata currency,
    uint256 newLimit
) external;
```

Calling `updateCurrencyLimit` on a key with `enforceLimits=false` automatically enables limit enforcement and sets `hasCurrencyLimits=true`.

### getRemainingCurrencyLimit (New)

```solidity
/// @notice Get remaining spending limit for a key-currency pair
/// @param account The account address
/// @param keyId The key ID
/// @param currency The currency code (e.g., "USD", "EUR")
/// @return Remaining spending amount (0 means unlimited if not set)
function getRemainingCurrencyLimit(
    address account,
    address keyId,
    string calldata currency
) external view returns (uint256);
```

### Events

```solidity
/// @notice Emitted when a currency limit is updated
event CurrencyLimitUpdated(
    address indexed account,
    address indexed publicKey,
    string currency,
    uint256 newLimit
);
```

## Spending Limit Enforcement

When `authorizeTransfer` is called, the following checks occur:

1. **Root key bypass:** If `keyId == address(0)`, no limits are checked (root key has unlimited access)

2. **Passthrough keys:** If `enforceLimits == false`, no limits are checked

3. **Token limit check:** If `hasTokenLimits == true`:
   - Read remaining limit for the specific token
   - If `amount > remaining`, set `overflow = amount - remaining`, zero out remaining, and pass `overflow` to step 4
   - Otherwise, deduct `amount` from the token's remaining limit; `overflow = 0`

4. **Currency limit check:** If `hasCurrencyLimits == true`:
   - Call `ITIP20(token).currency()` to get the token's currency code
   - Compute `currencyKey = keccak256(currency)`
   - Read remaining limit for that currency
   - If `amount > remaining` (or `overflow > remaining` when token limits also exist), revert with `SpendingLimitExceeded`
   - Otherwise, deduct `amount` (or `overflow`) from the currency's remaining limit

Both checks must pass if both limit types are set. This allows configurations like:
- "Max 100 USDC per key" (token limit only)
- "Max $1000 USD total across all USD tokens" (currency limit only)
- "Max 100 USDC AND max $500 USD total" (both limits)

## RLP Encoding

The `KeyAuthorization` struct in transaction payloads is extended:

```rust
pub struct KeyAuthorization {
    pub signature_type: SignatureType,
    pub key_id: Address,
    pub expiry: Option<u64>,
    pub limits: Option<Vec<TokenLimit>>,
    pub currency_limits: Option<Vec<CurrencyLimit>>,  // NEW
}

pub struct CurrencyLimit {
    pub limit: U256,
    pub currency: String,
}
```

# Invariants

1. **Combined limit ceiling:** If a key has token limit `T` and currency limit `C` for that token's currency, the key can spend at most `T + C` of that token.

2. **Currency deduction is shared across tokens:** If USDC and USDT both return `"USD"` from `currency()`, spending either token deducts from the same USD limit.

3. **Limit flags determine enforcement, not storage values:** If `hasCurrencyLimits == false`, currency limits are not checked regardless of storage values. If `hasCurrencyLimits == true`, a remaining value of 0 means the limit is exhausted (not unlimited).

4. **Updating limits enables enforcement:** Calling `updateCurrencyLimit` on a key with `enforceLimits=false` automatically sets `enforceLimits=true` and `hasCurrencyLimits=true`. Calling `updateSpendingLimit` sets `hasTokenLimits=true` instead.

5. **Revoked keys cannot be updated:** Attempting to update currency limits on a revoked key reverts with `KeyAlreadyRevoked`.

## Test Coverage

- Authorizing a key with currency limits and verifying storage
- Currency limits enforced across multiple tokens sharing the same currency (e.g., USDC + USDT both count against USD limit)
- Updating currency limits on an existing key
- Adding currency limits to an unlimited key (verifying `enforceLimits` becomes true)
- Combined token and currency limits on the same key
- Missing currency limits treated as unlimited
- Currency limit depletion blocks further spending
- Integration with real TIP-20 tokens that implement `currency()`
