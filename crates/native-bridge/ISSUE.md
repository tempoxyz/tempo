# TokenBridge Cannot Call TIP-20 Precompiles from Solidity Contracts

## Issue

The TokenBridge E2E test fails because TIP-20 precompiles reject calls from other contracts.

## Root Cause

In `crates/precompiles/src/lib.rs`, the `tempo_precompile!` macro checks:

```rust
if !$input.is_direct_call() {
    return Ok(PrecompileOutput::new_reverted(
        0,
        DelegateCallNotAllowed {}.abi_encode().into(),
    ));
}
```

This means TIP-20 precompiles only accept "direct calls" (calls from EOAs, not from contracts). When the TokenBridge Solidity contract calls `mint()` on a TIP-20 token, it's a nested call from a contract, so the precompile reverts with `DelegateCallNotAllowed`.

## Affected Flow

1. User calls `claimTokens()` on TokenBridge contract (EOA → Contract)
2. TokenBridge calls `mint(recipient, amount)` on TIP-20 token (Contract → Precompile)
3. TIP-20 precompile rejects the call because `is_direct_call()` returns false

## Evidence

Test output shows:
- `receivedAt` check passes (message is attested)
- `ISSUER_ROLE` is verified as granted to TokenBridge
- Message hashes match between chains
- Transaction reverts during `claimTokens` at the `mint()` call
- No error data returned (precompile returns `DelegateCallNotAllowed` but Solidity doesn't propagate it)

## Possible Solutions

### Option 1: Remove the `is_direct_call()` check for TIP-20 minting

Modify the precompile to allow calls from contracts. This requires careful security analysis to ensure role-based access control is sufficient.

### Option 2: Use a native bridge precompile

Implement a dedicated bridge precompile that can mint TIP-20 tokens directly, bypassing the contract-to-precompile call restriction.

### Option 3: Use wrapped tokens that are regular ERC-20 contracts

Deploy standard ERC-20 "wrapped" tokens on Tempo instead of using TIP-20 precompiles for bridged assets. The TokenBridge would mint/burn these wrapped ERC-20s.

## Current Test Status

The test `test_token_bridge_full_flow_lock_mint_burn_unlock` verifies:
- ✅ MockERC20 deployment on Anvil
- ✅ TIP-20 creation via factory on Tempo
- ✅ ISSUER_ROLE granting to TokenBridge
- ✅ Asset registration on both chains
- ✅ USDC locking on Ethereum
- ✅ BLS threshold signature aggregation
- ✅ Attestation submission to Tempo MessageBridge
- ❌ claimTokens fails because mint() is rejected by TIP-20 precompile

## Recommendation

This is a design decision that needs team discussion. The `is_direct_call()` check was likely added for security, but it prevents valid use cases where contracts need to interact with TIP-20 tokens programmatically.

Consider whether the role-based access control (`ISSUER_ROLE`) is sufficient security, or if additional safeguards are needed when relaxing the direct-call restriction.
