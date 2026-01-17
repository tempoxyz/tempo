# Tempo Stablecoin Bridge - Security Audit Round 2

**Auditor**: samczsun (simulated)  
**Date**: 2026-01-17  
**Scope**: Post-remediation review of all bridge components  
**Commit**: `6e1b789c` (audit-fixes branch)

---

## Executive Summary

The remediation work addressed all 14 findings from Round 1. This follow-up audit identified **3 new findings** (1 Medium, 2 Low) and **4 informational observations**.

**Overall Assessment**: The bridge is significantly more secure after remediation. The validator-attested model is well-documented, and critical cryptographic issues have been fixed. The remaining findings are defense-in-depth recommendations rather than exploitable vulnerabilities.

---

## New Findings

### S-01 [MEDIUM]: Hash-to-G1 Uses Non-Standard Domain Separation

**Location**: `contracts/bridge/src/libraries/BLS12381.sol:78-90`

**Description**: The `hashToG1` function uses `MAP_FP_TO_G1` with a simple zero-padded hash as input. This does not follow the hash-to-curve specification (RFC 9380) which requires:
1. Domain separation tag (DST)
2. Expand message (XMD) 
3. Map to curve with cofactor clearing

The current implementation maps `Fp` elements directly to G1, which:
- May not produce uniformly distributed points
- Uses different domain than what validators sign with `blst`

**Impact**: Signature verification may fail even for valid signatures, or (worse) could accept invalid signatures in edge cases.

**Recommendation**:
```solidity
// Use proper hash_to_g1 with DST matching validator signing
bytes memory dst = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
// Implement full hash_to_curve or use a library that does
```

**Note**: This is partially mitigated because BLS mode isn't active in production yet. Fix before enabling BLS mode.

---

### S-02 [LOW]: Validator Removal Doesn't Invalidate Existing Votes

**Location**: `crates/precompiles/src/bridge/mod.rs:380-418`

**Description**: When a validator is deactivated via `change_validator_status`, their existing deposit votes remain counted. A malicious owner could:
1. Have 3 validators (threshold=2)
2. Validator A votes for deposit
3. Owner deactivates validator A
4. Validator B votes → threshold reached (but A's vote is stale)

**Impact**: Low - requires owner collusion, and votes are still from formerly-valid validators. But it violates the principle that only *currently* active validators should contribute to threshold.

**Recommendation**: Either:
1. Re-check `validator.active` when counting votes in `finalize_deposit`
2. Clear votes for a validator when they're deactivated (expensive)
3. Document as known limitation

---

### S-03 [LOW]: `_denormalizeAmount` Rounding Truncates for < 6 Decimal Tokens

**Location**: `contracts/bridge/src/StablecoinEscrow.sol:277-285`

**Description**: For tokens with <6 decimals, denormalization divides:
```solidity
if (decimals < 6) {
    return uint256(amount) / (10 ** (6 - decimals));
}
```

This loses precision. A burn of 999999 (6 decimals) for a 2-decimal token becomes `999999 / 10000 = 99` (value 0.99), losing 0.009999 worth of value.

**Impact**: Low - unlikely to have <6 decimal tokens, but dust loss is possible.

**Recommendation**: 
1. Require tokens to have ≥6 decimals in `addToken()`, OR
2. Track remainder and accumulate for later claims

---

## Informational Observations

### I-01: Threshold Calculation Edge Case with Even Validator Counts

**Location**: `contracts/bridge/src/TempoLightClient.sol:366-373`

The formula `(validators.length * 2 + 2) / 3` gives:
- 3 validators → threshold 3 (requires 100%, not 66%)
- 4 validators → threshold 3 (75%)
- 5 validators → threshold 4 (80%)
- 6 validators → threshold 5 (83%)

For 3 validators, this requires unanimous agreement. Consider if this is intended.

---

### I-02: No Mechanism to Recover Stuck Funds from Fee-on-Transfer Tokens

If a fee-on-transfer token is mistakenly added, the escrow receives less than `amount` but records the full `amount` in the deposit event. Unlocks would fail due to insufficient balance.

**Recommendation**: Document that fee-on-transfer tokens are not supported, or add balance-before/after check in `deposit()`.

---

### I-03: `finalizedAt` Timestamp Can Be Manipulated by Miners

The `finalizedAt[height]` timestamp uses `block.timestamp`, which miners can manipulate within ~15 seconds. This is only used for audit trail, so impact is informational only.

---

### I-04: Empty Signature Array Passes Threshold Check When Threshold is 0

**Location**: `contracts/bridge/src/TempoLightClient.sol:346-364`

If `validators.length == 0`, threshold is set to 1 (line 369), preventing the 0-threshold exploit. However, the check happens in `_updateThreshold()` which is only called on add/remove. If the contract is deployed and never adds validators, threshold remains 0 from default.

**Current Mitigation**: `_verifyThresholdSignatures` checks `signatures.length < threshold`, which passes if both are 0.

**Recommendation**: Initialize `threshold = 1` in constructor.

---

## Positive Security Properties Observed

1. **ReentrancyGuard** correctly applied to all external state-changing functions
2. **SafeERC20** used for all token transfers
3. **Ownable2Step** prevents accidental ownership transfer
4. **Sorted signature enforcement** prevents duplicate signer attacks
5. **Domain separation** properly implemented for burn IDs and attestations
6. **Pause mechanism** added with proper owner checks
7. **MIN_VALIDATORS** check prevents threshold collapse
8. **In-flight deduplication** prevents double-processing of deposits/burns

---

## Gas Optimizations (Non-Security)

1. `everSupportedTokens` could be packed with `supportedTokens` in a single mapping to struct
2. `_verifyValidatorSignatures` iterates validators even after threshold is met
3. BLS12381 library allocates new memory in loops; could be optimized

---

## Conclusion

The bridge remediation is thorough and addresses all Round 1 findings. The new findings are lower severity and represent defense-in-depth improvements rather than critical vulnerabilities.

**Recommended Priority**:
1. **S-01**: Fix before enabling BLS mode in production
2. **I-04**: Quick fix in constructor
3. **S-02, S-03**: Document as known limitations or fix in future update

The bridge is ready for testnet deployment. A focused review of the hash-to-curve implementation should be conducted before mainnet BLS mode activation.
