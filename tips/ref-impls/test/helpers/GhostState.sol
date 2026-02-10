// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity >=0.8.13 <0.9.0;

/// @title GhostState - Ghost Variable Tracking for Invariant Tests
/// @dev Ghost variables mirror what we expect on-chain state to be
abstract contract GhostState {

    // ============ Nonce Tracking ============

    mapping(address => uint256) public ghost_protocolNonce;
    mapping(address => mapping(uint256 => uint256)) public ghost_2dNonce;
    mapping(address => mapping(uint256 => bool)) public ghost_2dNonceUsed;
    /// @dev Array of 2D nonce keys used per account (for efficient iteration)
    mapping(address => uint256[]) public ghost_account2dNonceKeys;

    // ============ Transaction Tracking ============

    uint256 public ghost_totalTxExecuted;
    uint256 public ghost_totalTxReverted;
    uint256 public ghost_totalCallsExecuted;
    uint256 public ghost_totalCreatesExecuted;
    uint256 public ghost_totalProtocolNonceTxs;
    uint256 public ghost_total2dNonceTxs;
    uint256 public ghost_total2dNonceCreates;

    // ============ CREATE Tracking ============

    mapping(bytes32 => address) public ghost_createAddresses;
    mapping(address => uint256) public ghost_createCount;

    // ============ CREATE Rejection Tracking ============

    uint256 public ghost_createRejectedStructure; // C1, C2, C3, C4 rejections
    uint256 public ghost_createRejectedSize; // C8 rejections
    uint256 public ghost_createGasTracked; // C9 gas tracking count

    // Unexpected success tracking (for negative test cases)
    uint256 public ghost_createNotFirstAllowed; // C1 - CREATE not first unexpectedly allowed
    uint256 public ghost_createMultipleAllowed; // C2 - multiple creates unexpectedly allowed
    uint256 public ghost_createWithAuthAllowed; // C3 - CREATE with auth list unexpectedly allowed
    uint256 public ghost_createWithValueAllowed; // C4 - CREATE with value unexpectedly allowed
    uint256 public ghost_createOversizedAllowed; // C8 - oversized initcode unexpectedly allowed
    uint256 public ghost_replayProtocolAllowed; // N12 - protocol nonce replay unexpectedly allowed
    uint256 public ghost_replay2dAllowed; // N13 - 2D nonce replay unexpectedly allowed
    uint256 public ghost_nonceTooHighAllowed; // N14 - nonce too high unexpectedly allowed
    uint256 public ghost_nonceTooLowAllowed; // N15 - nonce too low unexpectedly allowed
    uint256 public ghost_keyWrongSignerAllowed; // K1 - wrong signer unexpectedly allowed
    uint256 public ghost_keyWrongChainAllowed; // K3 - wrong chain unexpectedly allowed
    uint256 public ghost_eip7702CreateWithAuthAllowed; // TX7 - CREATE with auth list unexpectedly allowed
    uint256 public ghost_timeBoundValidAfterAllowed; // T1 - validAfter not enforced
    uint256 public ghost_timeBoundValidBeforeAllowed; // T2 - validBefore not enforced

    // ============ Fee Collection Tracking (F1-F12) ============

    uint256 public ghost_totalFeesCollected;
    uint256 public ghost_totalFeesRefunded;
    mapping(address => uint256) public ghost_feesPaidByAccount;
    uint256 public ghost_feePrecollectedCount;
    uint256 public ghost_feeRefundOnSuccessCount;
    uint256 public ghost_feeNoRefundOnFailureCount;
    uint256 public ghost_feePaidOnRevertCount;
    uint256 public ghost_invalidFeeTokenRejected;
    uint256 public ghost_explicitFeeTokenUsed;
    uint256 public ghost_feeTokenFallbackUsed;
    uint256 public ghost_insufficientLiquidityRejected;
    uint256 public ghost_subblockFeesRejected;
    uint256 public ghost_subblockKeychainRejected;

    // ============ Access Key Tracking ============

    mapping(address => mapping(address => bool)) public ghost_keyAuthorized;
    mapping(address => mapping(address => uint256)) public ghost_keyExpiry;
    mapping(address => mapping(address => bool)) public ghost_keyEnforceLimits;
    mapping(address => mapping(address => mapping(address => uint256))) public
        ghost_keySpendingLimit;
    mapping(address => mapping(address => mapping(address => uint256))) public ghost_keySpentAmount;
    mapping(address => mapping(address => uint256)) public ghost_keySpendingPeriodStart;
    mapping(address => mapping(address => uint256)) public ghost_keySpendingPeriodDuration;
    mapping(address => mapping(address => uint8)) public ghost_keySignatureType;
    mapping(address => mapping(address => bool)) public ghost_keyUnlimitedSpending;

    // ============ Spending Limit Refund Tracking (K-REFUND) ============

    uint256 public ghost_keyRefundVerified;
    uint256 public ghost_keyRefundRevokedNoop;
    uint256 public ghost_keyRefundOverflowSafe;

    // ============ Access Key Invariant Tracking (K1-K3, K6, K10-K12, K16) ============

    uint256 public ghost_keyAuthRejectedWrongSigner;
    uint256 public ghost_keyAuthRejectedNotSelf;
    uint256 public ghost_keyAuthRejectedChainId;
    uint256 public ghost_keySameTxUsed;
    uint256 public ghost_keyPeriodReset;
    uint256 public ghost_keyUnlimitedUsed;
    uint256 public ghost_keyZeroLimitRejected;
    uint256 public ghost_keySigMismatchRejected;
    uint256 public ghost_keyZeroLimitAllowed; // K12 violation counter

    // ============ Negative Test Execution Tracking ============
    // These track that negative test handlers were actually executed (not just skipped)
    uint256 public ghost_replayProtocolAttempted;
    uint256 public ghost_replay2dAttempted;
    uint256 public ghost_nonceTooHighAttempted;
    uint256 public ghost_nonceTooLowAttempted;
    uint256 public ghost_createNotFirstAttempted;
    uint256 public ghost_createMultipleAttempted;
    uint256 public ghost_createWithAuthAttempted;
    uint256 public ghost_createWithValueAttempted;
    uint256 public ghost_createOversizedAttempted;

    // ============ Gas Tracking (G1-G10) ============

    uint256 public ghost_totalGasTracked;
    uint256 public ghost_gasTrackingBasic;
    uint256 public ghost_gasTrackingMulticall;
    uint256 public ghost_gasTrackingCreate;
    uint256 public ghost_gasTrackingSignature;
    uint256 public ghost_gasTrackingKeyAuth;

    // ============ Expiring Nonce Tracking (E1-E8) ============

    /// @dev Tracks which tx hashes have been executed (for replay detection)
    mapping(bytes32 => bool) public ghost_expiringNonceExecuted;
    /// @dev Total expiring nonce transactions executed
    uint256 public ghost_expiringNonceTxsExecuted;
    /// @dev E1 violation: replay within validity window allowed
    uint256 public ghost_expiringNonceReplayAllowed;
    /// @dev E2 violation: expired tx (validBefore <= now) allowed
    uint256 public ghost_expiringNonceExpiredAllowed;
    /// @dev E3 violation: validBefore > now + 30s allowed
    uint256 public ghost_expiringNonceWindowAllowed;
    /// @dev E4 violation: nonce != 0 allowed
    uint256 public ghost_expiringNonceNonZeroAllowed;
    /// @dev E5 violation: missing validBefore allowed
    uint256 public ghost_expiringNonceMissingVBAllowed;
    /// @dev Attempt counters for coverage tracking
    uint256 public ghost_expiringNonceReplayAttempted;
    uint256 public ghost_expiringNonceExpiredAttempted;
    uint256 public ghost_expiringNonceWindowAttempted;
    uint256 public ghost_expiringNonceNonZeroAttempted;
    uint256 public ghost_expiringNonceMissingVBAttempted;
    uint256 public ghost_expiringNonceConcurrentExecuted;

    // ============ Update Functions ============

    function _updateProtocolNonce(address account) internal {
        ghost_protocolNonce[account]++;
    }

    function _update2dNonce(address account, uint256 nonceKey) internal {
        ghost_2dNonce[account][nonceKey]++;
        _mark2dNonceKeyUsed(account, nonceKey);
    }

    /// @dev Mark a 2D nonce key as used and track in array for efficient iteration
    function _mark2dNonceKeyUsed(address account, uint256 nonceKey) internal {
        if (!ghost_2dNonceUsed[account][nonceKey]) {
            ghost_2dNonceUsed[account][nonceKey] = true;
            ghost_account2dNonceKeys[account].push(nonceKey);
        }
    }

    function _recordTxSuccess() internal {
        ghost_totalTxExecuted++;
    }

    function _recordTxRevert() internal {
        ghost_totalTxReverted++;
    }

    function _recordCallSuccess() internal {
        ghost_totalCallsExecuted++;
    }

    function _recordCreateSuccess(
        address caller,
        uint256 protocolNonce,
        address deployed
    )
        internal
    {
        bytes32 key = keccak256(abi.encodePacked(caller, protocolNonce));
        ghost_createAddresses[key] = deployed;
        ghost_createCount[caller]++;
        ghost_totalCreatesExecuted++;
    }

    function _authorizeKey(
        address owner,
        address keyId,
        uint256 expiry,
        bool enforceLimits,
        address[] memory tokens,
        uint256[] memory limits
    )
        internal
    {
        ghost_keyAuthorized[owner][keyId] = true;
        ghost_keyExpiry[owner][keyId] = expiry;
        ghost_keyEnforceLimits[owner][keyId] = enforceLimits;
        for (uint256 i = 0; i < tokens.length; i++) {
            ghost_keySpendingLimit[owner][keyId][tokens[i]] = limits[i];
        }
    }

    function _revokeKey(address owner, address keyId) internal {
        ghost_keyAuthorized[owner][keyId] = false;
        ghost_keyExpiry[owner][keyId] = 0;
    }

    function _recordKeySpending(
        address owner,
        address keyId,
        address token,
        uint256 amount
    )
        internal
    {
        ghost_keySpentAmount[owner][keyId][token] += amount;
    }

    function _recordCreateRejectedStructure() internal {
        ghost_createRejectedStructure++;
    }

    function _recordCreateRejectedSize() internal {
        ghost_createRejectedSize++;
    }

    function _recordCreateGasTracked() internal {
        ghost_createGasTracked++;
    }

    // ============ Fee Recording Functions ============

    function _recordFeeCollection(address account, uint256 amount) internal {
        ghost_totalFeesCollected += amount;
        ghost_feesPaidByAccount[account] += amount;
    }

    function _recordFeeRefund(uint256 amount) internal {
        ghost_totalFeesRefunded += amount;
    }

    function _recordFeePrecollected() internal {
        ghost_feePrecollectedCount++;
    }

    function _recordFeeRefundOnSuccess() internal {
        ghost_feeRefundOnSuccessCount++;
    }

    function _recordFeeNoRefundOnFailure() internal {
        ghost_feeNoRefundOnFailureCount++;
    }

    function _recordFeePaidOnRevert() internal {
        ghost_feePaidOnRevertCount++;
    }

    function _recordInvalidFeeTokenRejected() internal {
        ghost_invalidFeeTokenRejected++;
    }

    function _recordExplicitFeeTokenUsed() internal {
        ghost_explicitFeeTokenUsed++;
    }

    function _recordFeeTokenFallbackUsed() internal {
        ghost_feeTokenFallbackUsed++;
    }

    function _recordInsufficientLiquidityRejected() internal {
        ghost_insufficientLiquidityRejected++;
    }

    function _recordSubblockFeesRejected() internal {
        ghost_subblockFeesRejected++;
    }

    function _recordSubblockKeychainRejected() internal {
        ghost_subblockKeychainRejected++;
    }

    // ============ Gas Recording Functions ============

    function _recordGasTrackingBasic() internal {
        ghost_gasTrackingBasic++;
        ghost_totalGasTracked++;
    }

    function _recordGasTrackingMulticall() internal {
        ghost_gasTrackingMulticall++;
        ghost_totalGasTracked++;
    }

    function _recordGasTrackingCreate() internal {
        ghost_gasTrackingCreate++;
        ghost_totalGasTracked++;
    }

    function _recordGasTrackingSignature() internal {
        ghost_gasTrackingSignature++;
        ghost_totalGasTracked++;
    }

    function _recordGasTrackingKeyAuth() internal {
        ghost_gasTrackingKeyAuth++;
        ghost_totalGasTracked++;
    }

    // ============ Expected Rejection Recording Functions ============

    /// @notice Record key wrong signer rejection (K1, K7, K8)
    function _recordKeyWrongSigner() internal {
        ghost_keyAuthRejectedWrongSigner++;
    }

    /// @notice Record key zero limit rejection (K12)
    function _recordKeyZeroLimit() internal {
        ghost_keyZeroLimitRejected++;
    }

}
