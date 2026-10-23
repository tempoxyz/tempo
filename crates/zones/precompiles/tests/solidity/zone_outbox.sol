// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// Must remain identical to PendingWithdrawal in the deleted ZoneOutbox reference contract's
// IZone.sol dependency (removed in zones#1198).
struct PendingWithdrawal {
    address token;
    address sender;
    bytes32 txHash;
    address to;
    uint128 amount;
    bytes32 memo;
    uint64 gasLimit;
    uint64 fallbackNonce;
    bytes callbackData;
    bytes revealTo;
}

/// Storage-only schema for the native ZoneOutbox precompile.
contract ZoneOutboxStorage {
    uint128 public tempoGasRate;
    uint64 public nextWithdrawalIndex;
    bytes32 internal _withdrawalQueueHash;
    uint64 internal _withdrawalBatchIndex;
    uint32 public maxWithdrawalsPerBlock;
    uint32 internal _withdrawalsThisBlock;
    uint64 internal _currentBlockNumber;
    uint64 public lastFinalizedTimestamp;
    PendingWithdrawal[] internal _pendingWithdrawals;
    uint64 public lastFallbackNonce;
    mapping(uint64 fallbackNonce => address zoneFallbackRecipient) internal _zoneFallbackRecipients;
}
