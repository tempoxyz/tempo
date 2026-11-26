// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// Must remain identical to the native outbox's PendingWithdrawal. `senderOrg` packs into the
// `gasLimit`/`fallbackNonce` slot, so the element size matches the pre-T15 layout.
struct PendingWithdrawal {
    address token;
    address sender;
    bytes32 txHash;
    address to;
    uint128 amount;
    bytes32 memo;
    uint64 gasLimit;
    uint64 fallbackNonce;
    uint64 senderOrg;
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
