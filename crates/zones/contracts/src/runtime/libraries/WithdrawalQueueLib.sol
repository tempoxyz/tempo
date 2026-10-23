// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Withdrawal } from "../interfaces/IZone.sol";

/// @dev Sentinel returned by `enqueue` (and emitted in `BatchSubmitted`) when a batch
///      carries no withdrawals and therefore consumes no queue index. Logical queue
///      indices are monotonically increasing counters that can never reach this value.
uint256 constant NO_QUEUE_INDEX = type(uint256).max;

/// @title WithdrawalQueue
/// @notice Unbounded FIFO for zone→Tempo withdrawals
/// @dev Each batch with a non-zero withdrawal hash chain gets its own slot; empty
///      batches (withdrawalQueueHash == 0) advance the batch index but do not consume
///      a slot. Head points to the oldest unprocessed batch,
///      tail points to where the next batch will write. Slots contain hash chains
///      of withdrawals for that batch. Head and tail are raw uint256 values that
///      never wrap. Each logical index is used directly as its storage key.
struct WithdrawalQueue {
    uint256 head; // logical index of oldest unprocessed batch
    uint256 tail; // logical index where next batch will write
    mapping(uint256 => bytes32) slots; // hash chains per batch (zero = empty)
}

/// @title WithdrawalQueueLib
/// @notice Library for managing the withdrawal FIFO
/// @dev Withdrawals are inserted by proofs (one slot per batch) and dequeued
///      on-chain by the sequencer. The sequencer processes withdrawals from
///      the head slot, advancing head when the slot is exhausted.
///
///      Invariants:
///      - Slots between head (inclusive) and tail (exclusive) contain withdrawal hash chains
///      - If head == tail, the queue is empty
///      - Exhausted slots before head are cleared to reclaim storage credits
library WithdrawalQueueLib {

    error InvalidWithdrawalProof();

    /// @notice Add a batch's withdrawals to the queue
    /// @dev Called during submitBatch. The batch's withdrawal hash chain goes into
    ///      the slot at tail, then tail advances.
    /// @param queue The withdrawal queue
    /// @param withdrawalQueueHash The hash chain of withdrawals for this batch (0 if none)
    /// @return assignedIndex The logical queue index the hash chain was stored under,
    ///         or NO_QUEUE_INDEX if the batch had no withdrawals
    function enqueue(
        WithdrawalQueue storage queue,
        bytes32 withdrawalQueueHash
    )
        internal
        returns (uint256 assignedIndex)
    {
        if (withdrawalQueueHash == bytes32(0)) {
            return NO_QUEUE_INDEX;
        }
        uint256 tail = queue.tail;

        queue.slots[tail] = withdrawalQueueHash;

        queue.tail = tail + 1;
        return tail;
    }

    /// @notice Pop the next withdrawal from the queue
    /// @dev Verifies the withdrawal is at the head of the current slot and advances.
    ///      When a slot is exhausted (remainingQueue would be empty), we clear it
    ///      to mint a TIP-1060 storage credit and advance head.
    /// @param queue The withdrawal queue
    /// @param withdrawal The withdrawal to pop (must be at head of current slot)
    /// @param remainingQueue The hash of the remaining queue after this withdrawal
    function dequeue(
        WithdrawalQueue storage queue,
        Withdrawal calldata withdrawal,
        bytes32 remainingQueue
    )
        internal
    {
        uint256 head = queue.head;

        bytes32 currentSlot = queue.slots[head];

        if (keccak256(abi.encode(withdrawal, remainingQueue)) != currentSlot) {
            revert InvalidWithdrawalProof();
        }

        queue.slots[head] = remainingQueue;
        if (remainingQueue == bytes32(0)) {
            queue.head = head + 1;
        }
    }

    /// @notice Check if the queue has any pending withdrawals
    /// @param queue The withdrawal queue
    /// @return True if there are withdrawals to process
    function hasWithdrawals(WithdrawalQueue storage queue) internal view returns (bool) {
        return queue.head != queue.tail;
    }

    /// @notice Get current queue length
    /// @param queue The withdrawal queue
    /// @return The number of batch slots with pending withdrawals
    function length(WithdrawalQueue storage queue) internal view returns (uint256) {
        return queue.tail - queue.head;
    }

}
