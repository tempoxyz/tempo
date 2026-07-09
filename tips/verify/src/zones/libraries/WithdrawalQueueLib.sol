// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Withdrawal } from "../interfaces/IZone.sol";

/// @dev Sentinel value for empty slots. Using 0xff...ff instead of 0x00 to avoid
///      clearing storage (which would refund gas and create incentive issues).
bytes32 constant EMPTY_SENTINEL = bytes32(type(uint256).max);

/// @dev Fixed capacity for the withdrawal ring buffer (number of batch slots).
uint256 constant WITHDRAWAL_QUEUE_CAPACITY = 100;

/// @title WithdrawalQueue
/// @notice Fixed-size ring buffer for zone->Tempo withdrawals
/// @dev Each batch with a non-zero withdrawal hash chain gets its own slot; empty
///      batches (withdrawalQueueHash == 0) advance the batch index but do not consume
///      a slot. Head points to the oldest unprocessed batch,
///      tail points to where the next batch will write. Slots contain hash chains
///      of withdrawals for that batch. Head and tail are raw uint256 values that
///      never wrap; modular arithmetic (head % WITHDRAWAL_QUEUE_CAPACITY) is used
///      only for slot indexing.
struct WithdrawalQueue {
    uint256 head; // logical index of oldest unprocessed batch
    uint256 tail; // logical index where next batch will write
    mapping(uint256 => bytes32) slots; // hash chains per batch (EMPTY_SENTINEL = empty)
}

/// @title WithdrawalQueueLib
/// @notice Library for managing the withdrawal queue ring buffer
/// @dev Withdrawals are inserted by proofs (one slot per batch) and dequeued
///      on-chain by the sequencer. The sequencer processes withdrawals from
///      the head slot, advancing head when the slot is exhausted.
///
///      Invariants:
///      - Slots between head (inclusive) and tail (exclusive) contain withdrawal hash chains
///      - If head == tail, the queue is empty
///      - Slots at head contain EMPTY_SENTINEL only after being fully processed
///      - length() <= capacity at all times
library WithdrawalQueueLib {

    error NoWithdrawalsInQueue();
    error InvalidWithdrawalHash();
    error WithdrawalQueueFull();

    /// @notice Add a batch's withdrawals to the queue
    /// @dev Called during submitBatch. The batch's withdrawal hash chain goes into
    ///      the slot at tail % WITHDRAWAL_QUEUE_CAPACITY, then tail advances.
    /// @param queue The withdrawal queue
    /// @param withdrawalQueueHash The hash chain of withdrawals for this batch (0 if none)
    function enqueue(WithdrawalQueue storage queue, bytes32 withdrawalQueueHash) internal {
        if (withdrawalQueueHash == bytes32(0)) {
            return;
        }

        uint256 tail = queue.tail;

        if (tail - queue.head >= WITHDRAWAL_QUEUE_CAPACITY) {
            revert WithdrawalQueueFull();
        }

        queue.slots[tail % WITHDRAWAL_QUEUE_CAPACITY] = withdrawalQueueHash;

        queue.tail = tail + 1;
    }

    /// @notice Pop the next withdrawal from the queue
    /// @dev Verifies the withdrawal is at the head of the current slot and advances.
    ///      When a slot is exhausted (remainingQueue would be empty), we set it to
    ///      EMPTY_SENTINEL and advance head to the next slot.
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

        if (head == queue.tail) {
            revert NoWithdrawalsInQueue();
        }

        uint256 slotIndex = head % WITHDRAWAL_QUEUE_CAPACITY;
        bytes32 currentSlot = queue.slots[slotIndex];

        if (currentSlot == EMPTY_SENTINEL || remainingQueue == EMPTY_SENTINEL) {
            revert InvalidWithdrawalHash();
        }

        bytes32 expectedRemainingQueue =
            remainingQueue == bytes32(0) ? EMPTY_SENTINEL : remainingQueue;
        if (keccak256(abi.encode(withdrawal, expectedRemainingQueue)) != currentSlot) {
            revert InvalidWithdrawalHash();
        }

        if (remainingQueue == bytes32(0)) {
            queue.slots[slotIndex] = EMPTY_SENTINEL;
            queue.head = head + 1;
        } else {
            queue.slots[slotIndex] = remainingQueue;
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

    /// @notice Check if the queue is full
    /// @param queue The withdrawal queue
    /// @return True if length() == WITHDRAWAL_QUEUE_CAPACITY
    function isFull(WithdrawalQueue storage queue) internal view returns (bool) {
        return queue.tail - queue.head == WITHDRAWAL_QUEUE_CAPACITY;
    }

}
