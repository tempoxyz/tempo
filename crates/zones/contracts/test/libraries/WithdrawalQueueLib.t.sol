// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import { Withdrawal } from "../../src/runtime/interfaces/IZone.sol";
import {
    NO_QUEUE_INDEX,
    WithdrawalQueue,
    WithdrawalQueueLib
} from "../../src/runtime/libraries/WithdrawalQueueLib.sol";
import { Test } from "forge-std/Test.sol";

/// @title WithdrawalQueueHarness
/// @notice Test harness that wraps the library to convert memory to calldata
contract WithdrawalQueueHarness {

    using WithdrawalQueueLib for WithdrawalQueue;

    WithdrawalQueue internal queue;

    function enqueue(bytes32 withdrawalQueueHash) external returns (uint256 assignedIndex) {
        return queue.enqueue(withdrawalQueueHash);
    }

    function dequeue(Withdrawal calldata withdrawal, bytes32 remainingQueue) external {
        queue.dequeue(withdrawal, remainingQueue);
    }

    function hasWithdrawals() external view returns (bool) {
        return queue.hasWithdrawals();
    }

    function length() external view returns (uint256) {
        return queue.length();
    }

    function head() external view returns (uint256) {
        return queue.head;
    }

    function tail() external view returns (uint256) {
        return queue.tail;
    }

    function slots(uint256 index) external view returns (bytes32) {
        return queue.slots[index];
    }

    function setRawState(uint256 head, uint256 tail, uint256 slot, bytes32 value) external {
        queue.head = head;
        queue.tail = tail;
        queue.slots[slot] = value;
    }

}

/// @title WithdrawalQueueLibTest
/// @notice Direct tests for WithdrawalQueueLib functionality
contract WithdrawalQueueLibTest is Test {

    uint256 internal constant TEST_BATCH_COUNT = 100;

    WithdrawalQueueHarness internal harness;

    address public alice = address(0x200);
    address public bob = address(0x300);
    address public charlie = address(0x400);

    function setUp() public {
        harness = new WithdrawalQueueHarness();
    }

    /*//////////////////////////////////////////////////////////////
                          INITIAL STATE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_initialState() public view {
        assertEq(harness.head(), 0);
        assertEq(harness.tail(), 0);
        assertFalse(harness.hasWithdrawals());
        assertEq(harness.length(), 0);
    }

    /*//////////////////////////////////////////////////////////////
                            ENQUEUE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_enqueue_singleBatch() public {
        Withdrawal memory w = _makeWithdrawal(alice, bob, 100e6);
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        uint256 assignedIndex = harness.enqueue(wHash);

        assertEq(assignedIndex, 0);
        assertEq(harness.head(), 0);
        assertEq(harness.tail(), 1);
        assertEq(harness.slots(0), wHash);
        assertTrue(harness.hasWithdrawals());
        assertEq(harness.length(), 1);
    }

    function test_enqueue_multipleBatches() public {
        bytes32 h1 = keccak256("batch1");
        bytes32 h2 = keccak256("batch2");
        bytes32 h3 = keccak256("batch3");

        harness.enqueue(h1);
        assertEq(harness.tail(), 1);

        harness.enqueue(h2);
        assertEq(harness.tail(), 2);

        harness.enqueue(h3);
        assertEq(harness.tail(), 3);

        assertEq(harness.slots(0), h1);
        assertEq(harness.slots(1), h2);
        assertEq(harness.slots(2), h3);
        assertEq(harness.length(), 3);
    }

    function test_enqueue_emptyTransition_noOp() public {
        uint256 assignedIndex = harness.enqueue(bytes32(0));

        assertEq(assignedIndex, NO_QUEUE_INDEX);
        assertEq(harness.head(), 0);
        assertEq(harness.tail(), 0);
        assertFalse(harness.hasWithdrawals());
    }

    function test_enqueue_mixedEmptyAndNonEmpty() public {
        bytes32 h1 = keccak256("batch1");
        bytes32 h2 = keccak256("batch2");

        uint256 firstIndex = harness.enqueue(h1);
        assertEq(firstIndex, 0);
        assertEq(harness.tail(), 1);

        // Empty batch - no change
        uint256 emptyIndex = harness.enqueue(bytes32(0));
        assertEq(emptyIndex, NO_QUEUE_INDEX);
        assertEq(harness.tail(), 1);

        uint256 secondIndex = harness.enqueue(h2);
        assertEq(secondIndex, 1);
        assertEq(harness.tail(), 2);

        // Slots should be contiguous
        assertEq(harness.slots(0), h1);
        assertEq(harness.slots(1), h2);
    }

    function test_enqueue_isUnbounded() public {
        for (uint256 i = 0; i < TEST_BATCH_COUNT; i++) {
            harness.enqueue(keccak256(abi.encode("b", i)));
        }
        assertEq(harness.length(), TEST_BATCH_COUNT);

        bytes32 nextHash = keccak256("next");
        assertEq(harness.enqueue(nextHash), TEST_BATCH_COUNT);
        assertEq(harness.slots(TEST_BATCH_COUNT), nextHash);
        assertEq(harness.length(), TEST_BATCH_COUNT + 1);
    }

    function test_enqueue_afterDequeueUsesNextLogicalIndex() public {
        Withdrawal memory w1 = _makeWithdrawal(alice, bob, 100e6);
        bytes32 h1 = keccak256(abi.encode(w1, bytes32(0)));

        // Build a backlog.
        harness.enqueue(h1);
        for (uint256 i = 1; i < TEST_BATCH_COUNT; i++) {
            harness.enqueue(keccak256(abi.encode("b", i)));
        }
        assertEq(harness.length(), TEST_BATCH_COUNT);

        // Dequeue first to free a slot
        harness.dequeue(w1, bytes32(0));
        assertEq(harness.length(), TEST_BATCH_COUNT - 1);
        assertEq(harness.slots(0), bytes32(0));

        // Enqueue at the next logical index; cleared keys are not reused.
        bytes32 hNew = keccak256("new");
        uint256 assignedIndex = harness.enqueue(hNew);
        assertEq(assignedIndex, TEST_BATCH_COUNT);
        assertEq(harness.length(), TEST_BATCH_COUNT);

        assertEq(harness.slots(TEST_BATCH_COUNT), hNew);
    }

    /*//////////////////////////////////////////////////////////////
                            DEQUEUE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_dequeue_singleWithdrawal() public {
        Withdrawal memory w = _makeWithdrawal(alice, bob, 100e6);
        bytes32 wHash = keccak256(abi.encode(w, bytes32(0)));

        harness.enqueue(wHash);

        harness.dequeue(w, bytes32(0));

        assertEq(harness.head(), 1);
        assertEq(harness.tail(), 1);
        assertEq(harness.slots(0), bytes32(0));
        assertFalse(harness.hasWithdrawals());
    }

    function test_dequeue_multipleWithdrawalsInBatch() public {
        Withdrawal memory w1 = _makeWithdrawal(alice, bob, 100e6);
        Withdrawal memory w2 = _makeWithdrawal(bob, charlie, 200e6);

        // Build queue: w1 outermost, w2 innermost (terminates at zero)
        bytes32 innerHash = keccak256(abi.encode(w2, bytes32(0)));
        bytes32 batchHash = keccak256(abi.encode(w1, innerHash));

        harness.enqueue(batchHash);

        // Dequeue w1
        harness.dequeue(w1, innerHash);
        assertEq(harness.head(), 0); // Still on slot 0
        assertEq(harness.slots(0), innerHash);

        // Dequeue w2
        harness.dequeue(w2, bytes32(0));
        assertEq(harness.head(), 1);
        assertEq(harness.slots(0), bytes32(0));
    }

    function test_dequeue_multipleSlots() public {
        Withdrawal memory w1 = _makeWithdrawal(alice, bob, 100e6);
        Withdrawal memory w2 = _makeWithdrawal(bob, charlie, 200e6);

        bytes32 h1 = keccak256(abi.encode(w1, bytes32(0)));
        bytes32 h2 = keccak256(abi.encode(w2, bytes32(0)));

        harness.enqueue(h1);
        harness.enqueue(h2);

        // Dequeue from slot 0
        harness.dequeue(w1, bytes32(0));
        assertEq(harness.head(), 1);
        assertEq(harness.length(), 1);

        // Dequeue from slot 1
        harness.dequeue(w2, bytes32(0));
        assertEq(harness.head(), 2);
        assertEq(harness.length(), 0);
    }

    function test_dequeue_revertsIfEmpty() public {
        Withdrawal memory w = _makeWithdrawal(alice, bob, 100e6);

        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        harness.dequeue(w, bytes32(0));
    }

    function test_dequeue_revertsIfInvalidHash() public {
        Withdrawal memory w1 = _makeWithdrawal(alice, bob, 100e6);
        Withdrawal memory w2 = _makeWithdrawal(bob, charlie, 200e6);

        bytes32 h1 = keccak256(abi.encode(w1, bytes32(0)));
        harness.enqueue(h1);

        // Try to dequeue w2 (wrong withdrawal)
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        harness.dequeue(w2, bytes32(0));
    }

    function test_dequeue_revertsIfWrongRemainingQueue() public {
        Withdrawal memory w1 = _makeWithdrawal(alice, bob, 100e6);
        Withdrawal memory w2 = _makeWithdrawal(bob, charlie, 200e6);

        bytes32 innerHash = keccak256(abi.encode(w2, bytes32(0)));
        bytes32 batchHash = keccak256(abi.encode(w1, innerHash));

        harness.enqueue(batchHash);

        // Try to dequeue with wrong remaining queue
        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        harness.dequeue(w1, keccak256("wrongHash"));
    }

    function test_dequeue_revertsIfCurrentSlotIsEmpty() public {
        Withdrawal memory w = _makeWithdrawal(alice, bob, 100e6);
        harness.setRawState(0, 1, 0, bytes32(0));

        vm.expectRevert(WithdrawalQueueLib.InvalidWithdrawalProof.selector);
        harness.dequeue(w, bytes32(0));

        assertEq(harness.head(), 0);
        assertEq(harness.slots(0), bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
                         UNBOUNDED FIFO TESTS
    //////////////////////////////////////////////////////////////*/

    function test_enqueue_emptyTransitionDoesNotConsumeIndex() public {
        for (uint256 i = 0; i < TEST_BATCH_COUNT; i++) {
            harness.enqueue(keccak256(abi.encode("b", i)));
        }
        assertEq(harness.head(), 0);
        assertEq(harness.tail(), TEST_BATCH_COUNT);
        assertEq(harness.length(), TEST_BATCH_COUNT);

        harness.enqueue(bytes32(0));

        assertEq(harness.head(), 0);
        assertEq(harness.tail(), TEST_BATCH_COUNT);
        assertEq(harness.length(), TEST_BATCH_COUNT);
    }

    function test_fifoLogicalIndicesDoNotWrap() public {
        Withdrawal[] memory ws = new Withdrawal[](4);
        ws[0] = _makeWithdrawal(alice, bob, 100e6);
        ws[1] = _makeWithdrawal(bob, charlie, 200e6);
        ws[2] = _makeWithdrawal(alice, charlie, 300e6);
        ws[3] = _makeWithdrawal(charlie, alice, 400e6);

        bytes32[] memory hs = new bytes32[](4);
        for (uint256 i = 0; i < 4; i++) {
            hs[i] = keccak256(abi.encode(ws[i], bytes32(0)));
        }

        // Build a backlog and then advance the head.
        harness.enqueue(hs[0]);
        harness.enqueue(hs[1]);
        for (uint256 i = 2; i < TEST_BATCH_COUNT; i++) {
            harness.enqueue(keccak256(abi.encode("fill", i)));
        }
        assertEq(harness.head(), 0);
        assertEq(harness.tail(), TEST_BATCH_COUNT);

        // Cleared keys stay empty and new entries use monotonically increasing keys.
        harness.dequeue(ws[0], bytes32(0));
        harness.enqueue(hs[2]);
        assertEq(harness.head(), 1);
        assertEq(harness.tail(), TEST_BATCH_COUNT + 1);
        assertEq(harness.slots(0), bytes32(0));
        assertEq(harness.slots(TEST_BATCH_COUNT), hs[2]);

        harness.dequeue(ws[1], bytes32(0));
        harness.enqueue(hs[3]);
        assertEq(harness.head(), 2);
        assertEq(harness.tail(), TEST_BATCH_COUNT + 2);
        assertEq(harness.slots(1), bytes32(0));
        assertEq(harness.slots(TEST_BATCH_COUNT + 1), hs[3]);

        assertEq(harness.length(), TEST_BATCH_COUNT);
    }

    /// @notice A large queue dequeues every withdrawal in FIFO order and empties.
    function test_enqueueDequeue_largeBacklogInFifoOrder() public {
        Withdrawal[] memory withdrawals = new Withdrawal[](TEST_BATCH_COUNT);

        for (uint256 i = 0; i < TEST_BATCH_COUNT; i++) {
            withdrawals[i] = _makeWithdrawal(alice, bob, uint128(i + 1));
            harness.enqueue(keccak256(abi.encode(withdrawals[i], bytes32(0))));
            assertEq(harness.length(), i + 1);
        }

        assertEq(harness.length(), TEST_BATCH_COUNT);

        for (uint256 i = 0; i < TEST_BATCH_COUNT; i++) {
            harness.dequeue(withdrawals[i], bytes32(0));
            assertEq(harness.length(), TEST_BATCH_COUNT - i - 1);
        }

        assertFalse(harness.hasWithdrawals());
        assertEq(harness.head(), TEST_BATCH_COUNT);
        assertEq(harness.tail(), TEST_BATCH_COUNT);
    }

    /// @notice Dequeuing the last item clears the exhausted slot.
    function test_dequeue_clearsSlotWhenExhausted() public {
        Withdrawal memory w = _makeWithdrawal(alice, bob, 100e6);

        harness.enqueue(keccak256(abi.encode(w, bytes32(0))));
        harness.dequeue(w, bytes32(0));

        assertEq(harness.slots(0), bytes32(0));
        assertEq(harness.head(), 1);
        assertEq(harness.length(), 0);
    }

    /// @notice Fuzzed enqueues and dequeues preserve FIFO position and length.
    function testFuzz_enqueueDequeue_preservesFifoAndLength(bytes32 seed) public {
        uint256 count = (uint256(seed) % TEST_BATCH_COUNT) + 1;
        Withdrawal[] memory withdrawals = new Withdrawal[](count);

        for (uint256 i = 0; i < count; i++) {
            uint128 amount = uint128(uint256(keccak256(abi.encode(seed, "amount", i))));
            if (amount == 0) amount = 1;
            withdrawals[i] = _makeWithdrawal(
                address(uint160(uint256(keccak256(abi.encode(seed, "sender", i))))),
                address(uint160(uint256(keccak256(abi.encode(seed, "to", i))))),
                amount
            );
            harness.enqueue(keccak256(abi.encode(withdrawals[i], bytes32(0))));
            assertEq(harness.length(), i + 1);
        }

        uint256 dequeues = uint256(keccak256(abi.encode(seed, "dequeues"))) % (count + 1);
        for (uint256 i = 0; i < dequeues; i++) {
            harness.dequeue(withdrawals[i], bytes32(0));
            assertEq(harness.length(), count - i - 1);
            assertEq(harness.head(), i + 1);
        }

        if (dequeues == count) {
            assertFalse(harness.hasWithdrawals());
        } else {
            assertTrue(harness.hasWithdrawals());
            assertEq(harness.head(), dequeues);
            assertEq(harness.tail(), count);
        }
    }

    /*//////////////////////////////////////////////////////////////
                        LENGTH & HAS WITHDRAWALS
    //////////////////////////////////////////////////////////////*/

    function test_length_accurate() public {
        assertEq(harness.length(), 0);

        harness.enqueue(keccak256("b1"));
        assertEq(harness.length(), 1);

        harness.enqueue(keccak256("b2"));
        assertEq(harness.length(), 2);
    }

    function test_hasWithdrawals_accurate() public {
        assertFalse(harness.hasWithdrawals());

        harness.enqueue(keccak256("b1"));
        assertTrue(harness.hasWithdrawals());
    }

    /*//////////////////////////////////////////////////////////////
                            HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _makeWithdrawal(
        address sender,
        address to,
        uint128 amount
    )
        internal
        pure
        returns (Withdrawal memory)
    {
        return Withdrawal({
            token: address(0x100),
            senderTag: keccak256(abi.encodePacked(sender)),
            to: to,
            amount: amount,
            memo: bytes32(0),
            gasLimit: 0,
            fallbackNonce: uint64(uint160(sender)),
            callbackData: "",
            encryptedSender: ""
        });
    }

}
