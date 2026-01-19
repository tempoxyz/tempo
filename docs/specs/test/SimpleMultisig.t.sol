// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { SimpleMultisig } from "../src/SimpleMultisig.sol";
import { MultisigFactory } from "../src/MultisigFactory.sol";
import { IMultisigFactory } from "../src/interfaces/IMultisigFactory.sol";
import { Test } from "forge-std/Test.sol";

// ============ Mock Contracts ============

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function revertMe() external pure {
        revert("MockTarget: revert");
    }
}

contract ReentrantAttacker {
    SimpleMultisig public multisig;

    function setMultisig(SimpleMultisig m) external {
        multisig = m;
    }

    function attack() external {
        multisig.propose(address(this), 0, abi.encodeWithSelector(this.attack.selector));
    }
}

contract NotAMultisig {
    function MULTISIG_MAGIC() external pure returns (bytes4) {
        return 0xdeadbeef; // Wrong magic
    }
}

// ============ Factory Tests ============

contract MultisigFactoryTest is Test {
    MultisigFactory public factory;

    address public owner1 = address(0x100001);
    address public owner2 = address(0x100002);
    address public owner3 = address(0x100003);

    function setUp() public {
        factory = new MultisigFactory();
    }

    function test_createMultisig_basic() public {
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;

        address multisig = factory.createMultisig(owners, 1);

        assertTrue(factory.isMultisig(multisig));
        assertEq(SimpleMultisig(multisig).owners().length, 2);
        assertEq(SimpleMultisig(multisig).threshold(), 1);
    }

    function test_createMultisig_sortsOwners() public {
        address[] memory owners = new address[](3);
        owners[0] = owner3;
        owners[1] = owner1;
        owners[2] = owner2;

        address multisig = factory.createMultisig(owners, 2);

        address[] memory sorted = SimpleMultisig(multisig).owners();
        assertTrue(uint160(sorted[0]) < uint160(sorted[1]));
        assertTrue(uint160(sorted[1]) < uint160(sorted[2]));
    }

    function test_createMultisig_emitsEvent() public {
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner2;

        // We can't easily check the exact multisig address beforehand, but we can check the event is emitted
        vm.recordLogs();
        address multisig = factory.createMultisig(owners, 1);

        // Verify the multisig was created at a deterministic address
        address predicted = factory.getMultisigAddress(owners, 1);
        assertEq(multisig, predicted);
    }

    function test_createMultisig_revert_noOwners() public {
        address[] memory owners = new address[](0);
        vm.expectRevert(IMultisigFactory.NoOwners.selector);
        factory.createMultisig(owners, 1);
    }

    function test_createMultisig_revert_duplicateOwner() public {
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner1;
        vm.expectRevert(abi.encodeWithSelector(IMultisigFactory.DuplicateOwner.selector, owner1));
        factory.createMultisig(owners, 1);
    }

    function test_isMultisig_returnsFalseForEOA() public view {
        assertFalse(factory.isMultisig(owner1));
    }

    function test_isMultisig_returnsFalseForWrongMagic() public {
        NotAMultisig notMultisig = new NotAMultisig();
        assertFalse(factory.isMultisig(address(notMultisig)));
    }

    function test_isMultisig_returnsTrueForMultisig() public {
        address[] memory owners = new address[](1);
        owners[0] = owner1;
        address multisig = factory.createMultisig(owners, 1);

        assertTrue(factory.isMultisig(multisig));
    }

    function testFuzz_createMultisig(uint8 numOwners, uint8 threshold) public {
        numOwners = uint8(bound(numOwners, 1, 50));
        threshold = uint8(bound(threshold, 1, numOwners));

        address[] memory owners = new address[](numOwners);
        for (uint256 i = 0; i < numOwners; i++) {
            owners[i] = address(uint160(0x1000 + i));
        }

        address multisig = factory.createMultisig(owners, threshold);

        assertTrue(factory.isMultisig(multisig));
        assertEq(SimpleMultisig(multisig).threshold(), threshold);
    }
}

// ============ SimpleMultisig Tests ============

contract SimpleMultisigTest is Test {
    address public owner1 = address(0x1001);
    address public owner2 = address(0x1002);
    address public owner3 = address(0x1003);
    address public nonOwner = address(0x9999);

    function _createMultisig1of1() internal returns (SimpleMultisig) {
        address[] memory owners = new address[](1);
        owners[0] = owner1;
        return new SimpleMultisig(owners, 1);
    }

    function _createMultisig2of3() internal returns (SimpleMultisig) {
        address[] memory owners = new address[](3);
        owners[0] = owner1;
        owners[1] = owner2;
        owners[2] = owner3;
        return new SimpleMultisig(owners, 2);
    }

    // ============ Constructor Tests ============

    function test_constructor_singleOwner() public {
        SimpleMultisig multisig = _createMultisig1of1();
        assertEq(multisig.owners().length, 1);
        assertEq(multisig.threshold(), 1);
        assertTrue(multisig.isOwner(owner1));
    }

    function test_constructor_hasMagic() public {
        SimpleMultisig multisig = _createMultisig1of1();
        assertEq(multisig.MULTISIG_MAGIC(), bytes4(0x4d534947)); // "MSIG"
    }

    function test_constructor_revert_noOwners() public {
        address[] memory owners = new address[](0);
        vm.expectRevert(SimpleMultisig.NoOwners.selector);
        new SimpleMultisig(owners, 1);
    }

    function test_constructor_revert_duplicateOwner() public {
        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = owner1;
        vm.expectRevert(abi.encodeWithSelector(SimpleMultisig.DuplicateOwner.selector, owner1));
        new SimpleMultisig(owners, 1);
    }

    // ============ Propose Tests ============

    function test_propose_1of1_autoExecutes() public {
        SimpleMultisig multisig = _createMultisig1of1();
        MockTarget target = new MockTarget();

        vm.prank(owner1);
        uint256 txId =
            multisig.propose(address(target), 0, abi.encodeWithSelector(MockTarget.setValue.selector, 42));

        assertEq(txId, 0);
        assertEq(target.value(), 42);

        (,,, bool executed,,) = multisig.getTransaction(txId);
        assertTrue(executed);
    }

    function test_propose_2of3_requiresMultipleConfirmations() public {
        SimpleMultisig multisig = _createMultisig2of3();
        MockTarget target = new MockTarget();
        bytes memory data = abi.encodeWithSelector(MockTarget.setValue.selector, 100);

        // First proposal - creates tx
        vm.prank(owner1);
        uint256 txId = multisig.propose(address(target), 0, data);

        // Not yet executed
        (,,, bool executed1,,) = multisig.getTransaction(txId);
        assertFalse(executed1);
        assertEq(target.value(), 0);

        // Second proposal with same params - confirms and auto-executes
        vm.prank(owner2);
        uint256 txId2 = multisig.propose(address(target), 0, data);

        assertEq(txId, txId2); // Same txId
        (,,, bool executed2,,) = multisig.getTransaction(txId);
        assertTrue(executed2);
        assertEq(target.value(), 100);
    }

    function test_propose_revert_valueNotZero() public {
        SimpleMultisig multisig = _createMultisig1of1();

        vm.prank(owner1);
        vm.expectRevert(SimpleMultisig.ValueNotZero.selector);
        multisig.propose(address(0x1234), 100, "");
    }

    function test_propose_revert_notOwner() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(nonOwner);
        vm.expectRevert(abi.encodeWithSelector(SimpleMultisig.NotOwner.selector, nonOwner));
        multisig.propose(address(0x1234), 0, "");
    }

    function test_propose_revert_alreadyConfirmed() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        multisig.propose(address(0x1234), 0, "");

        // Same owner tries to confirm again
        vm.prank(owner1);
        vm.expectRevert(abi.encodeWithSelector(SimpleMultisig.AlreadyConfirmed.selector, 0, owner1));
        multisig.propose(address(0x1234), 0, "");
    }

    // ============ Revoke Tests ============

    function test_revoke_removesConfirmation() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        multisig.propose(address(0x1234), 0, "");

        assertEq(multisig.getValidConfirmationCount(0), 1);

        vm.prank(owner1);
        multisig.revoke(0);

        assertEq(multisig.getValidConfirmationCount(0), 0);
    }

    function test_revoke_revert_notConfirmed() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        multisig.propose(address(0x1234), 0, "");

        vm.prank(owner2);
        vm.expectRevert(abi.encodeWithSelector(SimpleMultisig.NotConfirmed.selector, 0, owner2));
        multisig.revoke(0);
    }

    // ============ Cancel Tests ============

    function test_cancel_requiresThreshold() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        uint256 txId = multisig.propose(address(0x1234), 0, "");

        // First cancel vote
        vm.prank(owner1);
        multisig.cancel(txId);

        (,,,, bool cancelled1,) = multisig.getTransaction(txId);
        assertFalse(cancelled1);

        // Second cancel vote reaches threshold
        vm.prank(owner2);
        multisig.cancel(txId);

        (,,,, bool cancelled2,) = multisig.getTransaction(txId);
        assertTrue(cancelled2);
    }

    function test_cancel_clearsProposal() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        multisig.propose(address(0x1234), 0, "");

        // Cancel it
        vm.prank(owner1);
        multisig.cancel(0);
        vm.prank(owner2);
        multisig.cancel(0);

        // Same proposal can be made again (gets new txId)
        vm.prank(owner1);
        uint256 newTxId = multisig.propose(address(0x1234), 0, "");

        assertEq(newTxId, 1); // New txId
    }

    // ============ Owner Management Tests ============

    function test_addOwner_viaSelfCall() public {
        SimpleMultisig multisig = _createMultisig1of1();
        address newOwner = address(0x5000);

        bytes memory data = abi.encodeWithSelector(SimpleMultisig.addOwner.selector, newOwner);

        vm.prank(owner1);
        multisig.propose(address(multisig), 0, data);

        assertTrue(multisig.isOwner(newOwner));
        assertEq(multisig.owners().length, 2);
    }

    function test_removeOwner_viaSelfCall() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // First lower threshold
        bytes memory data1 = abi.encodeWithSelector(SimpleMultisig.changeThreshold.selector, 1);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, data1);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, data1);

        // Then remove owner
        bytes memory data2 = abi.encodeWithSelector(SimpleMultisig.removeOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, data2);

        assertFalse(multisig.isOwner(owner3));
        assertEq(multisig.owners().length, 2);
    }

    function test_replaceOwner_viaSelfCall() public {
        SimpleMultisig multisig = _createMultisig2of3();
        address newOwner = address(0x5000);

        bytes memory data = abi.encodeWithSelector(SimpleMultisig.replaceOwner.selector, owner3, newOwner);

        vm.prank(owner1);
        multisig.propose(address(multisig), 0, data);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, data);

        assertFalse(multisig.isOwner(owner3));
        assertTrue(multisig.isOwner(newOwner));
    }

    // ============ Owner Change Effects on Confirmations ============

    function test_removedOwnerConfirmationDoesNotCount() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // Owner3 proposes a transaction
        vm.prank(owner3);
        multisig.propose(address(0x1234), 0, hex"01");

        // Change threshold to 1 first
        bytes memory thresholdData = abi.encodeWithSelector(SimpleMultisig.changeThreshold.selector, 1);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, thresholdData);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, thresholdData);

        // Remove owner3
        bytes memory removeData = abi.encodeWithSelector(SimpleMultisig.removeOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, removeData);

        // Owner3's confirmation no longer counts (they're not an owner)
        uint8 validCount = multisig.getValidConfirmationCount(0);
        assertEq(validCount, 0);
    }

    function test_replacedOwnerConfirmationDoesNotTransfer() public {
        SimpleMultisig multisig = _createMultisig2of3();
        address newOwner = address(0x5000);

        // Owner3 proposes
        vm.prank(owner3);
        multisig.propose(address(0x1234), 0, hex"02");

        // Replace owner3 with newOwner
        bytes memory data = abi.encodeWithSelector(SimpleMultisig.replaceOwner.selector, owner3, newOwner);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, data);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, data);

        // Owner3's confirmation does NOT transfer - newOwner must confirm separately
        uint8 validCount = multisig.getValidConfirmationCount(0);
        assertEq(validCount, 0); // No valid confirmations
    }

    function test_removedOwnerCancellationVoteDoesNotCount() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // Owner3 proposes a transaction
        vm.prank(owner3);
        multisig.propose(address(0x1234), 0, hex"01");

        // Owner3 votes to cancel
        vm.prank(owner3);
        multisig.cancel(0);

        // Change threshold to 1 first
        bytes memory thresholdData = abi.encodeWithSelector(SimpleMultisig.changeThreshold.selector, 1);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, thresholdData);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, thresholdData);

        // Remove owner3
        bytes memory removeData = abi.encodeWithSelector(SimpleMultisig.removeOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, removeData);

        // Owner3's cancellation vote should no longer count
        (,,,, bool cancelled,) = multisig.getTransaction(0);
        assertFalse(cancelled);

        // Now owner1 cancels - should work since threshold is 1
        vm.prank(owner1);
        multisig.cancel(0);

        (,,,, bool cancelledAfter,) = multisig.getTransaction(0);
        assertTrue(cancelledAfter);
    }

    // ============ Execution Failure Tests ============

    function test_propose_revert_executionFailed() public {
        SimpleMultisig multisig = _createMultisig1of1();
        MockTarget target = new MockTarget();

        bytes memory data = abi.encodeWithSelector(MockTarget.revertMe.selector);

        vm.prank(owner1);
        vm.expectRevert(); // ExecutionFailed
        multisig.propose(address(target), 0, data);
    }

    // ============ Reentrancy Tests ============

    function test_propose_revert_reentrancy() public {
        ReentrantAttacker attacker = new ReentrantAttacker();

        address[] memory owners = new address[](2);
        owners[0] = owner1;
        owners[1] = address(attacker);
        SimpleMultisig multisig = new SimpleMultisig(owners, 1);

        attacker.setMultisig(multisig);

        bytes memory data = abi.encodeWithSelector(ReentrantAttacker.attack.selector);

        vm.prank(owner1);
        vm.expectRevert(); // ReentrancyGuard
        multisig.propose(address(attacker), 0, data);
    }

    // ============ Execute Tests ============

    function test_execute_afterThresholdChange() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // Owner1 proposes (1 confirmation, needs 2)
        vm.prank(owner1);
        uint256 txId = multisig.propose(address(0x1234), 0, hex"aa");

        // Lower threshold to 1 via owner management
        bytes memory thresholdData = abi.encodeWithSelector(SimpleMultisig.changeThreshold.selector, 1);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, thresholdData);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, thresholdData);

        // Now txId 0 has 1 confirmation and threshold is 1
        // Owner1 already confirmed, so they call execute() instead
        vm.prank(owner1);
        multisig.execute(txId);

        (,,, bool executed,,) = multisig.getTransaction(txId);
        assertTrue(executed);
    }

    function test_execute_revert_thresholdNotMet() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        uint256 txId = multisig.propose(address(0x1234), 0, "");

        // Only 1 confirmation, needs 2
        vm.prank(owner1);
        vm.expectRevert(abi.encodeWithSelector(SimpleMultisig.ThresholdNotMet.selector, txId, 1, 2));
        multisig.execute(txId);
    }

    // ============ Owner Epoch Tests ============

    function test_readdedOwnerConfirmationInvalidated() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // Owner3 confirms tx 0
        vm.prank(owner3);
        multisig.propose(address(0x1234), 0, hex"bb");

        // Change threshold to 1
        bytes memory thresholdData = abi.encodeWithSelector(SimpleMultisig.changeThreshold.selector, 1);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, thresholdData);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, thresholdData);

        // Remove owner3
        bytes memory removeData = abi.encodeWithSelector(SimpleMultisig.removeOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, removeData);

        // Re-add owner3
        bytes memory addData = abi.encodeWithSelector(SimpleMultisig.addOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, addData);

        // Owner3's old confirmation should NOT count (epoch changed)
        uint8 validCount = multisig.getValidConfirmationCount(0);
        assertEq(validCount, 0);

        // Owner3 must re-confirm
        vm.prank(owner3);
        multisig.propose(address(0x1234), 0, hex"bb");

        validCount = multisig.getValidConfirmationCount(0);
        assertEq(validCount, 1);
    }

    function test_readdedOwnerCancellationVoteInvalidated() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // Owner3 proposes and votes to cancel
        vm.prank(owner3);
        multisig.propose(address(0x1234), 0, hex"cc");
        vm.prank(owner3);
        multisig.cancel(0);

        // Change threshold to 1
        bytes memory thresholdData = abi.encodeWithSelector(SimpleMultisig.changeThreshold.selector, 1);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, thresholdData);
        vm.prank(owner2);
        multisig.propose(address(multisig), 0, thresholdData);

        // Remove owner3
        bytes memory removeData = abi.encodeWithSelector(SimpleMultisig.removeOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, removeData);

        // Re-add owner3
        bytes memory addData = abi.encodeWithSelector(SimpleMultisig.addOwner.selector, owner3);
        vm.prank(owner1);
        multisig.propose(address(multisig), 0, addData);

        // Owner3's old cancellation vote should NOT count
        // Now owner3 votes again - should cancel since threshold is 1
        vm.prank(owner3);
        multisig.cancel(0);

        (,,,, bool cancelled,) = multisig.getTransaction(0);
        assertTrue(cancelled);
    }

    // ============ View Function Tests ============

    function test_getPendingTxId() public {
        SimpleMultisig multisig = _createMultisig2of3();

        // No pending tx yet
        uint256 pendingBefore = multisig.getPendingTxId(address(0x1234), 0, "");
        assertEq(pendingBefore, type(uint256).max);

        // Create proposal
        vm.prank(owner1);
        uint256 txId = multisig.propose(address(0x1234), 0, "");

        uint256 pendingAfter = multisig.getPendingTxId(address(0x1234), 0, "");
        assertEq(pendingAfter, txId);
    }

    function test_getConfirmations() public {
        SimpleMultisig multisig = _createMultisig2of3();

        vm.prank(owner1);
        uint256 txId = multisig.propose(address(0x1234), 0, hex"03");

        address[] memory confirmers = multisig.getConfirmations(txId);
        assertEq(confirmers.length, 1);
        assertEq(confirmers[0], owner1);
    }
}
